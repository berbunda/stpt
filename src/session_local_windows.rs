//! A local-only pipe instance stays owned by the Server for the Session lifetime.
use super::*;
use std::os::windows::io::AsRawHandle;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions},
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED},
    Storage::FileSystem::SECURITY_ANONYMOUS,
    System::Pipes::GetNamedPipeClientProcessId,
};
fn name(id: &str) -> String {
    format!(r"\\.\pipe\stpt-session-{id}")
}
pub struct Endpoint(NamedPipeServer);
impl Endpoint {
    pub fn new(id: crate::terminal::SessionId, _: &mut Vec<(String, String)>) -> io::Result<Self> {
        Ok(Self(
            ServerOptions::new()
                .first_pipe_instance(true)
                .max_instances(1)
                .reject_remote_clients(true)
                .create(name(&id.to_string()))?,
        ))
    }
    pub async fn serve(mut self, session: &Session) -> io::Result<()> {
        loop {
            if let Err(e) = self.0.connect().await {
                // An opener can leave before ConnectNamedPipe observes it.
                if e.raw_os_error() == Some(ERROR_NO_DATA as i32) {
                    let _ = self.0.disconnect();
                    continue;
                }
                return Err(e);
            }
            let mut pid = 0;
            // Kernel-reported opener, checked against the owned Session Job.
            if unsafe { GetNamedPipeClientProcessId(self.0.as_raw_handle(), &mut pid) } != 0
                && session.owns_local_pid(pid)
            {
                let _ = tokio::time::timeout(TIMEOUT, async {
                    let mut b = [0u8; 18];
                    self.0.read_exact(&mut b).await?;
                    let data = super::reply(session, &b);
                    self.0.write_u16(data.len() as u16).await?;
                    self.0.write_all(&data).await?;
                    // Avoid DisconnectNamedPipe discarding bytes before the caller reads them.
                    self.0.read_u8().await
                })
                .await;
            }
            if let Err(e) = self.0.disconnect()
                && e.raw_os_error() != Some(ERROR_PIPE_NOT_CONNECTED as i32)
            {
                return Err(e);
            }
        }
    }
}
pub fn call(b: [u8; 18]) -> io::Result<Vec<u8>> {
    let id =
        std::env::var("STPT_SESSION").map_err(|_| io::Error::other("outside an STPT Session"))?;
    if id.len() != 32 || !id.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err(io::Error::other("invalid Session ID"));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(TIMEOUT, async {
            let mut pipe = loop {
                match ClientOptions::new()
                    .security_qos_flags(SECURITY_ANONYMOUS)
                    .open(name(&id))
                {
                    Ok(p) => break p,
                    Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(e) => return Err(e),
                }
            };
            pipe.write_all(&b).await?;
            let n = pipe.read_u16().await? as usize;
            if n > MAX_REPLY {
                return Err(io::Error::other("oversized Session reply"));
            }
            let mut data = vec![0; n];
            pipe.read_exact(&mut data).await?;
            let _ = pipe.write_u8(1).await;
            Ok(data)
        })
        .await?
    })
}
