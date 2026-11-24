//! Trusted local terminal. A private pairing file authenticates the local
//! connection in both directions, including if a stale port has been reused.
use aws_lc_rs::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
#[cfg(unix)]
use std::fs::File;
use std::{
    io::{self, IsTerminal, Read, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
pub const ENV: &str = "STPT_CONSENT_FILE";
pub fn random() -> io::Result<[u8; 32]> {
    let mut b = [0; 32];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| io::Error::other("random source unavailable"))?;
    Ok(b)
}
#[derive(Clone)]
pub struct Pair {
    pub mount: bool,
    pub port: u16,
    key: [u8; 32],
}
impl Pair {
    pub fn new(port: u16) -> io::Result<Self> {
        Ok(Self {
            mount: false,
            port,
            key: random()?,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.port.to_be_bytes().to_vec();
        b.extend(self.key);
        b
    }
    pub fn decode(b: &[u8]) -> io::Result<Self> {
        if b.len() != 34 {
            return Err(io::Error::other("invalid local pairing"));
        }
        Ok(Self {
            mount: false,
            port: u16::from_be_bytes([b[0], b[1]]),
            key: b[2..].try_into().unwrap(),
        })
    }
    fn proof(&self, role: u8, a: &[u8], b: &[u8]) -> hmac::Tag {
        let mut c = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, &self.key));
        c.update(&[role]);
        c.update(a);
        c.update(b);
        c.sign()
    }
    async fn verify(stream: &mut TcpStream, tag: hmac::Tag) -> io::Result<()> {
        let mut got = [0; 32];
        stream.read_exact(&mut got).await?;
        aws_lc_rs::constant_time::verify_slices_are_equal(&got, tag.as_ref())
            .map_err(|_| io::Error::other("local authentication failed"))
    }
    pub async fn connect(&self) -> io::Result<TcpStream> {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)).await?;
        let a = random()?;
        s.write_all(&a).await?;
        let mut b = [0; 32];
        s.read_exact(&mut b).await?;
        Self::verify(&mut s, self.proof(1, &a, &b)).await?;
        s.write_all(self.proof(2, &a, &b).as_ref()).await?;
        Ok(s)
    }
    pub async fn accept(&self, l: &TcpListener) -> io::Result<TcpStream> {
        let (mut s, _) = l.accept().await?;
        let mut a = [0; 32];
        s.read_exact(&mut a).await?;
        let b = random()?;
        s.write_all(&b).await?;
        s.write_all(self.proof(1, &a, &b).as_ref()).await?;
        Self::verify(&mut s, self.proof(2, &a, &b)).await?;
        Ok(s)
    }
    pub fn load(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        let f = {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let f = File::options()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(path)?;
            if f.metadata()?.uid() != nix::unistd::geteuid().as_raw()
                || f.metadata()?.mode() & 0o077 != 0
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            f
        };
        #[cfg(windows)]
        let f = {
            let f = crate::windows_security::open_read(path)?;
            crate::windows_security::check_handle(&f, true)?;
            f
        };
        if !f.metadata()?.is_file() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut data = Vec::new();
        f.take(35).read_to_end(&mut data)?;
        Self::decode(&data)
    }
}
pub async fn put(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    let len = u16::try_from(b.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    s.write_u16(len).await?;
    s.write_all(b).await
}
pub async fn get(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut b = vec![0; s.read_u16().await? as usize];
    s.read_exact(&mut b).await?;
    Ok(b)
}
pub fn run() -> io::Result<ExitCode> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(io::Error::other(
            "consent requires a dedicated local terminal",
        ));
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve())
}
async fn serve() -> io::Result<ExitCode> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let pair = Pair::new(l.local_addr()?.port())?;
    let dir = crate::config::client_dir()
        .ok_or_else(|| io::Error::other("no Client configuration directory"))?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "consent-{}",
        crate::terminal::SessionId::generate()
    ));
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?
    };
    #[cfg(windows)]
    let mut file = crate::windows_security::create_private(&path)?;
    file.write_all(&pair.encode())?;
    drop(file);
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(path.clone());
    eprintln!(
        "In the local shell that starts stpt connect or exec, set {ENV} to the following file and keep this terminal open:\n{}",
        path.display()
    );
    let (tx, mut lines) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in io::stdin().lock().lines() {
            if let Ok(line) = line
                && tx.blocking_send(line).is_ok()
            {
                continue;
            }
            break;
        }
    });
    let service = async {
        loop {
            // A slow or unauthenticated local connector cannot hold the prompt.
            let mut s = match tokio::time::timeout(Duration::from_secs(3), pair.accept(&l)).await {
                Ok(Ok(s)) => s,
                _ => continue,
            };
            let interaction = async {
                let context = get(&mut s).await?;
                let text = std::str::from_utf8(&context).map_err(|_| io::ErrorKind::InvalidData)?;
                eprintln!(
                    "File request: {}\nEnter an absolute local path, or press Enter to refuse:",
                    text.escape_debug()
                );
                let Some(path) = line_or_cancel(&mut s, &mut lines).await? else {
                    return Ok::<_, io::Error>(false);
                };
                if !Path::new(&path).is_absolute() {
                    put(&mut s, &[]).await?;
                    return Ok(false);
                }
                put(&mut s, path.as_bytes()).await?;
                if s.read_u8().await? != 1 {
                    return Ok(false);
                }
                let token = crate::terminal::SessionId::generate().to_string();
                let answer = format!("yes {}", &token[..8]);
                eprintln!(
                    "Allow {} for {:?}? Type {answer} to approve:",
                    text.escape_debug(),
                    path
                );
                let confirmed = line_or_cancel(&mut s, &mut lines)
                    .await?
                    .is_some_and(|line| line == answer);
                s.write_u8(u8::from(confirmed)).await?;
                Ok(confirmed && text.starts_with("mount directory read-only"))
            };
            if let Ok(Ok(true)) = tokio::time::timeout(Duration::from_secs(70), interaction).await {
                eprintln!("Read-only directory approved. Press Enter to revoke.");
                let _ = line_or_cancel(&mut s, &mut lines).await;
            }
            eprintln!("Request closed.");
        }
    };
    tokio::select! {_ = service=>{}, _=tokio::signal::ctrl_c()=>{}}
    Ok(ExitCode::SUCCESS)
}
async fn line_or_cancel(
    s: &mut TcpStream,
    lines: &mut tokio::sync::mpsc::Receiver<String>,
) -> io::Result<Option<String>> {
    tokio::select! {biased;_ =s.read_u8()=>Ok(None),line=lines.recv()=>Ok(line)}
}
