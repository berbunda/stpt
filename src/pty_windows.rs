//! ConPTY byte transport. Separate bounded reader/writer threads service the
//! synchronous pipes; the reader drains during asynchronous ConPTY teardown.
pub use crate::terminal::Size;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use windows_sys::Win32::System::{Console::*, Pipes::CreatePipe};

pub struct Console(
    Mutex<Option<HPCON>>,
    Mutex<Option<(OwnedHandle, OwnedHandle)>>,
);
impl Console {
    pub fn handle(&self) -> io::Result<HPCON> {
        self.0
            .lock()
            .unwrap()
            .ok_or_else(|| io::Error::other("ConPTY closed"))
    }
    pub fn release_endpoints(&self) {
        self.1.lock().unwrap().take();
    }
    pub fn close(&self) {
        self.release_endpoints();
        let Some(handle) = self.0.lock().unwrap().take() else {
            return;
        };
        if std::thread::Builder::new()
            .name("stpt-conpty-close".into())
            .spawn(move || {
                // SAFETY: this thread uniquely owns this live pseudoconsole handle.
                unsafe { ClosePseudoConsole(handle) };
            })
            .is_err()
        {
            // Reader queues are closed before teardown, so their independent
            // thread drains even if the OS cannot create another thread.
            unsafe { ClosePseudoConsole(handle) };
        }
    }
}
impl Drop for Console {
    fn drop(&mut self) {
        self.close();
    }
}
struct Input {
    data: Vec<u8>,
    done: oneshot::Sender<io::Result<()>>,
}
struct Output {
    receiver: mpsc::Receiver<io::Result<Vec<u8>>>,
    pending: Vec<u8>,
    position: usize,
}
pub struct Master {
    console: Arc<Console>,
    input: mpsc::Sender<Input>,
    output: tokio::sync::Mutex<Output>,
}
pub struct Pty {
    pub master: Master,
    pub slave: Arc<Console>,
}
fn coordinate(size: Size) -> io::Result<COORD> {
    Ok(COORD {
        X: i16::try_from(size.columns)
            .map_err(|_| io::Error::other("ConPTY columns exceed 32767"))?,
        Y: i16::try_from(size.rows).map_err(|_| io::Error::other("ConPTY rows exceed 32767"))?,
    })
}
pub(crate) fn pipe(inherit: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    let sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: inherit as i32,
    };
    // SAFETY: initialized out pointers; success transfers unique kernel handles.
    unsafe {
        if CreatePipe(&mut read, &mut write, &sa, 65536) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        ))
    }
}
impl Pty {
    pub fn open(size: Size) -> io::Result<Self> {
        let (input_read, input_write) = pipe(false)?;
        let (output_read, output_write) = pipe(false)?;
        let mut handle = 0;
        // SAFETY: pipe handles are retained through child creation, as required
        // by ConPTY; the Console releases these parent copies after CreateProcess.
        let hr = unsafe {
            CreatePseudoConsole(
                coordinate(size)?,
                input_read.as_raw_handle(),
                output_write.as_raw_handle(),
                0,
                &mut handle,
            )
        };
        if hr < 0 {
            return Err(io::Error::other(format!(
                "CreatePseudoConsole HRESULT {hr:#x}"
            )));
        }
        let console = Arc::new(Console(
            Mutex::new(Some(handle)),
            Mutex::new(Some((input_read, output_write))),
        ));
        let (tx, mut rx) = mpsc::channel::<Input>(8);
        std::thread::Builder::new()
            .name("stpt-conpty-input".into())
            .spawn(move || {
                let mut file = File::from(input_write);
                while let Some(input) = rx.blocking_recv() {
                    if input.data.is_empty() {
                        break;
                    }
                    let result = file.write_all(&input.data);
                    let failed = result.is_err();
                    let _ = input.done.send(result);
                    if failed {
                        break;
                    }
                }
            })?;
        let (out_tx, out_rx) = mpsc::channel(8);
        std::thread::Builder::new()
            .name("stpt-conpty-output".into())
            .spawn(move || {
                let mut file = File::from(output_read);
                let mut buf = vec![0; 16384];
                let mut discard = false;
                loop {
                    let result = match file.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => Ok(buf[..n].to_vec()),
                        Err(e) if matches!(e.raw_os_error(), Some(109 | 232)) => break,
                        Err(e) => Err(e),
                    };
                    let failed = result.is_err();
                    if !discard && out_tx.blocking_send(result).is_err() {
                        discard = true;
                    }
                    if failed {
                        break;
                    }
                }
            })?;
        Ok(Self {
            master: Master {
                console: console.clone(),
                input: tx,
                output: tokio::sync::Mutex::new(Output {
                    receiver: out_rx,
                    pending: Vec::new(),
                    position: 0,
                }),
            },
            slave: console,
        })
    }
}
impl Master {
    pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut out = self.output.lock().await;
        if out.position == out.pending.len() {
            match out.receiver.recv().await {
                Some(Ok(bytes)) => {
                    out.pending = bytes;
                    out.position = 0;
                }
                Some(Err(e)) => return Err(e),
                None => return Ok(0),
            }
        }
        let n = buffer.len().min(out.pending.len() - out.position);
        buffer[..n].copy_from_slice(&out.pending[out.position..out.position + n]);
        out.position += n;
        Ok(n)
    }
    pub async fn write_all(&self, data: &[u8]) -> io::Result<()> {
        for data in data.chunks(16384) {
            let (tx, rx) = oneshot::channel();
            self.input
                .send(Input {
                    data: data.to_vec(),
                    done: tx,
                })
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            rx.await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))??;
        }
        Ok(())
    }
    pub fn resize(&self, size: Size) -> io::Result<()> {
        // SAFETY: the Console keeps the pseudoconsole live during this call.
        let guard = self.console.0.lock().unwrap();
        let h = guard.ok_or_else(|| io::Error::other("ConPTY closed"))?;
        let result = unsafe { ResizePseudoConsole(h, coordinate(size)?) };
        if result < 0 {
            Err(io::Error::other(format!(
                "ResizePseudoConsole HRESULT {result:#x}"
            )))
        } else {
            Ok(())
        }
    }
    pub fn close(&self) {
        let (done, _) = oneshot::channel();
        let _ = self.input.try_send(Input {
            data: Vec::new(),
            done,
        });
        if let Ok(mut output) = self.output.try_lock() {
            output.receiver.close();
        }
        self.console.close();
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        self.close();
    }
}
