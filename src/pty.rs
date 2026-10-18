//! Pseudo-terminals of the Server (Unix; PROTOCOL.md §14.6, §14.8).
//!
//! The Server keeps the master side; the slave side becomes the controlling terminal
//! of the Session's processes. Terminal modes are the system defaults plus UTF-8 input
//! processing (`IUTF8`) where the platform has it. Both descriptors are close-on-exec,
//! so no other process inherits them by accident.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::pty::{Winsize, openpty};
use tokio::io::unix::AsyncFd;

pub use crate::terminal::Size;

fn winsize(size: Size) -> Winsize {
    Winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: size.width,
        ws_ypixel: size.height,
    }
}

/// A new PTY: the master for the Server, the slave for the processes.
pub struct Pty {
    pub master: Master,
    pub slave: OwnedFd,
}

impl Pty {
    /// Opens a PTY with the given window size. Needs a Tokio runtime.
    pub fn open(size: Size) -> io::Result<Pty> {
        let pair = openpty(&winsize(size), None)?;
        set_cloexec(&pair.master)?;
        set_cloexec(&pair.slave)?;
        set_utf8_input(&pair.slave)?;
        Ok(Pty {
            master: Master::new(pair.master)?,
            slave: pair.slave,
        })
    }
}

/// The master side: input is written to it, output read from it.
pub struct Master(AsyncFd<OwnedFd>);

nix::ioctl_write_ptr_bad!(set_winsize, nix::libc::TIOCSWINSZ, Winsize);

impl Master {
    fn new(fd: OwnedFd) -> io::Result<Master> {
        let flags = OFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFL)?);
        fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        // SAFETY: the OwnedFd is moved into the AsyncFd, so the descriptor stays open
        // and the same for the AsyncFd's whole lifetime.
        Ok(Master(unsafe { AsyncFd::register(fd) }?))
    }

    /// Reads output. 0 means end of output: no process holds the slave side any more
    /// (Linux reports that as EIO).
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.0.readable().await?;
            match guard.try_io(|fd| Ok(nix::unistd::read(fd.get_ref(), buf)?)) {
                Ok(Err(e)) if e.raw_os_error() == Some(nix::libc::EIO) => return Ok(0),
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes all of `data` as input, waiting while the PTY input buffer is full.
    pub async fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let mut guard = self.0.writable().await?;
            match guard.try_io(|fd| Ok(nix::unistd::write(fd.get_ref(), data)?)) {
                Ok(Ok(n)) => data = &data[n..],
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }

    /// Sets the window size; the kernel sends SIGWINCH to the foreground process group.
    #[allow(dead_code, reason = "applied from RC004 on")]
    pub fn resize(&self, size: Size) -> io::Result<()> {
        // SAFETY: the descriptor is open and the pointer refers to a valid winsize.
        unsafe { set_winsize(self.0.as_raw_fd(), &winsize(size)) }?;
        Ok(())
    }
}

fn set_cloexec(fd: impl AsFd) -> io::Result<()> {
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn set_utf8_input(slave: &OwnedFd) -> io::Result<()> {
    use nix::sys::termios::{InputFlags, SetArg, tcgetattr, tcsetattr};
    let mut modes = tcgetattr(slave)?;
    modes.input_flags |= InputFlags::IUTF8;
    tcsetattr(slave, SetArg::TCSANOW, &modes)?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn set_utf8_input(_slave: &OwnedFd) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    nix::ioctl_read_bad!(get_winsize, nix::libc::TIOCGWINSZ, Winsize);

    const SIZE: Size = Size {
        columns: 80,
        rows: 24,
        width: 640,
        height: 480,
    };

    fn size_of(fd: &OwnedFd) -> Size {
        let mut w = winsize(Size {
            columns: 0,
            rows: 0,
            width: 0,
            height: 0,
        });
        unsafe { get_winsize(fd.as_raw_fd(), &mut w) }.unwrap();
        Size {
            columns: w.ws_col,
            rows: w.ws_row,
            width: w.ws_xpixel,
            height: w.ws_ypixel,
        }
    }

    async fn read_until_end(master: &Master) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0; 1024];
        loop {
            match master.read(&mut buf).await.unwrap() {
                0 => return out,
                n => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    #[tokio::test]
    async fn size_on_open_and_resize() {
        let pty = Pty::open(SIZE).unwrap();
        assert_eq!(size_of(&pty.slave), SIZE);
        let new = Size {
            columns: 132,
            rows: 43,
            width: 0,
            height: 0,
        };
        pty.master.resize(new).unwrap();
        assert_eq!(size_of(&pty.slave), new);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn utf8_input() {
        use nix::sys::termios::{InputFlags, tcgetattr};
        let pty = Pty::open(SIZE).unwrap();
        let modes = tcgetattr(&pty.slave).unwrap();
        assert!(modes.input_flags.contains(InputFlags::IUTF8));
    }

    #[tokio::test]
    async fn close_on_exec() {
        let pty = Pty::open(SIZE).unwrap();
        for fd in [pty.master.0.get_ref(), &pty.slave] {
            let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD).unwrap());
            assert!(flags.contains(FdFlag::FD_CLOEXEC));
        }
    }

    #[tokio::test]
    async fn output_then_end() {
        let Pty { master, slave } = Pty::open(SIZE).unwrap();
        nix::unistd::write(&slave, b"hello\n").unwrap();
        drop(slave);
        // The PTY turns "\n" into "\r\n" (ONLCR).
        assert_eq!(read_until_end(&master).await, b"hello\r\n");
    }

    #[tokio::test]
    async fn input_is_echoed_and_read_as_line() {
        let Pty { master, slave } = Pty::open(SIZE).unwrap();
        master.write_all(b"ls\n").await.unwrap();
        let mut line = [0; 16];
        let n = nix::unistd::read(&slave, &mut line).unwrap();
        assert_eq!(&line[..n], b"ls\n");
        drop(slave);
        assert_eq!(read_until_end(&master).await, b"ls\r\n");
    }
}
