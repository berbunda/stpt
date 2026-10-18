//! The Client's local terminal: raw mode, window size, input and output as bytes.
//!
//! Output is written unchanged (PROTOCOL.md §14.7). On Windows it goes to the console
//! with WriteFile in the UTF-8 code page, as the console API of the standard library
//! accepts only valid UTF-8; console input is read with ReadConsoleW, as the standard
//! library would end the input at Ctrl+Z, which is an ordinary key for the Server.

use std::io;

use crate::terminal::Size;

/// Local terminal settings for a terminal Channel, restored when dropped.
pub struct Console {
    _saved: sys::Saved,
}

impl Console {
    /// With `raw`, input goes to the Server key by key, without local echo, line
    /// editing or signals (Ctrl+C is input for the remote PTY); only if standard
    /// input is a terminal.
    pub fn setup(raw: bool) -> io::Result<Console> {
        sys::setup(raw).map(|saved| Console { _saved: saved })
    }
}

/// Window size of the terminal on standard output; `None` without a terminal.
pub fn size() -> Option<Size> {
    sys::size().filter(|s| s.columns > 0 && s.rows > 0)
}

/// Notices that the window size may have changed: SIGWINCH on Unix. A Windows
/// console read with ReadConsoleW reports no size changes, so there it is a poll.
pub struct SizeChanges(sys::SizeChanges);

impl SizeChanges {
    pub fn new() -> io::Result<Self> {
        sys::SizeChanges::new().map(Self)
    }

    /// Waits for the next notice; false when there will be none.
    pub async fn next(&mut self) -> bool {
        self.0.next().await
    }
}

/// Prepares for the Client being told to end: on Unix HUP (the terminal window was
/// closed) and TERM; on Windows closing the console window, logoff, shutdown and
/// Ctrl+Break. Until then they end the process at once; afterwards the returned future
/// completes with the name of the event, so the Client can detach and close the
/// Connection regularly first. Windows gives the process 5 s after a close event.
pub fn termination() -> io::Result<impl Future<Output = &'static str>> {
    sys::termination()
}

/// Writes remote output to standard output, unbuffered.
pub fn write_out(data: &[u8]) -> io::Result<()> {
    sys::write(sys::Stream::Out, data)
}

/// Writes remote error output to standard error.
pub fn write_err(data: &[u8]) -> io::Result<()> {
    sys::write(sys::Stream::Err, data)
}

/// Reads standard input in its own thread and hands each piece to `deliver`, then
/// `None` at its end; stops when `deliver` returns false.
pub fn read_input(mut deliver: impl FnMut(Option<Vec<u8>>) -> bool + Send + 'static) {
    std::thread::spawn(move || {
        let mut reader = sys::Input::new();
        loop {
            match reader.read() {
                Ok(Some(data)) if data.is_empty() => continue,
                Ok(Some(data)) => {
                    if !deliver(Some(data)) {
                        return;
                    }
                }
                Ok(None) | Err(_) => {
                    deliver(None);
                    return;
                }
            }
        }
    });
}

#[cfg(unix)]
mod sys {
    use std::io::{self, IsTerminal, Read, Write};
    use std::os::fd::AsRawFd;

    use nix::pty::Winsize;
    use nix::sys::termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};

    use crate::terminal::Size;

    pub struct Saved(Option<Termios>);

    pub fn setup(raw: bool) -> io::Result<Saved> {
        let stdin = io::stdin();
        if !raw || !stdin.is_terminal() {
            return Ok(Saved(None));
        }
        let saved = tcgetattr(&stdin)?;
        let mut modes = saved.clone();
        cfmakeraw(&mut modes);
        tcsetattr(&stdin, SetArg::TCSADRAIN, &modes)?;
        Ok(Saved(Some(saved)))
    }

    impl Drop for Saved {
        fn drop(&mut self) {
            if let Some(saved) = &self.0 {
                let _ = tcsetattr(io::stdin(), SetArg::TCSADRAIN, saved);
            }
        }
    }

    nix::ioctl_read_bad!(get_winsize, nix::libc::TIOCGWINSZ, Winsize);

    pub fn size() -> Option<Size> {
        let mut w = Winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: the descriptor is standard output, the pointer a valid winsize.
        unsafe { get_winsize(io::stdout().as_raw_fd(), &mut w) }.ok()?;
        Some(Size {
            columns: w.ws_col,
            rows: w.ws_row,
            width: w.ws_xpixel,
            height: w.ws_ypixel,
        })
    }

    pub fn termination() -> io::Result<impl Future<Output = &'static str>> {
        use tokio::signal::unix::{SignalKind, signal};
        let mut hangup = signal(SignalKind::hangup())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok(async move {
            tokio::select! {
                _ = hangup.recv() => "HUP",
                _ = terminate.recv() => "TERM",
            }
        })
    }

    pub struct SizeChanges(tokio::signal::unix::Signal);

    impl SizeChanges {
        pub fn new() -> io::Result<Self> {
            use tokio::signal::unix::{SignalKind, signal};
            signal(SignalKind::window_change()).map(Self)
        }

        pub async fn next(&mut self) -> bool {
            self.0.recv().await.is_some()
        }
    }

    pub enum Stream {
        Out,
        Err,
    }

    pub fn write(stream: Stream, data: &[u8]) -> io::Result<()> {
        match stream {
            Stream::Out => {
                let mut out = io::stdout().lock();
                out.write_all(data)?;
                out.flush()
            }
            Stream::Err => io::stderr().lock().write_all(data),
        }
    }

    pub struct Input([u8; 4096]);

    impl Input {
        pub fn new() -> Self {
            Self([0; 4096])
        }

        /// The next piece of input; `None` at its end.
        pub fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
            match io::stdin().lock().read(&mut self.0)? {
                0 => Ok(None),
                n => Ok(Some(self.0[..n].to_vec())),
            }
        }
    }
}

#[cfg(windows)]
mod sys {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::ManuallyDrop;
    use std::os::windows::io::FromRawHandle;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleOutputCP,
        GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleW, STD_ERROR_HANDLE, STD_HANDLE,
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode, SetConsoleOutputCP,
    };

    use crate::terminal::Size;

    const CP_UTF8: u32 = 65001;

    fn handle(which: STD_HANDLE) -> HANDLE {
        // SAFETY: GetStdHandle has no preconditions.
        unsafe { GetStdHandle(which) }
    }

    /// The console mode of a handle; `None` if it is not a console.
    fn mode(handle: HANDLE) -> Option<CONSOLE_MODE> {
        let mut mode = 0;
        // SAFETY: `mode` is a valid out pointer; a non-console handle fails.
        (unsafe { GetConsoleMode(handle, &mut mode) } != 0).then_some(mode)
    }

    pub struct Saved {
        input: Option<CONSOLE_MODE>,
        output: Option<(CONSOLE_MODE, u32)>,
    }

    pub fn setup(raw: bool) -> io::Result<Saved> {
        let mut saved = Saved {
            input: None,
            output: None,
        };
        let out = handle(STD_OUTPUT_HANDLE);
        if let Some(old) = mode(out) {
            let mut new = old | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if raw {
                // A remote PTY sends CR LF itself.
                new |= DISABLE_NEWLINE_AUTO_RETURN;
            }
            // SAFETY: plain calls on the console handle.
            unsafe {
                saved.output = Some((old, GetConsoleOutputCP()));
                SetConsoleMode(out, new);
                SetConsoleOutputCP(CP_UTF8);
            }
        }
        let input = handle(STD_INPUT_HANDLE);
        if raw && let Some(old) = mode(input) {
            let new = (old & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT;
            // SAFETY: plain call on the console handle.
            if unsafe { SetConsoleMode(input, new) } == 0 {
                return Err(io::Error::last_os_error());
            }
            saved.input = Some(old);
        }
        Ok(saved)
    }

    impl Drop for Saved {
        fn drop(&mut self) {
            // SAFETY: plain calls on the console handles.
            unsafe {
                if let Some((mode, code_page)) = self.output {
                    SetConsoleMode(handle(STD_OUTPUT_HANDLE), mode);
                    SetConsoleOutputCP(code_page);
                }
                if let Some(mode) = self.input {
                    SetConsoleMode(handle(STD_INPUT_HANDLE), mode);
                }
            }
        }
    }

    pub fn size() -> Option<Size> {
        // SAFETY: an all-zero CONSOLE_SCREEN_BUFFER_INFO is valid.
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid out pointer.
        if unsafe { GetConsoleScreenBufferInfo(handle(STD_OUTPUT_HANDLE), &mut info) } == 0 {
            return None;
        }
        let window = info.srWindow;
        Some(Size {
            columns: (window.Right - window.Left + 1).max(0) as u16,
            rows: (window.Bottom - window.Top + 1).max(0) as u16,
            width: 0,
            height: 0,
        })
    }

    pub fn termination() -> io::Result<impl Future<Output = &'static str>> {
        use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_logoff, ctrl_shutdown};
        let mut close = ctrl_close()?;
        let mut logoff = ctrl_logoff()?;
        let mut shutdown = ctrl_shutdown()?;
        let mut ctrl_break = ctrl_break()?;
        Ok(async move {
            tokio::select! {
                _ = close.recv() => "closing the console",
                _ = logoff.recv() => "logoff",
                _ = shutdown.recv() => "shutdown",
                _ = ctrl_break.recv() => "Ctrl+Break",
            }
        })
    }

    /// Polling interval of the window size.
    const SIZE_POLL: std::time::Duration = std::time::Duration::from_millis(250);

    pub struct SizeChanges(tokio::time::Interval);

    impl SizeChanges {
        pub fn new() -> io::Result<Self> {
            let mut interval = tokio::time::interval(SIZE_POLL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            Ok(Self(interval))
        }

        pub async fn next(&mut self) -> bool {
            self.0.tick().await;
            true
        }
    }

    pub enum Stream {
        Out,
        Err,
    }

    /// Writes with WriteFile, so bytes reach a console (in the UTF-8 code page) or a
    /// pipe unchanged.
    pub fn write(stream: Stream, data: &[u8]) -> io::Result<()> {
        let which = match stream {
            Stream::Out => STD_OUTPUT_HANDLE,
            Stream::Err => STD_ERROR_HANDLE,
        };
        // SAFETY: the standard handle stays open; ManuallyDrop never closes it.
        let file = ManuallyDrop::new(unsafe { File::from_raw_handle(handle(which)) });
        (&*file).write_all(data)
    }

    pub struct Input {
        console: bool,
        /// A high surrogate whose low half has not been read yet.
        pending: Option<u16>,
    }

    impl Input {
        pub fn new() -> Self {
            Self {
                console: mode(handle(STD_INPUT_HANDLE)).is_some(),
                pending: None,
            }
        }

        /// The next piece of input as UTF-8 (console) or bytes (pipe, file); `None` at
        /// its end. May return an empty piece.
        pub fn read(&mut self) -> io::Result<Option<Vec<u8>>> {
            if !self.console {
                let mut buf = [0; 4096];
                return match io::stdin().lock().read(&mut buf)? {
                    0 => Ok(None),
                    n => Ok(Some(buf[..n].to_vec())),
                };
            }
            let mut buf = [0u16; 1024];
            let mut read = 0;
            // SAFETY: `buf` holds 1024 units, `read` is a valid out pointer.
            let ok = unsafe {
                ReadConsoleW(
                    handle(STD_INPUT_HANDLE),
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut units: Vec<u16> = self.pending.take().into_iter().collect();
            units.extend_from_slice(&buf[..read as usize]);
            if let Some(&last) = units.last()
                && (0xD800..0xDC00).contains(&last)
            {
                self.pending = units.pop();
            }
            let text: String = char::decode_utf16(units)
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect();
            Ok(Some(text.into_bytes()))
        }
    }
}
