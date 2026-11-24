//! Session-local PF002 commands. Local messages carry no Session ID or path.
use crate::session::Session;
use clap::Subcommand;
use std::{io, process::ExitCode, time::Duration};

#[cfg(target_os = "linux")]
#[path = "session_local_linux.rs"]
mod transport;
#[cfg(windows)]
#[path = "session_local_windows.rs"]
mod transport;
#[cfg(not(any(windows, target_os = "linux")))]
mod transport {
    use super::*;
    pub struct Endpoint;
    impl Endpoint {
        pub fn new(
            _: crate::terminal::SessionId,
            _: &mut Vec<(String, String)>,
        ) -> io::Result<Self> {
            Ok(Self)
        }
        pub async fn serve(self, _: &Session) -> io::Result<()> {
            Ok(())
        }
    }
    pub fn call(_: [u8; 18]) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no Session command transport on this platform",
        ))
    }
}
pub use transport::Endpoint;

pub const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REPLY: usize = 8192;
#[derive(Debug, Subcommand)]
pub enum Action {
    /// List live Attachment IDs in this Session
    Attachments,
    /// Request a regular file from the selected Client
    Read {
        #[arg(long)]
        attachment: Option<u64>,
    },
    /// Ask the selected Client to create a new file of this size
    Create {
        bytes: u64,
        #[arg(long)]
        attachment: Option<u64>,
    },
    /// Ask to mount a directory of the selected Client read-only
    Mount {
        #[arg(long)]
        attachment: Option<u64>,
    },
}
impl Action {
    fn encode(&self) -> [u8; 18] {
        let (op, target, bytes) = match *self {
            Self::Attachments => (0, None, 0),
            Self::Read { attachment } => (1, attachment, 0),
            Self::Create { bytes, attachment } => (2, attachment, bytes),
            Self::Mount { attachment } => (3, attachment, 0),
        };
        let mut b = [0; 18];
        b[0] = op;
        b[1] = u8::from(target.is_some()) | if matches!(op, 1..=3) { 0x80 } else { 0 };
        b[2..10].copy_from_slice(&target.unwrap_or(0).to_be_bytes());
        b[10..].copy_from_slice(&bytes.to_be_bytes());
        b
    }
    fn decode(b: &[u8; 18]) -> Option<Self> {
        let id = u64::from_be_bytes(b[2..10].try_into().ok()?);
        let flag = if matches!(b[0], 1..=3) { 0x80 } else { 0 };
        let target = match (b[1] ^ flag, id) {
            (0, 0) => None,
            (1, n) => Some(n),
            _ => return None,
        };
        let bytes = u64::from_be_bytes(b[10..].try_into().ok()?);
        match (b[0], bytes) {
            (0, 0) if target.is_none() => Some(Self::Attachments),
            (1, 0) => Some(Self::Read { attachment: target }),
            (2, 0..=2305843009213693951) => Some(Self::Create {
                bytes,
                attachment: target,
            }),
            (3, 0) => Some(Self::Mount { attachment: target }),
            _ => None,
        }
    }
    pub fn target(&self) -> Option<u64> {
        match *self {
            Self::Attachments => None,
            Self::Read { attachment }
            | Self::Create { attachment, .. }
            | Self::Mount { attachment } => attachment,
        }
    }
}
pub fn select<T>(
    mut slots: impl Iterator<Item = (u64, T)>,
    target: Option<u64>,
) -> Result<(u64, T), &'static str> {
    if let Some(id) = target {
        return slots.find(|s| s.0 == id).ok_or("Attachment is not live");
    }
    let first = slots.next().ok_or("no live Attachment")?;
    if slots.next().is_some() {
        return Err("several live Attachments; specify --attachment ID");
    }
    Ok(first)
}

pub enum Reply {
    Ids(String),
    Transfer(crate::consent::Pair),
}
fn reply(session: &Session, b: &[u8; 18]) -> Vec<u8> {
    let result = Action::decode(b)
        .ok_or_else(|| "invalid Session request".to_string())
        .and_then(|action| session.local_request(action));
    let (code, msg) = match result {
        Ok(Reply::Ids(text)) => (0, text),
        Ok(Reply::Transfer(p)) => {
            let mut b = vec![2];
            b.extend(p.encode());
            return b;
        }
        Err(text) => (1, text),
    };
    if msg.len() >= MAX_REPLY {
        return b"\x01Attachment list exceeds local limit".to_vec();
    }
    let mut data = vec![code];
    data.extend(msg.bytes());
    data
}
pub fn run(action: Action) -> io::Result<ExitCode> {
    let request = action.encode();
    if Action::decode(&request).is_none() {
        return Err(io::Error::other("invalid Session request or file size"));
    }
    let data = transport::call(request)?;
    let (&status, body) = data
        .split_first()
        .ok_or_else(|| io::Error::other("empty Session reply"))?;
    if status == 2 {
        return crate::reverse::caller(crate::consent::Pair::decode(body)?, action);
    }
    // Only decimal IDs and line breaks may reach stdout; diagnostics are escaped.
    if status == 0 && body.iter().all(|b| b.is_ascii_digit() || *b == b'\n') {
        use io::Write;
        io::stdout().lock().write_all(body)?;
        Ok(ExitCode::SUCCESS)
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(body).escape_debug().to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attachment_selection_is_scoped_to_one_snapshot() {
        assert!(select(std::iter::empty::<(u64, ())>(), None).is_err());
        let old = select([(7, "A")].into_iter(), None).unwrap();
        let shared = [(7, "A"), (8, "B (read-only)")];
        assert!(select(shared.into_iter(), None).is_err());
        assert_eq!(select(shared.into_iter(), Some(8)).unwrap(), shared[1]);
        assert_eq!(old, (7, "A"));
        assert!(select([shared[1]].into_iter(), Some(old.0)).is_err());
    }
    #[test]
    fn create_request_preserves_size_and_explicit_target() {
        let request = Action::Create {
            bytes: 500,
            attachment: Some(9),
        };
        assert!(matches!(
            Action::decode(&request.encode()),
            Some(Action::Create {
                bytes: 500,
                attachment: Some(9)
            })
        ));
        let mut bad = request.encode();
        bad[0] = 1;
        assert!(Action::decode(&bad).is_none());
    }
}
