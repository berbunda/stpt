//! File profile messages shared by the CLI and the unprivileged worker (§16).
use crate::cbor::Value;
use crate::wire::{Failure, Message};

pub const RESULT: u64 = 0x4002;
pub const ENTRIES: u64 = 0x4003;
pub const ACCEPTED: u64 = 0x4004;
pub const DATA: u64 = 0x4005;
pub const END: u64 = 0x4006;
pub const RECEIVED: u64 = 0x4007;
pub const MAX_SIZE: u64 = (1u64 << 61) - 1;
pub const CHUNK: usize = 32768;
pub const MAX_CHUNK: usize = 61440;
pub const DEFAULT_MAX_SIZE: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    Access = 2,
    Exists = 3,
    NotDirectory = 4,
    IsDirectory = 5,
    NotEmpty = 6,
    InvalidPath = 7,
    NoSpace = 8,
    ReadOnly = 9,
    Unsupported = 10,
    Limit = 11,
    Io = 12,
    Integrity = 13,
    ResumeUnavailable = 14,
    ResumeBusy = 15,
}
impl Status {
    pub fn from_value(n: u64) -> Self {
        match n {
            0 => Self::Ok,
            1 => Self::NotFound,
            2 => Self::Access,
            3 => Self::Exists,
            4 => Self::NotDirectory,
            5 => Self::IsDirectory,
            6 => Self::NotEmpty,
            7 => Self::InvalidPath,
            8 => Self::NoSpace,
            9 => Self::ReadOnly,
            10 => Self::Unsupported,
            11 => Self::Limit,
            13 => Self::Integrity,
            14 => Self::ResumeUnavailable,
            15 => Self::ResumeBusy,
            _ => Self::Io,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::NotFound => "NOT_FOUND",
            Self::Access => "ACCESS_DENIED",
            Self::Exists => "ALREADY_EXISTS",
            Self::NotDirectory => "NOT_DIRECTORY",
            Self::IsDirectory => "IS_DIRECTORY",
            Self::NotEmpty => "NOT_EMPTY",
            Self::InvalidPath => "INVALID_PATH",
            Self::NoSpace => "NO_SPACE",
            Self::ReadOnly => "READ_ONLY",
            Self::Unsupported => "UNSUPPORTED",
            Self::Limit => "LIMIT_EXCEEDED",
            Self::Io => "IO_ERROR",
            Self::Integrity => "INTEGRITY_ERROR",
            Self::ResumeUnavailable => "RESUME_UNAVAILABLE",
            Self::ResumeBusy => "RESUME_BUSY",
        }
    }
}
pub fn uint(m: &Message, k: u64) -> Result<u64, Failure> {
    m.field(k).and_then(Value::as_uint).ok_or_else(|| {
        Failure::violation(format!(
            "file message {}: field {k} missing or not uint",
            m.kind
        ))
    })
}
pub fn id(m: &Message, expected: u64) -> Result<(), Failure> {
    if uint(m, 0)? != expected {
        return Err(Failure::violation("incorrect file operation ID"));
    }
    Ok(())
}
pub fn size(m: &Message, k: u64) -> Result<u64, Failure> {
    let n = uint(m, k)?;
    if n > MAX_SIZE {
        return Err(Failure::violation("file size exceeds wire bound"));
    }
    Ok(n)
}
pub fn status(m: &Message) -> Result<Status, Failure> {
    Ok(Status::from_value(uint(m, 1)?))
}
pub fn result(id: u64, status: Status, metadata: Option<Value>) -> Message {
    let mut fields = vec![(0, Value::Uint(id)), (1, Value::Uint(status as u64))];
    if let Some(meta) = metadata {
        fields.push((2, meta));
    }
    Message::new(RESULT, fields)
}
pub fn accepted(id: u64, length: u64, algorithm: u64) -> Message {
    Message::new(
        ACCEPTED,
        vec![
            (0, Value::Uint(id)),
            (1, Value::Uint(length)),
            (2, Value::Uint(algorithm)),
        ],
    )
}
pub fn data(id: u64, offset: u64, bytes: Vec<u8>) -> Message {
    Message::new(
        DATA,
        vec![
            (0, Value::Uint(id)),
            (1, Value::Uint(offset)),
            (2, Value::Bytes(bytes)),
        ],
    )
}
pub fn end(id: u64, status: Status, count: u64, digest: Option<[u8; 32]>) -> Message {
    let mut f = vec![
        (0, Value::Uint(id)),
        (1, Value::Uint(status as u64)),
        (2, Value::Uint(count)),
    ];
    if let Some(d) = digest {
        f.push((3, Value::Bytes(d.to_vec())));
    }
    Message::new(END, f)
}
pub fn receipt(id: u64, status: Status) -> Message {
    Message::new(
        RECEIVED,
        vec![(0, Value::Uint(id)), (1, Value::Uint(status as u64))],
    )
}

#[derive(Clone)]
pub struct Request {
    pub id: u64,
    pub kind: u64,
    pub path: Value,
    pub destination: Option<Value>,
    pub replace: bool,
    pub length: Option<u64>,
    pub algorithm: u64,
    pub resume: Option<Value>,
}
impl Request {
    pub fn parse(m: &Message) -> Result<Self, Failure> {
        if m.kind != crate::wire::FILE_REQUEST {
            return Err(Failure::violation("expected FILE_REQUEST"));
        }
        let kind = uint(m, 1)?;
        let path = m
            .field(2)
            .ok_or_else(|| Failure::violation("missing file path"))?
            .clone();
        validate_path_shape(&path)?;
        if let Some(p) = m.field(3) {
            validate_path_shape(p)?;
        }
        let replace = match m.field(4) {
            None => false,
            Some(Value::Bool(b)) => *b,
            _ => return Err(Failure::violation("replace is not bool")),
        };
        let length = m.field(5).map(|_| size(m, 5)).transpose()?;
        let algorithm = m.field(6).map(|_| uint(m, 6)).transpose()?.unwrap_or(1);
        if (kind == 7) != m.field(3).is_some()
            || (kind == 2) != length.is_some()
            || (m.field(4).is_some() && kind != 2 && kind != 7)
            || (m.field(6).is_some() && kind != 1 && kind != 2)
            || (m.field(7).is_some() && kind != 1 && kind != 2)
        {
            return Err(Failure::violation(
                "fields not permitted for file operation",
            ));
        }
        if let Some(resume) = m.field(7) {
            let a = resume
                .as_array()
                .ok_or_else(|| Failure::violation("resume is not array"))?;
            let mode = a
                .first()
                .and_then(Value::as_uint)
                .ok_or_else(|| Failure::violation("invalid resume mode"))?;
            let valid = match mode {
                0 => kind == 2 && a.len() == 1,
                1 => kind == 2 && a.len() == 2 && matches!(&a[1],Value::Bytes(v) if v.len()==32),
                2 => {
                    kind == 1
                        && a.len() == 4
                        && a[1].as_uint().is_some_and(|n| n <= MAX_SIZE)
                        && a[2]
                            .as_uint()
                            .is_some_and(|n| n > 0 && n <= a[1].as_uint().unwrap_or(0))
                        && matches!(&a[3],Value::Bytes(v) if v.len()==32)
                }
                _ => true,
            };
            if !valid {
                return Err(Failure::violation("invalid resume request"));
            }
        }
        Ok(Self {
            id: uint(m, 0)?,
            kind,
            path,
            destination: m.field(3).cloned(),
            replace,
            length,
            algorithm,
            resume: m.field(7).cloned(),
        })
    }
}
pub fn validate_path_shape(path: &Value) -> Result<(), Failure> {
    let a = path
        .as_array()
        .ok_or_else(|| Failure::violation("file path is not array"))?;
    match a.first().and_then(Value::as_uint) {
        Some(0)
            if a.len() == 2
                && a[1]
                    .as_array()
                    .is_some_and(|v| v.iter().all(|n| matches!(n, Value::Bytes(_)))) =>
        {
            Ok(())
        }
        Some(1)
            if a.len() == 3
                && matches!(a[1], Value::Text(_))
                && a[2]
                    .as_array()
                    .is_some_and(|v| v.iter().all(|n| matches!(n, Value::Text(_)))) =>
        {
            Ok(())
        }
        _ => Err(Failure::violation("invalid file path shape")),
    }
}
pub fn valid_posix_component(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes != b"."
        && bytes != b".."
        && !bytes.contains(&0)
        && !bytes.contains(&b'/')
}

/// Component rules of the remote Windows namespace, independent of host OS.
/// Native volume type and reparse traversal checks belong to the Server backend.
pub fn valid_windows_component(name: &str) -> bool {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || name
            .chars()
            .any(|c| c <= '\u{1f}' || "<>:\"/\\|?*".contains(c))
    {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return false;
    }
    if let Some(suffix) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        && matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    {
        return false;
    }
    true
}
/// Shape errors are protocol violations; invalid contents are operation statuses.
pub fn valid_path_contents(path: &Value, root: bool) -> Result<bool, Failure> {
    validate_path_shape(path)?;
    let a = path.as_array().unwrap();
    let kind = a[0].as_uint().unwrap();
    let names = a[if kind == 0 { 1 } else { 2 }].as_array().unwrap();
    if names.is_empty() && !root {
        return Ok(false);
    }
    Ok(if kind == 0 {
        names
            .iter()
            .all(|n| matches!(n,Value::Bytes(b) if valid_posix_component(b)))
    } else {
        matches!(&a[1],Value::Text(d) if d.len()==1 && d.as_bytes()[0].is_ascii_uppercase())
            && names
                .iter()
                .all(|n| matches!(n,Value::Text(t) if valid_windows_component(t)))
    })
}
/// Validate one received listing name for the requested remote path kind.
pub fn valid_entry_name(name: &Value, path_kind: u64) -> bool {
    match (name, path_kind) {
        (Value::Bytes(b), 0) => valid_posix_component(b),
        (Value::Text(t), 1) => valid_windows_component(t),
        _ => false,
    }
}

#[derive(Clone)]
pub enum Hash {
    Blake3(Box<blake3::Hasher>),
    Sha256(aws_lc_rs::digest::Context),
}
impl Hash {
    pub fn new(id: u64) -> Option<Self> {
        match id {
            1 => Some(Self::Blake3(Box::new(blake3::Hasher::new()))),
            2 => Some(Self::Sha256(aws_lc_rs::digest::Context::new(
                &aws_lc_rs::digest::SHA256,
            ))),
            _ => None,
        }
    }
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Blake3(h) => {
                h.update(bytes);
            }
            Self::Sha256(h) => h.update(bytes),
        }
    }
    pub fn finish(self) -> [u8; 32] {
        match self {
            Self::Blake3(h) => *h.finalize().as_bytes(),
            Self::Sha256(h) => h.finish().as_ref().try_into().unwrap(),
        }
    }
}
pub fn bytes(m: &Message, expected: u64, offset: u64, length: u64) -> Result<&[u8], Failure> {
    id(m, expected)?;
    let data = match m.field(2) {
        Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= MAX_CHUNK => b.as_slice(),
        _ => return Err(Failure::violation("invalid FILE_DATA bytes")),
    };
    if size(m, 1)? != offset
        || offset
            .checked_add(data.len() as u64)
            .is_none_or(|n| n > length)
    {
        return Err(Failure::violation("noncontiguous or excess file data"));
    }
    Ok(data)
}
pub fn verify_end(
    m: &Message,
    expected: u64,
    count: u64,
    length: u64,
    digest: [u8; 32],
) -> Result<Status, Failure> {
    if m.kind != END {
        return Err(Failure::violation("expected FILE_END"));
    }
    id(m, expected)?;
    let status = status(m)?;
    let declared = size(m, 2)?;
    let received = match (status, m.field(3)) {
        (Status::Ok, Some(Value::Bytes(b))) if b.len() == 32 => Some(b.as_slice()),
        (Status::Ok, _) => return Err(Failure::violation("missing FILE_END digest")),
        (_, None) => None,
        _ => return Err(Failure::violation("digest in failed FILE_END")),
    };
    if declared != count
        || (status == Status::Ok && (count != length || received != Some(digest.as_slice())))
    {
        Ok(Status::Integrity)
    } else {
        Ok(status)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Metadata {
    pub kind: u64,
    pub size: Option<u64>,
    pub modified: Option<(i64, u32)>,
    pub mode: Option<u16>,
    pub readonly: Option<bool>,
}
pub fn validate_metadata(value: &Value, path_kind: u64) -> Result<Metadata, Failure> {
    let m = Message {
        kind: RESULT,
        body: value
            .as_map()
            .ok_or_else(|| Failure::violation("metadata is not map"))?
            .to_vec(),
    };
    if !m.body.iter().all(|(k, _)| k.is_int()) {
        return Err(Failure::violation("invalid metadata key"));
    }
    let kind = uint(&m, 0)?;
    let length = m.field(1).map(|_| uint(&m, 1)).transpose()?;
    if (kind == 1) != length.is_some() && kind <= 3 {
        return Err(Failure::violation("invalid metadata size"));
    }
    let mut modified = None;
    if let Some(t) = m.field(2) {
        let a = t
            .as_array()
            .ok_or_else(|| Failure::violation("invalid mtime"))?;
        if a.len() != 2
            || !matches!(&a[0],Value::Uint(v)|Value::Nint(v) if *v<=i64::MAX as u64)
            || a[1].as_uint().is_none_or(|v| v > 999999999)
        {
            return Err(Failure::violation("invalid mtime"));
        }
        let seconds = match a[0] {
            Value::Uint(v) => v as i64,
            Value::Nint(v) => -1 - (v as i64),
            _ => unreachable!(),
        };
        modified = Some((seconds, a[1].as_uint().unwrap() as u32));
    }
    if m.field(3)
        .is_some_and(|v| v.as_uint().is_none_or(|n| n > 511))
        || m.field(4).is_some_and(|v| !matches!(v, Value::Bool(_)))
    {
        return Err(Failure::violation("invalid metadata attributes"));
    }
    if (path_kind == 0 && m.field(4).is_some()) || (path_kind == 1 && m.field(3).is_some()) {
        return Err(Failure::violation(
            "metadata attribute belongs to the other path kind",
        ));
    }
    let mode = m.field(3).and_then(Value::as_uint).map(|n| n as u16);
    let readonly = m.field(4).map(|v| matches!(v, Value::Bool(true)));
    Ok(Metadata {
        kind,
        size: if kind <= 3 { length } else { None },
        modified: if kind <= 3 { modified } else { None },
        mode: if kind <= 3 { mode } else { None },
        readonly: if kind <= 3 { readonly } else { None },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Requested,
    Upload,
    Download,
    DownloadEnded,
    Result,
    Idle,
}
/// Validates input concurrently with bulk output, before forwarding it to a worker.
pub struct Exchange {
    phase: Phase,
    id: u64,
    kind: u64,
    length: u64,
    count: u64,
}
impl Exchange {
    pub fn new(q: &Request) -> Result<Self, Failure> {
        if q.id != 0 {
            return Err(Failure::violation("first file operation ID must be zero"));
        }
        Ok(Self {
            phase: Phase::Requested,
            id: q.id,
            kind: q.kind,
            length: 0,
            count: 0,
        })
    }
    pub fn retaining(&self) -> bool {
        self.kind == 2 && self.phase == Phase::Upload
    }
    pub fn active(&self) -> bool {
        self.phase != Phase::Idle
    }
    pub fn incoming(&mut self, m: &Message) -> Result<(), Failure> {
        if self.phase == Phase::Idle {
            let q = Request::parse(m)?;
            if q.id <= self.id {
                return Err(Failure::violation("file operation ID reused"));
            }
            self.id = q.id;
            self.kind = q.kind;
            self.phase = Phase::Requested;
            self.count = 0;
            return Ok(());
        }
        match (self.phase, m.kind) {
            (Phase::Upload, DATA) => {
                self.count += bytes(m, self.id, self.count, self.length)?.len() as u64;
            }
            (Phase::Upload, END) => {
                verify_end(m, self.id, self.count, self.length, [0; 32])?;
                self.phase = Phase::Result;
            }
            (Phase::DownloadEnded, RECEIVED) => {
                id(m, self.id)?;
                status(m)?;
                self.phase = Phase::Result;
            }
            _ => {
                return Err(Failure::violation(
                    "file message in wrong direction or phase",
                ));
            }
        }
        Ok(())
    }
    pub fn outgoing(&mut self, m: &Message) -> Result<(), Failure> {
        id(m, self.id)?;
        match m.kind {
            ACCEPTED => {
                self.length = size(m, 1)?;
                self.count = m
                    .field(3)
                    .and_then(Value::as_array)
                    .and_then(|a| a.get(if self.kind == 2 { 1 } else { 0 }))
                    .and_then(Value::as_uint)
                    .unwrap_or(0);
                self.phase = if self.kind == 2 {
                    Phase::Upload
                } else {
                    Phase::Download
                };
            }
            END => self.phase = Phase::DownloadEnded,
            RESULT => self.phase = Phase::Idle,
            _ => {}
        }
        Ok(())
    }
}

/// Private IPC uses a fixed u32 length, never exposed on a QUIC stream.
pub fn read_ipc(r: &mut impl std::io::Read) -> Result<Option<Message>, Failure> {
    let mut prefix = [0; 4];
    let n = r
        .read(&mut prefix[..1])
        .map_err(|_| Failure::new(crate::wire::Code::InternalError, "worker read"))?;
    if n == 0 {
        return Ok(None);
    }
    r.read_exact(&mut prefix[1..])
        .map_err(|_| Failure::new(crate::wire::Code::InternalError, "worker frame"))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > 65535 {
        return Err(Failure::violation("worker message limit"));
    }
    let mut b = vec![0; length];
    r.read_exact(&mut b)
        .map_err(|_| Failure::new(crate::wire::Code::InternalError, "worker truncated message"))?;
    Message::decode(&b).map(Some)
}
pub fn write_ipc(w: &mut impl std::io::Write, m: &Message) -> std::io::Result<()> {
    let b = m.encode();
    w.write_all(&(b.len() as u32).to_be_bytes())?;
    w.write_all(&b)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(kind: u64) -> Message {
        Message::new(
            crate::wire::FILE_REQUEST,
            vec![
                (0, Value::Uint(0)),
                (1, Value::Uint(kind)),
                (2, Value::Array(vec![Value::Uint(0), Value::Array(vec![])])),
            ],
        )
    }
    #[test]
    fn request_fields_and_resume_are_strict() {
        assert!(Request::parse(&request(3)).is_ok());
        assert!(Request::parse(&request(7)).is_err());
        assert!(Request::parse(&request(2)).is_err());
        for kind in [1, 3, 4, 5, 6, 7, 99] {
            let mut m = request(kind);
            m.body.push((Value::Uint(5), Value::Uint(1)));
            assert!(Request::parse(&m).is_err());
        }
        let mut m = request(1);
        m.body.push((
            Value::Uint(7),
            Value::Array(vec![
                Value::Uint(2),
                Value::Uint(10),
                Value::Uint(11),
                Value::Bytes(vec![0; 32]),
            ]),
        ));
        assert!(Request::parse(&m).is_err());
        assert!(Request::parse(&request(99)).is_ok());
    }
    #[test]
    fn maximum_frame_and_all_data_boundary_refusals() {
        let m = data(u64::MAX, MAX_SIZE - MAX_CHUNK as u64, vec![7; MAX_CHUNK]);
        assert_eq!(m.encode().len(), 61469);
        assert!(m.encode().len() <= 65535);
        assert_eq!(
            bytes(&m, u64::MAX, MAX_SIZE - MAX_CHUNK as u64, MAX_SIZE)
                .unwrap()
                .len(),
            MAX_CHUNK
        );
        for m in [
            data(0, 0, vec![]),
            data(0, 0, vec![0; MAX_CHUNK + 1]),
            data(0, 1, vec![1]),
            data(1, 0, vec![1]),
            data(0, 0, vec![0; 4]),
        ] {
            assert!(bytes(&m, 0, 0, 3).is_err());
        }
        assert!(bytes(&data(0, MAX_SIZE, vec![1]), 0, MAX_SIZE, MAX_SIZE).is_err());
    }
    #[test]
    fn counts_above_four_gib_and_failed_end_precedence() {
        let offset = 1u64 << 32;
        let m = data(8, offset, vec![1; 3]);
        assert_eq!(bytes(&m, 8, offset, offset + 3).unwrap(), [1; 3]);
        assert!(bytes(&m, 8, offset + 1, offset + 4).is_err());
        assert_eq!(
            verify_end(&end(8, Status::Io, 2, None), 8, 3, 3, [0; 32]).unwrap(),
            Status::Integrity
        );
        assert_eq!(
            verify_end(&end(8, Status::Ok, 3, Some([0; 32])), 8, 3, 3, [1; 32]).unwrap(),
            Status::Integrity
        );
        assert!(verify_end(&end(8, Status::Ok, 3, None), 8, 3, 3, [0; 32]).is_err());
        assert_eq!(Status::from_value(u64::MAX), Status::Io);
    }
    #[test]
    fn concurrent_input_cannot_acknowledge_download_early_or_pipeline_requests() {
        let q = Request::parse(&request(1)).unwrap();
        let mut exchange = Exchange::new(&q).unwrap();
        assert!(exchange.incoming(&request(1)).is_err());
        exchange.outgoing(&accepted(0, 1, 1)).unwrap();
        assert!(exchange.incoming(&receipt(0, Status::Ok)).is_err());
        exchange
            .outgoing(&end(0, Status::Ok, 1, Some([0; 32])))
            .unwrap();
        exchange.incoming(&receipt(0, Status::Ok)).unwrap();
        assert!(exchange.incoming(&receipt(0, Status::Ok)).is_err());
        exchange.outgoing(&result(0, Status::Ok, None)).unwrap();
        assert!(!exchange.active());
        assert!(exchange.incoming(&request(1)).is_err());
        let mut second = request(3);
        second.body[0].1 = Value::Uint(2);
        exchange.incoming(&second).unwrap();
        assert!(exchange.active());
    }
    #[test]
    fn metadata_is_bounded_and_regular_size_is_required() {
        assert!(validate_metadata(&Value::Map(vec![(Value::Uint(0), Value::Uint(1))]), 0).is_err());
        let bad_time = Value::Array(vec![Value::Uint(u64::MAX), Value::Uint(0)]);
        assert!(
            validate_metadata(
                &Value::Map(vec![
                    (Value::Uint(0), Value::Uint(2)),
                    (Value::Uint(2), bad_time)
                ]),
                0
            )
            .is_err()
        );
    }
    #[test]
    fn windows_components_reject_devices_aliases_and_escapes() {
        for name in [
            "",
            ".",
            "..",
            "trailing.",
            "trailing ",
            "CON",
            "con.txt",
            "NuL.tar.gz",
            "AUX .txt",
            "PRN",
            "COM1",
            "com9.log",
            "LPT1",
            "lpt9.txt",
            "COM¹.txt",
            "lpt²",
            "LPT³.log",
            "CONIN$",
            "conout$.log",
            "stream:secret",
            "a/b",
            "a\\b",
            "a*",
            "a?",
            "a|",
            "a<",
            "a>",
            "a\"",
            "a\0",
            "a\u{1f}",
        ] {
            assert!(!valid_windows_component(name), "{name:?}");
        }
        for name in [
            "normal",
            ".hidden",
            "a b",
            "CONSOLE",
            "NUL2",
            "COM0",
            "COM10",
            "LPT10",
            "COM⁴",
            "COM¹x",
            "é",
            "e\u{301}",
            "東京",
            "résumé.txt",
        ] {
            assert!(valid_windows_component(name), "{name:?}");
        }
        let windows = |drive: &str, names: Vec<Value>| {
            Value::Array(vec![
                Value::Uint(1),
                Value::Text(drive.into()),
                Value::Array(names),
            ])
        };
        assert!(valid_path_contents(&windows("C", vec![]), true).unwrap());
        assert!(!valid_path_contents(&windows("C", vec![]), false).unwrap());
        for drive in ["c", "C:", "CC", "é", ""] {
            assert!(!valid_path_contents(&windows(drive, vec![]), true).unwrap());
        }
        assert!(validate_path_shape(&windows("C", vec![Value::Bytes(vec![1])])).is_err());
        assert!(!valid_entry_name(&Value::Bytes(b"name".to_vec()), 1));
        assert!(!valid_entry_name(&Value::Text("name".into()), 0));
        assert!(valid_entry_name(&Value::Bytes(vec![0xff, b'\\']), 0));
    }
    #[test]
    fn metadata_platforms_negative_time_extremes_and_unknown_kinds() {
        let metadata = |kind: u64, fields: Vec<(Value, Value)>| {
            let mut f = vec![(Value::Uint(0), Value::Uint(kind))];
            f.extend(fields);
            Value::Map(f)
        };
        for seconds in [
            Value::Nint(i64::MAX as u64),
            Value::Nint(0),
            Value::Uint(0),
            Value::Uint(i64::MAX as u64),
        ] {
            let value = metadata(
                2,
                vec![
                    (
                        Value::Uint(2),
                        Value::Array(vec![seconds, Value::Uint(999999999)]),
                    ),
                    (Value::Uint(3), Value::Uint(511)),
                ],
            );
            let parsed = validate_metadata(&value, 0).unwrap();
            assert!(parsed.modified.is_some());
            assert_eq!(parsed.mode, Some(511));
            assert!(validate_metadata(&value, 1).is_err());
        }
        let value = metadata(
            1,
            vec![
                (Value::Uint(1), Value::Uint(u64::MAX)),
                (Value::Uint(4), Value::Bool(true)),
            ],
        );
        assert_eq!(validate_metadata(&value, 1).unwrap().size, Some(u64::MAX));
        assert!(validate_metadata(&value, 0).is_err());
        for bad in [Value::Uint(512), Value::Nint(0), Value::Bool(false)] {
            assert!(validate_metadata(&metadata(0, vec![(Value::Uint(3), bad)]), 0).is_err());
        }
        for nanos in [Value::Uint(1000000000), Value::Nint(0), Value::Bool(false)] {
            assert!(
                validate_metadata(
                    &metadata(
                        2,
                        vec![(Value::Uint(2), Value::Array(vec![Value::Nint(0), nanos]))]
                    ),
                    0
                )
                .is_err()
            );
        }
        let unknown = metadata(
            99,
            vec![
                (Value::Uint(1), Value::Uint(22)),
                (Value::Uint(3), Value::Uint(511)),
                (Value::Uint(77), Value::Text("future".into())),
            ],
        );
        let parsed = validate_metadata(&unknown, 0).unwrap();
        assert_eq!(parsed.kind, 99);
        assert_eq!(parsed.size, None);
        assert_eq!(parsed.mode, None);
    }
}
