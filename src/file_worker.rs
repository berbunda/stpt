//! Shared bounded file worker and resumable transfer state machine.
use crate::cbor::Value;
use crate::file_protocol::{self as p, Request, Status};
use crate::file_storage as storage;
use crate::wire::{Code, Failure, Message};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    process::ExitCode,
};
#[derive(Debug)]
pub(crate) enum Error {
    Failure(Failure),
    Status(Status),
}
impl From<Failure> for Error {
    fn from(f: Failure) -> Self {
        Self::Failure(f)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Status(storage::io_status(&e))
    }
}
pub(crate) fn abort(reason: &str) -> Error {
    Failure::new(Code::InternalError, reason).into()
}
pub fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let Some(peer_limit) = args
        .get(2)
        .and_then(|s| s.to_str())
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 65535)
    else {
        return ExitCode::from(255);
    };
    let Some(max_size) = args
        .get(3)
        .and_then(|s| s.to_str())
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n <= p::MAX_SIZE)
    else {
        return ExitCode::from(255);
    };
    let (mut input, mut output) = (std::io::stdin().lock(), std::io::stdout().lock());
    let mut last = None;
    let mut saved = None;
    let run = (|| -> Result<(), Error> {
        while let Some(message) = p::read_ipc(&mut input)? {
            if message.kind == 2 {
                break;
            }
            if message.kind == 1 {
                saved = None;
                continue;
            }
            let request = Request::parse(&message)?;
            if last.is_none() && request.id != 0 || last.is_some_and(|id| request.id <= id) {
                return Err(Failure::violation(
                    "file operation ID not strictly increasing from zero",
                )
                .into());
            }
            last = Some(request.id);
            let id = request.id;
            match handle(
                request,
                &mut input,
                &mut output,
                peer_limit.min(65535),
                max_size,
                &mut saved,
            ) {
                Ok(()) => {
                    if saved.is_some() {
                        last = None;
                    }
                }
                Err(Error::Status(status)) => {
                    send(&mut output, &p::result(id, status, None), peer_limit)?
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })();
    if let Err(e) = run {
        let failure = match e {
            Error::Failure(f) => f,
            Error::Status(_) => Failure::new(Code::InternalError, "file worker I/O"),
        };
        let _ = p::write_ipc(
            &mut output,
            &Message::new(0, vec![(0, Value::Uint(failure.code as u64))]),
        );
        return ExitCode::from(255);
    }
    ExitCode::SUCCESS
}
fn send(w: &mut impl Write, m: &Message, limit: u64) -> Result<(), Error> {
    if m.encode().len() as u64 > limit {
        return Err(Error::Status(Status::Limit));
    }
    p::write_ipc(w, m).map_err(|_| abort("worker output closed"))
}
fn next(r: &mut impl Read) -> Result<Message, Error> {
    p::read_ipc(r)?.ok_or_else(|| abort("file Channel interrupted"))
}
fn handle(
    q: Request,
    r: &mut impl Read,
    w: &mut impl Write,
    limit: u64,
    max_size: u64,
    saved: &mut Option<Saved>,
) -> Result<(), Error> {
    if q.resume
        .as_ref()
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_uint)
        .is_some_and(|n| n > 2)
        || !(1..=7).contains(&q.kind)
    {
        return Err(Error::Status(Status::Unsupported));
    }
    let path = storage::target(&q.path, matches!(q.kind, 3 | 4))?;
    match q.kind {
        1 => return download(&q, &path, r, w, limit, max_size),
        2 => return upload(&q, &path, r, w, limit, max_size, saved),
        3 => {
            return send(
                w,
                &p::result(q.id, Status::Ok, Some(storage::stat(&path)?)),
                limit,
            );
        }
        4 => storage::list(&path, |name, meta| {
            send(
                w,
                &Message::new(
                    p::ENTRIES,
                    vec![
                        (0, Value::Uint(q.id)),
                        (1, Value::Array(vec![Value::Array(vec![name, meta])])),
                    ],
                ),
                limit,
            )
        })?,
        5 => storage::mkdir(&path)?,
        6 => storage::remove(&path)?,
        7 => storage::rename(
            &path,
            &storage::target(q.destination.as_ref().unwrap(), false)?,
            q.replace,
        )?,
        _ => unreachable!(),
    }
    send(w, &p::result(q.id, Status::Ok, None), limit)
}
struct Saved {
    upload: storage::Upload,
    count: u64,
    request: Request,
    token: Vec<u8>,
}
fn upload(
    q: &Request,
    path: &storage::Target,
    r: &mut impl Read,
    w: &mut impl Write,
    limit: u64,
    max_size: u64,
    saved: &mut Option<Saved>,
) -> Result<(), Error> {
    let length = q.length.unwrap();
    if length > max_size {
        return Err(Error::Status(Status::Limit));
    }
    let mut hash = p::Hash::new(q.algorithm).ok_or(Error::Status(Status::Unsupported))?;
    let mode = q.resume.as_ref().and_then(Value::as_array);
    let resumed = mode.is_some_and(|a| a[0].as_uint() == Some(1));
    let retained = mode.is_some();
    let mut state = if resumed {
        let mut state = saved
            .take()
            .ok_or(Error::Status(Status::ResumeUnavailable))?;
        let old = &state.request;
        if old.path != q.path
            || old.length != q.length
            || old.algorithm != q.algorithm
            || old.replace != q.replace
            || mode.unwrap()[1] != Value::Bytes(state.token.clone())
        {
            return Err(Error::Status(Status::ResumeUnavailable));
        }
        state.upload.verify_parent(path)?;
        let count = state.count;
        state.upload.file().set_len(count)?;
        state.upload.file().seek(SeekFrom::Start(0))?;
        hash_prefix(state.upload.file(), count, &mut hash)?;
        state
    } else {
        let upload = storage::Upload::new(path, q.replace)?;
        let mut token = vec![0; 32];
        if retained {
            use aws_lc_rs::rand::{SecureRandom, SystemRandom};
            SystemRandom::new()
                .fill(&mut token)
                .map_err(|_| abort("resume randomness"))?;
        }
        Saved {
            upload,
            count: 0,
            request: q.clone(),
            token,
        }
    };
    let mut acceptance = p::accepted(q.id, length, q.algorithm);
    if retained {
        acceptance.body.push((
            Value::Uint(3),
            Value::Array(vec![
                Value::Bytes(state.token.clone()),
                Value::Uint(state.count),
                Value::Bytes(hash.clone().finish().to_vec()),
            ]),
        ));
    }
    send(w, &acceptance, limit)?;
    let status = loop {
        let m = next(r)?;
        // Private parent command, never accepted from the wire. Checkpoint only
        // after the relay established eligible loss/timeout before complete END.
        if m.kind == 1 {
            if retained {
                let count = state.count;
                state.upload.file().set_len(count)?;
                state.upload.file().flush()?;
                *saved = Some(state);
                send(w, &Message::new(1, vec![]), limit)?;
                return Ok(());
            }
            return Err(abort("unexpected checkpoint"));
        }
        if m.kind == p::DATA {
            let bytes = p::bytes(&m, q.id, state.count, length)?;
            state.upload.file().write_all(bytes).map_err(|error| {
                Error::Failure(Failure::new(
                    if storage::io_status(&error) == Status::NoSpace {
                        Code::LimitExceeded
                    } else {
                        Code::InternalError
                    },
                    "staging write failed",
                ))
            })?;
            hash.update(bytes);
            state.count += bytes.len() as u64;
        } else {
            break p::verify_end(&m, q.id, state.count, length, hash.finish())?;
        }
    };
    if status != Status::Ok {
        return send(w, &p::result(q.id, status, None), limit);
    }
    state.upload.publish(path)?;
    send(w, &p::result(q.id, Status::Ok, None), limit)
}
fn hash_prefix(file: &mut File, mut remaining: u64, hash: &mut p::Hash) -> Result<(), Error> {
    let mut buffer = vec![0; p::CHUNK];
    while remaining > 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let n = file.read(&mut buffer[..wanted])?;
        if n == 0 {
            return Err(Error::Status(Status::ResumeUnavailable));
        }
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    Ok(())
}
fn download(
    q: &Request,
    path: &storage::Target,
    r: &mut impl Read,
    w: &mut impl Write,
    limit: u64,
    max_size: u64,
) -> Result<(), Error> {
    let mut hash = p::Hash::new(q.algorithm).ok_or(Error::Status(Status::Unsupported))?;
    let mut file = storage::read(path)?;
    let metadata = file.metadata()?;
    let length = metadata.len();
    if length > max_size || length > p::MAX_SIZE {
        return Err(Error::Status(Status::Limit));
    }
    let mut count = 0;
    let mut acceptance = p::accepted(q.id, length, q.algorithm);
    if let Some(a) = q.resume.as_ref().and_then(Value::as_array) {
        if a[0].as_uint() != Some(2) {
            return Err(Error::Status(Status::Unsupported));
        }
        count = a[2].as_uint().unwrap();
        if a[1].as_uint() != Some(length) {
            return Err(Error::Status(Status::ResumeUnavailable));
        }
        hash_prefix(&mut file, count, &mut hash)?;
        if a[3] != Value::Bytes(hash.clone().finish().to_vec()) {
            return Err(Error::Status(Status::ResumeUnavailable));
        }
        acceptance
            .body
            .push((Value::Uint(3), Value::Array(vec![Value::Uint(count)])));
    }
    send(w, &acceptance, limit)?;
    let mut buffer = vec![0; p::CHUNK];
    let mut status = Status::Ok;
    while count < length {
        let wanted = ((length - count).min(buffer.len() as u64)) as usize;
        match file.read(&mut buffer[..wanted]) {
            Ok(0) | Err(_) => {
                status = Status::Io;
                break;
            }
            Ok(n) => {
                hash.update(&buffer[..n]);
                send(w, &p::data(q.id, count, buffer[..n].to_vec()), limit)?;
                count += n as u64;
            }
        }
    }
    send(
        w,
        &p::end(
            q.id,
            status,
            count,
            (status == Status::Ok).then(|| hash.finish()),
        ),
        limit,
    )?;
    let receipt = next(r)?;
    if receipt.kind != p::RECEIVED {
        return Err(Failure::violation("expected FILE_RECEIVED").into());
    }
    p::id(&receipt, q.id)?;
    let received = p::status(&receipt)?;
    let status = if received == Status::Integrity {
        received
    } else if status != Status::Ok {
        status
    } else {
        received
    };
    send(w, &p::result(q.id, status, None), limit)
}
