//! Client commands on Sessions (PROTOCOL.md §15.6, §15.9, §15.10): `sessions`,
//! `terminate`, `detach`, and finding the Session a command names.

use std::io::Write;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::client::Connection;
use crate::error::Error;
use crate::listing::{self, EXITED, Listed, RUNNING};
use crate::terminal::{self, Exit};
use crate::wire::Code;

/// Characters of the Session ID shown in the list; a unique prefix names a Session.
const SHORT_ID: usize = 12;

/// All Sessions of the Account, page by page (§15.10).
pub async fn list_all(connection: &mut Connection) -> Result<Vec<Listed>, Error> {
    let mut sessions: Vec<Listed> = Vec::new();
    loop {
        let after = sessions.last().map(|s| s.id);
        let result = connection
            .request(|id| listing::list_request(id, None, after))
            .await?;
        if let Some(code) = connection.failed_result(&result).await? {
            return Err(Error::Request("sessions", code));
        }
        let (page, more) = match listing::list_of(&result) {
            Ok(page) => page,
            Err(failure) => return Err(connection.failed(failure.into()).await),
        };
        let progress = !page.is_empty();
        sessions.extend(page);
        if !more || !progress {
            return Ok(sessions);
        }
    }
}

/// The Session `text` names: its full ID, its name, or a unique prefix of its ID
/// (§15.1, §15.3), in this order.
pub async fn resolve(connection: &mut Connection, text: &str) -> Result<Listed, Error> {
    let sessions = list_all(connection).await?;
    find(sessions, text)
}

fn find(sessions: Vec<Listed>, text: &str) -> Result<Listed, Error> {
    let not_found = || Error::NoSuchSession(text.to_owned());
    if let Some(found) = sessions.iter().find(|s| s.id.to_string() == text) {
        return Ok(found.clone());
    }
    if let Some(found) = sessions.iter().find(|s| s.name.as_deref() == Some(text)) {
        return Ok(found.clone());
    }
    let prefix = text.to_ascii_lowercase();
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(not_found());
    }
    let mut matching = sessions
        .into_iter()
        .filter(|s| s.id.to_string().starts_with(&prefix));
    match (matching.next(), matching.count()) {
        (Some(found), 0) => Ok(found),
        (Some(_), others) => Err(Error::AmbiguousSession(text.to_owned(), others + 1)),
        (None, _) => Err(not_found()),
    }
}

/// `stpt sessions`: the Sessions of the Account as a table.
pub async fn sessions(connection: &mut Connection) -> Result<ExitCode, Error> {
    let sessions = list_all(connection).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut out = std::io::stdout().lock();
    out.write_all(table(&sessions, now).as_bytes())
        .map_err(Error::Terminal)?;
    Ok(ExitCode::SUCCESS)
}

/// `stpt terminate`: ends the Session and waits until it is Terminated (§15.6).
pub async fn terminate(
    connection: &mut Connection,
    text: &str,
    force: bool,
) -> Result<ExitCode, Error> {
    let session = resolve(connection, text).await?;
    let result = connection
        .request(|id| listing::terminate_request(id, session.id, force))
        .await?;
    match connection.failed_result(&result).await? {
        None => Ok(ExitCode::SUCCESS),
        Some(code) => Err(Error::Request("terminate", code)),
    }
}

/// `stpt detach`: ends one Attachment of the Session, or all (§15.9).
pub async fn detach(
    connection: &mut Connection,
    text: &str,
    attachment: Option<u64>,
) -> Result<ExitCode, Error> {
    let session = resolve(connection, text).await?;
    let result = connection
        .request(|id| listing::detach_request(id, session.id, attachment))
        .await?;
    match connection.failed_result(&result).await? {
        None => Ok(ExitCode::SUCCESS),
        Some(code) if code == Code::AttachmentNotFound as u64 => Err(Error::NoSuchAttachment(
            session.id.to_string(),
            attachment.unwrap_or_default(),
        )),
        Some(code) => Err(Error::Request("detach", code)),
    }
}

/// The list as a table, newest Sessions last; `now` is Unix time.
fn table(sessions: &[Listed], now: u64) -> String {
    let rows: Vec<[String; 6]> = sessions
        .iter()
        .map(|s| {
            let mut id = s.id.to_string();
            id.truncate(SHORT_ID);
            [
                id,
                s.name.clone().unwrap_or_else(|| "-".into()),
                state(s),
                age(now.saturating_sub(s.created)),
                attachments(s),
                s.command.clone().unwrap_or_else(|| "(login shell)".into()),
            ]
        })
        .collect();
    let header = ["ID", "NAME", "STATE", "AGE", "ATTACHED", "COMMAND"].map(String::from);
    let mut widths = header.clone().map(|h| h.chars().count());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in std::iter::once(&header).chain(&rows) {
        let mut line = String::new();
        for (i, (cell, width)) in row.iter().zip(widths).enumerate() {
            if i + 1 == row.len() {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:width$}  "));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn state(session: &Listed) -> String {
    match (session.state, session.exit) {
        (RUNNING, _) => "running".into(),
        (EXITED, Some(Exit::Code(code))) => format!("exited {code}"),
        (EXITED, Some(Exit::Signal { id, .. })) => {
            format!("killed {}", terminal::signal_name(id).unwrap_or("?"))
        }
        (EXITED, None) => "exited".into(),
        _ => "terminating".into(),
    }
}

fn attachments(session: &Listed) -> String {
    match session.attachments.len() {
        0 => "-".into(),
        n => n.to_string(),
    }
}

/// An age in its largest unit: `45s`, `12m`, `5h`, `3d`.
fn age(seconds: u64) -> String {
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        3600..86400 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::SessionId;

    fn session(first: u8, name: Option<&str>) -> Listed {
        let mut id = [0; 16];
        id[0] = first;
        Listed {
            id: SessionId(id),
            name: name.map(String::from),
            state: RUNNING,
            created: 1000,
            key: [0; 32],
            label: None,
            pty: true,
            command: None,
            exit: None,
            removal: None,
            attachments: Vec::new(),
        }
    }

    #[test]
    fn sessions_are_found_by_id_name_or_prefix() {
        let all = vec![
            session(0xab, Some("work")),
            session(0xac, None),
            session(0x12, Some("ab")),
        ];
        let id = |text: &str| find(all.clone(), text).map(|s| s.id.0[0]);
        assert_eq!(id(&all[1].id.to_string()).unwrap(), 0xac);
        assert_eq!(id("work").unwrap(), 0xab);
        // A name wins over a prefix.
        assert_eq!(id("ab").unwrap(), 0x12);
        assert_eq!(id("AC").unwrap(), 0xac);
        assert!(matches!(
            find(all.clone(), "a"),
            Err(Error::AmbiguousSession(_, 2))
        ));
        assert!(matches!(
            find(all.clone(), "ff"),
            Err(Error::NoSuchSession(_))
        ));
        assert!(matches!(find(all, "x"), Err(Error::NoSuchSession(_))));
    }

    #[test]
    fn table_layout() {
        let mut exited = session(0x12, Some("build"));
        exited.state = EXITED;
        exited.exit = Some(Exit::Code(2));
        exited.command = Some("make -j4".into());
        exited.created = 1000 + 50;
        let text = table(&[session(0xab, None), exited], 1000 + 7250);
        assert_eq!(
            text,
            "ID            NAME   STATE     AGE  ATTACHED  COMMAND\n\
             ab0000000000  -      running   2h   -         (login shell)\n\
             120000000000  build  exited 2  2h   -         make -j4\n"
        );
        assert_eq!(table(&[], 0), "ID  NAME  STATE  AGE  ATTACHED  COMMAND\n");
    }

    #[test]
    fn ages() {
        assert_eq!(age(59), "59s");
        assert_eq!(age(60), "1m");
        assert_eq!(age(7199), "1h");
        assert_eq!(age(3 * 86400 + 5), "3d");
    }
}
