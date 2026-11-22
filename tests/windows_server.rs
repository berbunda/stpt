//! Native Windows Server, ConPTY and process-tree integration.
#![cfg(windows)]
#![allow(dead_code)]
#[path = "../src/auth.rs"]
mod auth;
#[path = "../src/cbor.rs"]
mod cbor;
mod common;
#[path = "../src/control.rs"]
mod control;
#[path = "../src/file_protocol.rs"]
mod file_protocol;
#[path = "../src/identity.rs"]
mod identity;
#[path = "../src/quic.rs"]
mod quic;
#[path = "../src/terminal.rs"]
mod terminal;
#[path = "../src/tls.rs"]
mod tls;
use common::windows_security;
#[path = "../src/wire.rs"]
mod wire;
mod hello {
    pub const AUTH_PUBLICKEY_ED25519: u64 = 1;
}
use cbor::Value;
use common::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use wire::Message;
struct Setup {
    server: RunningServer,
    home: PathBuf,
    config: String,
    account: String,
    fp: String,
    destination: String,
}
impl Setup {
    fn new(name: &str) -> Self {
        Self::with_config(name, "")
    }
    fn with_config(name: &str, extra: &str) -> Self {
        let config = server_config(name, extra);
        let fp = stdout(&stpt(&["server", "--fingerprint", "--config", &config]));
        let mut user = vec![0u16; 257];
        let mut length = user.len() as u32;
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::WindowsProgramming::GetUserNameW(
                    user.as_mut_ptr(),
                    &mut length,
                )
            },
            0
        );
        let account = String::from_utf16(&user[..length as usize - 1]).unwrap();
        std::fs::write(
            Path::new(&config)
                .with_file_name("authorized_keys")
                .join(&account),
            format!("{TEST_USER_KEY_LINE}\n"),
        )
        .unwrap();
        let home = dir(&format!("{name}-home"));
        user_key(&home);
        let server = RunningServer::start(&["--listen", "127.0.0.1:0", "--config", &config]);
        let destination = format!("{account}@127.0.0.1:{}", server.port);
        Self {
            server,
            home,
            config,
            account,
            fp,
            destination,
        }
    }
    fn fs(&self, command: &str, args: &[&str]) -> std::process::Output {
        let mut a = vec!["fs", command, &self.destination, "--fingerprint", &self.fp];
        a.extend_from_slice(args);
        stpt_in(&self.home, &a)
    }
    fn ok(&self, command: &str, args: &[&str]) -> String {
        let out = self.fs(command, args);
        assert!(out.status.success(), "{command} {args:?}: {}", stderr(&out));
        stdout(&out)
    }
    fn exec(&self, argv: &[&str]) -> std::process::Output {
        let mut args = vec!["exec", &self.destination, "--fingerprint", &self.fp];
        args.extend_from_slice(argv);
        stpt_in(&self.home, &args)
    }
    fn probe(&self) -> PathBuf {
        let source = Path::new(&self.config).with_file_name("probe.rs");
        std::fs::write(&source,r#"fn main(){let args:Vec<_>=std::env::args().skip(1).collect();if args.first().map(String::as_str)==Some("tree"){let child=std::process::Command::new(std::env::current_exe().unwrap()).arg("wait").spawn().unwrap();std::fs::write(&args[1],child.id().to_string()).unwrap();println!("tree-ready");loop{std::thread::sleep(std::time::Duration::from_secs(1));}}if args.first().map(String::as_str)==Some("wait"){loop{std::thread::sleep(std::time::Duration::from_secs(1));}}println!("{:?}",args);eprintln!("probe-stderr");std::process::exit(17);}"#).unwrap();
        let exe = source.with_extension("exe");
        let out = Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        exe
    }
}
struct Raw {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}
impl Raw {
    async fn login(s: &Setup) -> Self {
        let address = format!("127.0.0.1:{}", s.server.port).parse().unwrap();
        let endpoint = quic::client(address).unwrap();
        let check = tls::ServerKeyCheck::new(tls::Expected {
            stored: None,
            fingerprint: Some(s.fp.parse().unwrap()),
        });
        let connection = quic::connect(&endpoint, address, "localhost", check)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let hello = Message::new(
            wire::CLIENT_HELLO,
            vec![
                (0, Value::Array(vec![Value::Uint(0xff000001)])),
                (
                    1,
                    Value::Map(vec![(
                        Value::Uint(1),
                        Value::Map(vec![
                            (Value::Uint(0), Value::Uint(1)),
                            (Value::Uint(1), Value::Uint(8)),
                        ]),
                    )]),
                ),
            ],
        );
        wire::write_message(&mut send, &hello, 65535).await.unwrap();
        assert_eq!(
            wire::read_message(&mut recv, 65535)
                .await
                .unwrap()
                .unwrap()
                .kind,
            wire::SERVER_HELLO
        );
        let key = auth::UserKey::load(&s.home.join("stpt/id_ed25519")).unwrap();
        wire::write_message(
            &mut send,
            &key.request(&auth::exporter(&connection).unwrap(), &s.account)
                .to_message(),
            65535,
        )
        .await
        .unwrap();
        assert!(
            auth::result_from_message(
                &wire::read_message(&mut recv, 65535).await.unwrap().unwrap()
            )
            .unwrap()
        );
        Self {
            endpoint,
            connection,
            send,
            recv,
        }
    }
    async fn file(&self, q: &Message) -> (quinn::SendStream, quinn::RecvStream, Message) {
        let (mut send, mut recv) = self.connection.open_bi().await.unwrap();
        wire::write_message(
            &mut send,
            &Message::new(wire::CHANNEL_OPEN, vec![(0, Value::Uint(2))]),
            65535,
        )
        .await
        .unwrap();
        assert_eq!(
            wire::read_message(&mut recv, 65535)
                .await
                .unwrap()
                .unwrap()
                .kind,
            wire::FILES_READY
        );
        wire::write_message(&mut send, q, 65535).await.unwrap();
        let first = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
        (send, recv, first)
    }
    async fn open(
        &self,
        open: terminal::Open,
    ) -> (quinn::SendStream, quinn::RecvStream, terminal::Attached) {
        let (mut send, mut recv) = self.connection.open_bi().await.unwrap();
        wire::write_message(&mut send, &open.to_message(), 65535)
            .await
            .unwrap();
        let m = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
        assert_eq!(m.kind, wire::TERMINAL_ATTACHED);
        let a = terminal::Attached::from_message(&m).unwrap();
        (send, recv, a)
    }
    async fn close(self) {
        self.connection.close(wire::Code::NoError.varint(), b"");
        self.endpoint.wait_idle().await;
    }
}
async fn read_until(recv: &mut quinn::RecvStream, needle: &str) -> Vec<u8> {
    let mut output = Vec::new();
    while !String::from_utf8_lossy(&output).contains(needle) {
        let m = wire::read_message(recv, 65535).await.unwrap().unwrap();
        assert!(
            m.kind == wire::TERMINAL_DATA || m.kind == wire::TERMINAL_STDERR,
            "{m:?}"
        );
        output.extend_from_slice(terminal::data_of(&m).unwrap());
    }
    output
}
#[test]
fn windows_exec_preserves_argv_stdout_stderr_and_exit() {
    let s = Setup::new("win-exec");
    let exe = s.probe();
    let args = [
        "",
        "hello space",
        "a'b",
        "\"quoted\"",
        "& $() %PATH% | >",
        "東京",
        "trailing\\",
        "line\nnext",
    ];
    let mut command = vec!["--no-shell", exe.to_str().unwrap()];
    command.extend(args);
    let out = s.exec(&command);
    assert_eq!(out.status.code(), Some(17), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("{args:?}"));
    assert_eq!(stderr(&out), "probe-stderr");
    let batch = Path::new(&s.config).with_file_name("explicit.cmd");
    std::fs::write(&batch, "@echo batch-executed\r\n").unwrap();
    let rejected = s.exec(&["--no-shell", batch.to_str().unwrap()]);
    assert_eq!(rejected.status.code(), Some(255));
    assert!(stderr(&rejected).contains("batch files require an explicit shell"));
    let out = s.exec(&["Write-Output 'shell-ready'; exit 23"]);
    assert_eq!(out.status.code(), Some(23), "{}", stderr(&out));
    assert!(stdout(&out).contains("shell-ready"));
    let foreign = format!("not-the-account@127.0.0.1:{}", s.server.port);
    let out = stpt_in(
        &s.home,
        &[
            "exec",
            &foreign,
            "--fingerprint",
            &s.fp,
            "Write-Output denied",
        ],
    );
    assert_eq!(out.status.code(), Some(255));
    let out = stpt_in(
        &s.home,
        &["fs", "stat", &s.destination, "--fingerprint", &s.fp, r"C:\"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "directory\t-");
}
#[test]
fn conpty_input_resize_and_exit_over_authenticated_quic() {
    let s = Setup::new("win-conpty");
    quic::runtime().unwrap().block_on(async{
        tokio::time::timeout(Duration::from_secs(20),async{
            let client=Raw::login(&s).await;
            let open=terminal::Open{command:Some(terminal::Command::Line("Write-Output 'conpty-ready'; $value=Read-Host; Write-Output ('got-'+$value); Write-Output ('size='+[Console]::WindowWidth); exit 19".into())),term:Some("xterm-256color".into()),size:Some(terminal::Size{columns:80,rows:24,width:0,height:0}),..Default::default()};
            let(send,mut recv,attached)=client.open(open).await;read_until(&mut recv,"conpty-ready").await;
            drop(send);drop(recv);client.close().await;
            let client=Raw::login(&s).await;
            let(mut send,mut recv,_)=client.open(terminal::Open{session:Some(attached.session),takeover:Some(true),..Default::default()}).await;
            read_until(&mut recv,"conpty-ready").await;
            wire::write_message(&mut send,&terminal::Size{columns:132,rows:40,width:0,height:0}.resize_message(),65535).await.unwrap();
            wire::write_message(&mut send,&terminal::data(wire::TERMINAL_DATA,"значение東京\r".as_bytes()),65535).await.unwrap();let mut output=Vec::new();
            loop{let m=wire::read_message(&mut recv,65535).await.unwrap().unwrap();if m.kind==wire::TERMINAL_EXIT{assert_eq!(terminal::Exit::from_message(&m).unwrap(),terminal::Exit::Code(19));break;}output.extend_from_slice(terminal::data_of(&m).unwrap());}
            let output=String::from_utf8_lossy(&output);assert!(output.contains("got-значение東京"),"{output}");assert!(output.contains("size=132"),"{output}");send.finish().unwrap();client.close().await;
        }).await.unwrap();
    });
}
#[test]
fn session_survives_connection_and_force_termination_kills_descendants() {
    let s = Setup::new("win-session");
    let exe = s.probe();
    let pidfile = Path::new(&s.config).with_file_name("child.pid");
    quic::runtime().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let first = Raw::login(&s).await;
            let open = terminal::Open {
                command: Some(terminal::Command::Argv(vec![
                    exe.to_str().unwrap().into(),
                    "tree".into(),
                    pidfile.to_str().unwrap().into(),
                ])),
                name: Some("retained".into()),
                ..Default::default()
            };
            let (send, mut recv, attached) = first.open(open).await;
            read_until(&mut recv, "tree-ready").await;
            drop(send);
            drop(recv);
            first.close().await;
            let out = stpt_in(
                &s.home,
                &["sessions", &s.destination, "--fingerprint", &s.fp],
            );
            assert!(out.status.success(), "{}", stderr(&out));
            assert!(stdout(&out).contains("retained"));
            let second = Raw::login(&s).await;
            let (mut send, mut recv, _) = second
                .open(terminal::Open {
                    session: Some(attached.session),
                    takeover: Some(true),
                    ..Default::default()
                })
                .await;
            read_until(&mut recv, "tree-ready").await;
            let pid: u32 = std::fs::read_to_string(&pidfile).unwrap().parse().unwrap();
            use windows_sys::Win32::{Foundation::*, System::Threading::*};
            let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert!(!process.is_null());
            let out = stpt_in(
                &s.home,
                &[
                    "terminate",
                    &s.destination,
                    "--fingerprint",
                    &s.fp,
                    "--force",
                    "retained",
                ],
            );
            assert!(out.status.success(), "{}", stderr(&out));
            assert_eq!(unsafe { WaitForSingleObject(process, 3000) }, WAIT_OBJECT_0);
            unsafe { CloseHandle(process) };
            loop {
                let m = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                if m.kind == wire::TERMINAL_EXIT {
                    break;
                }
            }
            send.finish().unwrap();
            second.close().await;
        })
        .await
        .unwrap();
    });
}

#[test]
fn conpty_explicit_interrupt_stops_foreground_command() {
    let s = Setup::new("win-conpty-int");
    quic::runtime().unwrap().block_on(async{
        tokio::time::timeout(Duration::from_secs(10),async{
            let client=Raw::login(&s).await;
            let open=terminal::Open{command:Some(terminal::Command::Line("Write-Output 'interrupt-ready'; Start-Sleep -Seconds 60; Write-Output 'must-not-run'".into())),term:Some("xterm".into()),size:Some(terminal::Size{columns:80,rows:24,width:0,height:0}),..Default::default()};
            let(mut send,mut recv,_)=client.open(open).await;read_until(&mut recv,"interrupt-ready").await;
            wire::write_message(&mut send,&terminal::signal(terminal::SIGNAL_INT),65535).await.unwrap();
            let mut output=Vec::new();loop{let m=wire::read_message(&mut recv,65535).await.unwrap().unwrap();if m.kind==wire::TERMINAL_EXIT{break;}output.extend_from_slice(terminal::data_of(&m).unwrap());}
            assert!(!String::from_utf8_lossy(&output).contains("must-not-run"));send.finish().unwrap();client.close().await;
        }).await.unwrap();
    });
}
#[test]
fn server_process_exit_closes_job_and_kills_session_tree() {
    let s = Setup::new("win-shutdown-job");
    let exe = s.probe();
    let pidfile = Path::new(&s.config).with_file_name("shutdown-child.pid");
    quic::runtime().unwrap().block_on(async move {
        tokio::time::timeout(Duration::from_secs(15), async move {
            let client = Raw::login(&s).await;
            let open = terminal::Open {
                command: Some(terminal::Command::Argv(vec![
                    exe.to_str().unwrap().into(),
                    "tree".into(),
                    pidfile.to_str().unwrap().into(),
                ])),
                ..Default::default()
            };
            let (send, mut recv, _) = client.open(open).await;
            read_until(&mut recv, "tree-ready").await;
            let pid: u32 = std::fs::read_to_string(pidfile).unwrap().parse().unwrap();
            use windows_sys::Win32::{Foundation::*, System::Threading::*};
            let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            assert!(!raw.is_null());
            drop(s);
            assert_eq!(unsafe { WaitForSingleObject(raw, 3000) }, WAIT_OBJECT_0);
            unsafe { CloseHandle(raw) };
            drop(send);
            drop(recv);
            client.close().await;
        })
        .await
        .unwrap();
    });
}

#[test]
fn conpty_login_shell_accepts_commands_and_sets_utf8_terminal_environment() {
    let s = Setup::new("win-login-shell");
    quic::runtime().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let client = Raw::login(&s).await;
            let open = terminal::Open {
                term: Some("xterm-256color".into()),
                size: Some(terminal::Size {
                    columns: 100,
                    rows: 30,
                    width: 0,
                    height: 0,
                }),
                ..Default::default()
            };
            let (mut send, mut recv, _) = client.open(open).await;
            wire::write_message(
                &mut send,
                &terminal::data(
                    wire::TERMINAL_DATA,
                    b"Write-Output ('TERM='+$env:TERM); Write-Output 'login-ready'; exit 0\r",
                ),
                65535,
            )
            .await
            .unwrap();
            let mut output = Vec::new();
            let mut reports = 0;
            loop {
                let m = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                if m.kind == wire::TERMINAL_EXIT {
                    assert_eq!(
                        terminal::Exit::from_message(&m).unwrap(),
                        terminal::Exit::Code(0)
                    );
                    break;
                }
                output.extend_from_slice(terminal::data_of(&m).unwrap());
                let queries = output.windows(4).filter(|w| *w == b"\x1b[6n").count();
                while reports < queries {
                    wire::write_message(
                        &mut send,
                        &terminal::data(wire::TERMINAL_DATA, b"\x1b[1;1R"),
                        65535,
                    )
                    .await
                    .unwrap();
                    reports += 1;
                }
            }
            let out = String::from_utf8_lossy(&output);
            assert!(out.contains("TERM=xterm-256color"), "{out}");
            assert!(out.contains("login-ready"));
            send.finish().unwrap();
            client.close().await;
        })
        .await
        .unwrap();
    });
}

fn path_value(path: &Path) -> Value {
    let text = path.to_str().unwrap();
    assert_eq!(&text[1..3], ":\\");
    Value::Array(vec![
        Value::Uint(1),
        Value::Text(text[..1].to_ascii_uppercase()),
        Value::Array(
            text[3..]
                .split('\\')
                .filter(|s| !s.is_empty())
                .map(|s| Value::Text(s.into()))
                .collect(),
        ),
    ])
}
fn upload_request(path: &Path, mode: Value) -> Message {
    Message::new(
        wire::FILE_REQUEST,
        vec![
            (0, Value::Uint(0)),
            (1, Value::Uint(2)),
            (2, path_value(path)),
            (5, Value::Uint(6)),
            (6, Value::Uint(1)),
            (7, mode),
        ],
    )
}
#[test]
fn windows_files_cli_roundtrip_management_and_private_publication() {
    let s = Setup::new("win-files-cli");
    let data = dir("win-files-cli-data");
    let source = data.join("source");
    let remote = data.join("東京.txt");
    let copy = data.join("copy");
    let bytes: Vec<_> = (0..150000).map(|n| (n % 251) as u8).collect();
    std::fs::write(&source, &bytes).unwrap();
    for hash in ["blake3", "sha256"] {
        s.ok(
            "push",
            &[
                source.to_str().unwrap(),
                remote.to_str().unwrap(),
                "--hash",
                hash,
            ],
        );
        windows_security::check_private(&remote).unwrap();
        s.ok(
            "pull",
            &[
                remote.to_str().unwrap(),
                copy.to_str().unwrap(),
                "--hash",
                hash,
            ],
        );
        assert_eq!(std::fs::read(&copy).unwrap(), bytes);
        assert_eq!(s.ok("stat", &[remote.to_str().unwrap()]), "file\t150000");
        assert!(s.ok("list", &[data.to_str().unwrap()]).contains("東京.txt"));
        assert!(
            stderr(&s.fs(
                "push",
                &[source.to_str().unwrap(), remote.to_str().unwrap()]
            ))
            .contains("ALREADY_EXISTS")
        );
        assert!(
            stderr(&s.fs(
                "push",
                &[
                    source.to_str().unwrap(),
                    remote.to_str().unwrap(),
                    "--replace"
                ]
            ))
            .contains("UNSUPPORTED")
        );
        s.ok("remove", &[remote.to_str().unwrap()]);
        s.ok("remove", &[copy.to_str().unwrap()]);
    }
    let moved = data.join("moved");
    let folder = data.join("folder");
    s.ok("mkdir", &[folder.to_str().unwrap()]);
    assert_eq!(s.ok("list", &[folder.to_str().unwrap()]), "");
    s.ok(
        "rename",
        &[source.to_str().unwrap(), moved.to_str().unwrap()],
    );
    std::fs::write(&source, b"old").unwrap();
    assert!(
        stderr(&s.fs(
            "rename",
            &[moved.to_str().unwrap(), source.to_str().unwrap()]
        ))
        .contains("ALREADY_EXISTS")
    );
    s.ok(
        "rename",
        &[
            moved.to_str().unwrap(),
            source.to_str().unwrap(),
            "--replace",
        ],
    );
    assert_eq!(std::fs::read(&source).unwrap(), bytes);
    std::fs::write(folder.join("child"), b"x").unwrap();
    assert!(stderr(&s.fs("remove", &[folder.to_str().unwrap()])).contains("NOT_EMPTY"));
    s.ok("remove", &[folder.join("child").to_str().unwrap()]);
    s.ok("remove", &[folder.to_str().unwrap()]);
    for hash in ["blake3", "sha256"] {
        std::fs::write(&source, []).unwrap();
        s.ok(
            "push",
            &[
                source.to_str().unwrap(),
                remote.to_str().unwrap(),
                "--hash",
                hash,
            ],
        );
        s.ok(
            "pull",
            &[
                remote.to_str().unwrap(),
                copy.to_str().unwrap(),
                "--hash",
                hash,
            ],
        );
        assert_eq!(std::fs::metadata(&copy).unwrap().len(), 0);
        s.ok("remove", &[remote.to_str().unwrap()]);
        s.ok("remove", &[copy.to_str().unwrap()]);
    }
    assert!(std::fs::read_dir(&data).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".stpt-")
    }));
}
#[test]
fn windows_files_resume_cross_connection_busy_consumed_cancel_and_parent_pin() {
    use file_protocol as p;
    quic::runtime().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let s = Setup::new("win-files-resume");
            let data = dir("win-files-resume-data");
            let target = data.join("target");
            let client = Raw::login(&s).await;
            let fresh = upload_request(&target, Value::Array(vec![Value::Uint(0)]));
            let (mut send, mut recv, a) = client.file(&fresh).await;
            assert_eq!(a.kind, p::ACCEPTED, "{a:?}");
            let token = a.field(3).unwrap().as_array().unwrap()[0].clone();
            let resume = upload_request(&target, Value::Array(vec![Value::Uint(1), token]));
            let (_, _, busy) = client.file(&resume).await;
            assert_eq!(p::status(&busy).unwrap(), p::Status::ResumeBusy);
            assert!(
                std::fs::rename(&data, data.with_extension("moved")).is_err(),
                "pinned parent must not move"
            );
            wire::write_message(&mut send, &p::data(0, 0, b"abc".to_vec()), 65535)
                .await
                .unwrap();
            loop {
                if std::fs::read_dir(&data)
                    .unwrap()
                    .filter_map(Result::ok)
                    .any(|e| {
                        e.file_name().to_string_lossy().starts_with(".stpt-upload-")
                            && std::fs::metadata(e.path()).is_ok_and(|m| m.len() == 3)
                    })
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            send.reset(wire::Code::Timeout.varint()).unwrap();
            recv.stop(wire::Code::Timeout.varint()).unwrap();
            let second = Raw::login(&s).await;
            let (mut send, mut recv, a) = loop {
                let a = second.file(&resume).await;
                if a.2.kind == p::RESULT && p::status(&a.2).unwrap() == p::Status::ResumeBusy {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                break a;
            };
            assert_eq!(a.kind, p::ACCEPTED, "{a:?}");
            assert_eq!(a.field(3).unwrap().as_array().unwrap()[1], Value::Uint(3));
            wire::write_message(&mut send, &p::data(0, 3, b"def".to_vec()), 65535)
                .await
                .unwrap();
            let mut h = p::Hash::new(1).unwrap();
            h.update(b"abcdef");
            wire::write_message(
                &mut send,
                &p::end(0, p::Status::Ok, 6, Some(h.finish())),
                65535,
            )
            .await
            .unwrap();
            assert_eq!(
                p::status(&wire::read_message(&mut recv, 65535).await.unwrap().unwrap()).unwrap(),
                p::Status::Ok
            );
            let (_, _, a) = second.file(&resume).await;
            assert_eq!(p::status(&a).unwrap(), p::Status::ResumeUnavailable);
            assert_eq!(std::fs::read(&target).unwrap(), b"abcdef");
            send.finish().unwrap();
            let _ = wire::read_message(&mut recv, 65535).await;
            let cancel = data.join("cancel");
            let (mut send, mut recv, a) = second
                .file(&upload_request(&cancel, Value::Array(vec![Value::Uint(0)])))
                .await;
            let token = a.field(3).unwrap().as_array().unwrap()[0].clone();
            send.reset(wire::Code::NoError.varint()).unwrap();
            recv.stop(wire::Code::NoError.varint()).unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let (_, _, a) = second
                .file(&upload_request(
                    &cancel,
                    Value::Array(vec![Value::Uint(1), token]),
                ))
                .await;
            assert_eq!(p::status(&a).unwrap(), p::Status::ResumeUnavailable);
            let (open_send, mut terminal, attached) = client
                .open(terminal::Open {
                    command: Some(terminal::Command::Line(
                        "Write-Output 'files-and-terminal'; exit 0".into(),
                    )),
                    ..Default::default()
                })
                .await;
            let _ = attached.session;
            read_until(&mut terminal, "files-and-terminal").await;
            drop(open_send);
            client.close().await;
            second.close().await;
        })
        .await
        .unwrap();
    });
}

#[test]
fn windows_files_reparse_metadata_and_native_name_refusals() {
    use file_protocol as p;
    let s = Setup::new("win-files-paths");
    let data = dir("win-files-paths-data");
    let real = data.join("real");
    std::fs::create_dir(&real).unwrap();
    let source = real.join("source");
    std::fs::write(&source, b"kept").unwrap();
    let junction = data.join("junction");
    let out = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&real)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(s.ok("stat", &[junction.to_str().unwrap()]), "symlink\t-");
    assert!(
        s.ok("list", &[data.to_str().unwrap()])
            .contains("symlink\t-\tjunction")
    );
    for (op, args) in [
        ("list", vec![junction.clone()]),
        ("stat", vec![junction.join("source")]),
        ("pull", vec![junction.join("source"), data.join("copy")]),
        ("mkdir", vec![junction.join("new")]),
        ("push", vec![source.clone(), junction.join("upload")]),
    ] {
        let args: Vec<_> = args.iter().map(|p| p.to_str().unwrap()).collect();
        assert!(stderr(&s.fs(op, &args)).contains("UNSUPPORTED"), "{op}");
    }
    let renamed = data.join("renamed-junction");
    s.ok(
        "rename",
        &[junction.to_str().unwrap(), renamed.to_str().unwrap()],
    );
    s.ok("remove", &[renamed.to_str().unwrap()]);
    assert_eq!(std::fs::read(&source).unwrap(), b"kept");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&source)
        .unwrap();
    file.set_modified(std::time::UNIX_EPOCH - Duration::new(1, 123456700))
        .unwrap();
    drop(file);
    let mut permissions = std::fs::metadata(&source).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&source, permissions).unwrap();
    quic::runtime().unwrap().block_on(async {
        let client = Raw::login(&s).await;
        let request = |path| {
            Message::new(
                wire::FILE_REQUEST,
                vec![(0, Value::Uint(0)), (1, Value::Uint(3)), (2, path)],
            )
        };
        let (_, _, m) = client.file(&request(path_value(&source))).await;
        assert_eq!(p::status(&m).unwrap(), p::Status::Ok);
        let meta = p::validate_metadata(m.field(2).unwrap(), 1).unwrap();
        assert_eq!(meta.readonly, Some(true));
        assert_eq!(meta.modified, Some((-2, 876543300)));
        let (_, _, m) = client
            .file(&request(Value::Array(vec![
                Value::Uint(0),
                Value::Array(vec![]),
            ])))
            .await;
        assert_eq!(p::status(&m).unwrap(), p::Status::Unsupported);
        for name in ["NUL", "x:stream", "..", "trailing."] {
            let mut path = path_value(&source);
            if let Value::Array(a) = &mut path
                && let Value::Array(names) = &mut a[2]
            {
                *names.last_mut().unwrap() = Value::Text(name.into());
            }
            let (_, _, m) = client.file(&request(path)).await;
            assert_eq!(p::status(&m).unwrap(), p::Status::InvalidPath);
        }
        client.close().await;
    });
    assert!(!s.fs("remove", &[source.to_str().unwrap()]).status.success());
    let mut permissions = std::fs::metadata(&source).unwrap().permissions();
    #[allow(
        clippy::permissions_set_readonly_false,
        reason = "Windows-only attribute restoration"
    )]
    permissions.set_readonly(false);
    std::fs::set_permissions(&source, permissions).unwrap();
    use std::os::windows::ffi::OsStringExt;
    let odd = real.join(std::ffi::OsString::from_wide(&[0xd800]));
    std::fs::write(&odd, b"unrepresentable").unwrap();
    assert!(stderr(&s.fs("list", &[real.to_str().unwrap()])).contains("UNSUPPORTED"));
    std::fs::remove_file(odd).unwrap();
}
#[test]
fn windows_worker_integrity_race_and_forced_exit_clean_staging() {
    use file_protocol as p;
    use std::process::Stdio;
    let data = dir("win-files-worker-data");
    let target = data.join("target");
    let spawn = || {
        Command::new(env!("CARGO_BIN_EXE_stpt"))
            .args(["__stpt-file-worker", "65535", "1048576"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    };
    for force in [false, true] {
        let mut child = spawn();
        let mut input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        let q = upload_request(&target, Value::Array(vec![Value::Uint(0)]));
        p::write_ipc(&mut input, &q).unwrap();
        assert_eq!(p::read_ipc(&mut output).unwrap().unwrap().kind, p::ACCEPTED);
        p::write_ipc(&mut input, &p::data(0, 0, b"abcdef".to_vec())).unwrap();
        if force {
            child.kill().unwrap();
            child.wait().unwrap();
        } else {
            p::write_ipc(&mut input, &p::end(0, p::Status::Ok, 6, Some([0; 32]))).unwrap();
            assert_eq!(
                p::status(&p::read_ipc(&mut output).unwrap().unwrap()).unwrap(),
                p::Status::Integrity
            );
            drop(input);
            assert!(child.wait().unwrap().success());
        }
        assert!(!target.exists());
        assert!(std::fs::read_dir(&data).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".stpt-upload-")
        }));
    }
    let mut child = spawn();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    p::write_ipc(
        &mut input,
        &upload_request(&target, Value::Array(vec![Value::Uint(0)])),
    )
    .unwrap();
    assert_eq!(p::read_ipc(&mut output).unwrap().unwrap().kind, p::ACCEPTED);
    std::fs::write(&target, b"raced").unwrap();
    p::write_ipc(&mut input, &p::data(0, 0, b"abcdef".to_vec())).unwrap();
    let mut h = p::Hash::new(1).unwrap();
    h.update(b"abcdef");
    p::write_ipc(&mut input, &p::end(0, p::Status::Ok, 6, Some(h.finish()))).unwrap();
    assert_eq!(
        p::status(&p::read_ipc(&mut output).unwrap().unwrap()).unwrap(),
        p::Status::Exists
    );
    drop(input);
    assert!(child.wait().unwrap().success());
    assert_eq!(std::fs::read(target).unwrap(), b"raced");
}
#[test]
fn windows_server_restart_discards_retained_token_and_stage() {
    use file_protocol as p;
    quic::runtime().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut s = Setup::new("win-files-restart");
            let data = dir("win-files-restart-data");
            let target = data.join("target");
            let client = Raw::login(&s).await;
            let (mut send, mut recv, a) = client
                .file(&upload_request(&target, Value::Array(vec![Value::Uint(0)])))
                .await;
            assert_eq!(a.kind, p::ACCEPTED);
            let token = a.field(3).unwrap().as_array().unwrap()[0].clone();
            send.reset(wire::Code::Timeout.varint()).unwrap();
            recv.stop(wire::Code::Timeout.varint()).unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            let new = RunningServer::start(&["--listen", "127.0.0.1:0", "--config", &s.config]);
            let old = std::mem::replace(&mut s.server, new);
            old.stop();
            client.close().await;
            loop {
                if std::fs::read_dir(&data).unwrap().all(|e| {
                    !e.unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".stpt-upload-")
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let client = Raw::login(&s).await;
            let (_, _, a) = client
                .file(&upload_request(
                    &target,
                    Value::Array(vec![Value::Uint(1), token]),
                ))
                .await;
            assert_eq!(p::status(&a).unwrap(), p::Status::ResumeUnavailable);
            assert!(!target.exists());
            client.close().await;
        })
        .await
        .unwrap();
    });
}

#[test]
fn windows_download_resume_verifies_prefix_and_full_hash_both_algorithms() {
    use file_protocol as p;
    let s = Setup::new("win-files-download-resume");
    let data = dir("win-files-download-resume-data");
    let source = data.join("source");
    std::fs::write(&source, b"abcdef").unwrap();
    quic::runtime().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(12), async {
            let client = Raw::login(&s).await;
            for algorithm in [1, 2] {
                for offset in [3, 6] {
                    let mut prefix = p::Hash::new(algorithm).unwrap();
                    prefix.update(&b"abcdef"[..offset]);
                    let request = |digest| {
                        Message::new(
                            wire::FILE_REQUEST,
                            vec![
                                (0, Value::Uint(0)),
                                (1, Value::Uint(1)),
                                (2, path_value(&source)),
                                (6, Value::Uint(algorithm)),
                                (
                                    7,
                                    Value::Array(vec![
                                        Value::Uint(2),
                                        Value::Uint(6),
                                        Value::Uint(offset as u64),
                                        Value::Bytes(digest),
                                    ]),
                                ),
                            ],
                        )
                    };
                    let (_, _, m) = client.file(&request(vec![0; 32])).await;
                    assert_eq!(p::status(&m).unwrap(), p::Status::ResumeUnavailable);
                    let (mut send, mut recv, a) =
                        client.file(&request(prefix.finish().to_vec())).await;
                    assert_eq!(a.kind, p::ACCEPTED);
                    let mut suffix = Vec::new();
                    let end = loop {
                        let m = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                        if m.kind == p::END {
                            break m;
                        }
                        assert_eq!(m.kind, p::DATA);
                        if let Value::Bytes(b) = m.field(2).unwrap() {
                            suffix.extend_from_slice(b);
                        }
                    };
                    assert_eq!(suffix, &b"abcdef"[offset..]);
                    let mut full = p::Hash::new(algorithm).unwrap();
                    full.update(b"abcdef");
                    assert_eq!(
                        p::verify_end(&end, 0, 6, 6, full.finish()).unwrap(),
                        p::Status::Ok
                    );
                    wire::write_message(
                        &mut send,
                        &Message::new(p::RECEIVED, vec![(0, Value::Uint(0)), (1, Value::Uint(0))]),
                        65535,
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        p::status(&wire::read_message(&mut recv, 65535).await.unwrap().unwrap())
                            .unwrap(),
                        p::Status::Ok
                    );
                    send.finish().unwrap();
                    let _ = wire::read_message(&mut recv, 65535).await;
                }
            }
            let q = Message::new(
                wire::FILE_REQUEST,
                vec![
                    (0, Value::Uint(0)),
                    (1, Value::Uint(1)),
                    (2, path_value(&source)),
                ],
            );
            let (mut send, mut recv, a) = client.file(&q).await;
            assert_eq!(p::size(&a, 1).unwrap(), 6);
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&source)
                .unwrap()
                .write_all(b"appended after acceptance")
                .unwrap();
            let mut count = 0;
            let mut hash = p::Hash::new(1).unwrap();
            loop {
                let m = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                if m.kind == p::DATA {
                    let bytes = p::bytes(&m, 0, count, 6).unwrap();
                    hash.update(bytes);
                    count += bytes.len() as u64;
                } else {
                    assert_eq!(count, 6);
                    assert_eq!(
                        p::verify_end(&m, 0, count, 6, hash.finish()).unwrap(),
                        p::Status::Ok
                    );
                    break;
                }
            }
            wire::write_message(&mut send, &p::receipt(0, p::Status::Ok), 65535)
                .await
                .unwrap();
            assert_eq!(
                p::status(&wire::read_message(&mut recv, 65535).await.unwrap().unwrap()).unwrap(),
                p::Status::Ok
            );
            send.finish().unwrap();
            let _ = wire::read_message(&mut recv, 65535).await;
            std::fs::File::create(&source)
                .unwrap()
                .set_len(32 * 1024 * 1024)
                .unwrap();
            let q = Message::new(
                wire::FILE_REQUEST,
                vec![
                    (0, Value::Uint(0)),
                    (1, Value::Uint(1)),
                    (2, path_value(&source)),
                ],
            );
            let (mut send, mut recv, a) = client.file(&q).await;
            let length = p::size(&a, 1).unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .open(&source)
                .unwrap()
                .set_len(0)
                .unwrap();
            let mut count = 0;
            loop {
                let m = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                if m.kind == p::DATA {
                    count += p::bytes(&m, 0, count, length).unwrap().len() as u64;
                } else {
                    assert_eq!(m.kind, p::END);
                    assert!(count < length);
                    assert_eq!(p::status(&m).unwrap(), p::Status::Io);
                    assert_eq!(p::size(&m, 2).unwrap(), count);
                    break;
                }
            }
            wire::write_message(&mut send, &p::receipt(0, p::Status::Io), 65535)
                .await
                .unwrap();
            assert_eq!(
                p::status(&wire::read_message(&mut recv, 65535).await.unwrap().unwrap()).unwrap(),
                p::Status::Io
            );
            send.finish().unwrap();
            let _ = wire::read_message(&mut recv, 65535).await;
            client.close().await;
        })
        .await
        .unwrap();
    });
}
#[test]
fn windows_file_deadline_retains_upload_and_server_policy_applies() {
    use file_protocol as p;
    let s = Setup::with_config("win-files-policy", "file_timeout=1\nmax_file_size=6\n");
    let data = dir("win-files-policy-data");
    let source = data.join("large");
    std::fs::write(&source, b"too large").unwrap();
    assert!(
        stderr(&s.fs(
            "push",
            &[
                source.to_str().unwrap(),
                data.join("target").to_str().unwrap()
            ]
        ))
        .contains("LIMIT_EXCEEDED")
    );
    quic::runtime().unwrap().block_on(async{tokio::time::timeout(Duration::from_secs(8),async{
 let client=Raw::login(&s).await;let target=data.join("target");let(_send,mut recv,a)=client.file(&upload_request(&target,Value::Array(vec![Value::Uint(0)]))).await;assert_eq!(a.kind,p::ACCEPTED);let token=a.field(3).unwrap().as_array().unwrap()[0].clone();assert!(matches!(wire::read_message(&mut recv,65535).await,Err(wire::StreamError::Reset(code)) if code==wire::Code::Timeout.varint()));
 let(mut send,mut recv,a)=loop{let a=client.file(&upload_request(&target,Value::Array(vec![Value::Uint(1),token.clone()]))).await;if a.2.kind==p::RESULT&&p::status(&a.2).unwrap()==p::Status::ResumeBusy{tokio::time::sleep(Duration::from_millis(10)).await;continue;}break a;};assert_eq!(a.kind,p::ACCEPTED);send.reset(wire::Code::NoError.varint()).unwrap();recv.stop(wire::Code::NoError.varint()).unwrap();client.close().await;
 }).await.unwrap();});
    let off = Setup::with_config("win-files-disabled", "max_file_channels=0\n");
    assert!(
        stderr(&off.fs("stat", &[data.to_str().unwrap()]))
            .contains("file capability was not selected")
    );
}

#[test]
fn windows_upload_keeps_private_acl_and_checks_destination_authority_at_publication() {
    use file_protocol as p;
    use std::process::Stdio;
    let s = Setup::new("win-files-acl");
    let data = dir("win-files-acl-data");
    let source = data.join("source");
    std::fs::write(&source, b"abcdef").unwrap();
    let target = data.join("public-parent-upload");
    let out = Command::new("icacls.exe")
        .arg(&data)
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    s.ok(
        "push",
        &[source.to_str().unwrap(), target.to_str().unwrap()],
    );
    windows_security::check_private(&target).unwrap();
    let dest = data.join("denied");
    let mut child = Command::new(env!("CARGO_BIN_EXE_stpt"))
        .args(["__stpt-file-worker", "65535", "1048576"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    p::write_ipc(
        &mut input,
        &upload_request(&dest, Value::Array(vec![Value::Uint(0)])),
    )
    .unwrap();
    assert_eq!(p::read_ipc(&mut output).unwrap().unwrap().kind, p::ACCEPTED);
    let out = Command::new("icacls.exe")
        .arg(&data)
        .arg("/deny")
        .arg(format!("{}:(WD)", s.account))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    p::write_ipc(&mut input, &p::data(0, 0, b"abcdef".to_vec())).unwrap();
    let mut hash = p::Hash::new(1).unwrap();
    hash.update(b"abcdef");
    p::write_ipc(
        &mut input,
        &p::end(0, p::Status::Ok, 6, Some(hash.finish())),
    )
    .unwrap();
    let result = p::read_ipc(&mut output).unwrap().unwrap();
    drop(input);
    child.wait().unwrap();
    let out = Command::new("icacls.exe")
        .arg(&data)
        .args(["/remove:d", &s.account])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(p::status(&result).unwrap(), p::Status::Access, "{result:?}");
    assert!(!dest.exists());
}

#[test]
fn file_fin_cancels_only_channel_under_download_backpressure() {
    use file_protocol as p;
    let s = Setup::with_config("re-review-fin", "file_timeout=1\n");
    let data = dir("re-review-fin-data");
    let source = data.join("source");
    std::fs::File::create(&source)
        .unwrap()
        .set_len(32 * 1024 * 1024)
        .unwrap();
    quic::runtime().unwrap().block_on(async{tokio::time::timeout(Duration::from_secs(8),async{
 let client=Raw::login(&s).await;let request=Message::new(wire::FILE_REQUEST,vec![(0,Value::Uint(0)),(1,Value::Uint(1)),(2,path_value(&source))]);let(mut send,mut recv,a)=client.file(&request).await;assert_eq!(a.kind,p::ACCEPTED);send.finish().unwrap();
 tokio::time::sleep(Duration::from_millis(2500)).await;
 assert!(matches!(wire::read_message(&mut recv,65535).await,Err(wire::StreamError::Reset(code)) if code==wire::Code::NoError.varint()),"FIN must cancel the active operation without a Connection error");
 assert!(client.connection.close_reason().is_none());let stat=Message::new(wire::FILE_REQUEST,vec![(0,Value::Uint(0)),(1,Value::Uint(3)),(2,path_value(&source))]);let(_,_,m)=client.file(&stat).await;assert_eq!(p::status(&m).unwrap(),p::Status::Ok);client.close().await;
 }).await.unwrap();});
}

#[test]
#[ignore = "manual Tier RE >4GiB scenario; sparse source and bounded hash sink"]
fn review_download_above_four_gib() {
    use file_protocol as p;
    let s = Setup::new("re-review-large");
    let data = dir("re-review-large-data");

    let length = (1u64 << 32) + 65536;
    let source = data.join("large-sparse");
    let file = std::fs::File::create(&source).unwrap();
    file.set_len(length).unwrap();
    drop(file);
    quic::runtime().unwrap().block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(600), async {
            let client = Raw::login(&s).await;
            let request = Message::new(
                wire::FILE_REQUEST,
                vec![
                    (0, Value::Uint(0)),
                    (1, Value::Uint(1)),
                    (2, path_value(&source)),
                ],
            );
            let (mut send, mut recv, a) = client.file(&request).await;
            assert_eq!(a.kind, p::ACCEPTED);
            assert_eq!(p::size(&a, 1).unwrap(), length);
            let mut count = 0u64;
            let mut hash = p::Hash::new(1).unwrap();
            loop {
                let m = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                if m.kind == p::DATA {
                    let bytes = p::bytes(&m, 0, count, length).unwrap();
                    assert!(bytes.iter().all(|b| *b == 0));
                    hash.update(bytes);
                    count += bytes.len() as u64;
                } else {
                    assert_eq!(count, length);
                    assert_eq!(
                        p::verify_end(&m, 0, count, length, hash.finish()).unwrap(),
                        p::Status::Ok
                    );
                    break;
                }
            }
            wire::write_message(&mut send, &p::receipt(0, p::Status::Ok), 65535)
                .await
                .unwrap();
            assert_eq!(
                p::status(&wire::read_message(&mut recv, 65535).await.unwrap().unwrap()).unwrap(),
                p::Status::Ok
            );
            send.finish().unwrap();
            let _ = wire::read_message(&mut recv, 65535).await;
            client.close().await;
        })
        .await
        .unwrap();
    });
    std::fs::remove_file(&source).unwrap();
}

#[test]
fn file_fin_during_upload_keeps_connection_usable() {
    use file_protocol as p;
    let s = Setup::new("re-review-upload-fin");
    let data = dir("re-review-upload-fin-data");
    let target = data.join("target");
    quic::runtime().unwrap().block_on(async{tokio::time::timeout(Duration::from_secs(8),async{let client=Raw::login(&s).await;let(mut send,mut recv,a)=client.file(&upload_request(&target,Value::Array(vec![Value::Uint(0)]))).await;assert_eq!(a.kind,p::ACCEPTED);send.finish().unwrap();assert!(matches!(wire::read_message(&mut recv,65535).await,Err(wire::StreamError::Reset(code)) if code==wire::Code::NoError.varint()),"interrupted upload must be Channel-local");assert!(client.connection.close_reason().is_none());let q=Message::new(wire::FILE_REQUEST,vec![(0,Value::Uint(0)),(1,Value::Uint(3)),(2,path_value(&target))]);let(_,_,m)=client.file(&q).await;assert_eq!(p::status(&m).unwrap(),p::Status::NotFound);client.close().await;}).await.unwrap();});
}
