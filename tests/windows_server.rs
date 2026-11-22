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
        let config = server_config(name, "");
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
            vec![(0, Value::Array(vec![Value::Uint(0xff000001)]))],
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
    assert_eq!(out.status.code(), Some(255));
    assert!(
        stderr(&out).contains("file capability was not selected"),
        "{}",
        stderr(&out)
    );
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
