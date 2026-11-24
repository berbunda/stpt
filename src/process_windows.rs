//! Windows process backend: current Account only, suspended startup into an
//! owned kill-on-close Job, ConPTY or three pipes, explicit shell environment.
use crate::pty::Console;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
    process::ExitStatusExt,
};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};
use windows_sys::Win32::{
    Foundation::*,
    System::{JobObjects::*, Threading::*, WindowsProgramming::GetUserNameW},
};
pub type ChildStdin = Box<tokio::fs::File>;
pub type ChildStdout = Box<tokio::fs::File>;
pub type ChildStderr = Box<tokio::fs::File>;
pub const SYSTEM_ENVIRONMENT: [&str; 0] = [];
pub fn system_environment(_: &[&str]) -> Vec<(String, String)> {
    Vec::new()
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    home: PathBuf,
}
impl Account {
    pub fn file_worker(&self, peer_limit: u64, max_size: u64) -> io::Result<tokio::process::Child> {
        if Self::lookup(&self.name)?.as_ref() != Some(self) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Account changed",
            ));
        }
        let mut command = tokio::process::Command::new(std::env::current_exe()?);
        command
            .arg("__stpt-file-worker")
            .arg(peer_limit.to_string())
            .arg(max_size.to_string())
            .env_clear()
            .current_dir(
                std::env::var_os("SystemRoot")
                    .ok_or_else(|| io::Error::other("SystemRoot unavailable"))?,
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        command.creation_flags(CREATE_NO_WINDOW);
        command.spawn()
    }
    pub fn current_name() -> io::Result<String> {
        let mut name = vec![0u16; 257];
        let mut length = name.len() as u32;
        // SAFETY: buffer and its length are valid for GetUserNameW.
        if unsafe { GetUserNameW(name.as_mut_ptr(), &mut length) } == 0 {
            return Err(io::Error::last_os_error());
        }
        String::from_utf16(&name[..length.saturating_sub(1) as usize])
            .map_err(|_| io::Error::other("Account name is not Unicode scalar text"))
    }
    pub fn lookup(name: &str) -> io::Result<Option<Self>> {
        // No account aliases: one canonical key filename and Session owner.
        if name != Self::current_name()? {
            return Ok(None);
        }
        let home = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| io::Error::other("USERPROFILE unavailable"))?;
        Ok(Some(Self {
            name: name.into(),
            home,
        }))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pid(u32);
impl Pid {
    pub fn from_raw(n: i32) -> Self {
        Self(n as u32)
    }
    pub fn as_raw(self) -> i32 {
        self.0 as i32
    }
}
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    SIGINT = 1,
    SIGQUIT = 2,
    SIGHUP = 3,
    SIGTERM = 4,
    SIGKILL = 5,
    SIGUSR1 = 6,
    SIGUSR2 = 7,
}
impl TryFrom<i32> for Signal {
    type Error = ();
    fn try_from(n: i32) -> Result<Self, ()> {
        match n {
            1 => Ok(Self::SIGINT),
            2 => Ok(Self::SIGQUIT),
            3 => Ok(Self::SIGHUP),
            4 => Ok(Self::SIGTERM),
            5 => Ok(Self::SIGKILL),
            6 => Ok(Self::SIGUSR1),
            7 => Ok(Self::SIGUSR2),
            _ => Err(()),
        }
    }
}
pub enum Program {
    LoginShell,
    Shell(String),
    Argv(Vec<String>),
}
pub enum Io {
    Pty { slave: Arc<Console>, term: String },
    Pipes,
}
struct Job(OwnedHandle);
fn registry() -> &'static Mutex<BTreeMap<u32, Weak<Job>>> {
    static JOBS: OnceLock<Mutex<BTreeMap<u32, Weak<Job>>>> = OnceLock::new();
    JOBS.get_or_init(Default::default)
}
impl Job {
    fn new() -> io::Result<Arc<Self>> {
        // SAFETY: create unnamed, non-inheritable Job; initialized limits match API size.
        unsafe {
            let raw = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Arc::new(Self(OwnedHandle::from_raw_handle(raw)));
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as _,
                std::mem::size_of_val(&limits) as u32,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }
    }
    fn terminate(&self) -> io::Result<()> {
        // SAFETY: owns a live Job handle, containing only this Session tree.
        if unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
pub struct Child {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    process: OwnedHandle,
    pid: u32,
    job: Arc<Job>,
    _console: Option<Arc<Console>>,
}
impl Child {
    pub fn id(&self) -> Option<u32> {
        Some(self.pid)
    }
    pub async fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        loop {
            // SAFETY: live process handle; zero wait is nonblocking.
            let state = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) };
            if state == WAIT_OBJECT_0 {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                return Ok(std::process::ExitStatus::from_raw(code));
            }
            if state == WAIT_FAILED {
                return Err(io::Error::last_os_error());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        registry().lock().unwrap().remove(&self.pid);
        let _ = self.job.terminate();
    }
}
struct Attributes {
    _storage: Vec<usize>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn new() -> io::Result<Self> {
        unsafe {
            let mut size = 0;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
            let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
            let ptr = storage.as_mut_ptr().cast();
            if InitializeProcThreadAttributeList(ptr, 1, 0, &mut size) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                _storage: storage,
                ptr,
            })
        }
    }
    fn set(&mut self, key: usize, value: *const std::ffi::c_void, size: usize) -> io::Result<()> {
        if unsafe {
            UpdateProcThreadAttribute(
                self.ptr,
                0,
                key,
                value,
                size,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.ptr) };
    }
}
fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut v: Vec<_> = s.encode_wide().collect();
    if v.contains(&0) {
        return Err(io::Error::other("embedded NUL"));
    }
    v.push(0);
    Ok(v)
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace(char::from(39), "''"))
}
fn shell(account: &Account, program: &Program) -> io::Result<(PathBuf, Vec<String>)> {
    let root =
        std::env::var_os("SystemRoot").ok_or_else(|| io::Error::other("SystemRoot unavailable"))?;
    let shell = PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut args = vec!["-NoLogo".into(), "-NoProfile".into()];
    let script = match program {
        Program::LoginShell => {
            args.push("-NoExit".into());
            String::new()
        }
        Program::Shell(line) => line.clone(),
        Program::Argv(argv) => {
            let bytes = crate::cbor::encode(&crate::cbor::Value::Array(
                argv.iter().cloned().map(crate::cbor::Value::Text).collect(),
            ));
            let executable = std::env::current_exe()?
                .into_os_string()
                .into_string()
                .map_err(|_| io::Error::other("Server executable path is not Unicode"))?;
            format!(
                "& {} '__stpt-native-exec' '{}'; exit $LASTEXITCODE",
                quote(&executable),
                STANDARD.encode(bytes)
            )
        }
    };
    let _ = account;
    let script = format!(
        "[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);{script}"
    );
    args.push("-EncodedCommand".into());
    args.push(
        STANDARD.encode(
            script
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        ),
    );
    Ok((shell, args))
}
/// CRT quoting for the fixed executable and opaque base64 shell arguments.
fn command_line(executable: &Path, args: &[String]) -> io::Result<Vec<u16>> {
    let exe = executable
        .to_str()
        .ok_or_else(|| io::Error::other("shell path is not Unicode"))?;
    let mut line = format!("\"{exe}\"");
    for arg in args {
        if arg.contains(['\"', ' ', '\t', '\r', '\n']) {
            return Err(io::Error::other("unsafe internal shell argument"));
        }
        line.push(' ');
        line.push_str(arg);
    }
    let result = wide(OsStr::new(&line))?;
    if result.len() > 32767 {
        return Err(io::Error::other(
            "command exceeds Windows command-line limit",
        ));
    }
    Ok(result)
}
pub fn spawn(
    account: &Account,
    program: &Program,
    env: &[(String, String)],
    io: Io,
) -> io::Result<Child> {
    if Account::lookup(&account.name)?.as_ref() != Some(account) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let (executable, args) = shell(account, program)?;
    let app = wide(executable.as_os_str())?;
    let mut line = command_line(&executable, &args)?;
    let home = wide(account.home.as_os_str())?;
    let allowed = [
        "SystemRoot",
        "WINDIR",
        "SystemDrive",
        "PATH",
        "PATHEXT",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "USERNAME",
        "USERDOMAIN",
        "COMSPEC",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
    ];
    let mut environment: BTreeMap<String, OsString> = BTreeMap::new();
    for name in allowed {
        if let Some(value) = std::env::var_os(name) {
            environment.insert(name.to_ascii_uppercase(), value);
        }
    }
    for (k, v) in env {
        environment.insert(k.to_ascii_uppercase(), v.into());
    }
    if let Io::Pty { term, .. } = &io {
        environment.insert("TERM".into(), term.into());
    }
    let mut block = Vec::<u16>::new();
    for (k, v) in environment {
        block.extend(wide(OsStr::new(&format!(
            "{k}={}",
            v.to_str()
                .ok_or_else(|| io::Error::other("non-Unicode environment"))?
        )))?);
    }
    block.push(0);
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of_val(&startup) as u32;
    let mut attrs = Attributes::new()?;
    let mut handles = Vec::new();
    let mut retained = Vec::new();
    let mut parent = Vec::new();
    let mut console = None;
    let mut flags = CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
    let inherit = match io {
        Io::Pty { slave, term } => {
            // Explicit null standard handles stop Windows from copying the
            // Server's redirected handles; ConPTY supplies the new console ones.
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            let _ = term;
            attrs.set(
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                slave.handle()? as _,
                std::mem::size_of::<isize>(),
            )?;
            console = Some(slave);
            false
        }
        Io::Pipes => {
            flags |= CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
            let (stdin_read, stdin_write) = crate::pty::pipe(true)?;
            let (stdout_read, stdout_write) = crate::pty::pipe(true)?;
            let (stderr_read, stderr_write) = crate::pty::pipe(true)?;
            parent = vec![stdin_write, stdout_read, stderr_read];
            for h in &parent {
                if unsafe { SetHandleInformation(h.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            retained.extend([stdin_read, stdout_write, stderr_write]);
            handles.extend(retained.iter().map(|h| h.as_raw_handle()));
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = handles[0];
            startup.StartupInfo.hStdOutput = handles[1];
            startup.StartupInfo.hStdError = handles[2];
            attrs.set(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                handles.len() * std::mem::size_of::<HANDLE>(),
            )?;
            true
        }
    };
    startup.lpAttributeList = attrs.ptr;
    let job = Job::new()?;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: all strings, environment, attribute storage and inherited handles
    // remain live until CreateProcess returns. No process runs before Job admission.
    unsafe {
        if CreateProcessW(
            app.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            inherit as i32,
            flags,
            block.as_ptr().cast(),
            home.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(c) = &console {
            c.release_endpoints();
        }
        let process = OwnedHandle::from_raw_handle(info.hProcess);
        let thread = OwnedHandle::from_raw_handle(info.hThread);
        if AssignProcessToJobObject(job.0.as_raw_handle(), process.as_raw_handle()) == 0 {
            let error = io::Error::last_os_error();
            TerminateProcess(process.as_raw_handle(), 1);
            return Err(error);
        }
        if ResumeThread(thread.as_raw_handle()) == u32::MAX {
            let error = io::Error::last_os_error();
            let _ = job.terminate();
            return Err(error);
        }
        registry()
            .lock()
            .unwrap()
            .insert(info.dwProcessId, Arc::downgrade(&job));
        let mut pipes = parent
            .into_iter()
            .map(|h| Box::new(tokio::fs::File::from_std(std::fs::File::from(h))));
        Ok(Child {
            stdin: pipes.next(),
            stdout: pipes.next(),
            stderr: pipes.next(),
            process,
            pid: info.dwProcessId,
            job,
            _console: console,
        })
    }
}
pub async fn signal_group(account: &Account, group: Pid, signal: Signal) -> io::Result<()> {
    if Account::lookup(&account.name)?.as_ref() != Some(account) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    if matches!(signal, Signal::SIGTERM | Signal::SIGKILL | Signal::SIGHUP)
        && let Some(job) = registry()
            .lock()
            .unwrap()
            .get(&group.0)
            .and_then(Weak::upgrade)
    {
        job.terminate()?;
    }
    Ok(())
}
pub fn in_session_job(leader: Pid, pid: u32) -> bool {
    let Some(job) = registry()
        .lock()
        .unwrap()
        .get(&leader.0)
        .and_then(Weak::upgrade)
    else {
        return false;
    };
    // SAFETY: own the process and Job handles during the kernel membership check.
    unsafe {
        let raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if raw.is_null() {
            return false;
        }
        let process = OwnedHandle::from_raw_handle(raw);
        let mut member = 0;
        IsProcessInJob(process.as_raw_handle(), job.0.as_raw_handle(), &mut member) != 0
            && member != 0
    }
}
pub fn groups_in_session(pid: Pid) -> Vec<Pid> {
    vec![pid]
}
/// Private argument-vector trampoline. The Account shell runs this binary with
/// fixed safe arguments; the decoded arguments never undergo shell parsing.
pub fn native_exec() -> std::process::ExitCode {
    let run = || -> io::Result<std::process::ExitStatus> {
        let encoded = std::env::args()
            .nth(2)
            .ok_or_else(|| io::Error::other("missing native arguments"))?;
        if encoded.len() > 65535 {
            return Err(io::Error::other("native arguments too large"));
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| io::Error::other("invalid native arguments"))?;
        let value = crate::cbor::decode(&bytes)
            .map_err(|_| io::Error::other("invalid native arguments"))?;
        let args = value
            .as_array()
            .ok_or_else(|| io::Error::other("invalid native argv"))?;
        let args: Vec<_> = args
            .iter()
            .map(|v| {
                if let crate::cbor::Value::Text(s) = v {
                    Ok(s)
                } else {
                    Err(io::Error::other("invalid native argument"))
                }
            })
            .collect::<io::Result<_>>()?;
        let (program, args) = args
            .split_first()
            .ok_or_else(|| io::Error::other("empty argv"))?;
        let native = program.trim_end_matches([' ', '.']);
        if Path::new(native)
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|e| e.eq_ignore_ascii_case("bat") || e.eq_ignore_ascii_case("cmd"))
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "batch files require an explicit shell command",
            ));
        }
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE,
        };
        let mut command = std::process::Command::new(program);
        let mut mode = 0;
        if unsafe { GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut mode) } == 0 {
            command.creation_flags(CREATE_NO_WINDOW);
        }
        command
            .args(args)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
    };
    match run() {
        Ok(status) => std::process::exit(status.code().unwrap_or(255)),
        Err(e) => {
            eprintln!("stpt: native execution: {e}");
            std::process::ExitCode::from(255)
        }
    }
}
