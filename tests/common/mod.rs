use std::path::PathBuf;
use std::process::{Command, Output};

/// Runs `stpt`; the user's own Client configuration is never read.
pub fn stpt(args: &[&str]) -> Output {
    let home = dir("home");
    Command::new(env!("CARGO_BIN_EXE_stpt"))
        .args(args)
        .env("APPDATA", &home)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &home)
        .output()
        .expect("run stpt")
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim_end().to_owned()
}

/// Directory for files of one test, created empty.
pub fn dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes a configuration file and returns its path as text.
pub fn config_file(name: &str, text: &str) -> String {
    let path = dir(name).join("config.toml");
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_owned()
}
