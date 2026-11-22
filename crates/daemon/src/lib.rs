//! pve-identityd internals (host side).
pub mod cert;
pub mod ct;
pub mod ctx;
pub mod discovery;
pub mod push;
pub mod qga;
pub mod reconcile;
pub mod vsock;

pub fn log(msg: impl AsRef<str>) {
    eprintln!("{}", msg.as_ref());
}

/// Run a command, returning stdout or an error with stderr.
pub fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let o = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        ))
    }
}
