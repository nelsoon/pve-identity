//! QGA push channel (R6, R24): host writes per-audience token files into
//! the guest via the existing qemu-guest-agent.
use crate::ctx::{Channel, Ctx};
use crate::qga::Qga;

pub const UNIX_BASE: &str = "/var/run/pve-identity";
pub const WIN_BASE: &str = "C:\\ProgramData\\pve-identity";

/// Push all registered audiences to `vmid`; returns the guest OS id.
pub fn push(ctx: &Ctx, vmid: u32) -> Result<String, String> {
    let mut q = Qga::connect(vmid)?;
    let os = q.osinfo_id().unwrap_or_else(|_| "unknown".into());
    let windows = os == "windows";
    for aud in ctx.audiences() {
        let (tok, _) = ctx.issue(vmid, &aud, Channel::Push).map_err(|e| e.to_string())?;
        if windows {
            let dir = format!("{WIN_BASE}\\{aud}");
            let _ = q.exec("cmd.exe", &["/c", "if", "not", "exist", &dir, "mkdir", &dir]);
            q.write_file(&format!("{dir}\\token"), tok.as_bytes())?;
        } else {
            let dir = format!("{UNIX_BASE}/{aud}");
            // qga writes with umask 0 (lab T0.7): protect the dir, write a
            // temp file, then chmod + rename.
            let rc = q.exec("/bin/sh", &["-c", &format!("umask 077; mkdir -p '{dir}' && chmod 700 '{UNIX_BASE}' '{dir}'")])?;
            if rc != 0 {
                return Err(format!("mkdir {dir}: exit {rc}"));
            }
            let tmp = format!("{dir}/.token.tmp");
            q.write_file(&tmp, tok.as_bytes())?;
            let rc = q.exec("/bin/sh", &["-c", &format!("chmod 600 '{tmp}' && mv -f '{tmp}' '{dir}/token'")])?;
            if rc != 0 {
                return Err(format!("install token: exit {rc}"));
            }
        }
    }
    Ok(os)
}

/// Only report the guest OS (used by `auto` mode selection).
pub fn osinfo(vmid: u32) -> Result<String, String> {
    Qga::connect(vmid)?.osinfo_id()
}
