//! LXC channel: per-CT host dir bind-mounted at /dev/pve-identity (R7).
use crate::ctx::{serve_guest, Channel, Ctx};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const HOST_BASE: &str = "/run/pve-identity/ct";

pub fn mount_entry(vmid: u32) -> String {
    format!("{HOST_BASE}/{vmid} dev/pve-identity none bind,ro,optional,create=dir 0 0")
}

pub fn host_dir(vmid: u32) -> PathBuf {
    PathBuf::from(HOST_BASE).join(vmid.to_string())
}

/// Peer process belongs to CT `vmid` (cgroup check, lab T0.3).
pub fn peer_in_ct(stream: &std::os::unix::net::UnixStream, vmid: u32) -> bool {
    use std::os::fd::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as u32;
    let r = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len,
        )
    };
    if r != 0 || cred.pid <= 0 {
        return false;
    }
    std::fs::read_to_string(format!("/proc/{}/cgroup", cred.pid))
        .map(|c| {
            c.lines().any(|l| {
                l.contains(&format!("/lxc/{vmid}/")) || l.ends_with(&format!("/lxc/{vmid}"))
            })
        })
        .unwrap_or(false)
}

#[derive(Default)]
pub struct CtSockets {
    running: Mutex<BTreeMap<u32, Arc<AtomicBool>>>,
}

impl CtSockets {
    /// Make sure the dir exists (all CTs in a pool, cluster-wide, so a
    /// migrated CT finds it) and, for local CTs, a socket listener runs.
    pub fn ensure(&self, ctx: &Arc<Ctx>, vmid: u32, local: bool) {
        let d = host_dir(vmid);
        if std::fs::create_dir_all(&d).is_ok() {
            let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755));
        }
        let mut run = self.running.lock().unwrap();
        if !local {
            if let Some(stop) = run.remove(&vmid) {
                stop.store(true, Ordering::SeqCst);
                let _ = std::fs::remove_file(d.join("sock"));
            }
            return;
        }
        if run.contains_key(&vmid) && d.join("sock").exists() {
            return;
        }
        let sock = d.join("sock");
        let _ = std::fs::remove_file(&sock);
        let l = match UnixListener::bind(&sock) {
            Ok(l) => l,
            Err(e) => {
                crate::log(format!("ct {vmid}: cannot bind socket: {e}"));
                return;
            }
        };
        let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666));
        let stop = Arc::new(AtomicBool::new(false));
        run.insert(vmid, stop.clone());
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut s) = c else { continue };
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                if !peer_in_ct(&s, vmid) {
                    crate::log(format!(
                        "refuse ct-socket vmid={vmid} reason=\"peer not in CT\""
                    ));
                    let _ = pve_identity_core::http::respond(
                        &mut s,
                        403,
                        "text/plain",
                        b"peer not in this CT\n",
                    );
                    continue;
                }
                serve_guest(&ctx, &mut s, vmid, Channel::CtSocket);
            }
        });
    }

    pub fn remove(&self, vmid: u32) {
        if let Some(stop) = self.running.lock().unwrap().remove(&vmid) {
            stop.store(true, Ordering::SeqCst);
            // wake the accept loop
            let _ = std::os::unix::net::UnixStream::connect(host_dir(vmid).join("sock"));
        }
        let _ = std::fs::remove_dir_all(host_dir(vmid));
    }

    pub fn known(&self) -> Vec<u32> {
        self.running.lock().unwrap().keys().copied().collect()
    }
}

/// Host-written token files `<aud>/token` for a running local CT.
pub fn write_tokens(ctx: &Ctx, vmid: u32) -> Result<usize, String> {
    let d = host_dir(vmid);
    let auds = ctx.audiences();
    let mut n = 0;
    for aud in &auds {
        let (t, _) = ctx
            .issue(vmid, aud, Channel::CtFiles)
            .map_err(|e| e.to_string())?;
        let ad = d.join(aud);
        std::fs::create_dir_all(&ad).map_err(|e| e.to_string())?;
        let _ = std::fs::set_permissions(&ad, std::fs::Permissions::from_mode(0o755));
        pve_identity_core::write_atomic(&ad.join("token"), t.as_bytes(), 0o644)
            .map_err(|e| e.to_string())?;
        n += 1;
    }
    // drop audiences no longer registered
    if let Ok(rd) = std::fs::read_dir(&d) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if e.path().is_dir() && !auds.contains(&name) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    Ok(n)
}
