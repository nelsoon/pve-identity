//! pve-identity guest agent (R8, R9): talks to the host over vsock
//! (CID 2, port 10245), keeps /run/pve-identity/<aud>/token fresh and serves
//! /run/pve-identity/agent.sock. Root/group-restricted, never mounted into
//! workloads.
use pve_identity_core::http::{read_request, read_response, respond, respond_json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const HOST_CID: u32 = 2;
const PORT: u32 = 10245;
const BASE: &str = "/run/pve-identity";
const GROUP: &str = "pve-identity";

struct Vs(OwnedFd);
impl Read for Vs {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.0.as_raw_fd(), b.as_mut_ptr() as *mut _, b.len()) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }
}
impl Write for Vs {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.0.as_raw_fd(), b.as_ptr() as *const _, b.len()) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn host_get(path: &str) -> Result<(u16, Vec<u8>), String> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(format!("vsock: {}", std::io::Error::last_os_error()));
        }
        let ofd = OwnedFd::from_raw_fd(fd);
        let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
        for o in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            libc::setsockopt(fd, libc::SOL_SOCKET, o, &tv as *const _ as *const _, std::mem::size_of_val(&tv) as u32);
        }
        let mut a: libc::sockaddr_vm = std::mem::zeroed();
        a.svm_family = libc::AF_VSOCK as u16;
        a.svm_cid = HOST_CID;
        a.svm_port = PORT;
        if libc::connect(fd, &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32) < 0 {
            return Err(format!("vsock connect: {}", std::io::Error::last_os_error()));
        }
        let mut s = Vs(ofd);
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: pve-identity\r\n\r\n").as_bytes()).map_err(|e| e.to_string())?;
        read_response(&mut s).map_err(|e| e.to_string())
    }
}

fn fetch_token(aud: &str) -> Result<(String, u64), String> {
    let (c, b) = host_get(&format!("/v1/token?aud={aud}&format=json"))?;
    if c != 200 {
        return Err(format!("host refused ({c}): {}", String::from_utf8_lossy(&b).trim()));
    }
    let v: serde_json::Value = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
    Ok((v["token"].as_str().unwrap_or("").to_string(), v["exp"].as_u64().unwrap_or(0)))
}

fn audiences() -> Result<Vec<String>, String> {
    if let Ok(s) = std::fs::read_to_string("/etc/pve-identity/audiences") {
        let v: Vec<String> = s.split_whitespace().map(String::from).collect();
        if !v.is_empty() {
            return Ok(v);
        }
    }
    let (c, b) = host_get("/v1/audiences")?;
    if c != 200 {
        return Err(format!("audiences: {c}"));
    }
    serde_json::from_slice(&b).map_err(|e| e.to_string())
}

fn group_gid() -> Option<u32> {
    std::fs::read_to_string("/etc/group").ok()?.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[0] == GROUP).then(|| f[2].parse().ok()).flatten()
    })
}

fn secure(p: &Path, mode: u32, gid: Option<u32>) {
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
    if let Some(g) = gid {
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        unsafe { libc::chown(c.as_ptr(), 0, g) };
    }
}

fn write_token(aud: &str, tok: &str, gid: Option<u32>) -> std::io::Result<()> {
    let d = PathBuf::from(BASE).join(aud);
    std::fs::create_dir_all(&d)?;
    secure(&d, 0o750, gid);
    let tmp = d.join(".token.tmp");
    std::fs::write(&tmp, tok)?;
    secure(&tmp, 0o640, gid);
    std::fs::rename(tmp, d.join("token"))
}

type Cache = Arc<Mutex<BTreeMap<String, (String, u64)>>>;

fn get_cached(cache: &Cache, aud: &str) -> Result<String, String> {
    let now = pve_identity_core::now();
    if let Some((t, exp)) = cache.lock().unwrap().get(aud) {
        if *exp > now + 60 {
            return Ok(t.clone());
        }
    }
    let (t, exp) = fetch_token(aud)?;
    cache.lock().unwrap().insert(aud.to_string(), (t.clone(), exp));
    Ok(t)
}

fn serve_socket(cache: Cache, gid: Option<u32>) {
    let p = PathBuf::from(BASE).join("agent.sock");
    let _ = std::fs::remove_file(&p);
    let l = match std::os::unix::net::UnixListener::bind(&p) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("agent.sock: {e}");
            return;
        }
    };
    secure(&p, 0o660, gid);
    for c in l.incoming().flatten() {
        let cache = cache.clone();
        std::thread::spawn(move || {
            let mut s = c;
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let Ok(req) = read_request(&mut s) else { return };
            let _ = match (req.path.as_str(), req.param("aud")) {
                ("/v1/token", Some(aud)) => match get_cached(&cache, aud) {
                    Ok(t) => respond(&mut s, 200, "application/jwt", t.as_bytes()),
                    Err(e) => respond(&mut s, 403, "text/plain", format!("{e}\n").as_bytes()),
                },
                ("/v1/audiences", _) => match audiences() {
                    Ok(a) => respond_json(&mut s, 200, &serde_json::json!(a)),
                    Err(e) => respond(&mut s, 503, "text/plain", format!("{e}\n").as_bytes()),
                },
                _ => respond(&mut s, 404, "text/plain", b"not found\n"),
            };
        });
    }
}

fn daemon() -> ! {
    let gid = group_gid();
    let _ = std::fs::create_dir_all(BASE);
    secure(Path::new(BASE), 0o750, gid);
    let cache: Cache = Default::default();
    let c = cache.clone();
    std::thread::spawn(move || serve_socket(c, gid));
    loop {
        let mut sleep = 60u64;
        match audiences() {
            Ok(auds) => {
                for aud in &auds {
                    match fetch_token(aud) {
                        Ok((t, exp)) => {
                            if let Err(e) = write_token(aud, &t, gid) {
                                eprintln!("{aud}: write: {e}");
                            }
                            let left = exp.saturating_sub(pve_identity_core::now());
                            sleep = sleep.min((left / 2).max(10));
                            cache.lock().unwrap().insert(aud.clone(), (t, exp));
                        }
                        Err(e) => {
                            eprintln!("{aud}: {e}");
                            sleep = sleep.min(15);
                        }
                    }
                }
                // drop files of audiences no longer registered
                if let Ok(rd) = std::fs::read_dir(BASE) {
                    for e in rd.flatten() {
                        let n = e.file_name().to_string_lossy().to_string();
                        if e.path().is_dir() && !auds.contains(&n) {
                            let _ = std::fs::remove_dir_all(e.path());
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("host: {e}");
                sleep = 15;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(sleep));
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("daemon") => daemon(),
        Some("token") => match a.get(1).map(|aud| fetch_token(aud)) {
            Some(Ok((t, _))) => println!("{t}"),
            Some(Err(e)) => {
                eprintln!("pve-identity: {e}");
                std::process::exit(1)
            }
            None => std::process::exit(2),
        },
        Some("whoami") => match host_get("/v1/identity") {
            Ok((200, b)) => println!("{}", String::from_utf8_lossy(&b)),
            Ok((c, b)) => {
                eprintln!("pve-identity: {c} {}", String::from_utf8_lossy(&b).trim());
                std::process::exit(1)
            }
            Err(e) => {
                eprintln!("pve-identity: {e}");
                std::process::exit(1)
            }
        },
        _ => {
            eprintln!("usage: pve-identity daemon | token AUD | whoami");
            std::process::exit(2)
        }
    }
}
