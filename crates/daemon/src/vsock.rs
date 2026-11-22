//! VM channel: AF_VSOCK listener, CID = VMID (R4, R5).
use crate::ctx::{serve_guest, Channel, Ctx};
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd, AsRawFd};
use std::sync::Arc;

pub struct VsockStream(OwnedFd);

impl Read for VsockStream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.0.as_raw_fd(), b.as_mut_ptr() as *mut _, b.len()) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }
}
impl Write for VsockStream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.0.as_raw_fd(), b.as_ptr() as *const _, b.len()) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn set_timeout(fd: i32, secs: i64) {
    let tv = libc::timeval { tv_sec: secs, tv_usec: 0 };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, opt, &tv as *const _ as *const _, std::mem::size_of_val(&tv) as u32)
        };
    }
}

pub fn listen(cid: u32, port: u32) -> std::io::Result<OwnedFd> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ofd = OwnedFd::from_raw_fd(fd);
        let mut a: libc::sockaddr_vm = std::mem::zeroed();
        a.svm_family = libc::AF_VSOCK as u16;
        a.svm_port = port;
        a.svm_cid = cid;
        if libc::bind(fd, &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32) < 0
            || libc::listen(fd, 64) < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ofd)
    }
}

/// Client connect (used by the guest agent).
pub fn connect(cid: u32, port: u32, timeout: i64) -> std::io::Result<VsockStream> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ofd = OwnedFd::from_raw_fd(fd);
        set_timeout(fd, timeout);
        let mut a: libc::sockaddr_vm = std::mem::zeroed();
        a.svm_family = libc::AF_VSOCK as u16;
        a.svm_port = port;
        a.svm_cid = cid;
        if libc::connect(fd, &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(VsockStream(ofd))
    }
}

/// The running QEMU process for `vmid` really carries guest-cid=<vmid>.
pub fn running_cid_matches(vmid: u32) -> bool {
    running_cmdline(vmid)
        .map(|c| c.split('\0').any(|a| a.starts_with("vhost-vsock-pci,") && a.split(',').any(|p| p == format!("guest-cid={vmid}"))))
        .unwrap_or(false)
}

pub fn running_cmdline(vmid: u32) -> Option<String> {
    let pid = std::fs::read_to_string(format!("/var/run/qemu-server/{vmid}.pid")).ok()?;
    let c = std::fs::read(format!("/proc/{}/cmdline", pid.trim())).ok()?;
    let s = String::from_utf8_lossy(&c).into_owned();
    s.contains(&format!("-id\0{vmid}\0")).then_some(s)
}

pub fn serve(ctx: Arc<Ctx>) -> std::io::Result<()> {
    let lfd = listen(libc::VMADDR_CID_ANY, crate::ctx::VSOCK_PORT)?;
    crate::log(format!("vsock listening on port {}", crate::ctx::VSOCK_PORT));
    loop {
        let mut a: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&a) as u32;
        let fd = unsafe { libc::accept4(lfd.as_raw_fd(), &mut a as *mut _ as *mut libc::sockaddr, &mut len, libc::SOCK_CLOEXEC) };
        if fd < 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            continue;
        }
        set_timeout(fd, 5);
        let mut st = VsockStream(unsafe { OwnedFd::from_raw_fd(fd) });
        let ctx = ctx.clone();
        let cid = a.svm_cid;
        std::thread::spawn(move || {
            // Kernel-assigned peer CID is the identity; the VM must run here
            // with exactly that CID (lab T0.2).
            if cid < 100 || !running_cid_matches(cid) {
                crate::log(format!("refuse vsock cid={cid} reason=\"no local VM with this CID\""));
                let _ = pve_identity_core::http::respond(&mut st, 403, "text/plain", b"unknown guest\n");
                return;
            }
            serve_guest(&ctx, &mut st, cid, Channel::Vsock);
        });
    }
}
