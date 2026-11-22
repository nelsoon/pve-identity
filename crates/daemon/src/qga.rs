//! Minimal QEMU guest agent client over /var/run/qemu-server/<vmid>.qga.
use base64::Engine;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct Qga {
    w: UnixStream,
    r: BufReader<UnixStream>,
}

impl Qga {
    pub fn connect(vmid: u32) -> Result<Qga, String> {
        let s = UnixStream::connect(format!("/var/run/qemu-server/{vmid}.qga")).map_err(|e| format!("qga connect: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        s.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let r = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
        let mut q = Qga { w: s, r };
        q.sync()?;
        Ok(q)
    }

    fn sync(&mut self) -> Result<(), String> {
        let id: u32 = rand_id();
        self.send(&json!({"execute": "guest-sync-delimited", "arguments": {"id": id}}))?;
        for _ in 0..20 {
            let v = self.read_line()?;
            if v["return"].as_u64() == Some(id as u64) {
                return Ok(());
            }
        }
        Err("qga sync failed".into())
    }

    fn send(&mut self, v: &Value) -> Result<(), String> {
        self.w.write_all(format!("{v}\n").as_bytes()).map_err(|e| format!("qga write: {e}"))
    }

    fn read_line(&mut self) -> Result<Value, String> {
        let mut buf = Vec::new();
        self.r.read_until(b'\n', &mut buf).map_err(|e| format!("qga read: {e}"))?;
        let s: Vec<u8> = buf.into_iter().filter(|&b| b != 0xff).collect();
        let t = String::from_utf8_lossy(&s);
        if t.trim().is_empty() {
            return Err("qga: empty reply".into());
        }
        serde_json::from_str(t.trim()).map_err(|e| format!("qga json: {e}"))
    }

    pub fn call(&mut self, cmd: &str, args: Value) -> Result<Value, String> {
        let mut m = json!({"execute": cmd});
        if !args.is_null() {
            m["arguments"] = args;
        }
        self.send(&m)?;
        let v = self.read_line()?;
        if let Some(e) = v.get("error") {
            return Err(format!("{cmd}: {}", e["desc"].as_str().unwrap_or("error")));
        }
        Ok(v["return"].clone())
    }

    /// "linux", "windows", or the guest's OS id (e.g. "freebsd").
    /// qga reports `kernel-name` only on some builds; `name` is reliable.
    pub fn osinfo_id(&mut self) -> Result<String, String> {
        let v = self.call("guest-get-osinfo", Value::Null)?;
        Ok(classify(&v))
    }

    pub fn exec(&mut self, path: &str, args: &[&str]) -> Result<i64, String> {
        let pid = self.call("guest-exec", json!({"path": path, "arg": args}))?["pid"]
            .as_i64()
            .ok_or("guest-exec: no pid")?;
        for _ in 0..50 {
            let st = self.call("guest-exec-status", json!({"pid": pid}))?;
            if st["exited"].as_bool() == Some(true) {
                return Ok(st["exitcode"].as_i64().unwrap_or(-1));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err("guest-exec timeout".into())
    }

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), String> {
        let h = self.call("guest-file-open", json!({"path": path, "mode": "w"}))?;
        let h = h.as_i64().ok_or("guest-file-open: no handle")?;
        let b = base64::engine::general_purpose::STANDARD.encode(data);
        let r = self.call("guest-file-write", json!({"handle": h, "buf-b64": b}));
        let c = self.call("guest-file-close", json!({"handle": h}));
        r.and(c).map(|_| ())
    }
}

fn rand_id() -> u32 {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (t.subsec_nanos() ^ std::process::id()) & 0x7fff_ffff
}

pub fn classify(v: &Value) -> String {
    let f = |k: &str| v[k].as_str().unwrap_or("").to_lowercase();
    if f("id") == "mswindows" || f("kernel-name").starts_with("windows") {
        "windows".into()
    } else if f("kernel-name") == "linux" || f("name").contains("linux") {
        "linux".into()
    } else if !f("id").is_empty() {
        f("id")
    } else {
        "unknown".into()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn os() {
        let c = |s: &str| super::classify(&serde_json::from_str(s).unwrap());
        assert_eq!(c(r#"{"id":"debian","name":"Debian GNU/Linux"}"#), "linux");
        assert_eq!(c(r#"{"id":"freebsd","name":"FreeBSD"}"#), "freebsd");
        assert_eq!(c(r#"{"id":"mswindows","name":"Microsoft Windows 11"}"#), "windows");
    }
}
