//! Minimal HTTP/1.x over any stream: one request, one response, close.
use std::io::{Read, Write};

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
}

impl Request {
    pub fn param(&self, k: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.as_str())
    }
}

pub fn read_request<R: Read>(s: &mut R) -> std::io::Result<Request> {
    let mut buf = Vec::with_capacity(512);
    let mut b = [0u8; 512];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && !buf.windows(2).any(|w| w == b"\n\n") {
        let n = s.read(&mut b)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&b[..n]);
        if buf.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().next().unwrap_or("");
    let mut it = line.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("/");
    let (path, q) = target.split_once('?').unwrap_or((target, ""));
    let query = q
        .split('&')
        .filter(|x| !x.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (pct_decode(k), pct_decode(v))
        })
        .collect();
    Ok(Request {
        method,
        path: path.to_string(),
        query,
    })
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Always sends Content-Length (RGW needs it, D13).
pub fn respond<W: Write>(s: &mut W, code: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Error",
    };
    write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    s.write_all(body)?;
    s.flush()
}

pub fn respond_json<W: Write>(s: &mut W, code: u16, v: &serde_json::Value) -> std::io::Result<()> {
    respond(s, code, "application/json", v.to_string().as_bytes())
}

/// Parse an HTTP response (client side): status + body.
pub fn read_response<R: Read>(s: &mut R) -> std::io::Result<(u16, Vec<u8>)> {
    let mut all = Vec::new();
    s.read_to_end(&mut all)?;
    let pos = all
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no header end"))?;
    let head = String::from_utf8_lossy(&all[..pos]);
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((code, all[pos + 4..].to_vec()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse() {
        let mut r: &[u8] = b"GET /v1/token?aud=s%33&x=1 HTTP/1.1\r\nHost: a\r\n\r\n";
        let q = super::read_request(&mut r).unwrap();
        assert_eq!(q.path, "/v1/token");
        assert_eq!(q.param("aud"), Some("s3"));
    }
}
