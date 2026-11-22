//! HTTPS OIDC discovery + JWKS (R19, D11, D13). Read-only.
use crate::ctx::Ctx;
use pve_identity_core::http::{read_request, respond, respond_json};
use std::net::TcpListener;
use std::sync::{Arc, RwLock};

pub struct Tls {
    pub cfg: RwLock<Option<Arc<rustls::ServerConfig>>>,
}

pub fn load_config(
    crt: &std::path::Path,
    key: &std::path::Path,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(crt).map_err(|e| e.to_string())?,
    ))
    .collect::<Result<_, _>>()
    .map_err(|e| e.to_string())?;
    let k = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?
    .ok_or("no private key")?;
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_no_client_auth()
    .with_single_cert(certs, k)
    .map_err(|e| e.to_string())?;
    Ok(Arc::new(cfg))
}

/// Path prefix of the issuer URL ("" or "/something").
pub fn prefix(iss: &str) -> String {
    let rest = iss.split_once("://").map(|x| x.1).unwrap_or(iss);
    rest.find('/')
        .map(|i| rest[i..].trim_end_matches('/').to_string())
        .unwrap_or_default()
}

pub fn discovery_doc(iss: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": iss,
        "jwks_uri": format!("{iss}/jwks.json"),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "pve"],
    })
}

pub fn serve(ctx: Arc<Ctx>, tls: Arc<Tls>, port: u16) -> std::io::Result<()> {
    let l = TcpListener::bind(("::", port)).or_else(|_| TcpListener::bind(("0.0.0.0", port)))?;
    crate::log(format!("https discovery listening on port {port}"));
    for c in l.incoming() {
        let Ok(sock) = c else { continue };
        let Some(cfg) = tls.cfg.read().unwrap().clone() else {
            continue;
        };
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let _ = sock.set_write_timeout(Some(std::time::Duration::from_secs(10)));
            let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                return;
            };
            let mut s = rustls::StreamOwned::new(conn, sock);
            let Ok(req) = read_request(&mut s) else {
                return;
            };
            let Some(iss) = ctx.issuer() else {
                let _ = respond(&mut s, 404, "text/plain", b"issuer not configured\n");
                return;
            };
            let p = prefix(&iss);
            let r = if req.method != "GET" {
                respond(&mut s, 400, "text/plain", b"GET only\n")
            } else if req.path == format!("{p}/.well-known/openid-configuration") {
                respond_json(&mut s, 200, &discovery_doc(&iss))
            } else if req.path == format!("{p}/jwks.json") {
                match ctx.keys.read().unwrap().jwks() {
                    Ok(j) => respond_json(&mut s, 200, &j),
                    Err(_) => respond(&mut s, 500, "text/plain", b"jwks error\n"),
                }
            } else {
                respond(&mut s, 404, "text/plain", b"not found\n")
            };
            let _ = r;
            s.conn.send_close_notify();
            let _ = std::io::Write::flush(&mut s);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn prefixes() {
        assert_eq!(super::prefix("https://a:8443"), "");
        assert_eq!(super::prefix("https://a/pve-identity/"), "/pve-identity");
    }
}
