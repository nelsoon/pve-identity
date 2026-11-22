//! Certificates from the PVE cluster CA, via openssl (D13).
use pve_identity_core::keys::Key;
use std::path::{Path, PathBuf};

pub const CA_CERT: &str = "/etc/pve/pve-root-ca.pem";
pub const CA_KEY: &str = "/etc/pve/priv/pve-root-ca.key";

fn tmpdir() -> Result<PathBuf, String> {
    let d = PathBuf::from(format!("/run/pve-identity/tmp-{}-{}", std::process::id(), pve_identity_core::now()));
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    Ok(d)
}

fn serial() -> String {
    crate::run("openssl", &["rand", "-hex", "16"])
        .map(|h| format!("0x7{}", &h.trim()[1..]))
        .unwrap_or_else(|_| format!("0x{:x}", pve_identity_core::now()))
}

fn sign_csr(csr: &Path, out: &Path, ext: &Path, days: u32) -> Result<(), String> {
    crate::run(
        "openssl",
        &[
            "x509", "-req", "-in", &csr.to_string_lossy(), "-CA", CA_CERT, "-CAkey", CA_KEY,
            "-set_serial", &serial(), "-days", &days.to_string(), "-sha256",
            "-extfile", &ext.to_string_lossy(), "-out", &out.to_string_lossy(),
        ],
    )
    .map(|_| ())
}

/// Issue the x5c cert for a signing key.
pub fn key_cert(k: &Key, cluster: &str) -> Result<String, String> {
    let d = tmpdir()?;
    let r = (|| {
        let kf = d.join("k.pem");
        pve_identity_core::write_atomic(&kf, k.private.as_bytes(), 0o600).map_err(|e| e.to_string())?;
        let csr = d.join("k.csr");
        crate::run("openssl", &["req", "-new", "-key", &kf.to_string_lossy(), "-subj",
            &format!("/O=pve-identity/OU={cluster}/CN={}", k.kid), "-out", &csr.to_string_lossy()])?;
        let ext = d.join("ext.cnf");
        std::fs::write(&ext, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n").map_err(|e| e.to_string())?;
        let out = d.join("k.crt");
        sign_csr(&csr, &out, &ext, 3650)?;
        std::fs::read_to_string(&out).map_err(|e| e.to_string())
    })();
    let _ = std::fs::remove_dir_all(&d);
    r
}

pub fn tls_dir(p: &pve_identity_core::registry::Paths) -> PathBuf {
    p.private().join("tls")
}

/// Ensure this node's HTTPS cert for the discovery listener; SANs = issuer
/// host + node name + node IP + configured extras. Returns (cert, key) paths.
pub fn ensure_tls(p: &pve_identity_core::registry::Paths, node: &str, sans: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let dir = tls_dir(p);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let (crt, key, sanf) = (dir.join(format!("{node}.pem")), dir.join(format!("{node}.key")), dir.join(format!("{node}.san")));
    let mut list: Vec<String> = sans
        .iter()
        .map(|s| if s.parse::<std::net::IpAddr>().is_ok() { format!("IP:{s}") } else { format!("DNS:{s}") })
        .collect();
    list.sort();
    list.dedup();
    let want = list.join(",");
    let fresh = crt.exists()
        && key.exists()
        && std::fs::read_to_string(&sanf).map(|s| s == want).unwrap_or(false)
        && crate::run("openssl", &["x509", "-in", &crt.to_string_lossy(), "-noout", "-checkend", "2592000"]).is_ok();
    if fresh {
        return Ok((crt, key));
    }
    let d = tmpdir()?;
    let r = (|| {
        let kf = d.join("tls.key");
        crate::run("openssl", &["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", &kf.to_string_lossy()])?;
        let csr = d.join("tls.csr");
        crate::run("openssl", &["req", "-new", "-key", &kf.to_string_lossy(), "-subj",
            &format!("/O=pve-identity/CN={node}"), "-out", &csr.to_string_lossy()])?;
        let ext = d.join("ext.cnf");
        std::fs::write(&ext, format!("subjectAltName={want}\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n"))
            .map_err(|e| e.to_string())?;
        let out = d.join("tls.crt");
        sign_csr(&csr, &out, &ext, 365)?;
        let mut chain = std::fs::read(&out).map_err(|e| e.to_string())?;
        chain.extend(std::fs::read(CA_CERT).map_err(|e| e.to_string())?);
        pve_identity_core::write_atomic(&key, &std::fs::read(&kf).map_err(|e| e.to_string())?, 0o600).map_err(|e| e.to_string())?;
        pve_identity_core::write_atomic(&crt, &chain, 0o644).map_err(|e| e.to_string())?;
        std::fs::write(&sanf, &want).map_err(|e| e.to_string())
    })();
    let _ = std::fs::remove_dir_all(&d);
    r.map(|_| (crt, key))
}
