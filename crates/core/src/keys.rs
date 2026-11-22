//! Signing key set stored root-only in pmxcfs (R1, R18, D13).
use crate::jwt::b64;
use base64::Engine;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use sha1::Digest;

/// Delay between publishing a `next` key and signing with it, so relying
/// parties have reloaded the registry / thumbprints (R18).
pub const PREPUBLISH_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Next,
    Current,
    Previous,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub kid: String,
    pub alg: String,
    pub state: State,
    pub created: u64,
    /// For `previous`: drop after this time (last token expired).
    #[serde(default)]
    pub retire_at: u64,
    /// PKCS#8 PEM private key.
    pub private: String,
    /// X.509 cert (PEM) for this key, issued by the PVE cluster CA (D13).
    #[serde(default)]
    pub cert: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeySet {
    pub keys: Vec<Key>,
}

pub fn new_key(state: State, now: u64) -> crate::Result<Key> {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let pem = sk
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| crate::Error::Invalid(format!("pkcs8: {e}")))?;
    let mut r = [0u8; 6];
    rand::Rng::fill(&mut rand::thread_rng(), &mut r);
    Ok(Key {
        kid: format!("pve-{}-{}", now, crate::jwt::b64(&r)),
        alg: "ES256".into(),
        state,
        created: now,
        retire_at: 0,
        private: pem.to_string(),
        cert: String::new(),
    })
}

impl Key {
    pub fn signing_key(&self) -> crate::Result<SigningKey> {
        SigningKey::from_pkcs8_pem(&self.private).map_err(|e| crate::Error::Invalid(format!("key {}: {e}", self.kid)))
    }
    pub fn verifying_key(&self) -> crate::Result<VerifyingKey> {
        Ok(*self.signing_key()?.verifying_key())
    }
    pub fn cert_der(&self) -> Option<Vec<u8>> {
        let body: String = self
            .cert
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        if body.is_empty() {
            return None;
        }
        base64::engine::general_purpose::STANDARD.decode(body).ok()
    }
    /// SHA1 thumbprint (hex) of the cert, as RGW/AWS register it.
    pub fn thumbprint(&self) -> Option<String> {
        self.cert_der().map(|d| hex(&sha1::Sha1::digest(&d)))
    }
    pub fn jwk(&self) -> crate::Result<serde_json::Value> {
        let vk = self.verifying_key()?;
        let pt = vk.to_encoded_point(false);
        let mut j = serde_json::json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": self.kid,
            "x": b64(pt.x().ok_or_else(|| crate::Error::Invalid("pt".into()))?),
            "y": b64(pt.y().ok_or_else(|| crate::Error::Invalid("pt".into()))?),
        });
        if let Some(der) = self.cert_der() {
            j["x5c"] = serde_json::json!([base64::engine::general_purpose::STANDARD.encode(&der)]);
            j["x5t"] = serde_json::json!(b64(&sha1::Sha1::digest(&der)));
        }
        Ok(j)
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl KeySet {
    pub fn load(path: &std::path::Path) -> crate::Result<KeySet> {
        match std::fs::read(path) {
            Ok(d) => Ok(serde_json::from_slice(&d)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KeySet::default()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        crate::write_atomic(path, &serde_json::to_vec_pretty(self)?, 0o600)?;
        Ok(())
    }
    pub fn current(&self) -> Option<&Key> {
        self.keys.iter().find(|k| k.state == State::Current)
    }
    pub fn jwks(&self) -> crate::Result<serde_json::Value> {
        let keys: crate::Result<Vec<_>> = self.keys.iter().map(|k| k.jwk()).collect();
        Ok(serde_json::json!({ "keys": keys? }))
    }
    pub fn verifiers(&self) -> Vec<(String, VerifyingKey)> {
        self.keys
            .iter()
            .filter_map(|k| k.verifying_key().ok().map(|v| (k.kid.clone(), v)))
            .collect()
    }
    /// Time-driven rotation steps; returns true when changed. Idempotent, so
    /// any host may run it.
    pub fn advance(&mut self, now: u64) -> bool {
        let before = serde_json::to_string(self).unwrap_or_default();
        self.keys.retain(|k| !(k.state == State::Previous && k.retire_at <= now));
        let ready = self
            .keys
            .iter()
            .position(|k| k.state == State::Next && now >= k.created + PREPUBLISH_SECS);
        if let Some(i) = ready {
            for k in self.keys.iter_mut() {
                if k.state == State::Current {
                    k.state = State::Previous;
                    k.retire_at = now + crate::claims::MAX_LIFETIME + 60;
                }
            }
            self.keys[i].state = State::Current;
        }
        before != serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_overlap() {
        let mut ks = KeySet { keys: vec![new_key(State::Current, 0).unwrap()] };
        let old = ks.keys[0].kid.clone();
        ks.keys.push(new_key(State::Next, 1000).unwrap());
        assert!(!ks.advance(1000 + PREPUBLISH_SECS - 1));
        assert_eq!(ks.current().unwrap().kid, old);
        assert!(ks.advance(1000 + PREPUBLISH_SECS));
        assert_ne!(ks.current().unwrap().kid, old);
        assert_eq!(ks.keys.len(), 2, "old key still published during overlap");
        assert!(ks.advance(1000 + PREPUBLISH_SECS + 700));
        assert_eq!(ks.keys.len(), 1);
    }
    #[test]
    fn jwk_shape() {
        let k = new_key(State::Current, 0).unwrap();
        let j = k.jwk().unwrap();
        assert_eq!(j["crv"], "P-256");
        assert!(j.get("x5c").is_none());
    }
}
