//! ES256 JWT signing and verification.
use base64::Engine;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};

pub fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
pub fn unb64(s: &str) -> crate::Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| crate::Error::Invalid(format!("base64: {e}")))
}

pub fn sign_es256<T: serde::Serialize>(key: &SigningKey, kid: &str, claims: &T) -> crate::Result<String> {
    let hdr = serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": kid});
    let si = format!("{}.{}", b64(&serde_json::to_vec(&hdr)?), b64(&serde_json::to_vec(claims)?));
    let sig: Signature = key.sign(si.as_bytes());
    Ok(format!("{si}.{}", b64(&sig.to_bytes())))
}

/// Verify signature against a set of (kid, key); returns the payload JSON.
/// Does not check exp/aud (callers do).
pub fn verify_es256(token: &str, keys: &[(String, VerifyingKey)]) -> crate::Result<serde_json::Value> {
    let mut it = token.split('.');
    let (h, p, s) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(crate::Error::Invalid("not a JWS".into())),
    };
    let hdr: serde_json::Value = serde_json::from_slice(&unb64(h)?)?;
    if hdr["alg"] != "ES256" {
        return Err(crate::Error::Invalid("alg".into()));
    }
    let kid = hdr["kid"].as_str().unwrap_or("");
    let key = keys
        .iter()
        .find(|(k, _)| k == kid)
        .ok_or_else(|| crate::Error::Invalid("unknown kid".into()))?;
    let sig = Signature::from_slice(&unb64(s)?).map_err(|_| crate::Error::Invalid("sig".into()))?;
    key.1
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| crate::Error::Invalid("bad signature".into()))?;
    Ok(serde_json::from_slice(&unb64(p)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let k = SigningKey::random(&mut rand::thread_rng());
        let t = sign_es256(&k, "k1", &serde_json::json!({"a": "b"})).unwrap();
        let v = verify_es256(&t, &[("k1".into(), *k.verifying_key())]).unwrap();
        assert_eq!(v["a"], "b");
        let other = SigningKey::random(&mut rand::thread_rng());
        assert!(verify_es256(&t, &[("k1".into(), *other.verifying_key())]).is_err());
        assert!(verify_es256(&t, &[("k2".into(), *k.verifying_key())]).is_err());
    }
}
