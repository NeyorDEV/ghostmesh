//! Signed update manifests.
//!
//! A release is described by a small JSON manifest signed with the maintainer's release key. A node
//! accepts an update only if the signature checks out under a key it already trusts, the version is
//! strictly newer than the running one (no rollback), the download address is HTTPS, and the
//! downloaded file matches the SHA-256 in the manifest. This module only does the verification;
//! downloading and installing are left to the caller.

use ghost_crypto::{ct_eq32, sha256, xeddsa_verify};
use serde::{Deserialize, Serialize};

/// Release signing key (X25519 public key, hex). Empty until the maintainer publishes one: with no
/// key, no manifest is ever accepted.
pub const RELEASE_PUBLIC_KEY_HEX: &str = "";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: String,
    pub url: String,
    /// SHA-256 of the installer, hex.
    pub sha256: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    BadKey,
    BadSignature,
    BadManifest(String),
    NotNewer,
    InsecureUrl,
    HashMismatch,
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey => write!(f, "no valid release key is configured"),
            Self::BadSignature => write!(f, "the manifest signature is not valid"),
            Self::BadManifest(e) => write!(f, "malformed manifest: {e}"),
            Self::NotNewer => write!(f, "the offered version is not newer than the installed one"),
            Self::InsecureUrl => write!(f, "the download address is not HTTPS"),
            Self::HashMismatch => write!(f, "the downloaded file does not match the signed hash"),
        }
    }
}

fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().trim_start_matches('v').split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.split(['-', '+']).next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

pub fn is_newer(current: &str, candidate: &str) -> bool {
    match (parse_version(current), parse_version(candidate)) {
        (Some(c), Some(n)) => n > c,
        _ => false,
    }
}

/// Checks the signature, the structure, the version and the URL of a manifest.
pub fn verify_manifest(
    manifest_json: &[u8],
    signature: &[u8; 64],
    trusted_public: &[u8; 32],
    current_version: &str,
) -> Result<UpdateManifest, UpdateError> {
    if trusted_public == &[0u8; 32] {
        return Err(UpdateError::BadKey);
    }
    if !xeddsa_verify(trusted_public, manifest_json, signature) {
        return Err(UpdateError::BadSignature);
    }
    let m: UpdateManifest = serde_json::from_slice(manifest_json)
        .map_err(|e| UpdateError::BadManifest(e.to_string()))?;
    if hex::decode(&m.sha256)
        .map(|h| h.len() != 32)
        .unwrap_or(true)
    {
        return Err(UpdateError::BadManifest(
            "sha256 must be 64 hex characters".into(),
        ));
    }
    if parse_version(&m.version).is_none() {
        return Err(UpdateError::BadManifest(
            "version must look like 1.2.3".into(),
        ));
    }
    if !m.url.starts_with("https://") {
        return Err(UpdateError::InsecureUrl);
    }
    if !is_newer(current_version, &m.version) {
        return Err(UpdateError::NotNewer);
    }
    Ok(m)
}

/// Compares downloaded bytes with the hash promised by a verified manifest.
pub fn verify_file(bytes: &[u8], manifest: &UpdateManifest) -> Result<(), UpdateError> {
    let expected: [u8; 32] = hex::decode(&manifest.sha256)
        .ok()
        .and_then(|h| h.try_into().ok())
        .ok_or_else(|| UpdateError::BadManifest("sha256 must be 64 hex characters".into()))?;
    if ct_eq32(&sha256(bytes), &expected) {
        Ok(())
    } else {
        Err(UpdateError::HashMismatch)
    }
}

/// The trusted release key, if the maintainer has published one.
pub fn release_key() -> Option<[u8; 32]> {
    hex::decode(RELEASE_PUBLIC_KEY_HEX).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_crypto::{xeddsa_sign, IdentityKeypair};

    fn signed(key: &IdentityKeypair, json: &str) -> ([u8; 64], Vec<u8>) {
        (
            xeddsa_sign(&key.private, json.as_bytes()),
            json.as_bytes().to_vec(),
        )
    }

    fn manifest(version: &str, url: &str, payload: &[u8]) -> String {
        format!(
            r#"{{"version":"{version}","url":"{url}","sha256":"{}","notes":"fix"}}"#,
            hex::encode(sha256(payload))
        )
    }

    #[test]
    fn accepts_a_genuine_newer_release_and_checks_the_file() {
        let key = IdentityKeypair::generate().unwrap();
        let file = b"installer bytes";
        let (sig, json) = signed(&key, &manifest("0.3.0", "https://example.org/gm.exe", file));
        let m = verify_manifest(&json, &sig, &key.public, "0.2.6").unwrap();
        assert_eq!(m.version, "0.3.0");
        assert_eq!(verify_file(file, &m), Ok(()));
        assert_eq!(verify_file(b"tampered", &m), Err(UpdateError::HashMismatch));
    }

    #[test]
    fn rejects_forgeries_rollbacks_and_insecure_urls() {
        let key = IdentityKeypair::generate().unwrap();
        let eve = IdentityKeypair::generate().unwrap();
        let ok = manifest("0.3.0", "https://example.org/gm.exe", b"x");

        let (sig, json) = signed(&eve, &ok);
        assert_eq!(
            verify_manifest(&json, &sig, &key.public, "0.2.6"),
            Err(UpdateError::BadSignature)
        );

        let (sig, json) = signed(&key, &ok);
        let mut changed = json.clone();
        changed[12] ^= 1;
        assert_eq!(
            verify_manifest(&changed, &sig, &key.public, "0.2.6"),
            Err(UpdateError::BadSignature)
        );

        let (sig, json) = signed(&key, &manifest("0.2.6", "https://example.org/gm.exe", b"x"));
        assert_eq!(
            verify_manifest(&json, &sig, &key.public, "0.2.6"),
            Err(UpdateError::NotNewer)
        );
        let (sig, json) = signed(&key, &manifest("0.1.0", "https://example.org/gm.exe", b"x"));
        assert_eq!(
            verify_manifest(&json, &sig, &key.public, "0.2.6"),
            Err(UpdateError::NotNewer)
        );

        let (sig, json) = signed(&key, &manifest("0.3.0", "http://example.org/gm.exe", b"x"));
        assert_eq!(
            verify_manifest(&json, &sig, &key.public, "0.2.6"),
            Err(UpdateError::InsecureUrl)
        );

        let (sig, json) = signed(&key, "{not json");
        assert!(matches!(
            verify_manifest(&json, &sig, &key.public, "0.2.6"),
            Err(UpdateError::BadManifest(_))
        ));

        assert_eq!(
            verify_manifest(&json, &sig, &[0u8; 32], "0.2.6"),
            Err(UpdateError::BadKey)
        );
        assert!(
            release_key().is_none(),
            "no key is trusted until the maintainer publishes one"
        );
    }

    #[test]
    fn version_comparison() {
        assert!(is_newer("0.2.6", "0.2.7"));
        assert!(is_newer("0.2.6", "v1.0.0"));
        assert!(is_newer("0.9.9", "0.10.0"));
        assert!(!is_newer("0.2.6", "0.2.6"));
        assert!(!is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.2.6", "garbage"));
        assert!(!is_newer("0.2.6", "1.2.3.4"));
    }
}
