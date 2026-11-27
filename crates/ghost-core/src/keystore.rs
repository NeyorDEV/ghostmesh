//! Where the node's private key lives.
//!
//! Order of preference:
//! 1. the operating system vault (Windows Credential Manager / DPAPI, macOS Keychain, Linux Secret Service);
//! 2. an encrypted file (Argon2id + ChaCha20-Poly1305) when `GHOSTMESH_KEY_PASSPHRASE` is set;
//! 3. a key file restricted to the current user (last resort, a warning is logged).
//!
//! A private key found in the old `config.json` is moved to the best available store and erased
//! from the config. Secrets are wiped from memory after use.

use crate::config::{get_config_path, AppConfig};
use chacha20poly1305::aead::{Aead, KeyInit};
use ghost_crypto::IdentityKeypair;
use rand::RngCore;
use std::path::PathBuf;
use tracing::{info, warn};
use zeroize::Zeroizing;

const SERVICE: &str = "ghostmesh";
const ACCOUNT: &str = "identity-private-key";
const FILE_MAGIC: &[u8; 4] = b"GMK1";
pub const PASSPHRASE_ENV: &str = "GHOSTMESH_KEY_PASSPHRASE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBackend {
    OsVault,
    EncryptedFile,
    ProtectedFile,
}

impl std::fmt::Display for KeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OsVault => "operating system vault",
            Self::EncryptedFile => "passphrase-encrypted file",
            Self::ProtectedFile => "user-only key file (no vault, no passphrase)",
        })
    }
}

/// A place able to hold one secret string.
pub trait SecretStore {
    fn get(&self) -> Result<Option<Zeroizing<String>>, String>;
    fn set(&self, secret: &str) -> Result<(), String>;
}

pub struct VaultStore {
    account: String,
}

impl VaultStore {
    pub fn new(account: &str) -> Self {
        Self {
            account: account.to_string(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, String> {
        keyring::Entry::new(SERVICE, &self.account).map_err(|e| e.to_string())
    }
}

impl SecretStore for VaultStore {
    fn get(&self) -> Result<Option<Zeroizing<String>>, String> {
        match self.entry()?.get_password() {
            Ok(p) => Ok(Some(Zeroizing::new(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn set(&self, secret: &str) -> Result<(), String> {
        self.entry()?
            .set_password(secret)
            .map_err(|e| e.to_string())
    }
}

/// Key file next to the config: encrypted when a passphrase is given, otherwise user-only.
pub struct FileStore {
    pub path: PathBuf,
    pub passphrase: Option<Zeroizing<String>>,
}

fn derive_file_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = argon2::Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| e.to_string())?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn encrypt_secret(secret: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = derive_file_key(passphrase, &salt)?;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new((&*key).into());
    let ct = cipher
        .encrypt((&nonce).into(), secret.as_bytes())
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_secret(data: &[u8], passphrase: &str) -> Result<Zeroizing<String>, String> {
    if data.len() < 32 || &data[..4] != FILE_MAGIC {
        return Err("not an encrypted GhostMesh key file".into());
    }
    let (salt, rest) = data[4..].split_at(16);
    let (nonce, ct) = rest.split_at(12);
    let key = derive_file_key(passphrase, salt)?;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new((&*key).into());
    let plain = cipher
        .decrypt(nonce.into(), ct)
        .map_err(|_| "wrong passphrase or corrupted key file".to_string())?;
    String::from_utf8(plain)
        .map(Zeroizing::new)
        .map_err(|_| "key file is not valid text".to_string())
}

impl SecretStore for FileStore {
    fn get(&self) -> Result<Option<Zeroizing<String>>, String> {
        let data = match std::fs::read(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        if data.starts_with(FILE_MAGIC) {
            let pass = self
                .passphrase
                .as_ref()
                .ok_or_else(|| format!("{PASSPHRASE_ENV} is required to read the key file"))?;
            decrypt_secret(&data, pass).map(Some)
        } else {
            String::from_utf8(data)
                .map(|s| Some(Zeroizing::new(s.trim().to_string())))
                .map_err(|e| e.to_string())
        }
    }

    fn set(&self, secret: &str) -> Result<(), String> {
        let bytes = match &self.passphrase {
            Some(p) => encrypt_secret(secret, p)?,
            None => secret.as_bytes().to_vec(),
        };
        std::fs::write(&self.path, bytes).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Store for another secret (for example the certificate authority key): the OS vault when it
/// works, otherwise a file next to the config, encrypted if a passphrase is set.
pub fn secret_store(account: &str, file_name: &str) -> (Box<dyn SecretStore>, KeyBackend) {
    let vault = VaultStore::new(account);
    if vault.get().is_ok() {
        return (Box::new(vault), KeyBackend::OsVault);
    }
    let passphrase = passphrase_from_env();
    let backend = if passphrase.is_some() {
        KeyBackend::EncryptedFile
    } else {
        KeyBackend::ProtectedFile
    };
    (
        Box::new(FileStore {
            path: get_config_path().with_file_name(file_name),
            passphrase,
        }),
        backend,
    )
}

fn key_file_path() -> PathBuf {
    get_config_path().with_file_name("identity.key")
}

fn passphrase_from_env() -> Option<Zeroizing<String>> {
    std::env::var(PASSPHRASE_ENV)
        .ok()
        .filter(|p| !p.is_empty())
        .map(Zeroizing::new)
}

fn parse_identity(secret: &str) -> Option<IdentityKeypair> {
    let bytes = Zeroizing::new(hex::decode(secret.trim()).ok()?);
    let private: [u8; 32] = bytes.as_slice().try_into().ok()?;
    let public = ghost_crypto::public_from_private(&private);
    Some(IdentityKeypair::from_key_bytes(private, public))
}

/// Core logic, independent of the real stores so it can be tested: returns the identity and whether
/// the config changed (legacy key erased, public key recorded).
pub fn load_or_create_with(
    cfg: &mut AppConfig,
    store: &dyn SecretStore,
) -> Result<(IdentityKeypair, bool), String> {
    let mut changed = false;

    // 1. Migration of a key stored in clear in config.json
    if let Some(legacy) = cfg.private_key_hex.take() {
        let legacy = Zeroizing::new(legacy);
        if let Some(id) = parse_identity(&legacy) {
            store.set(&legacy)?;
            // Only erase the old copy once the new store really gives the same key back.
            let back = store
                .get()?
                .ok_or("key store did not keep the migrated key")?;
            if *back != *legacy {
                cfg.private_key_hex = Some(legacy.to_string());
                return Err("key store returned a different key after migration".into());
            }
            cfg.public_key_hex = Some(id.public_hex());
            info!("Private key moved out of config.json into the key store");
            return Ok((id, true));
        }
        changed = true; // unusable legacy value: dropped
    }

    // 2. Existing key
    if let Some(secret) = store.get()? {
        if let Some(id) = parse_identity(&secret) {
            if cfg.public_key_hex.as_deref() != Some(&id.public_hex()) {
                cfg.public_key_hex = Some(id.public_hex());
                changed = true;
            }
            return Ok((id, changed));
        }
        warn!("Stored private key is unreadable, generating a new identity");
    }

    // 3. First run
    let id = IdentityKeypair::generate().map_err(|e| e.to_string())?;
    let secret = Zeroizing::new(hex::encode(id.private));
    store.set(&secret)?;
    cfg.public_key_hex = Some(id.public_hex());
    Ok((id, true))
}

/// Loads (or creates, or migrates) the identity using the best store available on this machine.
pub fn load_or_create_identity(
    cfg: &mut AppConfig,
) -> Result<(IdentityKeypair, KeyBackend, bool), String> {
    let vault = VaultStore::new(ACCOUNT);
    // The vault is usable only if it can both write and read back (headless Linux often has none).
    let vault_ok = match vault.get() {
        Ok(_) => true,
        Err(e) => {
            warn!("OS key vault unavailable: {e}");
            false
        }
    };
    if vault_ok {
        // A key that already lives in the file store (earlier fallback) is moved into the vault.
        let file = FileStore {
            path: key_file_path(),
            passphrase: passphrase_from_env(),
        };
        if vault.get()?.is_none() && cfg.private_key_hex.is_none() {
            if let Ok(Some(secret)) = file.get() {
                cfg.private_key_hex = Some(secret.to_string());
            }
        }
        let (id, changed) = load_or_create_with(cfg, &vault)?;
        if file.path.exists() && vault.get()?.is_some() {
            let _ = std::fs::remove_file(&file.path);
        }
        return Ok((id, KeyBackend::OsVault, changed));
    }

    let passphrase = passphrase_from_env();
    let backend = if passphrase.is_some() {
        KeyBackend::EncryptedFile
    } else {
        KeyBackend::ProtectedFile
    };
    if backend == KeyBackend::ProtectedFile {
        warn!("No OS vault and no {PASSPHRASE_ENV}: the private key is kept in a user-only file");
    }
    let store = FileStore {
        path: key_file_path(),
        passphrase,
    };
    let (id, changed) = load_or_create_with(cfg, &store)?;
    Ok((id, backend, changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MemStore(RefCell<Option<String>>);

    impl SecretStore for MemStore {
        fn get(&self) -> Result<Option<Zeroizing<String>>, String> {
            Ok(self.0.borrow().clone().map(Zeroizing::new))
        }
        fn set(&self, secret: &str) -> Result<(), String> {
            *self.0.borrow_mut() = Some(secret.to_string());
            Ok(())
        }
    }

    #[test]
    fn legacy_key_is_migrated_and_erased() {
        let id = IdentityKeypair::generate().unwrap();
        let mut cfg = AppConfig {
            private_key_hex: Some(hex::encode(id.private)),
            public_key_hex: Some(id.public_hex()),
            ..Default::default()
        };
        let store = MemStore::default();
        let (loaded, changed) = load_or_create_with(&mut cfg, &store).unwrap();
        assert!(changed);
        assert_eq!(
            loaded.public, id.public,
            "the identity must survive the migration"
        );
        assert!(
            cfg.private_key_hex.is_none(),
            "the clear-text copy must be erased from the config"
        );
        assert_eq!(
            store.get().unwrap().unwrap().as_str(),
            hex::encode(id.private)
        );

        // Second start: loaded from the store, same identity, nothing left in the config.
        let (again, _) = load_or_create_with(&mut cfg, &store).unwrap();
        assert_eq!(again.public, id.public);
        assert!(cfg.private_key_hex.is_none());
    }

    #[test]
    fn first_run_generates_and_stores() {
        let mut cfg = AppConfig::default();
        let store = MemStore::default();
        let (id, changed) = load_or_create_with(&mut cfg, &store).unwrap();
        assert!(changed && cfg.private_key_hex.is_none());
        assert_eq!(
            cfg.public_key_hex.as_deref(),
            Some(id.public_hex().as_str())
        );
        let (same, _) = load_or_create_with(&mut cfg, &store).unwrap();
        assert_eq!(same.public, id.public);
    }

    #[test]
    fn failed_store_keeps_the_legacy_key() {
        struct Lying;
        impl SecretStore for Lying {
            fn get(&self) -> Result<Option<Zeroizing<String>>, String> {
                Ok(Some(Zeroizing::new("00".repeat(32))))
            }
            fn set(&self, _: &str) -> Result<(), String> {
                Ok(())
            }
        }
        let id = IdentityKeypair::generate().unwrap();
        let mut cfg = AppConfig {
            private_key_hex: Some(hex::encode(id.private)),
            ..Default::default()
        };
        assert!(load_or_create_with(&mut cfg, &Lying).is_err());
        assert!(
            cfg.private_key_hex.is_some(),
            "never erase the old key when the new store is not proven"
        );
    }

    #[test]
    fn encrypted_file_roundtrip_and_wrong_passphrase() {
        let blob = encrypt_secret("deadbeef", "correct horse").unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("deadbeef"));
        assert_eq!(
            decrypt_secret(&blob, "correct horse").unwrap().as_str(),
            "deadbeef"
        );
        assert!(decrypt_secret(&blob, "wrong").is_err());
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt_secret(&tampered, "correct horse").is_err());
        assert!(decrypt_secret(b"short", "x").is_err());
    }

    #[test]
    fn file_store_encrypts_when_a_passphrase_is_set() {
        let dir = std::env::temp_dir().join(format!("gm-keystore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.key");
        let store = FileStore {
            path: path.clone(),
            passphrase: Some(Zeroizing::new("pw".into())),
        };
        store.set("abcd").unwrap();
        assert!(std::fs::read(&path).unwrap().starts_with(FILE_MAGIC));
        assert_eq!(store.get().unwrap().unwrap().as_str(), "abcd");
        let no_pass = FileStore {
            path: path.clone(),
            passphrase: None,
        };
        assert!(no_pass.get().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
