//! Certificate authority for the mesh and HTTPS exposure of local ports under `<name>.ghost`.
//!
//! The authority is limited by an X.509 name constraint to the `.ghost` zone, so installing it on a
//! phone or in a browser cannot be abused to impersonate any public website. Each machine has its
//! own authority; a device that wants to open `https://<name>.ghost` installs that machine's
//! authority certificate once. Leaf certificates are short-lived and made on demand.

use ghost_core::keystore::secret_store;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

pub use rustls;
pub use tokio_rustls;

pub const ZONE: &str = "ghost";
const CA_COMMON_NAME: &str = "GhostMesh local CA";
const CA_ACCOUNT: &str = "ca-private-key";
const CA_KEY_FILE: &str = "ca.key";
/// Apple platforms refuse certificates valid for more than 398 days.
const LEAF_DAYS: i64 = 90;
const CA_DAYS: i64 = 3650;
const MAX_CONNECTIONS: usize = 256;

#[derive(Error, Debug)]
pub enum PkiError {
    #[error("certificate error: {0}")]
    Cert(String),
    #[error("key storage error: {0}")]
    Store(String),
    #[error("invalid name '{0}': only single-label names under .ghost are allowed")]
    BadName(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<rcgen::Error> for PkiError {
    fn from(e: rcgen::Error) -> Self {
        Self::Cert(e.to_string())
    }
}

fn ca_params() -> Result<CertificateParams, PkiError> {
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    p.distinguished_name = dn;
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(ZONE.to_string())],
        excluded_subtrees: Vec::new(),
    });
    let now = OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::hours(1);
    p.not_after = now + time::Duration::days(CA_DAYS);
    Ok(p)
}

/// A name is valid when it is `<label>.ghost` with a plain DNS label.
pub fn full_name(name: &str) -> Result<String, PkiError> {
    let host = name.trim().to_ascii_lowercase();
    let host = host
        .strip_suffix(&format!(".{ZONE}"))
        .unwrap_or(&host)
        .to_string();
    let ok = !host.is_empty()
        && host.len() <= 63
        && !host.starts_with('-')
        && !host.ends_with('-')
        && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(format!("{host}.{ZONE}"))
    } else {
        Err(PkiError::BadName(name.to_string()))
    }
}

/// The certificate authority: its certificate (public, to install on devices) and its signing key.
pub struct CertAuthority {
    cert: Certificate,
    key: KeyPair,
    cert_pem: String,
}

impl CertAuthority {
    pub fn generate() -> Result<Self, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = ca_params()?.self_signed(&key)?;
        let cert_pem = cert.pem();
        Ok(Self {
            cert,
            key,
            cert_pem,
        })
    }

    /// Rebuilds the authority from its saved key and certificate. The signing identity (subject and
    /// key) is what leaf certificates are checked against, so the saved certificate stays valid.
    pub fn from_parts(key_pem: &str, cert_pem: String) -> Result<Self, PkiError> {
        let key = KeyPair::from_pem(key_pem)?;
        let cert = ca_params()?.self_signed(&key)?;
        Ok(Self {
            cert,
            key,
            cert_pem,
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        pem_to_der(&self.cert_pem)
    }

    pub fn key_pem(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(self.key.serialize_pem())
    }

    /// Issues a server certificate for `<name>.ghost` and returns it with its private key.
    pub fn issue(
        &self,
        name: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), PkiError> {
        let host = full_name(name)?;
        let mut p = CertificateParams::new(vec![host.clone()])?;
        p.is_ca = IsCa::NoCa;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::hours(1);
        p.not_after = now + time::Duration::days(LEAF_DAYS);
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let leaf = p.signed_by(&leaf_key, &self.cert, &self.key)?;
        let der = leaf.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((der, key))
    }

    /// TLS server settings presenting a fresh certificate for `<name>.ghost` (and the CA, so
    /// clients that only trust the authority can build the chain).
    pub fn server_config(&self, name: &str) -> Result<Arc<rustls::ServerConfig>, PkiError> {
        let (leaf, key) = self.issue(name)?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| PkiError::Cert(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![leaf, self.cert_der()], key)
        .map_err(|e| PkiError::Cert(e.to_string()))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

fn pem_to_der(pem: &str) -> CertificateDer<'static> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    CertificateDer::from(base64_decode(&body))
}

/// Minimal standard base64 decoder (the PEM bodies we produce ourselves).
fn base64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// Directory holding the public authority certificate (`ca.pem`), next to the config.
pub fn ca_dir() -> PathBuf {
    ghost_core::config::get_config_path().with_file_name("ca")
}

pub fn ca_cert_path() -> PathBuf {
    ca_dir().join("ghostmesh-ca.pem")
}

/// Loads the authority of this machine, creating it on first use. The private key goes to the OS
/// vault (or an encrypted/protected file); only the certificate is written in the open.
pub fn load_or_create_authority() -> Result<(CertAuthority, bool), PkiError> {
    let (store, backend) = secret_store(CA_ACCOUNT, CA_KEY_FILE);
    let cert_path = ca_cert_path();
    if let (Some(key), Ok(cert_pem)) = (
        store.get().map_err(PkiError::Store)?,
        std::fs::read_to_string(&cert_path),
    ) {
        if let Ok(ca) = CertAuthority::from_parts(&key, cert_pem) {
            return Ok((ca, false));
        }
        warn!("Saved certificate authority is unreadable, creating a new one");
    }
    let ca = CertAuthority::generate()?;
    store.set(&ca.key_pem()).map_err(PkiError::Store)?;
    std::fs::create_dir_all(ca_dir())?;
    std::fs::write(&cert_path, ca.cert_pem())?;
    info!("Created the certificate authority (key kept in: {backend})");
    Ok((ca, true))
}

/// Terminates TLS on `listen` and forwards each connection to `upstream` (a local web server or
/// WebSocket service). The upstream never sees TLS, and the data is opaque to this proxy.
pub async fn serve_https(
    listener: TcpListener,
    upstream: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            debug!("too many HTTPS connections, dropping {peer}");
            continue;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let handshake =
                tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await;
            let Ok(Ok(mut tls_stream)) = handshake else {
                return;
            };
            let Ok(Ok(mut backend)) =
                tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(upstream)).await
            else {
                debug!("upstream {upstream} unreachable");
                return;
            };
            let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut backend).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client_config(ca: &CertAuthority) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca.cert_der())
            .expect("CA certificate must be accepted as a trust anchor");
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    async fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    async fn start_proxy(ca: &CertAuthority, name: &str) -> SocketAddr {
        let upstream = echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls = ca.server_config(name).unwrap();
        tokio::spawn(serve_https(listener, upstream, tls));
        addr
    }

    #[tokio::test]
    async fn https_page_is_valid_for_a_client_that_trusts_the_authority() {
        let ca = CertAuthority::generate().unwrap();
        let addr = start_proxy(&ca, "pc").await;

        let connector = tokio_rustls::TlsConnector::from(client_config(&ca));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("pc.ghost").unwrap();
        let mut tls = connector
            .connect(name, tcp)
            .await
            .expect("valid HTTPS for pc.ghost");
        tls.write_all(b"hello through TLS").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello through TLS");
    }

    #[tokio::test]
    async fn wrong_name_or_unknown_authority_is_refused() {
        let ca = CertAuthority::generate().unwrap();
        let addr = start_proxy(&ca, "pc").await;
        let connector = tokio_rustls::TlsConnector::from(client_config(&ca));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let other = rustls::pki_types::ServerName::try_from("laptop.ghost").unwrap();
        assert!(
            connector.connect(other, tcp).await.is_err(),
            "certificate is for pc.ghost only"
        );

        // A client that trusts a different authority must not accept it.
        let stranger = CertAuthority::generate().unwrap();
        let connector = tokio_rustls::TlsConnector::from(client_config(&stranger));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("pc.ghost").unwrap();
        assert!(connector.connect(name, tcp).await.is_err());
    }

    #[test]
    fn names_are_limited_to_the_ghost_zone() {
        assert_eq!(full_name("PC").unwrap(), "pc.ghost");
        assert_eq!(full_name("my-laptop.ghost").unwrap(), "my-laptop.ghost");
        for bad in [
            "", "a.b", "-x", "x-", "exa mple", "evil.com", "a_b", "*.ghost",
        ] {
            assert!(full_name(bad).is_err(), "{bad}");
        }
        assert!(CertAuthority::generate()
            .unwrap()
            .issue("google.com")
            .is_err());
    }

    #[test]
    fn authority_can_be_saved_and_reloaded() {
        let ca = CertAuthority::generate().unwrap();
        let again = CertAuthority::from_parts(&ca.key_pem(), ca.cert_pem().to_string()).unwrap();
        // A leaf made by the reloaded authority is accepted by the original certificate.
        let (leaf, _) = again.issue("pc").unwrap();
        assert!(!leaf.is_empty());
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[tokio::test]
    async fn reloaded_authority_still_validates() {
        let ca = CertAuthority::generate().unwrap();
        let again = CertAuthority::from_parts(&ca.key_pem(), ca.cert_pem().to_string()).unwrap();
        let addr = start_proxy(&again, "pc").await;
        // The client trusts the ORIGINAL certificate, which is what devices installed.
        let connector = tokio_rustls::TlsConnector::from(client_config(&ca));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("pc.ghost").unwrap();
        assert!(connector.connect(name, tcp).await.is_ok());
    }
}
