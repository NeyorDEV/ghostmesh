use ghost_protocol::NodeId;
use snow::{Builder, HandshakeState, TransportState};
use thiserror::Error;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Noise cryptographic error: {0}")]
    NoiseError(#[from] snow::Error),
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
}

#[derive(Clone, Debug)]
pub struct IdentityKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl IdentityKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let keypair = builder.generate_keypair()?;
        let mut priv_arr = [0u8; 32];
        let mut pub_arr = [0u8; 32];
        priv_arr.copy_from_slice(&keypair.private);
        pub_arr.copy_from_slice(&keypair.public);
        Ok(Self {
            private: priv_arr,
            public: pub_arr,
        })
    }

    pub fn from_key_bytes(private: [u8; 32], public: [u8; 32]) -> Self {
        Self { private, public }
    }

    pub fn node_id(&self) -> NodeId {
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&self.public[0..16]);
        NodeId::new(id_bytes)
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }
}

pub struct InitiatorHandshake {
    state: HandshakeState,
}

impl InitiatorHandshake {
    pub fn new(local_keys: &IdentityKeypair) -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let state = builder
            .local_private_key(&local_keys.private)
            .build_initiator()?;
        Ok(Self { state })
    }

    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, CryptoError> {
        Ok(self.state.write_message(payload, message)?)
    }

    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, CryptoError> {
        Ok(self.state.read_message(message, payload)?)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn into_transport_mode(self) -> Result<TransportState, CryptoError> {
        Ok(self.state.into_transport_mode()?)
    }
}

pub struct ResponderHandshake {
    state: HandshakeState,
}

impl ResponderHandshake {
    pub fn new(local_keys: &IdentityKeypair) -> Result<Self, CryptoError> {
        let builder = Builder::new(NOISE_PATTERN.parse()?);
        let state = builder
            .local_private_key(&local_keys.private)
            .build_responder()?;
        Ok(Self { state })
    }

    pub fn read_message(&mut self, message: &[u8], payload: &mut [u8]) -> Result<usize, CryptoError> {
        Ok(self.state.read_message(message, payload)?)
    }

    pub fn write_message(&mut self, payload: &[u8], message: &mut [u8]) -> Result<usize, CryptoError> {
        Ok(self.state.write_message(payload, message)?)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn into_transport_mode(self) -> Result<TransportState, CryptoError> {
        Ok(self.state.into_transport_mode()?)
    }
}

/// Per-peer packet protection derived from the static X25519 identities of both nodes.
///
/// Each direction gets its own key (bound to sender and receiver public keys) so the packet
/// `sequence` number can be used directly as an AEAD nonce without risking nonce reuse.
/// A packet that opens successfully proves the sender owns the private key of its NodeId.
#[derive(Clone)]
pub struct SessionKeys {
    tx: [u8; 32],
    rx: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys(..)")
    }
}

fn derive_direction_key(dh: &[u8; 32], sender: &[u8; 32], receiver: &[u8; 32]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(b"ghostmesh/v1/packet-key");
    h.update(dh);
    h.update(sender);
    h.update(receiver);
    h.finalize().into()
}

impl SessionKeys {
    pub fn derive(local: &IdentityKeypair, remote_public: &[u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(local.private);
        let dh = secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*remote_public))
            .to_bytes();
        Self {
            tx: derive_direction_key(&dh, &local.public, remote_public),
            rx: derive_direction_key(&dh, remote_public, &local.public),
        }
    }

    fn nonce(sequence: u64) -> chacha20poly1305::Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&sequence.to_be_bytes());
        n.into()
    }

    /// Encrypts `plaintext`, authenticating `aad` (the packet header fields).
    pub fn seal(&self, sequence: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let cipher = chacha20poly1305::ChaCha20Poly1305::new((&self.tx).into());
        cipher
            .encrypt(&Self::nonce(sequence), Payload { msg: plaintext, aad })
            .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory buffers")
    }

    pub fn open(&self, sequence: u64, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let cipher = chacha20poly1305::ChaCha20Poly1305::new((&self.rx).into());
        cipher
            .decrypt(&Self::nonce(sequence), Payload { msg: ciphertext, aad })
            .ok()
    }
}

/// Sliding anti-replay window (64 packets) over authenticated sequence numbers.
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64,
}

impl ReplayWindow {
    /// Returns `true` and records the sequence if it was not seen before and is not too old.
    pub fn accept(&mut self, seq: u64) -> bool {
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = seq;
            true
        } else {
            let offset = self.highest - seq;
            if offset >= 64 {
                return false;
            }
            let bit = 1u64 << offset;
            if self.bitmap & bit != 0 {
                return false;
            }
            self.bitmap |= bit;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_handshake_and_transport() {
        let alice_keys = IdentityKeypair::generate().unwrap();
        let bob_keys = IdentityKeypair::generate().unwrap();

        let mut alice = InitiatorHandshake::new(&alice_keys).unwrap();
        let mut bob = ResponderHandshake::new(&bob_keys).unwrap();

        let mut buf_a = [0u8; 1024];
        let mut buf_b = [0u8; 1024];

        // Step 1: Alice -> Bob (-> e)
        let len = alice.write_message(b"", &mut buf_a).unwrap();
        bob.read_message(&buf_a[..len], &mut buf_b).unwrap();

        // Step 2: Bob -> Alice (<- e, ee, s, es)
        let len = bob.write_message(b"", &mut buf_b).unwrap();
        alice.read_message(&buf_b[..len], &mut buf_a).unwrap();

        // Step 3: Alice -> Bob (-> s, se)
        let len = alice.write_message(b"", &mut buf_a).unwrap();
        bob.read_message(&buf_a[..len], &mut buf_b).unwrap();

        assert!(alice.is_finished());
        assert!(bob.is_finished());

        let mut alice_transport = alice.into_transport_mode().unwrap();
        let mut bob_transport = bob.into_transport_mode().unwrap();

        // Encrypt message from Alice to Bob
        let secret = b"Secret GhostMesh Payload";
        let cipher_len = alice_transport.write_message(secret, &mut buf_a).unwrap();

        let mut decrypted = [0u8; 1024];
        let plain_len = bob_transport.read_message(&buf_a[..cipher_len], &mut decrypted).unwrap();

        assert_eq!(&decrypted[..plain_len], secret);
    }

    #[test]
    fn test_session_keys_roundtrip_and_tamper() {
        let a = IdentityKeypair::generate().unwrap();
        let b = IdentityKeypair::generate().unwrap();
        let sa = SessionKeys::derive(&a, &b.public);
        let sb = SessionKeys::derive(&b, &a.public);

        let ct = sa.seal(7, b"hdr", b"hello");
        assert_eq!(sb.open(7, b"hdr", &ct).as_deref(), Some(&b"hello"[..]));
        assert!(sb.open(8, b"hdr", &ct).is_none(), "wrong sequence must fail");
        assert!(sb.open(7, b"other", &ct).is_none(), "wrong header must fail");
        assert!(sa.open(7, b"hdr", &ct).is_none(), "own tx key must not open own packet");

        let eve = IdentityKeypair::generate().unwrap();
        let se = SessionKeys::derive(&eve, &a.public);
        assert!(se.open(7, b"hdr", &ct).is_none(), "third party must not decrypt");
    }

    #[test]
    fn test_replay_window() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(100));
        assert!(!w.accept(100));
        assert!(w.accept(99));
        assert!(!w.accept(99));
        assert!(w.accept(200));
        assert!(!w.accept(100), "older than the 64 window is rejected");
        assert!(w.accept(150));
    }
}
