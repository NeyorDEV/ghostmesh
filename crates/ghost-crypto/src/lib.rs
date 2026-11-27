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

#[derive(Clone, Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
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

    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Ok(self.state.write_message(payload, message)?)
    }

    pub fn read_message(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, CryptoError> {
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

    pub fn read_message(
        &mut self,
        message: &[u8],
        payload: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Ok(self.state.read_message(message, payload)?)
    }

    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, CryptoError> {
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
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
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

    /// Keys for one rekey epoch. They mix the long-term shared secret (authentication) with a fresh
    /// ephemeral Diffie-Hellman result (forward secrecy: once both ephemeral secrets are gone, a
    /// stolen identity key cannot decrypt traffic of this epoch).
    pub fn derive_epoch(
        local: &IdentityKeypair,
        remote_public: &[u8; 32],
        local_eph: EphemeralKey,
        remote_eph: &[u8; 32],
        epoch: u8,
    ) -> Self {
        use blake2::{Blake2s256, Digest};
        let secret = x25519_dalek::StaticSecret::from(local.private);
        let static_dh = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*remote_public));
        let eph_dh = local_eph
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(*remote_eph));
        let mut h = Blake2s256::new();
        h.update(b"ghostmesh/v1/epoch-secret");
        h.update(static_dh.as_bytes());
        h.update(eph_dh.as_bytes());
        h.update([epoch]);
        let mut mixed: [u8; 32] = h.finalize().into();
        let keys = Self {
            tx: derive_direction_key(&mixed, &local.public, remote_public),
            rx: derive_direction_key(&mixed, remote_public, &local.public),
        };
        zeroize::Zeroize::zeroize(&mut mixed);
        keys
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
            .encrypt(
                &Self::nonce(sequence),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory buffers")
    }

    pub fn open(&self, sequence: u64, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let cipher = chacha20poly1305::ChaCha20Poly1305::new((&self.rx).into());
        cipher
            .decrypt(
                &Self::nonce(sequence),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .ok()
    }
}

/// Proof that the holder of `node_public`'s private key took part in a relay registration.
///
/// Both sides derive the same X25519 shared secret (node private x relay public, or relay private x
/// node public), so only the real key owner can produce it, and only the real relay can check it.
/// Returns `None` for low-order public keys.
pub fn relay_proof(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    challenge: &[u8; 32],
    node_public: &[u8; 32],
    relay_public: &[u8; 32],
) -> Option<[u8; 32]> {
    use blake2::{Blake2s256, Digest};
    let secret = x25519_dalek::StaticSecret::from(*local_private);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*remote_public));
    if !shared.was_contributory() {
        return None;
    }
    let mut h = Blake2s256::new();
    h.update(b"ghostmesh/v1/relay-register");
    h.update(shared.as_bytes());
    h.update(challenge);
    h.update(node_public);
    h.update(relay_public);
    Some(h.finalize().into())
}

/// Public key matching an X25519 private key.
pub fn public_from_private(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).to_bytes()
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Constant-time comparison of two 32-byte secrets or proofs.
pub fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Signing with the existing X25519 identity key (XEdDSA): the signature verifies against the
/// node's X25519 public key, so no second key has to be stored, paired or distributed.
fn edwards_from_private(
    private: &[u8; 32],
) -> (curve25519_dalek::Scalar, curve25519_dalek::EdwardsPoint) {
    use curve25519_dalek::{scalar::clamp_integer, EdwardsPoint, Scalar};
    let k = Scalar::from_bytes_mod_order(clamp_integer(*private));
    let a = EdwardsPoint::mul_base(&k);
    // The public point must have a zero sign bit so that verifiers can rebuild it from the u coordinate.
    if a.compress().as_bytes()[31] >> 7 == 1 {
        (-k, -a)
    } else {
        (k, a)
    }
}

fn xeddsa_challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> curve25519_dalek::Scalar {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(b"ghostmesh/v1/xeddsa-challenge");
    h.update(r);
    h.update(a);
    h.update(msg);
    curve25519_dalek::Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

pub fn xeddsa_sign(private: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    use curve25519_dalek::{EdwardsPoint, Scalar};
    use rand::RngCore;
    use sha2::{Digest, Sha512};
    let (k, a) = edwards_from_private(private);
    let a_bytes = a.compress().to_bytes();
    let mut z = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut z);
    let mut h = Sha512::new();
    h.update(b"ghostmesh/v1/xeddsa-nonce");
    h.update(k.as_bytes());
    h.update(msg);
    h.update(z);
    let r = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let s = r + xeddsa_challenge(&big_r, &a_bytes, msg) * k;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

pub fn xeddsa_verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use curve25519_dalek::{
        edwards::CompressedEdwardsY, montgomery::MontgomeryPoint, EdwardsPoint, Scalar,
    };
    let Some(a) = MontgomeryPoint(*public).to_edwards(0) else {
        return false;
    };
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    let Some(r) = CompressedEdwardsY(r_bytes).decompress() else {
        return false;
    };
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    let h = xeddsa_challenge(&r_bytes, &a.compress().to_bytes(), msg);
    EdwardsPoint::mul_base(&s) - h * a == r
}

/// One-shot X25519 key pair used for a single rekey; the secret is wiped when it is consumed.
pub struct EphemeralKey {
    secret: x25519_dalek::StaticSecret,
    pub public: [u8; 32],
}

impl EphemeralKey {
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Self { secret, public }
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
        let plain_len = bob_transport
            .read_message(&buf_a[..cipher_len], &mut decrypted)
            .unwrap();

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
        assert!(
            sb.open(8, b"hdr", &ct).is_none(),
            "wrong sequence must fail"
        );
        assert!(
            sb.open(7, b"other", &ct).is_none(),
            "wrong header must fail"
        );
        assert!(
            sa.open(7, b"hdr", &ct).is_none(),
            "own tx key must not open own packet"
        );

        let eve = IdentityKeypair::generate().unwrap();
        let se = SessionKeys::derive(&eve, &a.public);
        assert!(
            se.open(7, b"hdr", &ct).is_none(),
            "third party must not decrypt"
        );
    }

    #[test]
    fn test_relay_proof_both_sides_agree() {
        let node = IdentityKeypair::generate().unwrap();
        let relay = IdentityKeypair::generate().unwrap();
        let ch = [9u8; 32];
        let a = relay_proof(
            &node.private,
            &relay.public,
            &ch,
            &node.public,
            &relay.public,
        )
        .unwrap();
        let b = relay_proof(
            &relay.private,
            &node.public,
            &ch,
            &node.public,
            &relay.public,
        )
        .unwrap();
        assert!(ct_eq32(&a, &b));

        let eve = IdentityKeypair::generate().unwrap();
        let forged = relay_proof(
            &eve.private,
            &relay.public,
            &ch,
            &node.public,
            &relay.public,
        )
        .unwrap();
        assert!(
            !ct_eq32(&forged, &b),
            "a proof made with another key must not verify"
        );
        assert!(relay_proof(&node.private, &[0u8; 32], &ch, &node.public, &relay.public).is_none());
    }

    #[test]
    fn test_xeddsa_sign_verify() {
        for _ in 0..50 {
            let id = IdentityKeypair::generate().unwrap();
            let sig = xeddsa_sign(&id.private, b"record");
            assert!(xeddsa_verify(&id.public, b"record", &sig));
            assert!(
                !xeddsa_verify(&id.public, b"recorD", &sig),
                "other message must fail"
            );
            let other = IdentityKeypair::generate().unwrap();
            assert!(
                !xeddsa_verify(&other.public, b"record", &sig),
                "other key must fail"
            );
            let mut bad = sig;
            bad[40] ^= 1;
            assert!(
                !xeddsa_verify(&id.public, b"record", &bad),
                "tampered signature must fail"
            );
        }
    }

    #[test]
    fn test_epoch_keys_agree_and_differ_from_base() {
        let a = IdentityKeypair::generate().unwrap();
        let b = IdentityKeypair::generate().unwrap();
        let ea = EphemeralKey::generate();
        let eb = EphemeralKey::generate();
        let (pa, pb) = (ea.public, eb.public);
        let ka = SessionKeys::derive_epoch(&a, &b.public, ea, &pb, 1);
        let kb = SessionKeys::derive_epoch(&b, &a.public, eb, &pa, 1);
        let ct = ka.seal(5, b"h", b"data");
        assert_eq!(kb.open(5, b"h", &ct).as_deref(), Some(&b"data"[..]));
        let base = SessionKeys::derive(&b, &a.public);
        assert!(
            base.open(5, b"h", &ct).is_none(),
            "epoch keys must not match the base keys"
        );
        // Same inputs but another epoch number give unrelated keys.
        let ec = EphemeralKey::generate();
        let ed = EphemeralKey::generate();
        let (pc, pd) = (ec.public, ed.public);
        let k1 = SessionKeys::derive_epoch(&a, &b.public, ec, &pd, 1);
        let k2 = SessionKeys::derive_epoch(&b, &a.public, ed, &pc, 2);
        assert!(k2.open(5, b"h", &k1.seal(5, b"h", b"x")).is_none());
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
