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
}
