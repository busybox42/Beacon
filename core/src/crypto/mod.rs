use std::error::Error;
use std::fmt;

use ed25519_dalek::{
    SigningKey, 
    VerifyingKey, 
    Signature,
    Signer,
    Verifier,
};
use x25519_dalek::{
    EphemeralSecret, 
    PublicKey as X25519PublicKey, 
    SharedSecret,
};
use rand::rngs::OsRng;
use aes_gcm::{
    Aes256Gcm, 
    Key, 
    Nonce,
    aead::{Aead, AeadCore, KeyInit}
};
use serde::{Serialize, Deserialize};

/// Represents a user's complete cryptographic identity
#[derive(Clone)]
pub struct CryptoIdentity {
    /// Ed25519 signing key for signatures
    ed25519_signing_key: SigningKey,
    /// Ed25519 verifying key for signatures
    ed25519_verifying_key: VerifyingKey,
    /// X25519 key for key exchange (stored as bytes)
    x25519_secret: [u8; 32],
    /// X25519 public key for key exchange
    x25519_public: X25519PublicKey,
}

/// Custom error type for cryptographic operations
#[derive(Debug)]
pub enum CryptoError {
    KeyGenerationError,
    EncryptionError,
    DecryptionError,
    SerializationError,
    SignatureError,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::KeyGenerationError => write!(f, "Failed to generate cryptographic keys"),
            CryptoError::EncryptionError => write!(f, "Encryption failed"),
            CryptoError::DecryptionError => write!(f, "Decryption failed"),
            CryptoError::SerializationError => write!(f, "Serialization failed"),
            CryptoError::SignatureError => write!(f, "Signature verification failed"),
        }
    }
}

impl Error for CryptoError {}

/// Represents an encrypted message with associated metadata
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedMessage {
    /// The encrypted payload
    pub(crate) ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub(crate) nonce: Vec<u8>,
    /// Optional signature for message authenticity
    pub(crate) signature: Option<Vec<u8>>,
}

impl CryptoIdentity {
    /// Create a new cryptographic identity
    pub fn new() -> Result<Self, CryptoError> {
        let mut csprng = OsRng;
        
        // Generate Ed25519 keys
        let ed25519_signing_key = SigningKey::generate(&mut csprng);
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();
        
        // Generate X25519 keys for key exchange
        let x25519_secret = EphemeralSecret::random_from_rng(&mut csprng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        
        // Generate a derived secret for storage
        let derived_secret = x25519_secret.diffie_hellman(&x25519_public).as_bytes().clone();
        
        Ok(CryptoIdentity {
            ed25519_signing_key,
            ed25519_verifying_key,
            x25519_secret: derived_secret,
            x25519_public,
        })
    }

    /// Get the X25519 public key for key exchange
    pub fn x25519_public_key(&self) -> X25519PublicKey {
        self.x25519_public
    }

    /// Get the Ed25519 verifying key for signatures
    pub fn ed25519_public_key(&self) -> VerifyingKey {
        self.ed25519_verifying_key
    }

    /// Get the stored secret bytes
    pub fn get_secret_bytes(&self) -> &[u8; 32] {
        &self.x25519_secret
    }

    /// Perform a key exchange with another peer's public key
    pub fn perform_key_exchange(&self, peer_public_key: X25519PublicKey) -> SharedSecret {
        let mut csprng = OsRng;
        let secret = EphemeralSecret::random_from_rng(&mut csprng);
        
        secret.diffie_hellman(&peer_public_key)
    }

    /// Sign a message with Ed25519
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.ed25519_signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Verify a signature
    pub fn verify_signature(
        public_key: &VerifyingKey, 
        message: &[u8], 
        signature: &[u8]
    ) -> Result<(), CryptoError> {
        // Convert signature to fixed-size array
        let sig_array: [u8; 64] = signature.try_into()
            .map_err(|_| CryptoError::SignatureError)?;
        
        public_key.verify(message, &Signature::from_bytes(&sig_array))
            .map_err(|_| CryptoError::SignatureError)
    }

    /// Encrypt a message for a specific peer
    pub fn encrypt_message(
        &self, 
        peer_public_key: X25519PublicKey, 
        message: &[u8]
    ) -> Result<EncryptedMessage, CryptoError> {
        // Perform key exchange to get a shared secret
        let mut csprng = OsRng;
        let secret = EphemeralSecret::random_from_rng(&mut csprng);
        let shared_secret = secret.diffie_hellman(&peer_public_key);
        
        // Derive a symmetric key from the shared secret
        let symmetric_key = derive_symmetric_key(&shared_secret);
        
        // Create an AES-GCM cipher
        let cipher = Aes256Gcm::new(&symmetric_key);
        
        // Generate a random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt the message
        let ciphertext = cipher.encrypt(&nonce, message)
            .map_err(|_| CryptoError::EncryptionError)?;
        
        // Optionally sign the message
        let signature = Some(self.sign_message(message));
        
        Ok(EncryptedMessage {
            ciphertext,
            nonce: nonce.to_vec(),
            signature,
        })
    }

    /// Decrypt a message from a specific peer
    pub fn decrypt_message(
        &self, 
        peer_public_key: X25519PublicKey, 
        encrypted_msg: &EncryptedMessage
    ) -> Result<Vec<u8>, CryptoError> {
        // Perform key exchange to get a shared secret
        let mut csprng = OsRng;
        let secret = EphemeralSecret::random_from_rng(&mut csprng);
        let shared_secret = secret.diffie_hellman(&peer_public_key);
        
        // Derive a symmetric key from the shared secret
        let symmetric_key = derive_symmetric_key(&shared_secret);
        
        // Create an AES-GCM cipher
        let cipher = Aes256Gcm::new(&symmetric_key);
        
        // Convert nonce to fixed-size array
        let nonce = Nonce::from_slice(&encrypted_msg.nonce);
        
        // Decrypt the message
        let decrypted_message = cipher.decrypt(nonce, encrypted_msg.ciphertext.as_slice())
            .map_err(|_| CryptoError::DecryptionError)?;
        
        Ok(decrypted_message)
    }
}

/// Derive a symmetric key from a shared secret
fn derive_symmetric_key(shared_secret: &SharedSecret) -> Key<Aes256Gcm> {
    // Use the first 32 bytes of the shared secret as the key
    let key_material = shared_secret.as_bytes();
    Key::<Aes256Gcm>::from_slice(&key_material[..32]).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end_encryption() {
        // Create two identities
        let alice_identity = CryptoIdentity::new().unwrap();
        let bob_identity = CryptoIdentity::new().unwrap();

        // Message to encrypt
        let original_message = b"Hello, secure communication!";

        // Alice encrypts a message for Bob
        let encrypted_msg = alice_identity
            .encrypt_message(bob_identity.x25519_public_key(), original_message)
            .unwrap();

        // Bob decrypts the message from Alice
        let decrypted_message = bob_identity
            .decrypt_message(alice_identity.x25519_public_key(), &encrypted_msg)
            .unwrap();

        // Verify the decrypted message matches the original
        assert_eq!(original_message, decrypted_message.as_slice());
    }

    #[test]
    fn test_key_exchange() {
        let alice_identity = CryptoIdentity::new().unwrap();
        let bob_identity = CryptoIdentity::new().unwrap();

        // Perform key exchange in both directions
        let alice_shared = alice_identity.perform_key_exchange(bob_identity.x25519_public_key());
        let bob_shared = bob_identity.perform_key_exchange(alice_identity.x25519_public_key());

        // Shared secrets should be equal
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }
}