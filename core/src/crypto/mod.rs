use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, SharedSecret};
use rand::rngs::OsRng;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce,
};

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
}

pub struct CryptoManager {
    signing_key: SigningKey,
    public_key: X25519Public,
}

impl CryptoManager {
    pub fn new() -> Self {
        let mut rng = OsRng;
        
        // Generate Ed25519 keypair for signing
        let signing_key = SigningKey::generate(&mut rng);
        
        // Generate initial X25519 key pair
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public_key = X25519Public::from(&secret);

        Self {
            signing_key,
            public_key,
        }
    }

    pub fn get_public_key(&self) -> X25519Public {
        self.public_key
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        Ok(self.signing_key.sign(message))
    }

    pub fn verify_signature(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        verifying_key
            .verify_strict(message, signature)
            .map_err(|e| CryptoError::SignatureError(e.to_string()))
    }

    fn generate_shared_secret(peer_public_key: &X25519Public) -> SharedSecret {
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        ephemeral_secret.diffie_hellman(peer_public_key)
    }

    pub fn encrypt_message(
        &self,
        peer_public_key: &X25519Public,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let shared_secret = Self::generate_shared_secret(peer_public_key);
        
        let cipher = Aes256Gcm::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        
        let nonce = Nonce::from_slice(&[0u8; 12]); // Use a proper nonce generation in production
        
        let ciphertext = cipher
            .encrypt(nonce, message)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        
        Ok(ciphertext)
    }

    pub fn decrypt_message(
        &self,
        peer_public_key: &X25519Public,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let shared_secret = Self::generate_shared_secret(peer_public_key);
        
        let cipher = Aes256Gcm::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
        
        let nonce = Nonce::from_slice(&[0u8; 12]); // Use same nonce as encryption
        
        let plaintext = cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
        
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let alice = CryptoManager::new();
        let bob = CryptoManager::new();
        
        let message = b"Hello, Bob!";
        
        let encrypted = alice
            .encrypt_message(&bob.get_public_key(), message)
            .unwrap();
        
        let decrypted = bob
            .decrypt_message(&alice.get_public_key(), &encrypted)
            .unwrap();
        
        assert_eq!(message, &decrypted[..]);
    }

    #[test]
    fn test_signing_verification() {
        let manager = CryptoManager::new();
        let message = b"Hello, World!";
        
        let signature = manager.sign_message(message).unwrap();
        
        let verifying_key = manager.signing_key.verifying_key();
        let result = CryptoManager::verify_signature(&verifying_key, message, &signature);
        
        assert!(result.is_ok());
    }
}