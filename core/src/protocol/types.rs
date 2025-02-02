use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;
use ed25519_dalek::{VerifyingKey};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub peer_id: String,
    pub display_name: Option<String>,
    pub status: UserStatus,
    pub public_keys: PublicIdentityKeys,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum UserStatus {
    Online,
    Away,
    Offline,
}

/// Represents a user's public cryptographic keys
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicIdentityKeys {
    /// X25519 public key for key exchange
    pub x25519_public_key: Vec<u8>,
    /// Ed25519 public key for signatures
    pub ed25519_public_key: Vec<u8>,
}

impl PublicIdentityKeys {
    /// Create PublicIdentityKeys from X25519 and Ed25519 public keys
    pub fn new(x25519_public: &X25519PublicKey, ed25519_public: &VerifyingKey) -> Self {
        PublicIdentityKeys {
            x25519_public_key: x25519_public.as_bytes().to_vec(),
            ed25519_public_key: ed25519_public.to_bytes().to_vec(),
        }
    }

    /// Convert X25519 public key bytes back to PublicKey
    pub fn get_x25519_public_key(&self) -> Option<X25519PublicKey> {
        // Use from_slice method from x25519_dalek
        let bytes: [u8; 32] = self.x25519_public_key.clone().try_into().ok()?;
        Some(X25519PublicKey::from(bytes))
    }

    /// Convert Ed25519 public key bytes back to VerifyingKey
    pub fn get_ed25519_public_key(&self) -> Option<VerifyingKey> {
        let bytes: [u8; 32] = self.ed25519_public_key.clone().try_into().ok()?;
        VerifyingKey::from_bytes(&bytes).ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SystemMessageType {
    /// User joined the network
    UserJoined,
    /// User left the network
    UserLeft,
    /// Connection request
    ConnectionRequest,
    /// Connection accepted
    ConnectionAccepted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_public_identity_keys_conversion() {
        let mut csprng = OsRng;
        
        // Generate X25519 key pair
        let x25519_secret = EphemeralSecret::random_from_rng(&mut csprng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        
        // Generate Ed25519 key pair
        let ed25519_signing_key = SigningKey::generate(&mut csprng);
        let ed25519_public = ed25519_signing_key.verifying_key();
        
        // Create PublicIdentityKeys
        let keys = PublicIdentityKeys::new(&x25519_public, &ed25519_public);
        
        // Verify key conversion back
        let recovered_x25519 = keys.get_x25519_public_key().unwrap();
        let recovered_ed25519 = keys.get_ed25519_public_key().unwrap();
        
        assert_eq!(x25519_public.as_bytes(), recovered_x25519.as_bytes());
        assert_eq!(ed25519_public.to_bytes(), recovered_ed25519.to_bytes());
    }
}