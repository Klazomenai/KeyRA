//! Authentication module for KeyRA
//!
//! Implements SIWE (Sign-In with Ethereum) authentication flow:
//! 1. Generate challenge (nonce)
//! 2. User signs message with wallet
//! 3. Server verifies signature and checks access list contract

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use alloy::sol;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use siwe::Message;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Session cookie name
pub const SESSION_COOKIE: &str = "keyra_session";

/// Default session TTL (1 hour)
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600);

/// Error type for authentication operations
#[derive(Debug)]
pub enum AuthError {
    InvalidSignature,
    InvalidMessage,
    AddressRecoveryFailed,
    AccessDenied,
    ContractCallFailed(String),
    InvalidSession,
    SessionExpired,
    ProviderError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidSignature => write!(f, "Invalid signature"),
            AuthError::InvalidMessage => write!(f, "Invalid SIWE message"),
            AuthError::AddressRecoveryFailed => {
                write!(f, "Failed to recover address from signature")
            }
            AuthError::AccessDenied => write!(f, "Access denied"),
            AuthError::ContractCallFailed(e) => write!(f, "Contract call failed: {}", e),
            AuthError::InvalidSession => write!(f, "Invalid session"),
            AuthError::SessionExpired => write!(f, "Session expired"),
            AuthError::ProviderError(e) => write!(f, "Provider error: {}", e),
        }
    }
}

impl std::error::Error for AuthError {}

// Define the contract interface using alloy's sol! macro
sol! {
    #[sol(rpc)]
    interface IKeyRAAccessControl {
        function hasAccess(address account) external view returns (bool);
        function isAdmin(address account) external view returns (bool);
    }
}

/// Authentication service configuration
#[derive(Clone)]
pub struct AuthConfig {
    /// Ethereum RPC URL
    pub rpc_url: String,
    /// Access control contract address
    pub contract_address: Address,
    /// HMAC secret for session signing
    pub session_secret: Vec<u8>,
    /// Session TTL
    pub session_ttl: Duration,
    /// Domain for SIWE message
    pub domain: String,
    /// Chain ID
    pub chain_id: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:8545".to_string(),
            contract_address: Address::ZERO,
            session_secret: rand::thread_rng().gen::<[u8; 32]>().to_vec(),
            session_ttl: DEFAULT_SESSION_TTL,
            domain: "localhost".to_string(),
            chain_id: 1337, // Default dev chain ID
        }
    }
}

/// Authentication service
pub struct AuthService {
    config: AuthConfig,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Generate a random nonce for SIWE
    pub fn generate_nonce() -> String {
        let bytes: [u8; 16] = rand::thread_rng().gen();
        hex::encode(bytes)
    }

    /// Create a SIWE message for the user to sign
    pub fn create_siwe_message(&self, address: Address, nonce: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Format as ISO 8601
        let issued_at = time::OffsetDateTime::from_unix_timestamp(now as i64)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        let expiration = time::OffsetDateTime::from_unix_timestamp(
            (now + self.config.session_ttl.as_secs()) as i64,
        )
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

        format!(
            "{domain} wants you to sign in with your Ethereum account:\n\
            {address}\n\n\
            Sign in to KeyRA\n\n\
            URI: https://{domain}\n\
            Version: 1\n\
            Chain ID: {chain_id}\n\
            Nonce: {nonce}\n\
            Issued At: {issued_at}\n\
            Expiration Time: {expiration}",
            domain = self.config.domain,
            address = address,
            chain_id = self.config.chain_id,
            nonce = nonce,
            issued_at = issued_at,
            expiration = expiration,
        )
    }

    /// Verify a SIWE message signature and recover the signer address
    pub fn verify_signature(&self, message: &str, signature: &[u8]) -> Result<Address, AuthError> {
        // Parse the SIWE message
        let siwe_message: Message = message.parse().map_err(|_| AuthError::InvalidMessage)?;

        // Verify the signature
        let sig_bytes: [u8; 65] = signature
            .try_into()
            .map_err(|_| AuthError::InvalidSignature)?;

        siwe_message
            .verify_eip191(&sig_bytes)
            .map_err(|_| AuthError::InvalidSignature)?;

        // Extract the address from the message
        let addr_bytes: [u8; 20] = siwe_message.address;
        Ok(Address::from(addr_bytes))
    }

    /// Check if an address has access via the contract
    pub async fn has_access(&self, address: Address) -> Result<bool, AuthError> {
        if self.config.contract_address == Address::ZERO {
            // No contract configured, deny all
            return Ok(false);
        }

        let url: url::Url = self.config.rpc_url.parse().map_err(|e| {
            AuthError::ProviderError(format!("Invalid RPC URL: {}", e))
        })?;

        let provider = ProviderBuilder::new().connect_http(url);

        let contract = IKeyRAAccessControl::new(self.config.contract_address, provider);

        let has_access: bool = contract
            .hasAccess(address)
            .call()
            .await
            .map_err(|e: alloy::contract::Error| AuthError::ContractCallFailed(e.to_string()))?;

        Ok(has_access)
    }

    /// Create a signed session cookie value
    pub fn create_session(&self, address: Address) -> String {
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.config.session_ttl.as_secs();

        let data = format!("{}|{}", address, expiry);

        // Sign the data
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.config.session_secret).expect("HMAC init failed");
        mac.update(data.as_bytes());
        let signature = mac.finalize().into_bytes();

        format!(
            "{}|{}",
            data,
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, signature)
        )
    }

    /// Verify and parse a session cookie
    pub fn verify_session(&self, cookie: &str) -> Result<Address, AuthError> {
        let parts: Vec<&str> = cookie.split('|').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidSession);
        }

        let address_str = parts[0];
        let expiry_str = parts[1];
        let signature_b64 = parts[2];

        // Verify signature
        let data = format!("{}|{}", address_str, expiry_str);
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.config.session_secret).expect("HMAC init failed");
        mac.update(data.as_bytes());

        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signature_b64,
        )
        .map_err(|_| AuthError::InvalidSession)?;

        mac.verify_slice(&signature)
            .map_err(|_| AuthError::InvalidSession)?;

        // Check expiry
        let expiry: u64 = expiry_str.parse().map_err(|_| AuthError::InvalidSession)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > expiry {
            return Err(AuthError::SessionExpired);
        }

        // Parse address
        Address::from_str(address_str).map_err(|_| AuthError::InvalidSession)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce() {
        let nonce1 = AuthService::generate_nonce();
        let nonce2 = AuthService::generate_nonce();

        assert_eq!(nonce1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_session_roundtrip() {
        let config = AuthConfig::default();
        let service = AuthService::new(config);

        let address = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f3fE75").unwrap();
        let session = service.create_session(address);

        let recovered = service.verify_session(&session).unwrap();
        assert_eq!(recovered, address);
    }

    #[test]
    fn test_session_tampered() {
        let config = AuthConfig::default();
        let service = AuthService::new(config);

        let address = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f3fE75").unwrap();
        let session = service.create_session(address);

        // Tamper with the session
        let tampered = session.replace("742d35", "000000");

        assert!(service.verify_session(&tampered).is_err());
    }

    #[test]
    fn test_siwe_message_format() {
        let config = AuthConfig {
            domain: "example.com".to_string(),
            chain_id: 1,
            ..Default::default()
        };
        let service = AuthService::new(config);

        let address = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f3fE75").unwrap();
        let nonce = "abc123def456";
        let message = service.create_siwe_message(address, nonce);

        assert!(message.contains("example.com wants you to sign in"));
        // Address may be formatted with different case
        assert!(message.to_lowercase().contains("0x742d35cc6634c0532925a3b844bc9e7595f3fe75"));
        assert!(message.contains("Chain ID: 1"));
        assert!(message.contains(&format!("Nonce: {}", nonce)));
    }
}
