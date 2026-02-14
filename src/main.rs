use alloy::primitives::Address;
use alpha::auth::AuthConfig;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a valid u16");

    // Build auth config from environment
    let auth_config = AuthConfig {
        rpc_url: std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string()),
        contract_address: std::env::var("CONTRACT_ADDRESS")
            .ok()
            .and_then(|s| Address::from_str(&s).ok())
            .unwrap_or(Address::ZERO),
        session_secret: std::env::var("SESSION_SECRET")
            .map(|s| s.into_bytes())
            .unwrap_or_else(|_| {
                eprintln!("WARNING: SESSION_SECRET not set, using random secret");
                rand::random::<[u8; 32]>().to_vec()
            }),
        session_ttl: std::env::var("SESSION_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(3600)),
        domain: std::env::var("DOMAIN").unwrap_or_else(|_| "localhost".to_string()),
        chain_id: std::env::var("CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1337),
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let (listener, local_addr) = alpha::bind(addr).await?;

    eprintln!("alpha listening on http://{}", local_addr);
    eprintln!("  RPC URL: {}", auth_config.rpc_url);
    eprintln!("  Contract: {:?}", auth_config.contract_address);
    eprintln!("  Domain: {}", auth_config.domain);
    eprintln!("  Chain ID: {}", auth_config.chain_id);

    alpha::serve(listener, Some(auth_config)).await
}
