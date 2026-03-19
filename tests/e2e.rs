//! End-to-end tests for the KeyRA authentication flow
//!
//! These tests require a running Autonity node in dev mode.
//! Run with: `./scripts/start-autonity.sh` in a separate terminal.
//!
//! If no node is running, tests will be skipped.

mod common;

use alpha::auth::AuthConfig;
use alloy::primitives::Address;
use common::{deploy_access_contract, dev_wallet, grant_access, is_node_running, sign_message};
use std::net::SocketAddr;
use std::time::Duration;

const RPC_URL: &str = "http://127.0.0.1:8545";

/// Helper to start a test server with optional jwt-auth-service URL
async fn start_test_server(
    contract_address: Address,
    jwt_service_url: Option<&str>,
) -> String {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let (listener, local_addr) = alpha::bind(addr).await.unwrap();

    let auth_config = AuthConfig {
        rpc_url: RPC_URL.to_string(),
        contract_address,
        session_secret: b"test-secret-key-for-e2e-tests!!".to_vec(),
        session_ttl: Duration::from_secs(3600),
        domain: "localhost".to_string(),
        chain_id: 1337,
        jwt_service_url: jwt_service_url.map(|s| s.to_string()),
    };

    tokio::spawn(async move {
        let _ = alpha::serve(listener, Some(auth_config)).await;
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    format!("http://{}", local_addr)
}

/// Get a URL pointing at a likely-unreachable port (bind then close)
async fn unreachable_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{}", port)
}

/// Helper to perform challenge + sign flow, returning (message, signature_hex)
async fn challenge_and_sign(
    client: &reqwest::Client,
    base_url: &str,
    signer: &alloy::signers::local::PrivateKeySigner,
    address: Address,
) -> (String, String) {
    let payload = serde_json::json!({ "address": format!("{}", address) });
    let challenge_resp = client
        .post(format!("{}/auth/challenge", base_url))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(challenge_resp.status(), 200);
    let challenge: serde_json::Value = challenge_resp.json().await.unwrap();
    let message = challenge["message"].as_str().unwrap().to_string();

    let signature = sign_message(signer, &message);
    let sig_hex = format!("0x{}", hex::encode(&signature));

    (message, sig_hex)
}

/// Helper to POST to /auth/token with a signed SIWE message
async fn post_auth_token(
    client: &reqwest::Client,
    base_url: &str,
    message: &str,
    signature: &str,
) -> reqwest::Response {
    let payload = serde_json::json!({
        "message": message,
        "signature": signature,
    });
    client
        .post(format!("{}/auth/token", base_url))
        .json(&payload)
        .send()
        .await
        .unwrap()
}

/// Full authentication flow test
///
/// 1. Deploy contract
/// 2. Grant access to test address
/// 3. Start server
/// 4. Get challenge
/// 5. Sign message
/// 6. Verify signature
/// 7. Access protected resource
#[tokio::test]
async fn full_auth_flow_with_access() {
    // Check if node is running
    if !is_node_running(RPC_URL).await {
        eprintln!("Skipping e2e test: Autonity node not running at {}", RPC_URL);
        return;
    }

    let (signer, address) = dev_wallet();

    // Deploy contract with dev account as admin
    let contract_address = deploy_access_contract(RPC_URL, signer.clone(), address)
        .await
        .expect("failed to deploy contract");

    eprintln!("Contract deployed at: {:?}", contract_address);

    // Grant access to the dev account
    grant_access(RPC_URL, signer.clone(), contract_address, address)
        .await
        .expect("failed to grant access");

    eprintln!("Access granted to: {:?}", address);

    // Start server with contract configured
    let base_url = start_test_server(contract_address, None).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    // 1. Verify index redirects to auth when not authenticated
    let resp = client.get(&base_url).send().await.unwrap();
    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/auth"
    );

    // 2. Request challenge
    let challenge_resp = client
        .post(format!("{}/auth/challenge", base_url))
        .header("content-type", "application/json")
        .body(format!(r#"{{"address":"{}"}}"#, address))
        .send()
        .await
        .unwrap();

    assert_eq!(challenge_resp.status(), 200);
    let challenge: serde_json::Value = challenge_resp.json().await.unwrap();
    let message = challenge["message"].as_str().unwrap();
    let _nonce = challenge["nonce"].as_str().unwrap();

    eprintln!("Got challenge message:\n{}", message);

    // 3. Sign the message
    let signature = sign_message(&signer, message);
    let sig_hex = format!("0x{}", hex::encode(&signature));

    eprintln!("Signature: {}", sig_hex);

    // 4. Submit signature for verification
    let verify_resp = client
        .post(format!("{}/auth/verify", base_url))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"message":"{}","signature":"{}"}}"#,
            message.replace('\n', "\\n"),
            sig_hex
        ))
        .send()
        .await
        .unwrap();

    eprintln!("Verify response status: {}", verify_resp.status());

    if verify_resp.status() != 200 {
        let body = verify_resp.text().await.unwrap();
        panic!("Verification failed: {}", body);
    }

    // Check for session cookie
    // Note: reqwest's cookie_store handles this automatically

    // 5. Access protected resource - should now work
    let index_resp = client.get(&base_url).send().await.unwrap();

    eprintln!("Index response status: {}", index_resp.status());
    eprintln!("Index response headers: {:?}", index_resp.headers());

    // With valid session, should get 200 and index.html content
    let status = index_resp.status();
    let body = index_resp.text().await.unwrap();
    eprintln!("Index response body: {}", &body[..body.len().min(500)]);

    assert_eq!(status, 200, "Expected 200, got {} with body: {}", status, body);
    assert!(body.contains("<title>alpha</title>"), "Body doesn't contain expected title: {}", &body[..body.len().min(500)]);
}

/// Test that access is denied when address is not in access list
#[tokio::test]
async fn access_denied_without_access() {
    if !is_node_running(RPC_URL).await {
        eprintln!("Skipping e2e test: Autonity node not running at {}", RPC_URL);
        return;
    }

    let (signer, address) = dev_wallet();

    // Deploy contract but DON'T grant access
    let contract_address = deploy_access_contract(RPC_URL, signer.clone(), address)
        .await
        .expect("failed to deploy contract");

    eprintln!("Contract deployed at: {:?}", contract_address);
    eprintln!("NOT granting access to: {:?}", address);

    let base_url = start_test_server(contract_address, None).await;

    let client = reqwest::Client::new();

    // Request challenge
    let challenge_resp = client
        .post(format!("{}/auth/challenge", base_url))
        .header("content-type", "application/json")
        .body(format!(r#"{{"address":"{}"}}"#, address))
        .send()
        .await
        .unwrap();

    assert_eq!(challenge_resp.status(), 200);
    let challenge: serde_json::Value = challenge_resp.json().await.unwrap();
    let message = challenge["message"].as_str().unwrap();

    // Sign the message
    let signature = sign_message(&signer, message);
    let sig_hex = format!("0x{}", hex::encode(&signature));

    // Submit signature - should be denied
    let verify_resp = client
        .post(format!("{}/auth/verify", base_url))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"message":"{}","signature":"{}"}}"#,
            message.replace('\n', "\\n"),
            sig_hex
        ))
        .send()
        .await
        .unwrap();

    // Should get 403 Forbidden
    assert_eq!(verify_resp.status(), 403);
    let body = verify_resp.text().await.unwrap();
    assert!(body.contains("Access denied"));
}

/// Test that invalid signatures are rejected
#[tokio::test]
async fn invalid_signature_rejected() {
    if !is_node_running(RPC_URL).await {
        eprintln!("Skipping e2e test: Autonity node not running at {}", RPC_URL);
        return;
    }

    let (signer, address) = dev_wallet();

    let contract_address = deploy_access_contract(RPC_URL, signer.clone(), address)
        .await
        .expect("failed to deploy contract");

    grant_access(RPC_URL, signer.clone(), contract_address, address)
        .await
        .expect("failed to grant access");

    let base_url = start_test_server(contract_address, None).await;

    let client = reqwest::Client::new();

    // Request challenge
    let challenge_resp = client
        .post(format!("{}/auth/challenge", base_url))
        .header("content-type", "application/json")
        .body(format!(r#"{{"address":"{}"}}"#, address))
        .send()
        .await
        .unwrap();

    let challenge: serde_json::Value = challenge_resp.json().await.unwrap();
    let message = challenge["message"].as_str().unwrap();

    // Sign a DIFFERENT message (simulating tampering)
    let wrong_signature = sign_message(&signer, "wrong message");
    let sig_hex = format!("0x{}", hex::encode(&wrong_signature));

    // Submit wrong signature
    let verify_resp = client
        .post(format!("{}/auth/verify", base_url))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"message":"{}","signature":"{}"}}"#,
            message.replace('\n', "\\n"),
            sig_hex
        ))
        .send()
        .await
        .unwrap();

    // Should get 401 Unauthorized
    assert_eq!(verify_resp.status(), 401);
}

/// Test /auth/token returns 502 when jwt-auth-service is unreachable
///
/// This test verifies the full SIWE flow through to the jwt-auth-service
/// call, which fails because there's no real jwt-auth-service running.
/// The 502 proves all prior steps (SIWE verify, nonce, access check) passed.
#[tokio::test]
async fn token_endpoint_returns_502_when_jwt_service_unreachable() {
    if !is_node_running(RPC_URL).await {
        eprintln!("Skipping e2e test: Autonity node not running at {}", RPC_URL);
        return;
    }

    let (signer, address) = dev_wallet();

    // Deploy contract and grant access
    let contract_address = deploy_access_contract(RPC_URL, signer.clone(), address)
        .await
        .expect("failed to deploy contract");

    grant_access(RPC_URL, signer.clone(), contract_address, address)
        .await
        .expect("failed to grant access");

    // Point jwt_service_url at a guaranteed-unreachable port
    let dead_url = unreachable_url().await;
    let base_url = start_test_server(contract_address, Some(&dead_url)).await;

    let client = reqwest::Client::new();

    // Challenge + sign
    let (message, sig_hex) = challenge_and_sign(&client, &base_url, &signer, address).await;

    // POST /auth/token — SIWE passes, but jwt-auth-service call fails
    let token_resp = post_auth_token(&client, &base_url, &message, &sig_hex).await;

    // 502 proves SIWE verification, nonce consumption, and access check all passed
    assert_eq!(token_resp.status(), 502);
    let body = token_resp.text().await.unwrap();
    assert!(body.contains("Token service unavailable"), "Expected 'Token service unavailable', got: {}", body);
}

/// Test /auth/token returns 403 when address lacks access
#[tokio::test]
async fn token_endpoint_denied_without_access() {
    if !is_node_running(RPC_URL).await {
        eprintln!("Skipping e2e test: Autonity node not running at {}", RPC_URL);
        return;
    }

    let (signer, address) = dev_wallet();

    // Deploy contract but DON'T grant access
    let contract_address = deploy_access_contract(RPC_URL, signer.clone(), address)
        .await
        .expect("failed to deploy contract");

    let dead_url = unreachable_url().await;
    let base_url = start_test_server(contract_address, Some(&dead_url)).await;

    let client = reqwest::Client::new();

    // Challenge + sign
    let (message, sig_hex) = challenge_and_sign(&client, &base_url, &signer, address).await;

    // POST /auth/token — should be denied before reaching jwt-auth-service
    let token_resp = post_auth_token(&client, &base_url, &message, &sig_hex).await;

    assert_eq!(token_resp.status(), 403);
}

/// Test /auth/token returns 503 when jwt_service_url is not configured
///
/// This test does NOT require a running Autonity node — the 503 is returned
/// before any SIWE verification or chain interaction.
#[tokio::test]
async fn token_endpoint_returns_503_without_jwt_config() {
    // No node needed — 503 returns before any chain interaction
    let base_url = start_test_server(Address::ZERO, None).await;

    let client = reqwest::Client::new();

    // POST /auth/token with any body — should fail immediately
    let payload = serde_json::json!({
        "message": "dummy",
        "signature": "0x00",
    });
    let token_resp = client
        .post(format!("{}/auth/token", base_url))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(token_resp.status(), 503);
    let body = token_resp.text().await.unwrap();
    assert!(body.contains("Token service not configured"));
}
