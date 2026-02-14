use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Start a test server on a random port and return the base URL.
async fn start_server() -> String {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let (listener, local_addr) = alpha::bind(addr).await.unwrap();

    tokio::spawn(async move {
        let _ = alpha::serve(listener, None).await;
    });

    // Small delay to ensure server is ready
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    format!("http://{}", local_addr)
}

#[tokio::test]
async fn health_returns_ok() {
    let base_url = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "OK");
}

#[tokio::test]
async fn index_redirects_to_auth_when_unauthenticated() {
    let base_url = start_server().await;
    // Don't follow redirects
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let resp = client.get(&base_url).send().await.unwrap();

    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/auth"
    );
}

#[tokio::test]
async fn auth_page_returns_html() {
    let base_url = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/auth", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let content_type = resp.headers().get("content-type").unwrap();
    assert!(content_type.to_str().unwrap().contains("text/html"));

    let body = resp.text().await.unwrap();
    assert!(body.contains("<!DOCTYPE html>"));
    assert!(body.contains("KeyRA"));
    assert!(body.contains("Connect Wallet"));
}

#[tokio::test]
async fn auth_page_has_csp_header() {
    let base_url = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/auth", base_url))
        .send()
        .await
        .unwrap();

    let csp = resp
        .headers()
        .get("content-security-policy")
        .expect("CSP header missing");

    let csp_str = csp.to_str().unwrap();
    // Auth page allows inline scripts for MetaMask
    assert!(csp_str.contains("script-src"));
    assert!(csp_str.contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn auth_page_has_security_headers() {
    let base_url = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/auth", base_url))
        .send()
        .await
        .unwrap();

    let xcto = resp
        .headers()
        .get("x-content-type-options")
        .expect("X-Content-Type-Options header missing");
    assert_eq!(xcto.to_str().unwrap(), "nosniff");

    let xfo = resp
        .headers()
        .get("x-frame-options")
        .expect("X-Frame-Options header missing");
    assert_eq!(xfo.to_str().unwrap(), "DENY");
}

#[tokio::test]
async fn css_returns_stylesheet() {
    let base_url = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/style.css", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let content_type = resp.headers().get("content-type").unwrap();
    assert!(content_type.to_str().unwrap().contains("text/css"));

    let body = resp.text().await.unwrap();
    assert!(body.contains(":root"));
    assert!(body.contains("--background: #000000"));
    assert!(body.contains("--foreground: #00ff00"));
}

#[tokio::test]
async fn challenge_endpoint_returns_message() {
    let base_url = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/auth/challenge", base_url))
        .header("content-type", "application/json")
        .body(r#"{"address":"0x742d35Cc6634C0532925a3b844Bc9e7595f3fE75"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("wants you to sign in"));
    assert!(body["nonce"].as_str().is_some());
}

#[tokio::test]
async fn challenge_endpoint_rejects_invalid_address() {
    let base_url = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/auth/challenge", base_url))
        .header("content-type", "application/json")
        .body(r#"{"address":"not-a-valid-address"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn verify_endpoint_rejects_invalid_signature() {
    let base_url = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/auth/verify", base_url))
        .header("content-type", "application/json")
        .body(r#"{"message":"test","signature":"0x1234"}"#)
        .send()
        .await
        .unwrap();

    // Should fail - invalid signature
    assert!(resp.status().is_client_error() || resp.status().is_server_error());
}

#[tokio::test]
async fn path_traversal_blocked() {
    let base_url = start_server().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Attempt path traversal - should redirect to auth (not serve system files)
    let resp = client
        .get(format!("{}/../../../etc/passwd", base_url))
        .send()
        .await
        .unwrap();

    // Should redirect to auth or return 404
    assert!(resp.status() == 302 || resp.status() == 404);
}

#[tokio::test]
async fn server_survives_http2_prior_knowledge() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let (listener, local_addr) = alpha::bind(addr).await.unwrap();

    tokio::spawn(async move {
        let _ = alpha::serve(listener, None).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Send HTTP/2 connection preface (prior knowledge) - this should fail gracefully
    let mut stream = TcpStream::connect(local_addr).await.unwrap();
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    drop(stream);

    // Small delay for server to process the bad request
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Server should still be alive
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/healthz", local_addr))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "OK");
}

#[tokio::test]
async fn server_survives_tls_handshake_attempt() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let (listener, local_addr) = alpha::bind(addr).await.unwrap();

    tokio::spawn(async move {
        let _ = alpha::serve(listener, None).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Send TLS ClientHello-like bytes
    let mut stream = TcpStream::connect(local_addr).await.unwrap();
    stream
        .write_all(&[0x16, 0x03, 0x01, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'])
        .await
        .unwrap();
    drop(stream);

    // Small delay for server to process the bad request
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Server should still be alive
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/healthz", local_addr))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "OK");
}
