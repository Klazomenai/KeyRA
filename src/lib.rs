//! # KeyRA Alpha
//!
//! A minimal, secure landing page server for the KeyRA project with
//! Ethereum wallet authentication.
//!
//! ## Features
//!
//! - Embedded static assets (HTML, CSS)
//! - Security headers on all responses
//! - Health check endpoint for Kubernetes probes
//! - SIWE (Sign-In with Ethereum) authentication
//! - Access control via on-chain contract
//!
//! ## Usage
//!
//! ```no_run
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//!     let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
//!     let (listener, local_addr) = alpha::bind(addr).await?;
//!     eprintln!("Listening on http://{}", local_addr);
//!     alpha::serve(listener, None).await
//! }
//! ```
//!
//! ## Security Headers
//!
//! All responses include:
//! - `Content-Security-Policy`: Restrictive CSP preventing XSS
//! - `X-Content-Type-Options: nosniff`: Prevents MIME sniffing
//! - `X-Frame-Options: DENY`: Prevents clickjacking

pub mod auth;

use crate::auth::{AuthConfig, AuthError, AuthService, SESSION_COOKIE};
use alloy::primitives::Address;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{COOKIE, SET_COOKIE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rust_embed::Embed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

/// Embedded static assets from the `assets/` directory.
#[derive(Embed)]
#[folder = "assets/"]
struct Assets;

/// Boxed error type for convenience.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Server state shared across all connections
pub struct AppState {
    /// Authentication service
    pub auth: AuthService,
    /// Pending nonces (address -> nonce) - in production, use Redis with TTL
    pub pending_nonces: RwLock<HashMap<String, String>>,
}

impl AppState {
    /// Create new app state with the given auth config
    pub fn new(auth_config: AuthConfig) -> Self {
        Self {
            auth: AuthService::new(auth_config),
            pending_nonces: RwLock::new(HashMap::new()),
        }
    }
}

/// Build an HTTP response with security headers.
fn response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    response_with_headers(status, content_type, body, vec![])
}

/// Build an HTTP response with security headers and additional headers.
fn response_with_headers(
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
    extra_headers: Vec<(&str, String)>,
) -> Response<Full<Bytes>> {
    // Auth page needs inline script for MetaMask interaction
    let csp = if content_type.contains("text/html") {
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'; connect-src 'self'"
    } else {
        "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    };

    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Content-Security-Policy", csp)
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY");

    for (name, value) in extra_headers {
        builder = builder.header(name, value);
    }

    builder.body(Full::new(Bytes::from(body))).unwrap()
}

/// Redirect response
fn redirect(location: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// JSON response
fn json_response<T: Serialize>(status: StatusCode, data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(data).unwrap_or_default();
    response(status, "application/json", body)
}

/// Error response
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    response(status, "text/plain", message.as_bytes().to_vec())
}

/// Parse cookies from request
fn get_cookie(req: &Request<hyper::body::Incoming>, name: &str) -> Option<String> {
    req.headers()
        .get(COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let mut parts = cookie.trim().splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next()?;
            if key == name {
                Some(value.to_string())
            } else {
                None
            }
        })
}

/// Challenge request
#[derive(Deserialize)]
struct ChallengeRequest {
    address: String,
}

/// Challenge response
#[derive(Serialize)]
struct ChallengeResponse {
    message: String,
    nonce: String,
}

/// Verify request
#[derive(Deserialize)]
struct VerifyRequest {
    message: String,
    signature: String,
}

/// Handle an incoming HTTP request.
async fn handle(
    req: Request<hyper::body::Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method, path.as_str()) {
        // Health check - always accessible
        (Method::GET, "/healthz") => Ok(response(StatusCode::OK, "text/plain", b"OK".to_vec())),

        // Auth page - public
        (Method::GET, "/auth") => serve_asset("auth.html"),

        // Challenge endpoint - POST
        (Method::POST, "/auth/challenge") => handle_challenge(req, state).await,

        // Verify endpoint - POST
        (Method::POST, "/auth/verify") => handle_verify(req, state).await,

        // Protected index page
        (Method::GET, "/") => {
            // Check session
            if let Some(cookie) = get_cookie(&req, SESSION_COOKIE) {
                if state.auth.verify_session(&cookie).is_ok() {
                    return serve_asset("index.html");
                }
            }
            // Not authenticated - redirect to auth
            Ok(redirect("/auth"))
        }

        // Static assets - check if protected or public
        (Method::GET, _) => {
            let asset_path = path.trim_start_matches('/');

            // CSS and other assets are public
            if asset_path == "style.css" || asset_path == "auth.html" {
                return serve_asset(asset_path);
            }

            // Other assets require authentication
            if let Some(cookie) = get_cookie(&req, SESSION_COOKIE) {
                if state.auth.verify_session(&cookie).is_ok() {
                    return serve_asset(asset_path);
                }
            }
            Ok(redirect("/auth"))
        }

        // Method not allowed
        _ => Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed",
        )),
    }
}

/// Handle challenge request
async fn handle_challenge(
    req: Request<hyper::body::Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    // Read body
    let body = req.collect().await?.to_bytes();
    let challenge_req: ChallengeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid JSON",
            ))
        }
    };

    // Parse address
    let address = match Address::from_str(&challenge_req.address) {
        Ok(a) => a,
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid address",
            ))
        }
    };

    // Generate nonce and message
    let nonce = AuthService::generate_nonce();
    let message = state.auth.create_siwe_message(address, &nonce);

    // Store nonce for verification
    {
        let mut nonces = state.pending_nonces.write().await;
        nonces.insert(challenge_req.address.to_lowercase(), nonce.clone());
    }

    let resp = ChallengeResponse { message, nonce };
    Ok(json_response(StatusCode::OK, &resp))
}

/// Handle verify request
async fn handle_verify(
    req: Request<hyper::body::Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    // Read body
    let body = req.collect().await?.to_bytes();
    let verify_req: VerifyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid JSON",
            ))
        }
    };

    // Decode signature (remove 0x prefix if present)
    let sig_hex = verify_req.signature.trim_start_matches("0x");
    let signature = match hex::decode(sig_hex) {
        Ok(s) => s,
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid signature format",
            ))
        }
    };

    // Verify signature and recover address
    let address = match state.auth.verify_signature(&verify_req.message, &signature) {
        Ok(a) => a,
        Err(AuthError::InvalidSignature) => {
            return Ok(error_response(
                StatusCode::UNAUTHORIZED,
                "Invalid signature",
            ))
        }
        Err(AuthError::InvalidMessage) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid message format",
            ))
        }
        Err(e) => {
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &e.to_string(),
            ))
        }
    };

    // Check pending nonce
    {
        let mut nonces = state.pending_nonces.write().await;
        let addr_key = format!("{:?}", address).to_lowercase();
        if nonces.remove(&addr_key).is_none() {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "No pending challenge for this address",
            ));
        }
    }

    // Check access on contract (if configured)
    match state.auth.has_access(address).await {
        Ok(true) => {
            // Grant access - create session cookie
            let session = state.auth.create_session(address);
            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600",
                SESSION_COOKIE, session
            );

            Ok(response_with_headers(
                StatusCode::OK,
                "application/json",
                b"{\"success\":true}".to_vec(),
                vec![(SET_COOKIE.as_str(), cookie)],
            ))
        }
        Ok(false) => Ok(error_response(StatusCode::FORBIDDEN, "Access denied")),
        Err(e) => {
            eprintln!("Contract call error: {}", e);
            // If contract is not configured (Address::ZERO), deny access
            Ok(error_response(StatusCode::FORBIDDEN, "Access denied"))
        }
    }
}

/// Serve an embedded asset by path.
fn serve_asset(path: &str) -> Result<Response<Full<Bytes>>, BoxError> {
    match Assets::get(path) {
        Some(asset) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Ok(response(StatusCode::OK, mime.as_ref(), asset.data.to_vec()))
        }
        None => Ok(response(
            StatusCode::NOT_FOUND,
            "text/plain",
            b"Not Found".to_vec(),
        )),
    }
}

/// Bind to the given address and return the listener with its actual bound address.
///
/// Use port 0 to get a random available port (useful for testing).
///
/// # Arguments
///
/// * `addr` - The socket address to bind to
///
/// # Returns
///
/// A tuple of the TCP listener and the actual bound address.
///
/// # Example
///
/// ```no_run
/// use std::net::SocketAddr;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// // Bind to a specific port
/// let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
/// let (listener, local_addr) = alpha::bind(addr).await?;
///
/// // Or bind to a random port
/// let addr = SocketAddr::from(([127, 0, 0, 1], 0));
/// let (listener, local_addr) = alpha::bind(addr).await?;
/// println!("Bound to port {}", local_addr.port());
/// # Ok(())
/// # }
/// ```
pub async fn bind(addr: SocketAddr) -> Result<(TcpListener, SocketAddr), BoxError> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    Ok((listener, local_addr))
}

/// Run the server accept loop.
///
/// This function runs forever, accepting connections and spawning tasks
/// to handle each one. It only returns if there's an error accepting
/// a connection.
///
/// # Arguments
///
/// * `listener` - The TCP listener to accept connections from
/// * `auth_config` - Optional auth configuration. If None, uses defaults.
///
/// # Example
///
/// ```no_run
/// use std::net::SocketAddr;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
/// let (listener, _) = alpha::bind(addr).await?;
/// alpha::serve(listener, None).await?;
/// # Ok(())
/// # }
/// ```
pub async fn serve(listener: TcpListener, auth_config: Option<AuthConfig>) -> Result<(), BoxError> {
    let state = Arc::new(AppState::new(auth_config.unwrap_or_default()));

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let state = state;
            let service = service_fn(|req| {
                let state = Arc::clone(&state);
                async move {
                    handle(req, state)
                        .await
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("connection error: {}", e);
            }
        });
    }
}
