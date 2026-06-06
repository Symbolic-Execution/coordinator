use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use coordinator::api::router;
use coordinator::backends::{HttpCoprocessorBackend, HttpMpcBackend, InMemoryAuthorizationBackend};
use coordinator::clock::SystemClock;
use coordinator::state::{AppState, CoordinatorRuntimeConfig};
use coordinator::types::Bytes32;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "coordinator=info".into()),
        )
        .init();

    let bind_addr =
        std::env::var("COORDINATOR_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:4000".to_string());
    let mpc_url = std::env::var("COORDINATOR_MPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let coprocessor_url = std::env::var("COORDINATOR_COPROCESSOR_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5000".to_string());
    let eip712_name =
        std::env::var("COORDINATOR_EIP712_NAME").unwrap_or_else(|_| "Coordinator".to_string());
    let eip712_version =
        std::env::var("COORDINATOR_EIP712_VERSION").unwrap_or_else(|_| "1".to_string());
    let eip712_salt = std::env::var("COORDINATOR_EIP712_SALT")
        .ok()
        .and_then(|value| serde_json::from_value(serde_json::Value::String(value)).ok())
        .unwrap_or(Bytes32([0x99; 32]));

    let state = AppState::new(
        CoordinatorRuntimeConfig {
            version: 1,
            eip712_name,
            eip712_version,
            eip712_salt,
        },
        Arc::new(HttpMpcBackend::new(mpc_url)),
        Arc::new(HttpCoprocessorBackend::new(coprocessor_url)),
        Arc::new(InMemoryAuthorizationBackend::new()),
        Arc::new(SystemClock),
    );

    let addr: SocketAddr = match bind_addr.parse() {
        Ok(addr) => addr,
        Err(error) => {
            eprintln!("coordinator: invalid bind addr: {error}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("coordinator: failed to bind {addr}: {error}");
            return ExitCode::from(3);
        }
    };

    info!("coordinator listening on {addr}");
    if let Err(error) = axum::serve(listener, router(state)).await {
        eprintln!("coordinator: server failed: {error}");
        return ExitCode::from(4);
    }

    ExitCode::SUCCESS
}
