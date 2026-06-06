use std::process::ExitCode;
use std::sync::Arc;

use coordinator::api::router;
use coordinator::backends::{HttpAuthorizationBackend, HttpCoprocessorBackend, HttpMpcBackend};
use coordinator::clock::SystemClock;
use coordinator::config::CoordinatorProcessConfig;
use coordinator::state::AppState;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    let process_config = match CoordinatorProcessConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("coordinator: {error}");
            return ExitCode::from(2);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| process_config.log_filter.into()),
        )
        .init();

    let state = AppState::new(
        process_config.runtime,
        Arc::new(HttpMpcBackend::new(process_config.mpc_url)),
        Arc::new(HttpCoprocessorBackend::new(process_config.coprocessor_url)),
        Arc::new(HttpAuthorizationBackend::new(process_config.eth_rpc_url)),
        Arc::new(SystemClock),
    );

    let listener = match TcpListener::bind(process_config.bind_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!(
                "coordinator: failed to bind {}: {error}",
                process_config.bind_addr
            );
            return ExitCode::from(3);
        }
    };

    info!("coordinator listening on {}", process_config.bind_addr);
    if let Err(error) = axum::serve(listener, router(state)).await {
        eprintln!("coordinator: server failed: {error}");
        return ExitCode::from(4);
    }

    ExitCode::SUCCESS
}
