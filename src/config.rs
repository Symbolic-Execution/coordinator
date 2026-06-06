use std::net::SocketAddr;

use crate::state::CoordinatorRuntimeConfig;
use crate::types::Bytes32;

#[derive(Clone, Debug)]
pub struct CoordinatorProcessConfig {
    pub bind_addr: SocketAddr,
    pub log_filter: String,
    pub mpc_url: String,
    pub coprocessor_url: String,
    pub eth_rpc_url: String,
    pub runtime: CoordinatorRuntimeConfig,
}

impl CoordinatorProcessConfig {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = std::env::var("COORDINATOR_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:4000".to_string())
            .parse()
            .map_err(|error| format!("invalid COORDINATOR_BIND_ADDR: {error}"))?;
        let log_filter = std::env::var("COORDINATOR_LOG_FILTER")
            .unwrap_or_else(|_| "coordinator=info".to_string());
        let mpc_url = std::env::var("COORDINATOR_MPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let coprocessor_url = std::env::var("COORDINATOR_COPROCESSOR_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:5000".to_string());
        let eth_rpc_url = std::env::var("COORDINATOR_ETH_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
        let eip712_name =
            std::env::var("COORDINATOR_EIP712_NAME").unwrap_or_else(|_| "Coordinator".to_string());
        let eip712_version =
            std::env::var("COORDINATOR_EIP712_VERSION").unwrap_or_else(|_| "1".to_string());
        let eip712_salt = std::env::var("COORDINATOR_EIP712_SALT")
            .ok()
            .and_then(|value| serde_json::from_value(serde_json::Value::String(value)).ok())
            .unwrap_or(Bytes32([0x99; 32]));

        Ok(Self {
            bind_addr,
            log_filter,
            mpc_url,
            coprocessor_url,
            eth_rpc_url,
            runtime: CoordinatorRuntimeConfig {
                version: 1,
                eip712_name,
                eip712_version,
                eip712_salt,
            },
        })
    }
}
