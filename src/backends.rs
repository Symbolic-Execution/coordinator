use async_trait::async_trait;
use reqwest::StatusCode;
use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::CoordinatorError;
use crate::types::{
    Address, GetHandleResponse, HandleId, MpcConfigResponse, MpcPutReaderRequest,
    MpcPutReaderResponse, ReaderId, ResolveHandleRequest, ResolveHandleResponse, ToReaderRequest,
    ToReaderResponse,
};

#[async_trait]
pub trait MpcBackend: Send + Sync {
    async fn get_config(&self) -> Result<MpcConfigResponse, CoordinatorError>;
    async fn put_reader(
        &self,
        reader_id: ReaderId,
        request: MpcPutReaderRequest,
    ) -> Result<MpcPutReaderResponse, CoordinatorError>;
    async fn to_reader(
        &self,
        request: ToReaderRequest,
    ) -> Result<ToReaderResponse, CoordinatorError>;
}

#[async_trait]
pub trait CoprocessorBackend: Send + Sync {
    async fn resolve_handle(
        &self,
        request: ResolveHandleRequest,
    ) -> Result<ResolveHandleResponse, CoordinatorError>;
    async fn get_handle(
        &self,
        contract: Address,
        handle_id: HandleId,
    ) -> Result<GetHandleResponse, CoordinatorError>;
}

#[async_trait]
pub trait AuthorizationBackend: Send + Sync {
    async fn resolve_controller(
        &self,
        contract: Address,
        handle_id: HandleId,
    ) -> Result<Address, CoordinatorError>;
}

const DISCLOSURE_CONTROLLER_SIGNATURE: &str = "disclosureController(bytes32)";

#[derive(Clone)]
pub struct HttpMpcBackend {
    client: reqwest::Client,
    base_url: String,
}

impl HttpMpcBackend {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait]
impl MpcBackend for HttpMpcBackend {
    async fn get_config(&self) -> Result<MpcConfigResponse, CoordinatorError> {
        let response = self
            .client
            .get(format!("{}/v1/config", self.base_url))
            .send()
            .await
            .map_err(|error| {
                CoordinatorError::Unavailable(format!("mpc config request failed: {error}"))
            })?;
        decode_json_response(response).await
    }

    async fn put_reader(
        &self,
        reader_id: ReaderId,
        request: MpcPutReaderRequest,
    ) -> Result<MpcPutReaderResponse, CoordinatorError> {
        let reader_id = serde_json::to_value(reader_id)
            .map_err(|error| CoordinatorError::BadRequest(format!("serialize reader_id: {error}")))?
            .as_str()
            .ok_or_else(|| {
                CoordinatorError::BadRequest("reader_id did not serialize to string".to_string())
            })?
            .to_string();
        let response = self
            .client
            .put(format!("{}/v1/readers/{reader_id}", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                CoordinatorError::Unavailable(format!("mpc put_reader failed: {error}"))
            })?;
        decode_json_response(response).await
    }

    async fn to_reader(
        &self,
        request: ToReaderRequest,
    ) -> Result<ToReaderResponse, CoordinatorError> {
        let response = self
            .client
            .post(format!("{}/v1/operations/to-reader", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                CoordinatorError::Unavailable(format!("mpc to_reader failed: {error}"))
            })?;
        decode_json_response(response).await
    }
}

#[derive(Clone)]
pub struct HttpCoprocessorBackend {
    client: reqwest::Client,
    base_url: String,
}

impl HttpCoprocessorBackend {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait]
impl CoprocessorBackend for HttpCoprocessorBackend {
    async fn resolve_handle(
        &self,
        request: ResolveHandleRequest,
    ) -> Result<ResolveHandleResponse, CoordinatorError> {
        let response = self
            .client
            .post(format!("{}/internal/v1/handles/resolve", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                CoordinatorError::Unavailable(format!("coprocessor resolve failed: {error}"))
            })?;
        decode_json_response(response).await
    }

    async fn get_handle(
        &self,
        contract: Address,
        handle_id: HandleId,
    ) -> Result<GetHandleResponse, CoordinatorError> {
        let contract = serde_json::to_value(contract)
            .map_err(|error| CoordinatorError::BadRequest(format!("serialize contract: {error}")))?
            .as_str()
            .ok_or_else(|| {
                CoordinatorError::BadRequest("contract did not serialize to string".to_string())
            })?
            .to_string();
        let handle_id = serde_json::to_value(handle_id)
            .map_err(|error| CoordinatorError::BadRequest(format!("serialize handle_id: {error}")))?
            .as_str()
            .ok_or_else(|| {
                CoordinatorError::BadRequest("handle_id did not serialize to string".to_string())
            })?
            .to_string();
        let response = self
            .client
            .get(format!(
                "{}/internal/v1/contracts/{contract}/handles/{handle_id}",
                self.base_url
            ))
            .send()
            .await
            .map_err(|error| {
                CoordinatorError::Unavailable(format!("coprocessor get_handle failed: {error}"))
            })?;
        decode_json_response(response).await
    }
}

pub async fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, CoordinatorError> {
    let status = response.status();
    if status.is_success() {
        return response.json().await.map_err(|error| {
            CoordinatorError::Unavailable(format!("backend response decode failed: {error}"))
        });
    }

    let body = response.text().await.unwrap_or_default();
    let message = if body.is_empty() {
        format!("backend returned HTTP {}", status.as_u16())
    } else {
        format!("backend returned HTTP {}: {body}", status.as_u16())
    };
    Err(match status {
        StatusCode::BAD_REQUEST => CoordinatorError::BadRequest(message),
        StatusCode::UNAUTHORIZED => CoordinatorError::Unauthorized(message),
        StatusCode::FORBIDDEN => CoordinatorError::Forbidden(message),
        StatusCode::NOT_FOUND => CoordinatorError::NotFound(message),
        StatusCode::CONFLICT => CoordinatorError::Conflict(message),
        StatusCode::GONE => CoordinatorError::Gone(message),
        StatusCode::UNPROCESSABLE_ENTITY => CoordinatorError::Unprocessable(message),
        _ => CoordinatorError::Unavailable(message),
    })
}

#[derive(Clone)]
pub struct HttpAuthorizationBackend {
    client: reqwest::Client,
    rpc_url: String,
}

impl HttpAuthorizationBackend {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            rpc_url: rpc_url.into().trim_end_matches('/').to_string(),
        }
    }
}

#[derive(Serialize)]
struct JsonRpcRequest<'a, P> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

#[derive(Serialize)]
struct EthCallParams<'a> {
    to: &'a str,
    data: &'a str,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

fn hex_encode_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn encode_disclosure_controller_call(handle_id: HandleId) -> String {
    let selector = Keccak256::digest(DISCLOSURE_CONTROLLER_SIGNATURE.as_bytes());
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&selector[..4]);
    calldata.extend_from_slice(&handle_id.0);
    hex_encode_prefixed(&calldata)
}

fn decode_address_word(result: &str) -> Result<Address, CoordinatorError> {
    let raw = result.strip_prefix("0x").ok_or_else(|| {
        CoordinatorError::Forbidden("disclosure controller lookup returned non-hex data".to_string())
    })?;
    if raw.len() != 64 {
        return Err(CoordinatorError::Forbidden(
            "disclosure controller lookup returned malformed data".to_string(),
        ));
    }

    let decoded = hex::decode(raw).map_err(|error| {
        CoordinatorError::Forbidden(format!(
            "disclosure controller lookup returned invalid hex: {error}"
        ))
    })?;
    let mut address = [0u8; 20];
    address.copy_from_slice(&decoded[12..32]);
    Ok(Address(address))
}

#[async_trait]
impl AuthorizationBackend for HttpAuthorizationBackend {
    async fn resolve_controller(
        &self,
        contract: Address,
        handle_id: HandleId,
    ) -> Result<Address, CoordinatorError> {
        let contract = hex_encode_prefixed(&contract.0);
        let data = encode_disclosure_controller_call(handle_id);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "eth_call",
            params: (
                EthCallParams {
                    to: &contract,
                    data: &data,
                },
                "safe",
            ),
        };

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                CoordinatorError::Unavailable(format!(
                    "authorization eth_call failed: {error}"
                ))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(CoordinatorError::Unavailable(format!(
                "authorization RPC returned HTTP {}: {}",
                status.as_u16(),
                body
            )));
        }

        let body: JsonRpcResponse<String> = response.json().await.map_err(|error| {
            CoordinatorError::Unavailable(format!(
                "authorization RPC response decode failed: {error}"
            ))
        })?;

        if let Some(error) = body.error {
            return Err(CoordinatorError::Forbidden(format!(
                "disclosure controller lookup failed: {} ({})",
                error.message, error.code
            )));
        }

        let controller = decode_address_word(&body.result.ok_or_else(|| {
            CoordinatorError::Unavailable(
                "authorization RPC response was missing result".to_string(),
            )
        })?)?;

        if controller == Address([0u8; 20]) {
            return Err(CoordinatorError::Forbidden(
                "handle has no disclosure controller".to_string(),
            ));
        }

        Ok(controller)
    }
}

#[derive(Clone, Default)]
pub struct InMemoryAuthorizationBackend {
    controllers: Arc<RwLock<HashMap<(Address, HandleId), Address>>>,
}

impl InMemoryAuthorizationBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind_controller(&self, contract: Address, handle_id: HandleId, controller: Address) {
        self.controllers
            .write()
            .unwrap()
            .insert((contract, handle_id), controller);
    }
}

#[async_trait]
impl AuthorizationBackend for InMemoryAuthorizationBackend {
    async fn resolve_controller(
        &self,
        contract: Address,
        handle_id: HandleId,
    ) -> Result<Address, CoordinatorError> {
        self.controllers
            .read()
            .map_err(|_| {
                CoordinatorError::Unavailable("controller registry lock poisoned".to_string())
            })?
            .get(&(contract, handle_id))
            .copied()
            .ok_or_else(|| CoordinatorError::NotFound("handle controller not found".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DISCLOSURE_CONTROLLER_SIGNATURE, decode_address_word,
        encode_disclosure_controller_call,
    };
    use crate::types::{Address, HandleId};
    use sha3::{Digest, Keccak256};

    #[test]
    fn disclosure_controller_call_matches_expected_abi_encoding() {
        let handle_id = HandleId([0x11; 32]);
        let calldata = encode_disclosure_controller_call(handle_id);
        let selector = &Keccak256::digest(DISCLOSURE_CONTROLLER_SIGNATURE.as_bytes())[..4];
        assert_eq!(calldata, format!("0x{}{}", hex::encode(selector), hex::encode(handle_id.0)));
    }

    #[test]
    fn decodes_eth_call_address_word() {
        let decoded = decode_address_word(
            "0x0000000000000000000000001234567890abcdef1234567890abcdef12345678",
        )
        .unwrap();
        assert_eq!(
            decoded,
            Address([
                0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34,
                0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
            ])
        );
    }
}
