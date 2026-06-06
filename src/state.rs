use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use sha3::{Digest, Keccak256};

use crate::backends::{AuthorizationBackend, CoprocessorBackend, MpcBackend};
use crate::clock::Clock;
use crate::error::CoordinatorError;
use crate::types::{
    Address, Bytes32, Eip712Domain, HandleId, Nonce, ReaderCiphertextV1, ReaderId, RequestId,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub config: CoordinatorRuntimeConfig,
    pub mpc: Arc<dyn MpcBackend>,
    pub coprocessor: Arc<dyn CoprocessorBackend>,
    pub authorization: Arc<dyn AuthorizationBackend>,
    pub clock: Arc<dyn Clock>,
    pub readers: RwLock<HashMap<ReaderId, ReaderRegistration>>,
    pub used_nonces: RwLock<HashSet<(Address, Nonce)>>,
    pub disclosures: RwLock<HashMap<RequestId, DisclosureRecord>>,
    pub request_sequence: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct CoordinatorRuntimeConfig {
    pub version: u16,
    pub eip712_name: String,
    pub eip712_version: String,
    pub eip712_salt: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderRegistration {
    pub controller: Address,
    pub registered_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisclosureRecord {
    pub request_id: RequestId,
    pub contract: Address,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub controller: Address,
    pub expiry: u64,
    pub state: DisclosureRecordState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisclosureRecordState {
    Pending,
    Ready { ciphertext: ReaderCiphertextV1 },
    Failed { error: String },
    Expired,
}

impl AppState {
    pub fn new(
        config: CoordinatorRuntimeConfig,
        mpc: Arc<dyn MpcBackend>,
        coprocessor: Arc<dyn CoprocessorBackend>,
        authorization: Arc<dyn AuthorizationBackend>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                config,
                mpc,
                coprocessor,
                authorization,
                clock,
                readers: RwLock::new(HashMap::new()),
                used_nonces: RwLock::new(HashSet::new()),
                disclosures: RwLock::new(HashMap::new()),
                request_sequence: AtomicU64::new(1),
            }),
        }
    }

    pub fn config(&self) -> &CoordinatorRuntimeConfig {
        &self.inner.config
    }

    pub fn mpc(&self) -> &Arc<dyn MpcBackend> {
        &self.inner.mpc
    }

    pub fn coprocessor(&self) -> &Arc<dyn CoprocessorBackend> {
        &self.inner.coprocessor
    }

    pub fn authorization(&self) -> &Arc<dyn AuthorizationBackend> {
        &self.inner.authorization
    }

    pub fn now(&self) -> u64 {
        self.inner.clock.now()
    }

    pub fn eip712_domain(&self, chain_id: u64) -> Eip712Domain {
        Eip712Domain {
            name: self.inner.config.eip712_name.clone(),
            version: self.inner.config.eip712_version.clone(),
            chain_id,
            salt: self.inner.config.eip712_salt,
        }
    }

    pub fn ensure_nonce_unused(
        &self,
        controller: Address,
        nonce: Nonce,
    ) -> Result<(), CoordinatorError> {
        let used = self.inner.used_nonces.read().map_err(|_| {
            CoordinatorError::Unavailable("nonce registry lock poisoned".to_string())
        })?;
        if used.contains(&(controller, nonce)) {
            return Err(CoordinatorError::Conflict(
                "nonce already used for controller".to_string(),
            ));
        }
        Ok(())
    }

    pub fn mark_nonce_used(
        &self,
        controller: Address,
        nonce: Nonce,
    ) -> Result<(), CoordinatorError> {
        self.inner
            .used_nonces
            .write()
            .map_err(|_| CoordinatorError::Unavailable("nonce registry lock poisoned".to_string()))?
            .insert((controller, nonce));
        Ok(())
    }

    pub fn register_reader(
        &self,
        reader_id: ReaderId,
        registration: ReaderRegistration,
    ) -> Result<(), CoordinatorError> {
        self.inner
            .readers
            .write()
            .map_err(|_| {
                CoordinatorError::Unavailable("reader registry lock poisoned".to_string())
            })?
            .insert(reader_id, registration);
        Ok(())
    }

    pub fn reader_registration(
        &self,
        reader_id: ReaderId,
    ) -> Result<ReaderRegistration, CoordinatorError> {
        self.inner
            .readers
            .read()
            .map_err(|_| {
                CoordinatorError::Unavailable("reader registry lock poisoned".to_string())
            })?
            .get(&reader_id)
            .cloned()
            .ok_or_else(|| CoordinatorError::Unprocessable("reader_id not registered".to_string()))
    }

    pub fn next_request_id(
        &self,
        contract: Address,
        handle_id: HandleId,
        reader_id: ReaderId,
        nonce: Nonce,
    ) -> RequestId {
        let sequence = self.inner.request_sequence.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Keccak256::new();
        hasher.update(b"coordinator-request-id-v1");
        hasher.update(sequence.to_be_bytes());
        hasher.update(contract.0);
        hasher.update(handle_id.0);
        hasher.update(reader_id.0);
        hasher.update(nonce.0);
        let digest = hasher.finalize();
        let mut id = [0_u8; 32];
        id.copy_from_slice(&digest);
        RequestId(id)
    }

    pub fn upsert_disclosure(&self, disclosure: DisclosureRecord) -> Result<(), CoordinatorError> {
        self.inner
            .disclosures
            .write()
            .map_err(|_| {
                CoordinatorError::Unavailable("disclosure registry lock poisoned".to_string())
            })?
            .insert(disclosure.request_id, disclosure);
        Ok(())
    }

    pub fn disclosure(&self, request_id: RequestId) -> Result<DisclosureRecord, CoordinatorError> {
        self.inner
            .disclosures
            .read()
            .map_err(|_| {
                CoordinatorError::Unavailable("disclosure registry lock poisoned".to_string())
            })?
            .get(&request_id)
            .cloned()
            .ok_or_else(|| CoordinatorError::NotFound("disclosure request not found".to_string()))
    }
}
