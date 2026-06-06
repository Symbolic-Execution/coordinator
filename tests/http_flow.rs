use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode};
use coordinator::api::router;
use coordinator::backends::{AuthorizationBackend, CoprocessorBackend, MpcBackend};
use coordinator::clock::FixedClock;
use coordinator::eip712::test_helpers::{
    address_for_signing_key, sign_disclosure, sign_register_reader, signing_key_for_tests,
    test_domain,
};
use coordinator::error::CoordinatorError;
use coordinator::state::{AppState, CoordinatorRuntimeConfig};
use coordinator::types::*;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

#[derive(Clone)]
struct MockMpc {
    config: MpcConfigResponse,
    readers: Arc<RwLock<HashMap<ReaderId, X25519PublicKey>>>,
}

impl MockMpc {
    fn new() -> Self {
        Self {
            config: MpcConfigResponse {
                version: 1,
                chain_id: 31337,
                domain_id: DomainId([0x11; 32]),
                key_id: KeyId([0x22; 32]),
                hpke_public_key: X25519PublicKey([0x33; 32]),
                reader_key_algorithm: ReaderKeyAlgorithm::X25519,
                ciphertext_suite: CiphertextSuite::HpkeX25519HkdfSha256Aes256Gcm,
            },
            readers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl MpcBackend for MockMpc {
    async fn get_config(&self) -> Result<MpcConfigResponse, CoordinatorError> {
        Ok(self.config.clone())
    }

    async fn put_reader(
        &self,
        reader_id: ReaderId,
        request: MpcPutReaderRequest,
    ) -> Result<MpcPutReaderResponse, CoordinatorError> {
        self.readers
            .write()
            .unwrap()
            .insert(reader_id, request.reader_pubkey);
        Ok(MpcPutReaderResponse { reader_id })
    }

    async fn to_reader(
        &self,
        request: ToReaderRequest,
    ) -> Result<ToReaderResponse, CoordinatorError> {
        if !self
            .readers
            .read()
            .unwrap()
            .contains_key(&request.reader_id)
        {
            return Err(CoordinatorError::NotFound("reader not found".to_string()));
        }
        Ok(ToReaderResponse {
            ciphertext: ReaderCiphertextV1 {
                key_id: request.system_ciphertext.key_id,
                enc: PayloadBytes(vec![1, 2, 3]),
                ciphertext: request.system_ciphertext.ciphertext.clone(),
                aad: request.system_ciphertext.aad.clone(),
            },
        })
    }
}

#[derive(Clone, Default)]
struct MockCoprocessor {
    resolve: Arc<RwLock<HashMap<(Address, HandleId), ResolveHandleResponse>>>,
    get: Arc<RwLock<HashMap<(Address, HandleId), GetHandleResponse>>>,
}

impl MockCoprocessor {
    fn set_ready(&self, contract: Address, handle_id: HandleId, ciphertext: SystemCiphertextV1) {
        self.resolve.write().unwrap().insert(
            (contract, handle_id),
            ResolveHandleResponse::Ready {
                system_ciphertext: ciphertext.clone(),
                receipt: PayloadBytes(vec![9]),
            },
        );
        self.get.write().unwrap().insert(
            (contract, handle_id),
            GetHandleResponse::Ready {
                handle_id,
                system_ciphertext: ciphertext,
                receipt: PayloadBytes(vec![9]),
            },
        );
    }

    fn set_pending(&self, contract: Address, handle_id: HandleId) {
        self.resolve
            .write()
            .unwrap()
            .insert((contract, handle_id), ResolveHandleResponse::Pending);
        self.get.write().unwrap().insert(
            (contract, handle_id),
            GetHandleResponse::Pending { handle_id },
        );
    }

    fn complete_pending(
        &self,
        contract: Address,
        handle_id: HandleId,
        ciphertext: SystemCiphertextV1,
    ) {
        self.get.write().unwrap().insert(
            (contract, handle_id),
            GetHandleResponse::Ready {
                handle_id,
                system_ciphertext: ciphertext,
                receipt: PayloadBytes(vec![7]),
            },
        );
    }
}

#[async_trait]
impl CoprocessorBackend for MockCoprocessor {
    async fn resolve_handle(
        &self,
        request: ResolveHandleRequest,
    ) -> Result<ResolveHandleResponse, CoordinatorError> {
        self.resolve
            .read()
            .unwrap()
            .get(&(request.contract, request.handle_id))
            .cloned()
            .ok_or_else(|| CoordinatorError::NotFound("handle not found".to_string()))
    }

    async fn get_handle(
        &self,
        contract: Address,
        handle_id: HandleId,
    ) -> Result<GetHandleResponse, CoordinatorError> {
        self.get
            .read()
            .unwrap()
            .get(&(contract, handle_id))
            .cloned()
            .ok_or_else(|| CoordinatorError::NotFound("handle not found".to_string()))
    }
}

#[derive(Clone, Default)]
struct MockAuthorization {
    bindings: Arc<RwLock<HashMap<(Address, HandleId), Address>>>,
}

impl MockAuthorization {
    fn bind(&self, contract: Address, handle_id: HandleId, controller: Address) {
        self.bindings
            .write()
            .unwrap()
            .insert((contract, handle_id), controller);
    }
}

#[async_trait]
impl AuthorizationBackend for MockAuthorization {
    async fn resolve_controller(
        &self,
        contract: Address,
        handle_id: HandleId,
    ) -> Result<Address, CoordinatorError> {
        self.bindings
            .read()
            .unwrap()
            .get(&(contract, handle_id))
            .copied()
            .ok_or_else(|| CoordinatorError::NotFound("controller not found".to_string()))
    }
}

fn app_state(
    clock: FixedClock,
    mpc: MockMpc,
    coprocessor: MockCoprocessor,
    authorization: MockAuthorization,
) -> AppState {
    AppState::new(
        CoordinatorRuntimeConfig {
            version: 1,
            eip712_name: "Coordinator".to_string(),
            eip712_version: "1".to_string(),
            eip712_salt: Bytes32([0x99; 32]),
        },
        Arc::new(mpc),
        Arc::new(coprocessor),
        Arc::new(authorization),
        Arc::new(clock),
    )
}

fn system_ciphertext() -> SystemCiphertextV1 {
    SystemCiphertextV1 {
        key_id: KeyId([0x22; 32]),
        enc: PayloadBytes(vec![1]),
        wrapped_key: PayloadBytes(vec![2]),
        nonce: FixedBytes([3; 12]),
        ciphertext: PayloadBytes(vec![4, 5, 6]),
        aad: PayloadBytes(vec![7, 8]),
    }
}

fn json_request<T: serde::Serialize>(
    method: Method,
    uri: impl AsRef<str>,
    body: &T,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri.as_ref())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

async fn read_json<T: DeserializeOwned>(response: Response<Body>) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.unwrap()
}

fn json_path<T: serde::Serialize>(id: T) -> String {
    serde_json::to_value(id)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn get_config_returns_public_configuration() {
    let clock = FixedClock::new(100);
    let app = router(app_state(
        clock,
        MockMpc::new(),
        MockCoprocessor::default(),
        MockAuthorization::default(),
    ));

    let response = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/v1/config")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: CoordinatorConfigResponse = read_json(response).await;
    assert_eq!(body.chain_id, 31337);
    assert_eq!(body.eip712_domain, test_domain(31337));
}

#[tokio::test]
async fn put_reader_registers_reader_key() {
    let clock = FixedClock::new(100);
    let mpc = MockMpc::new();
    let app = router(app_state(
        clock.clone(),
        mpc.clone(),
        MockCoprocessor::default(),
        MockAuthorization::default(),
    ));
    let signing_key = signing_key_for_tests([7; 32]);
    let controller = address_for_signing_key(&signing_key);
    let reader_pubkey = X25519PublicKey([0x44; 32]);
    let reader_id = coordinator::eip712::reader_id(reader_pubkey);
    let message = RegisterReader {
        controller,
        reader_id,
        nonce: Nonce([0x55; 32]),
        expiry: 200,
    };
    let body = PutReaderRequest {
        controller,
        reader_pubkey,
        nonce: message.nonce,
        expiry: message.expiry,
        signature: sign_register_reader(&signing_key, &test_domain(31337), &message),
    };

    let response = send(
        &app,
        json_request(
            Method::PUT,
            format!("/v1/readers/{}", json_path(reader_id)),
            &body,
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: PutReaderResponse = read_json(response).await;
    assert_eq!(body.reader_id, reader_id);
    assert_eq!(body.controller, controller);
    assert_eq!(
        *mpc.readers.read().unwrap().get(&reader_id).unwrap(),
        reader_pubkey
    );
}

#[tokio::test]
async fn post_disclosure_returns_ready_when_handle_is_materialized() {
    let clock = FixedClock::new(100);
    let mpc = MockMpc::new();
    let coprocessor = MockCoprocessor::default();
    let authorization = MockAuthorization::default();
    let state = app_state(
        clock.clone(),
        mpc.clone(),
        coprocessor.clone(),
        authorization.clone(),
    );
    let app = router(state.clone());

    let signing_key = signing_key_for_tests([7; 32]);
    let controller = address_for_signing_key(&signing_key);
    let reader_pubkey = X25519PublicKey([0x44; 32]);
    let reader_id = coordinator::eip712::reader_id(reader_pubkey);
    let register = RegisterReader {
        controller,
        reader_id,
        nonce: Nonce([1; 32]),
        expiry: 200,
    };
    let _ = coordinator::service::put_reader(
        &state,
        reader_id,
        PutReaderRequest {
            controller,
            reader_pubkey,
            nonce: register.nonce,
            expiry: register.expiry,
            signature: sign_register_reader(&signing_key, &test_domain(31337), &register),
        },
    )
    .await
    .unwrap();

    let contract = Address([0x66; 20]);
    let handle_id = HandleId([0x77; 32]);
    authorization.bind(contract, handle_id, controller);
    coprocessor.set_ready(contract, handle_id, system_ciphertext());

    let disclosure = DisclosureRequest {
        contract,
        handle_id,
        reader_id,
        nonce: Nonce([2; 32]),
        expiry: 300,
    };
    let response = send(
        &app,
        json_request(
            Method::POST,
            "/v1/disclosures",
            &PostDisclosureRequest {
                contract,
                handle_id,
                reader_id,
                nonce: disclosure.nonce,
                expiry: disclosure.expiry,
                signature: sign_disclosure(&signing_key, &test_domain(31337), &disclosure),
            },
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: PostDisclosureResponse = read_json(response).await;
    match body {
        PostDisclosureResponse::Ready {
            request_id: _,
            ciphertext,
        } => {
            assert_eq!(ciphertext.ciphertext, PayloadBytes(vec![4, 5, 6]));
        }
        other => panic!("expected ready response, got {other:?}"),
    }
}

#[tokio::test]
async fn pending_disclosure_becomes_ready_on_poll() {
    let clock = FixedClock::new(100);
    let mpc = MockMpc::new();
    let coprocessor = MockCoprocessor::default();
    let authorization = MockAuthorization::default();
    let state = app_state(
        clock.clone(),
        mpc.clone(),
        coprocessor.clone(),
        authorization.clone(),
    );
    let app = router(state.clone());

    let signing_key = signing_key_for_tests([7; 32]);
    let controller = address_for_signing_key(&signing_key);
    let reader_pubkey = X25519PublicKey([0x44; 32]);
    let reader_id = coordinator::eip712::reader_id(reader_pubkey);
    let register = RegisterReader {
        controller,
        reader_id,
        nonce: Nonce([1; 32]),
        expiry: 200,
    };
    coordinator::service::put_reader(
        &state,
        reader_id,
        PutReaderRequest {
            controller,
            reader_pubkey,
            nonce: register.nonce,
            expiry: register.expiry,
            signature: sign_register_reader(&signing_key, &test_domain(31337), &register),
        },
    )
    .await
    .unwrap();

    let contract = Address([0x66; 20]);
    let handle_id = HandleId([0x77; 32]);
    authorization.bind(contract, handle_id, controller);
    coprocessor.set_pending(contract, handle_id);

    let disclosure = DisclosureRequest {
        contract,
        handle_id,
        reader_id,
        nonce: Nonce([2; 32]),
        expiry: 300,
    };
    let response = send(
        &app,
        json_request(
            Method::POST,
            "/v1/disclosures",
            &PostDisclosureRequest {
                contract,
                handle_id,
                reader_id,
                nonce: disclosure.nonce,
                expiry: disclosure.expiry,
                signature: sign_disclosure(&signing_key, &test_domain(31337), &disclosure),
            },
        ),
    )
    .await;

    let body: PostDisclosureResponse = read_json(response).await;
    let request_id = match body {
        PostDisclosureResponse::Pending { request_id } => request_id,
        other => panic!("expected pending response, got {other:?}"),
    };

    coprocessor.complete_pending(contract, handle_id, system_ciphertext());

    let response = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/disclosures/{}", json_path(request_id)))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: GetDisclosureResponse = read_json(response).await;
    match body {
        GetDisclosureResponse::Ready {
            request_id: got, ..
        } => assert_eq!(got, request_id),
        other => panic!("expected ready response, got {other:?}"),
    }
}

#[tokio::test]
async fn reused_nonce_returns_conflict() {
    let clock = FixedClock::new(100);
    let state = app_state(
        clock.clone(),
        MockMpc::new(),
        MockCoprocessor::default(),
        MockAuthorization::default(),
    );
    let app = router(state.clone());
    let signing_key = signing_key_for_tests([7; 32]);
    let controller = address_for_signing_key(&signing_key);
    let reader_pubkey = X25519PublicKey([0x44; 32]);
    let reader_id = coordinator::eip712::reader_id(reader_pubkey);
    let message = RegisterReader {
        controller,
        reader_id,
        nonce: Nonce([0x55; 32]),
        expiry: 200,
    };
    let body = PutReaderRequest {
        controller,
        reader_pubkey,
        nonce: message.nonce,
        expiry: message.expiry,
        signature: sign_register_reader(&signing_key, &test_domain(31337), &message),
    };

    let first = send(
        &app,
        json_request(
            Method::PUT,
            format!("/v1/readers/{}", json_path(reader_id)),
            &body,
        ),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = send(
        &app,
        json_request(
            Method::PUT,
            format!("/v1/readers/{}", json_path(reader_id)),
            &body,
        ),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
}
