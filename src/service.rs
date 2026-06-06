use crate::eip712::{reader_id, verify_disclosure_signature, verify_register_reader_signature};
use crate::error::CoordinatorError;
use crate::state::{AppState, DisclosureRecord, DisclosureRecordState, ReaderRegistration};
use crate::types::{
    CoordinatorConfigResponse, DisclosureRequest, DisclosureStatus, GetDisclosureResponse,
    GetHandleResponse, MpcPutReaderRequest, PostDisclosureRequest, PostDisclosureResponse,
    PutReaderRequest, PutReaderResponse, RegisterReader, ResolveHandleRequest,
    ResolveHandleResponse, ToReaderRequest,
};

pub async fn get_config(state: &AppState) -> Result<CoordinatorConfigResponse, CoordinatorError> {
    let mpc = state.mpc().get_config().await?;
    Ok(CoordinatorConfigResponse {
        version: state.config().version,
        chain_id: mpc.chain_id,
        domain_id: mpc.domain_id,
        mpc_key_id: mpc.key_id,
        mpc_hpke_public_key: mpc.hpke_public_key,
        reader_key_algorithm: mpc.reader_key_algorithm,
        ciphertext_suite: mpc.ciphertext_suite,
        eip712_domain: state.eip712_domain(mpc.chain_id),
    })
}

pub async fn put_reader(
    state: &AppState,
    path_reader_id: crate::types::ReaderId,
    request: PutReaderRequest,
) -> Result<PutReaderResponse, CoordinatorError> {
    let now = state.now();
    if request.expiry < now {
        return Err(CoordinatorError::Gone(
            "reader registration request expired".to_string(),
        ));
    }

    let derived_reader_id = reader_id(request.reader_pubkey);
    if path_reader_id != derived_reader_id {
        return Err(CoordinatorError::Conflict(
            "reader_id path does not match reader_pubkey".to_string(),
        ));
    }

    state.ensure_nonce_unused(request.controller, request.nonce)?;
    let domain = state.eip712_domain(state.mpc().get_config().await?.chain_id);
    verify_register_reader_signature(
        &domain,
        &RegisterReader {
            controller: request.controller,
            reader_id: path_reader_id,
            nonce: request.nonce,
            expiry: request.expiry,
        },
        request.signature,
    )?;

    state
        .mpc()
        .put_reader(
            path_reader_id,
            MpcPutReaderRequest {
                reader_pubkey: request.reader_pubkey,
            },
        )
        .await?;

    let registration = ReaderRegistration {
        controller: request.controller,
        registered_at: now,
        expires_at: Some(request.expiry),
    };
    state.register_reader(path_reader_id, registration)?;
    state.mark_nonce_used(request.controller, request.nonce)?;

    Ok(PutReaderResponse {
        reader_id: path_reader_id,
        controller: request.controller,
        registered_at: now,
        expires_at: Some(request.expiry),
    })
}

pub async fn post_disclosure(
    state: &AppState,
    request: PostDisclosureRequest,
) -> Result<PostDisclosureResponse, CoordinatorError> {
    let now = state.now();
    if request.expiry < now {
        return Err(CoordinatorError::Gone(
            "disclosure request expired".to_string(),
        ));
    }

    let controller = state
        .authorization()
        .resolve_controller(request.contract, request.handle_id)
        .await?;
    state.ensure_nonce_unused(controller, request.nonce)?;

    let registration = state.reader_registration(request.reader_id)?;
    if let Some(expires_at) = registration.expires_at
        && expires_at < now
    {
        return Err(CoordinatorError::Unprocessable(
            "reader registration expired".to_string(),
        ));
    }
    if registration.controller != controller {
        return Err(CoordinatorError::Conflict(
            "reader_id is registered to a different controller".to_string(),
        ));
    }

    let mpc_config = state.mpc().get_config().await?;
    let domain = state.eip712_domain(mpc_config.chain_id);
    verify_disclosure_signature(
        &domain,
        controller,
        &DisclosureRequest {
            contract: request.contract,
            handle_id: request.handle_id,
            reader_id: request.reader_id,
            nonce: request.nonce,
            expiry: request.expiry,
        },
        request.signature,
    )?;

    let request_id = state.next_request_id(
        request.contract,
        request.handle_id,
        request.reader_id,
        request.nonce,
    );
    let resolve = state
        .coprocessor()
        .resolve_handle(ResolveHandleRequest {
            request_id,
            chain_id: mpc_config.chain_id,
            contract: request.contract,
            handle_id: request.handle_id,
        })
        .await?;

    let disclosure = match resolve {
        ResolveHandleResponse::Ready {
            system_ciphertext, ..
        } => {
            let ciphertext = state
                .mpc()
                .to_reader(ToReaderRequest {
                    request_id,
                    chain_id: mpc_config.chain_id,
                    handle_id: request.handle_id,
                    reader_id: request.reader_id,
                    system_ciphertext,
                })
                .await?
                .ciphertext;
            let disclosure = DisclosureRecord {
                request_id,
                contract: request.contract,
                handle_id: request.handle_id,
                reader_id: request.reader_id,
                controller,
                expiry: request.expiry,
                state: DisclosureRecordState::Ready {
                    ciphertext: ciphertext.clone(),
                },
            };
            state.upsert_disclosure(disclosure)?;
            state.mark_nonce_used(controller, request.nonce)?;
            return Ok(PostDisclosureResponse::Ready {
                request_id,
                ciphertext,
            });
        }
        ResolveHandleResponse::Pending => DisclosureRecord {
            request_id,
            contract: request.contract,
            handle_id: request.handle_id,
            reader_id: request.reader_id,
            controller,
            expiry: request.expiry,
            state: DisclosureRecordState::Pending,
        },
        ResolveHandleResponse::Failed { reason } => DisclosureRecord {
            request_id,
            contract: request.contract,
            handle_id: request.handle_id,
            reader_id: request.reader_id,
            controller,
            expiry: request.expiry,
            state: DisclosureRecordState::Failed { error: reason },
        },
    };
    state.upsert_disclosure(disclosure)?;
    state.mark_nonce_used(controller, request.nonce)?;

    Ok(PostDisclosureResponse::Pending { request_id })
}

pub async fn get_disclosure(
    state: &AppState,
    request_id: crate::types::RequestId,
) -> Result<GetDisclosureResponse, CoordinatorError> {
    let record = state.disclosure(request_id)?;
    if matches!(record.state, DisclosureRecordState::Pending) && record.expiry < state.now() {
        let expired = DisclosureRecord {
            state: DisclosureRecordState::Expired,
            ..record.clone()
        };
        state.upsert_disclosure(expired)?;
        return Ok(GetDisclosureResponse::Expired { request_id });
    }

    match record.state {
        DisclosureRecordState::Pending => refresh_pending_disclosure(state, record).await,
        DisclosureRecordState::Ready { ciphertext } => Ok(GetDisclosureResponse::Ready {
            request_id,
            ciphertext,
        }),
        DisclosureRecordState::Failed { error } => {
            Ok(GetDisclosureResponse::Failed { request_id, error })
        }
        DisclosureRecordState::Expired => Ok(GetDisclosureResponse::Expired { request_id }),
    }
}

async fn refresh_pending_disclosure(
    state: &AppState,
    record: DisclosureRecord,
) -> Result<GetDisclosureResponse, CoordinatorError> {
    let mpc_config = state.mpc().get_config().await?;
    let status = state
        .coprocessor()
        .get_handle(record.contract, record.handle_id)
        .await?;

    match status {
        GetHandleResponse::Pending { .. } => Ok(GetDisclosureResponse::Pending {
            request_id: record.request_id,
        }),
        GetHandleResponse::Ready {
            system_ciphertext, ..
        } => {
            let ciphertext = state
                .mpc()
                .to_reader(ToReaderRequest {
                    request_id: record.request_id,
                    chain_id: mpc_config.chain_id,
                    handle_id: record.handle_id,
                    reader_id: record.reader_id,
                    system_ciphertext,
                })
                .await?
                .ciphertext;
            state.upsert_disclosure(DisclosureRecord {
                state: DisclosureRecordState::Ready {
                    ciphertext: ciphertext.clone(),
                },
                ..record.clone()
            })?;
            Ok(GetDisclosureResponse::Ready {
                request_id: record.request_id,
                ciphertext,
            })
        }
        GetHandleResponse::Failed { error, .. } => {
            state.upsert_disclosure(DisclosureRecord {
                state: DisclosureRecordState::Failed {
                    error: error.clone(),
                },
                ..record.clone()
            })?;
            Ok(GetDisclosureResponse::Failed {
                request_id: record.request_id,
                error,
            })
        }
    }
}

pub fn disclosure_status(response: &GetDisclosureResponse) -> DisclosureStatus {
    match response {
        GetDisclosureResponse::Pending { .. } => DisclosureStatus::Pending,
        GetDisclosureResponse::Ready { .. } => DisclosureStatus::Ready,
        GetDisclosureResponse::Failed { .. } => DisclosureStatus::Failed,
        GetDisclosureResponse::Expired { .. } => DisclosureStatus::Expired,
    }
}
