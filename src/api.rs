use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::error::CoordinatorError;
use crate::state::AppState;
use crate::types::{PostDisclosureRequest, PutReaderRequest, ReaderId, RequestId};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/config", get(get_config_handler))
        .route("/v1/readers/{reader_id}", put(put_reader_handler))
        .route("/v1/disclosures", post(post_disclosure_handler))
        .route("/v1/disclosures/{request_id}", get(get_disclosure_handler))
        .with_state(state)
}

async fn get_config_handler(
    State(state): State<AppState>,
) -> Result<Json<crate::types::CoordinatorConfigResponse>, CoordinatorError> {
    crate::service::get_config(&state).await.map(Json)
}

async fn put_reader_handler(
    State(state): State<AppState>,
    Path(reader_id): Path<String>,
    CoordinatorJson(request): CoordinatorJson<PutReaderRequest>,
) -> Result<Json<crate::types::PutReaderResponse>, CoordinatorError> {
    let reader_id = parse_json_path::<ReaderId>(&reader_id, "reader_id")?;
    crate::service::put_reader(&state, reader_id, request)
        .await
        .map(Json)
}

async fn post_disclosure_handler(
    State(state): State<AppState>,
    CoordinatorJson(request): CoordinatorJson<PostDisclosureRequest>,
) -> Result<Json<crate::types::PostDisclosureResponse>, CoordinatorError> {
    crate::service::post_disclosure(&state, request)
        .await
        .map(Json)
}

async fn get_disclosure_handler(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<Json<crate::types::GetDisclosureResponse>, CoordinatorError> {
    let request_id = parse_json_path::<RequestId>(&request_id, "request_id")?;
    crate::service::get_disclosure(&state, request_id)
        .await
        .map(Json)
}

struct CoordinatorJson<T>(T);

impl<S, T> FromRequest<S> for CoordinatorJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = CoordinatorError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| CoordinatorError::BadRequest(rejection.body_text()))
    }
}

fn parse_json_path<T>(value: &str, label: &str) -> Result<T, CoordinatorError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(serde_json::Value::String(value.to_string())).map_err(|error| {
        CoordinatorError::BadRequest(format!("invalid {label} path parameter: {error}"))
    })
}
