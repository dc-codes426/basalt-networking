use axum::{
    body::Body,
    extract::State,
    http::{uri::Uri, Request},
    response::Response,
    routing::get,
    Router,
};
use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use std::net::SocketAddr;

use basalt_networking::apis;
use basalt_networking::apis::health::PingResponse;
use basalt_networking::models;

use basalt_admin_internal_client::apis::configuration::Configuration as AdminConfig;
use basalt_admin_internal_client::apis::default_api as admin_api;

use basalt_vultiserver_client::apis::configuration::Configuration as VultiserverConfig;
use basalt_vultiserver_client::apis::{
    batch_api, signing_api, utility_api, vault_api,
};
use basalt_vultiserver_client::models as vs_models;

/// Convert a networking model to a vultiserver client model via JSON roundtrip.
/// Both are generated from the same OpenAPI spec so their serde representations match.
fn convert<T: serde::Serialize, U: serde::de::DeserializeOwned>(from: &T) -> Result<U, String> {
    let json = serde_json::to_value(from).map_err(|e| e.to_string())?;
    serde_json::from_value(json).map_err(|e| e.to_string())
}

/// Map a vultiserver client error into a (status_code, error_json) pair.
fn client_error_to_status<E: std::fmt::Debug>(
    err: basalt_vultiserver_client::apis::Error<E>,
) -> (u16, String) {
    match err {
        basalt_vultiserver_client::apis::Error::ResponseError(resp) => {
            (resp.status.as_u16(), resp.content)
        }
        other => {
            tracing::error!("vultiserver client error: {other:?}");
            (502, "Bad Gateway".to_string())
        }
    }
}

#[derive(Clone)]
struct ApiImpl {
    upstream: String,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    admin_client: AdminConfig,
    vultiserver_client: VultiserverConfig,
}

impl AsRef<ApiImpl> for ApiImpl {
    fn as_ref(&self) -> &ApiImpl {
        self
    }
}

#[async_trait::async_trait]
impl apis::ErrorHandler<()> for ApiImpl {}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl apis::health::Health for ApiImpl {
    async fn ping(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
    ) -> Result<PingResponse, ()> {
        match admin_api::health(&self.admin_client).await {
            Ok(health_resp) => {
                let body = serde_json::to_string(&health_resp).unwrap_or_default();
                Ok(PingResponse::Status200_ServerIsHealthy(body))
            }
            Err(err) => {
                tracing::error!("admin-internal health check failed: {err}");
                Ok(PingResponse::Status502_OneOrMoreBackingServicesAreUnreachable(
                    "Bad Gateway".to_string(),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl apis::utility::Utility for ApiImpl {
    async fn get_derived_public_key(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        query_params: &models::GetDerivedPublicKeyQueryParams,
    ) -> Result<apis::utility::GetDerivedPublicKeyResponse, ()> {
        match utility_api::get_derived_public_key(
            &self.vultiserver_client,
            &query_params.public_key,
            &query_params.hex_chain_code,
            &query_params.derive_path,
            query_params.is_ed_dsa,
        )
        .await
        {
            Ok(key) => Ok(
                apis::utility::GetDerivedPublicKeyResponse::Status200_DerivedPublicKey(key),
            ),
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                if status == 400 {
                    let error: models::Error =
                        serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                    Ok(apis::utility::GetDerivedPublicKeyResponse::Status400_ValidationErrorOrMalformedRequest(error))
                } else {
                    tracing::error!("get_derived_public_key upstream error: {status} {content}");
                    Err(())
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl apis::vault::Vault for ApiImpl {
    async fn create_mldsa_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::CreateMldsaRequest,
    ) -> Result<apis::vault::CreateMldsaVaultResponse, ()> {
        let req: vs_models::CreateMldsaRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::create_mldsa_vault(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::vault::CreateMldsaVaultResponse::Status200_ML),
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::vault::CreateMldsaVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::CreateMldsaVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }

    async fn create_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::VaultCreateRequest,
    ) -> Result<apis::vault::CreateVaultResponse, ()> {
        let req: vs_models::VaultCreateRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::create_vault(&self.vultiserver_client, req).await {
            Ok(resp) => {
                let resp: models::VaultCreateResponse = convert(&resp).map_err(|e| {
                    tracing::error!("response conversion error: {e}");
                })?;
                Ok(apis::vault::CreateVaultResponse::Status200_VaultCreationInitiated(resp))
            }
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::vault::CreateVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::CreateVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }

    async fn exist_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        path_params: &models::ExistVaultPathParams,
    ) -> Result<apis::vault::ExistVaultResponse, ()> {
        match vault_api::exist_vault(&self.vultiserver_client, &path_params.public_key_ecdsa).await
        {
            Ok(()) => Ok(apis::vault::ExistVaultResponse::Status200_VaultExists),
            Err(basalt_vultiserver_client::apis::Error::ResponseError(resp))
                if resp.status == reqwest::StatusCode::NOT_FOUND =>
            {
                Ok(apis::vault::ExistVaultResponse::Status404_VaultNotFound)
            }
            Err(err) => {
                tracing::error!("exist_vault upstream error: {err}");
                Err(())
            }
        }
    }

    async fn get_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        header_params: &models::GetVaultHeaderParams,
        path_params: &models::GetVaultPathParams,
    ) -> Result<apis::vault::GetVaultResponse, ()> {
        match vault_api::get_vault(
            &self.vultiserver_client,
            &path_params.public_key_ecdsa,
            &header_params.x_password,
        )
        .await
        {
            Ok(resp) => {
                let resp: models::VaultGetResponse = convert(&resp).map_err(|e| {
                    tracing::error!("response conversion error: {e}");
                })?;
                Ok(apis::vault::GetVaultResponse::Status200_VaultMetadata(resp))
            }
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                if status == 400 {
                    Ok(apis::vault::GetVaultResponse::Status400_ValidationErrorOrMalformedRequest(error))
                } else {
                    Err(())
                }
            }
        }
    }

    async fn import_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::KeyImportRequest,
    ) -> Result<apis::vault::ImportVaultResponse, ()> {
        let req: vs_models::KeyImportRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::import_vault(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::vault::ImportVaultResponse::Status204_ImportTaskEnqueued),
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::vault::ImportVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::ImportVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }

    async fn migrate_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::MigrationRequest,
    ) -> Result<apis::vault::MigrateVaultResponse, ()> {
        let req: vs_models::MigrationRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::migrate_vault(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::vault::MigrateVaultResponse::Status204_MigrationTaskEnqueued),
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::vault::MigrateVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::MigrateVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }

    async fn reshare_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::ReshareRequest,
    ) -> Result<apis::vault::ReshareVaultResponse, ()> {
        let req: vs_models::ReshareRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match vault_api::reshare_vault(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::vault::ReshareVaultResponse::Status204_ReshareTaskEnqueued),
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::vault::ReshareVaultResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::vault::ReshareVaultResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl apis::signing::Signing for ApiImpl {
    async fn sign_messages(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::KeysignRequest,
    ) -> Result<apis::signing::SignMessagesResponse, ()> {
        let req: vs_models::KeysignRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match signing_api::sign_messages(&self.vultiserver_client, req).await {
            Ok(task_id) => Ok(
                apis::signing::SignMessagesResponse::Status200_SigningTaskEnqueued(task_id),
            ),
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::signing::SignMessagesResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::signing::SignMessagesResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Batch
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl apis::batch::Batch for ApiImpl {
    async fn create_vault_batch(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::BatchVaultRequest,
    ) -> Result<apis::batch::CreateVaultBatchResponse, ()> {
        let req: vs_models::BatchVaultRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match batch_api::create_vault_batch(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::batch::CreateVaultBatchResponse::Status204_BatchKeygenTaskEnqueued),
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::batch::CreateVaultBatchResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::batch::CreateVaultBatchResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }

    async fn import_vault_batch(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::BatchImportRequest,
    ) -> Result<apis::batch::ImportVaultBatchResponse, ()> {
        let req: vs_models::BatchImportRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match batch_api::import_vault_batch(&self.vultiserver_client, req).await {
            Ok(()) => Ok(apis::batch::ImportVaultBatchResponse::Status204_BatchImportTaskEnqueued),
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::batch::ImportVaultBatchResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::batch::ImportVaultBatchResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }

    async fn reshare_vault_batch(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::BatchReshareRequest,
    ) -> Result<apis::batch::ReshareVaultBatchResponse, ()> {
        let req: vs_models::BatchReshareRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match batch_api::reshare_vault_batch(&self.vultiserver_client, req).await {
            Ok(()) => {
                Ok(apis::batch::ReshareVaultBatchResponse::Status204_BatchReshareTaskEnqueued)
            }
            Err(err) => {
                let (status, content) = client_error_to_status(err);
                let error: models::Error =
                    serde_json::from_str(&content).unwrap_or(models::Error { message: Some(content) });
                match status {
                    400 => Ok(apis::batch::ReshareVaultBatchResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::batch::ReshareVaultBatchResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy fallback
// ---------------------------------------------------------------------------

async fn proxy_handler(
    State(state): State<ApiImpl>,
    mut req: Request<Body>,
) -> Response<Body> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let uri = format!("{}{}", state.upstream, path_and_query);
    *req.uri_mut() = Uri::try_from(uri).unwrap();

    state
        .client
        .request(req)
        .await
        .map(|resp| resp.map(Body::new))
        .unwrap_or_else(|err| {
            tracing::error!("upstream request failed: {err}");
            Response::builder()
                .status(502)
                .body(Body::from("Bad Gateway"))
                .unwrap()
        })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "basalt_networking=info".parse().unwrap()),
        )
        .init();

    let upstream =
        std::env::var("UPSTREAM_URL").unwrap_or_else(|_| "http://vultiserver:8080".to_string());
    let admin_url = std::env::var("ADMIN_INTERNAL_URL")
        .unwrap_or_else(|_| "http://admin-internal:3000".to_string());

    let client = Client::builder(TokioExecutor::new()).build_http();

    let mut admin_config = AdminConfig::new();
    admin_config.base_path = admin_url;

    let mut vultiserver_config = VultiserverConfig::new();
    vultiserver_config.base_path = upstream.clone();

    let api_impl = ApiImpl {
        upstream: upstream.clone(),
        client,
        admin_client: admin_config,
        vultiserver_client: vultiserver_config,
    };

    // External port — spec'd endpoints + fallback proxy
    let app = basalt_networking::server::new(api_impl.clone())
        .fallback(proxy_handler)
        .with_state(api_impl);

    // Internal port — accessible only within the Docker network
    let internal_app = Router::new().route("/health", get(|| async { "ok" }));
    let internal_listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    tracing::info!("basalt-networking internal listening on 0.0.0.0:8080");

    let addr = SocketAddr::from(([0, 0, 0, 0], 80));
    tracing::info!("basalt-networking listening on {addr}");
    tracing::info!("forwarding to {upstream}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tokio::join!(
        async { axum::serve(internal_listener, internal_app).await.unwrap() },
        async { axum::serve(listener, app).await.unwrap() },
    );
}
