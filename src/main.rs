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

#[derive(Clone)]
struct ApiImpl {
    upstream: String,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
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
        let uri = "http://admin-internal:3000/ping";
        let req = Request::builder()
            .uri(Uri::try_from(uri).unwrap())
            .body(Body::empty())
            .unwrap();

        match self.client.request(req).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let bytes = axum::body::to_bytes(Body::new(resp.into_body()), 1024)
                    .await
                    .unwrap_or_default();
                let body = String::from_utf8_lossy(&bytes).into_owned();

                if (200..300).contains(&status) {
                    Ok(PingResponse::Status200_ServerIsHealthy(body))
                } else {
                    Ok(PingResponse::Status502_OneOrMoreBackingServicesAreUnreachable(body))
                }
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
        _query_params: &models::GetDerivedPublicKeyQueryParams,
    ) -> Result<apis::utility::GetDerivedPublicKeyResponse, ()> {
        todo!("get_derived_public_key not yet implemented")
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
        _body: &models::CreateMldsaRequest,
    ) -> Result<apis::vault::CreateMldsaVaultResponse, ()> {
        todo!("create_mldsa_vault not yet implemented")
    }

    async fn create_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _body: &models::VaultCreateRequest,
    ) -> Result<apis::vault::CreateVaultResponse, ()> {
        todo!("create_vault not yet implemented")
    }

    async fn exist_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _path_params: &models::ExistVaultPathParams,
    ) -> Result<apis::vault::ExistVaultResponse, ()> {
        todo!("exist_vault not yet implemented")
    }

    async fn get_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _header_params: &models::GetVaultHeaderParams,
        _path_params: &models::GetVaultPathParams,
    ) -> Result<apis::vault::GetVaultResponse, ()> {
        todo!("get_vault not yet implemented")
    }

    async fn import_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _body: &models::KeyImportRequest,
    ) -> Result<apis::vault::ImportVaultResponse, ()> {
        todo!("import_vault not yet implemented")
    }

    async fn migrate_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _body: &models::MigrationRequest,
    ) -> Result<apis::vault::MigrateVaultResponse, ()> {
        todo!("migrate_vault not yet implemented")
    }

    async fn reshare_vault(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _body: &models::ReshareRequest,
    ) -> Result<apis::vault::ReshareVaultResponse, ()> {
        todo!("reshare_vault not yet implemented")
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
        _body: &models::KeysignRequest,
    ) -> Result<apis::signing::SignMessagesResponse, ()> {
        todo!("sign_messages not yet implemented")
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
        _body: &models::BatchVaultRequest,
    ) -> Result<apis::batch::CreateVaultBatchResponse, ()> {
        todo!("create_vault_batch not yet implemented")
    }

    async fn import_vault_batch(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _body: &models::BatchImportRequest,
    ) -> Result<apis::batch::ImportVaultBatchResponse, ()> {
        todo!("import_vault_batch not yet implemented")
    }

    async fn reshare_vault_batch(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _body: &models::BatchReshareRequest,
    ) -> Result<apis::batch::ReshareVaultBatchResponse, ()> {
        todo!("reshare_vault_batch not yet implemented")
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

    let client = Client::builder(TokioExecutor::new()).build_http();

    let api_impl = ApiImpl {
        upstream: upstream.clone(),
        client,
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
