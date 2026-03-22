use axum::{body::Body, extract::DefaultBodyLimit, response::Response, routing::get, Router};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

use basalt_networking_api_server::apis;

use basalt_admin_internal_client::apis::configuration::Configuration as AdminConfig;
use basalt_vultiserver_client::apis::configuration::Configuration as VultiserverConfig;

mod error;
mod handlers;

#[derive(Clone)]
pub struct ApiImpl {
    pub admin_client: AdminConfig,
    pub vultiserver_client: VultiserverConfig,
}

impl AsRef<ApiImpl> for ApiImpl {
    fn as_ref(&self) -> &ApiImpl {
        self
    }
}

#[async_trait::async_trait]
impl apis::ErrorHandler<()> for ApiImpl {}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "basalt_networking=info,tower_http=info".parse().unwrap()),
        )
        .init();

    let upstream =
        std::env::var("UPSTREAM_URL").unwrap_or_else(|_| "http://vultiserver:8080".to_string());
    let admin_url = std::env::var("ADMIN_INTERNAL_URL")
        .unwrap_or_else(|_| "http://admin-internal:3000".to_string());

    let http_client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    let mut admin_config = AdminConfig::new();
    admin_config.base_path = admin_url;
    admin_config.client = http_client.clone();

    let mut vultiserver_config = VultiserverConfig::new();
    vultiserver_config.base_path = upstream.clone();
    vultiserver_config.client = http_client;

    let api_impl = ApiImpl {
        admin_client: admin_config,
        vultiserver_client: vultiserver_config,
    };

    // Rate limit: 5 requests/second per IP, burst up to 30
    let governor_config = GovernorConfigBuilder::default()
        .per_second(5)
        .burst_size(30)
        .finish()
        .expect("failed to build rate limiter config");

    let app = basalt_networking_api_server::server::new(api_impl)
        .fallback(|| async {
            Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"endpoint not found"}"#))
                .unwrap()
        })
        .layer(
            ServiceBuilder::new()
                .layer(tower_http::trace::TraceLayer::new_for_http())
                .layer(DefaultBodyLimit::max(256 * 1024)) // 256 KB
                .layer(GovernorLayer {
                    config: governor_config.into(),
                }),
        );

    let internal_app = Router::new().route("/health", get(|| async { "ok" }));
    let internal_listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("failed to bind internal listener on 0.0.0.0:8080");
    tracing::info!("basalt-networking internal listening on 0.0.0.0:8080");

    let addr = SocketAddr::from(([0, 0, 0, 0], 80));
    tracing::info!("basalt-networking listening on {addr}");
    tracing::info!("upstream at {upstream}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind listener on 0.0.0.0:80");

    tokio::join!(
        async { axum::serve(internal_listener, internal_app).await.expect("internal server failed") },
        async { axum::serve(listener, app).await.expect("external server failed") },
    );
}
