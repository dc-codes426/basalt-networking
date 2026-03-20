use axum::{
    body::Body,
    extract::State,
    http::{uri::Uri, Request},
    response::Response,
    routing::get,
    Router,
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use std::net::SocketAddr;

#[derive(Clone)]
struct AppState {
    upstream: String,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
}

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

    let state = AppState { upstream, client };

    let app = Router::new()
        .route("/health", get(health_handler))
        .fallback(proxy_handler)
        .with_state(state);

    // Internal port — accessible only within the Docker network
    let internal_app = Router::new().route("/health", get(|| async { "ok" }));
    let internal_listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    tracing::info!("basalt-networking internal listening on 0.0.0.0:8080");

    // External port — exposed to the host
    let addr = SocketAddr::from(([0, 0, 0, 0], 80));
    tracing::info!("basalt-networking listening on {addr}");
    tracing::info!("forwarding to {}", std::env::var("UPSTREAM_URL").unwrap_or_else(|_| "http://vultiserver:8080".to_string()));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tokio::join!(
        async { axum::serve(internal_listener, internal_app).await.unwrap() },
        async { axum::serve(listener, app).await.unwrap() },
    );
}

async fn health_handler(State(state): State<AppState>) -> Response<Body> {
    let uri = "http://admin-internal:3000/ping";
    let req = Request::builder()
        .uri(Uri::try_from(uri).unwrap())
        .body(Body::empty())
        .unwrap();

    state
        .client
        .request(req)
        .await
        .map(|resp| resp.map(Body::new))
        .unwrap_or_else(|err| {
            tracing::error!("admin-internal health check failed: {err}");
            Response::builder()
                .status(502)
                .body(Body::from("Bad Gateway"))
                .unwrap()
        })
}

async fn proxy_handler(
    State(state): State<AppState>,
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
