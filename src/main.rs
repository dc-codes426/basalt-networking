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
use basalt_networking::apis::default::PingResponse;

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

#[async_trait::async_trait]
impl apis::default::Default for ApiImpl {
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
        upstream,
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
    tracing::info!(
        "forwarding to {}",
        std::env::var("UPSTREAM_URL").unwrap_or_else(|_| "http://vultiserver:8080".to_string())
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tokio::join!(
        async { axum::serve(internal_listener, internal_app).await.unwrap() },
        async { axum::serve(listener, app).await.unwrap() },
    );
}
