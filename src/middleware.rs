use axum::{middleware::Next, response::Response};
use http::StatusCode;

pub async fn remap_422(req: http::Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
        *response.status_mut() = StatusCode::BAD_REQUEST;
    }
    response
}
