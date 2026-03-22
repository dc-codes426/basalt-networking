use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;

use basalt_networking_api_server::apis;
use basalt_networking_api_server::apis::health::PingResponse;

use crate::ApiImpl;

#[async_trait::async_trait]
impl apis::health::Health for ApiImpl {
    async fn ping(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
    ) -> Result<PingResponse, ()> {
        Ok(PingResponse::Status200_ServerIsHealthy("pong".to_string()))
    }
}
