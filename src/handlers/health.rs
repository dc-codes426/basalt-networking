use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;

use basalt_networking_api_server::apis;
use basalt_networking_api_server::apis::health::PingResponse;

use basalt_admin_internal_client::apis::default_api as admin_api;

use crate::ApiImpl;

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
                Ok(PingResponse::Status200_ServerIsHealthy(
                    "unhealthy".to_string(),
                ))
            }
        }
    }
}
