use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;

use basalt_networking_api_server::apis;
use basalt_networking_api_server::apis::health::{HealthResponse, PingResponse};
use basalt_networking_api_server::models;

use basalt_admin_internal_client::apis::default_api;

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

    async fn health(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
    ) -> Result<HealthResponse, ()> {
        match default_api::health(&self.admin_client).await {
            Ok(resp) => {
                let containers: Vec<models::ContainerStatus> = resp
                    .containers
                    .iter()
                    .map(|c| models::ContainerStatus {
                        name: c.name.clone(),
                        healthy: c.healthy,
                        detail: c.detail.clone(),
                    })
                    .collect();

                let all_healthy = containers.iter().all(|c| c.healthy);
                let health_resp = models::HealthResponse::new(containers);

                if all_healthy {
                    Ok(HealthResponse::Status200_AllDependenciesAreHealthy(health_resp))
                } else {
                    Ok(HealthResponse::Status503_OneOrMoreDependenciesAreUnhealthy(health_resp))
                }
            }
            Err(err) => {
                tracing::error!("admin-internal health check failed: {err:?}");
                let health_resp = models::HealthResponse::new(vec![models::ContainerStatus {
                    name: "admin-internal".to_string(),
                    healthy: false,
                    detail: format!("unreachable: {err:?}"),
                }]);
                Ok(HealthResponse::Status503_OneOrMoreDependenciesAreUnhealthy(health_resp))
            }
        }
    }
}
