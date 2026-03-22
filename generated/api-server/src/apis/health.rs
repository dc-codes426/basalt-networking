use async_trait::async_trait;
use axum::extract::*;
use axum_extra::extract::CookieJar;
use bytes::Bytes;
use headers::Host;
use http::Method;
use serde::{Deserialize, Serialize};

use crate::{models, types::*};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum HealthResponse {
    /// All dependencies are healthy
    Status200_AllDependenciesAreHealthy
    (models::HealthResponse)
    ,
    /// One or more dependencies are unhealthy
    Status503_OneOrMoreDependenciesAreUnhealthy
    (models::HealthResponse)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum PingResponse {
    /// Server is healthy
    Status200_ServerIsHealthy
    (String)
    ,
    /// One or more dependencies are unhealthy
    Status503_OneOrMoreDependenciesAreUnhealthy
    (String)
}




/// Health
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Health<E: std::fmt::Debug + Send + Sync + 'static = ()>: super::ErrorHandler<E> {
    /// Dependency health check.
    ///
    /// Health - GET /health
    async fn health(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
    ) -> Result<HealthResponse, E>;

    /// Health check.
    ///
    /// Ping - GET /ping
    async fn ping(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
    ) -> Result<PingResponse, E>;
}
