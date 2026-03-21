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
pub enum SignMessagesResponse {
    /// Signing task enqueued; returns the async task ID
    Status200_SigningTaskEnqueued
    (String)
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
    ,
    /// Rate limit exceeded (5 req/s, 30 burst, 5-min window)
    Status429_RateLimitExceeded
    (models::Error)
}




/// Signing
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Signing<E: std::fmt::Debug + Send + Sync + 'static = ()>: super::ErrorHandler<E> {
    /// Sign messages with vault key.
    ///
    /// SignMessages - POST /vault/sign
    async fn sign_messages(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
            body: &models::KeysignRequest,
    ) -> Result<SignMessagesResponse, E>;
}
