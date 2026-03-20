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
pub enum GetDerivedPublicKeyResponse {
    /// Derived public key
    Status200_DerivedPublicKey
    (String)
    ,
    /// Validation error or malformed request
    Status400_ValidationErrorOrMalformedRequest
    (models::Error)
}




/// Utility
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait Utility<E: std::fmt::Debug + Send + Sync + 'static = ()>: super::ErrorHandler<E> {
    /// Derive a public key.
    ///
    /// GetDerivedPublicKey - GET /getDerivedPublicKey
    async fn get_derived_public_key(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
      query_params: &models::GetDerivedPublicKeyQueryParams,
    ) -> Result<GetDerivedPublicKeyResponse, E>;
}
