use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;

use basalt_networking_api_server::apis;
use basalt_networking_api_server::models;

use basalt_vultiserver_client::apis::utility_api;

use crate::error::map_upstream_error;
use crate::ApiImpl;

#[async_trait::async_trait]
impl apis::utility::Utility for ApiImpl {
    async fn get_derived_public_key(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        query_params: &models::GetDerivedPublicKeyQueryParams,
    ) -> Result<apis::utility::GetDerivedPublicKeyResponse, ()> {
        match utility_api::get_derived_public_key(
            &self.vultiserver_client,
            &query_params.public_key,
            &query_params.hex_chain_code,
            &query_params.derive_path,
            query_params.is_ed_dsa,
        )
        .await
        {
            Ok(key) => Ok(
                apis::utility::GetDerivedPublicKeyResponse::Status200_DerivedPublicKey(key),
            ),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::utility::GetDerivedPublicKeyResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    _ => {
                        tracing::error!("get_derived_public_key upstream error: {status}");
                        Err(())
                    }
                }
            }
        }
    }
}
