use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;

use basalt_networking_api_server::apis;
use basalt_networking_api_server::models;

use basalt_vultiserver_client::apis::signing_api;
use basalt_vultiserver_client::models as vs_models;

use crate::error::{convert, map_upstream_error};
use crate::ApiImpl;

#[async_trait::async_trait]
impl apis::signing::Signing for ApiImpl {
    async fn sign_messages(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        body: &models::KeysignRequest,
    ) -> Result<apis::signing::SignMessagesResponse, ()> {
        let req: vs_models::KeysignRequest = convert(body).map_err(|e| {
            tracing::error!("model conversion error: {e}");
        })?;
        match signing_api::sign_messages(&self.vultiserver_client, req).await {
            Ok(task_id) => Ok(
                apis::signing::SignMessagesResponse::Status200_SigningTaskEnqueued(task_id),
            ),
            Err(err) => {
                let (status, error) = map_upstream_error(err);
                match status {
                    400 => Ok(apis::signing::SignMessagesResponse::Status400_ValidationErrorOrMalformedRequest(error)),
                    429 => Ok(apis::signing::SignMessagesResponse::Status429_RateLimitExceeded(error)),
                    _ => Err(()),
                }
            }
        }
    }
}
