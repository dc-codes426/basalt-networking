use basalt_networking_api_server::models;

/// Convert a networking model to a vultiserver client model via JSON roundtrip.
/// Both are generated from the same OpenAPI spec so their serde representations match.
pub fn convert<T: serde::Serialize, U: serde::de::DeserializeOwned>(from: &T) -> Result<U, String> {
    let bytes = serde_json::to_vec(from).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

/// Map a vultiserver client error into a (status_code, error_json) pair.
pub fn client_error_to_status<E: std::fmt::Debug>(
    err: basalt_vultiserver_client::apis::Error<E>,
) -> (u16, String) {
    match err {
        basalt_vultiserver_client::apis::Error::ResponseError(resp) => {
            (resp.status.as_u16(), resp.content)
        }
        other => {
            tracing::error!("vultiserver client error: {other:?}");
            (502, "Bad Gateway".to_string())
        }
    }
}

/// Parse an error response body into a models::Error, falling back to the raw content.
pub fn parse_error(content: String) -> models::Error {
    serde_json::from_str(&content).unwrap_or(models::Error {
        message: Some(content),
    })
}

/// Handle a vultiserver client error by mapping to (status, parsed_error).
/// Use this to reduce boilerplate in handlers.
pub fn map_upstream_error<E: std::fmt::Debug>(
    err: basalt_vultiserver_client::apis::Error<E>,
) -> (u16, models::Error) {
    let (status, content) = client_error_to_status(err);
    (status, parse_error(content))
}
