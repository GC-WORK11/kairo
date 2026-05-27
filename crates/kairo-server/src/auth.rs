use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};

/// API key validation middleware.
/// When auth is disabled (V1 default), always passes through.
/// When enabled, requires a valid API key in Authorization header or X-Kairo-Key header.
pub async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let api_key = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            req.headers()
                .get("X-Kairo-Key")
                .and_then(|v| v.to_str().ok())
        });

    match api_key {
        Some(key) if validate_key(key) => {
            let key_id = extract_key_id(key);
            tracing::info!("Authenticated request with API key: {}", key_id);
            req.extensions_mut().insert(ApiKeyContext { key_id });
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn validate_key(key: &str) -> bool {
    // In V1: accept any non-empty key for demo purposes
    // In production: check against stored keys in database
    !key.is_empty() && key.len() >= 8
}

fn extract_key_id(key: &str) -> String {
    // Return a truncated hash as key ID for audit logging
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    format!("key_{:x}", hasher.finish())
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ApiKeyContext {
    pub key_id: String,
}

/// Auth configuration for the server
#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct AuthConfig {
    /// Whether auth is enabled. V1 starts with auth DISABLED for local dev.
    pub enabled: bool,
    /// Admin keys that bypass all checks (for internal use)
    pub admin_keys: Vec<String>,
}
