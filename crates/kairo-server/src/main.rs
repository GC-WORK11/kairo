use axum::{
    extract::{State, Query, Path},
    http::{StatusCode, HeaderMap},
    response::{Json, Html, IntoResponse, Response},
    routing::{get, post, delete},
    Router,
    middleware,
};
use kairo_core::{decide, Action, Ecosystem, PackageIntelligence, Verdict, VerdictType};
use serde::Deserialize;
use reqwest::Client;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use tower_http::{trace::TraceLayer, timeout::TimeoutLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;
use rand::Rng;
use clap::Parser;
use chrono::{DateTime, Utc};
use serde_json::json;
use opentelemetry::{KeyValue, trace::{Tracer, Span, Status}};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::runtime;

mod auth;
use auth::auth_middleware;

// Plugin system
mod plugin;
use plugin::{PluginConfig, PluginRegistry};

const RATE_LIMIT_WINDOW_SECS: u64 = 60;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Enable JSON logging format
    #[arg(long)]
    json_log: bool,
}

fn get_env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).map(|v| v.parse().unwrap_or(default)).unwrap_or(default)
}

fn get_env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn get_env_bool(key: &str, default: bool) -> bool {
    std::env::var(key).map(|v| v == "true" || v == "1").unwrap_or(default)
}

fn get_env_log_level(default: &str) -> String {
    std::env::var("KAIR0_LOG_LEVEL").unwrap_or_else(|_| default.to_string())
}

// YAML config file support
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServerConfig {
    pub host: Option<String>,
    pub port: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthKeyConfig {
    pub name: String,
    pub key: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthConfig {
    pub enabled: Option<bool>,
    pub keys: Option<Vec<AuthKeyConfig>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct LoggingConfig {
    pub level: Option<String>,
    pub json: Option<bool>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    pub server: Option<ServerConfig>,
    pub auth: Option<AuthConfig>,
    pub rate_limit: Option<RateLimitConfig>,
    pub logging: Option<LoggingConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: Some(ServerConfig {
                host: Some("127.0.0.1".to_string()),
                port: Some(8080),
            }),
            auth: Some(AuthConfig {
                enabled: Some(false),
                keys: None,
            }),
            rate_limit: Some(RateLimitConfig {
                requests_per_minute: Some(100),
            }),
            logging: Some(LoggingConfig {
                level: Some("info".to_string()),
                json: Some(false),
            }),
        }
    }
}

fn load_config_file() -> Option<Config> {
    let config_paths = [
        dirs::home_dir().map(|p| p.join(".kairo/server.yaml")),
        Some(std::path::PathBuf::from("/etc/kairo/server.yaml")),
    ];

    for path in config_paths.into_iter().flatten() {
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(config) = serde_yaml::from_str::<Config>(&contents) {
                    tracing::info!("Loaded config from {}", path.display());
                    return Some(config);
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
struct WebhookCreate {
    url: String,
    events: Vec<String>,
    secret: String,
}

#[derive(Debug, serde::Serialize)]
struct WebhookPayload {
    webhook_id: String,
    event: String,
    verdict: Verdict,
    action: Action,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub key_hash: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

impl From<&ApiKey> for ApiKeyResponse {
    fn from(key: &ApiKey) -> Self {
        Self {
            id: key.id.clone(),
            name: key.name.clone(),
            created_at: key.created_at,
            last_used_at: key.last_used_at,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApiKeyCreate {
    name: String,
}

struct RateLimiter {
    requests: HashMap<String, Vec<Instant>>,
    rate_limit: u64,
}

impl RateLimiter {
    fn new(rate_limit: u64) -> Self {
        Self { requests: HashMap::new(), rate_limit }
    }

    fn is_allowed(&mut self, ip: &str) -> (bool, u64, u64) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        let timestamps = self.requests.entry(ip.to_string()).or_default();

        // Remove expired timestamps
        timestamps.retain(|&t| now.duration_since(t) < window);

        let remaining = self.rate_limit.saturating_sub(timestamps.len() as u64);

        if timestamps.len() >= self.rate_limit as usize {
            (false, 0, RATE_LIMIT_WINDOW_SECS)
        } else {
            timestamps.push(now);
            (true, remaining - 1, RATE_LIMIT_WINDOW_SECS)
        }
    }

    fn get_status(&self, ip: &str) -> (u64, u64) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        let timestamps = self.requests.get(ip).map(|v| v.as_slice()).unwrap_or(&[]);

        let active = timestamps.iter().filter(|&&t| now.duration_since(t) < window).count() as u64;
        let remaining = self.rate_limit.saturating_sub(active);

        (remaining, RATE_LIMIT_WINDOW_SECS)
    }
}

struct AppState {
    http_client: Client,
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
    stats: Arc<RwLock<Stats>>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    rate_limit: u64,
    webhooks: Arc<RwLock<Vec<Webhook>>>,
    api_keys: Arc<RwLock<Vec<ApiKey>>>,
    start_time: std::time::Instant,
    request_duration: Arc<RequestDurationHistogram>,
    plugins: Arc<PluginRegistry>,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        AppState {
            http_client: self.http_client.clone(),
            audit_log: Arc::clone(&self.audit_log),
            stats: Arc::clone(&self.stats),
            rate_limiter: Arc::clone(&self.rate_limiter),
            rate_limit: self.rate_limit,
            webhooks: Arc::clone(&self.webhooks),
            api_keys: Arc::clone(&self.api_keys),
            start_time: self.start_time,
            request_duration: Arc::clone(&self.request_duration),
            plugins: Arc::clone(&self.plugins),
        }
    }
}

#[derive(Clone)]
struct Stats {
    total_checks: u64,
    block_count: u64,
    warn_count: u64,
    allow_count: u64,
}

const HISTOGRAM_BUCKETS: &[f64] = &[
    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];

struct RequestDurationHistogram {
    buckets: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl RequestDurationHistogram {
    fn new() -> Self {
        Self {
            buckets: HISTOGRAM_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, duration_ms: u64) {
        for (i, bucket) in HISTOGRAM_BUCKETS.iter().enumerate() {
            if *bucket as u64 >= duration_ms {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum.fetch_add(duration_ms, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn get_buckets(&self) -> Vec<u64> {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).collect()
    }

    fn get_sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    ecosystem: Option<String>,
    verdict: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AuditExportQuery {
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BatchDecisionRequest {
    actions: Vec<Action>,
}

#[derive(Debug, serde::Serialize)]
struct BatchDecisionResult {
    package: String,
    version: Option<String>,
    ecosystem: Ecosystem,
    verdict: Verdict,
}

#[derive(Debug, serde::Serialize)]
struct BatchDecisionResponse {
    results: Vec<BatchDecisionResult>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AuditEntry {
    timestamp: i64,
    package: String,
    version: Option<String>,
    ecosystem: Ecosystem,
    verdict: VerdictType,
    risk_score: u8,
    key_id: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Load config from file first, then env vars override
    let file_config = load_config_file();

    // Get server config (env var overrides file)
    let host = get_env_str("KAIR0_HOST",
        file_config.as_ref()
            .and_then(|c| c.server.as_ref())
            .and_then(|s| s.host.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("127.0.0.1"));
    let port = get_env_u64("KAIR0_PORT",
        file_config.as_ref()
            .and_then(|c| c.server.as_ref())
            .and_then(|s| s.port)
            .unwrap_or(8080));

    // Get logging config (env var overrides file)
    let log_level = get_env_log_level(
        file_config.as_ref()
            .and_then(|c| c.logging.as_ref())
            .and_then(|l| l.level.as_ref())
            .map(|s| s.as_str())
            .unwrap_or("info"));
    let json_log = args.json_log || get_env_bool("KAIR0_LOG_JSON",
        file_config.as_ref()
            .and_then(|c| c.logging.as_ref())
            .and_then(|l| l.json)
            .unwrap_or(false));

    // Get auth config (env var overrides file)
    let auth_enabled = get_env_bool("KAIR0_AUTH_ENABLED",
        file_config.as_ref()
            .and_then(|c| c.auth.as_ref())
            .and_then(|a| a.enabled)
            .unwrap_or(false));
    let _admin_keys: Vec<String> = std::env::var("KAIR0_ADMIN_KEYS")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|_err| {
            file_config.as_ref()
                .and_then(|c| c.auth.as_ref())
                .and_then(|a| a.keys.as_ref())
                .map(|keys| keys.iter().map(|k| k.key.clone()).collect())
                .unwrap_or_default()
        });

    // Get rate limit config (env var overrides file)
    let rate_limit = get_env_u64("KAIR0_RATE_LIMIT",
        file_config.as_ref()
            .and_then(|c| c.rate_limit.as_ref())
            .and_then(|r| r.requests_per_minute)
            .unwrap_or(100));

    // Get timeout configs
    let fetch_timeout_secs = get_env_u64("KAIR0_FETCH_TIMEOUT", 10);
    let request_timeout_secs = get_env_u64("KAIR0_REQUEST_TIMEOUT", 30);

    // Parse log level and set up tracing
    let log_level_filter = match log_level.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    // Initialize OpenTelemetry tracing
    let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    if let Some(endpoint) = otel_endpoint {
        // Export to configured OTLP collector
        opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(&endpoint),
            )
            .with_trace_config(
                opentelemetry_sdk::trace::Config::default().with_resource(
                    opentelemetry_sdk::Resource::new(vec![
                        opentelemetry::KeyValue::new("service.name", "kairo-server"),
                    ]),
                ),
            )
            .install_batch(runtime::TokioCurrentThread)
            .expect("Failed to install OpenTelemetry tracer");
    }

    if json_log {
        // JSON logging mode - minimal tracing init
        tracing_subscriber::registry()
            .with(EnvFilter::from_default_env().add_directive(log_level_filter.into()))
            .init();
    } else {
        // Normal logging mode
        tracing_subscriber::fmt()
            .with_max_level(log_level_filter)
            .init();
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(fetch_timeout_secs))
        .build()
        .expect("Failed to build HTTP client");

    let state = Arc::new(AppState {
        http_client: client,
        audit_log: Arc::new(RwLock::new(Vec::new())),
        stats: Arc::new(RwLock::new(Stats {
            total_checks: 0,
            block_count: 0,
            warn_count: 0,
            allow_count: 0,
        })),
        rate_limiter: Arc::new(RwLock::new(RateLimiter::new(rate_limit))),
        rate_limit,
        webhooks: Arc::new(RwLock::new(Vec::new())),
        api_keys: Arc::new(RwLock::new(Vec::new())),
        start_time: std::time::Instant::now(),
        request_duration: Arc::new(RequestDurationHistogram::new()),
        plugins: Arc::new(PluginRegistry::new()),
    });

    if json_log {
        let timestamp: DateTime<Utc> = Utc::now();
        let auth_msg = if auth_enabled {
            "Auth enabled - API key required for /v1/decide"
        } else {
            "Auth disabled (V1 demo mode) - accepting all requests"
        };
        println!("{}", json!({
            "timestamp": timestamp.to_rfc3339(),
            "level": "info",
            "message": auth_msg,
            "request_id": "",
            "endpoint": "",
            "duration_ms": 0,
        }));
    } else if auth_enabled {
        info!("Auth enabled - API key required for /v1/decide");
    } else {
        info!("Auth disabled (V1 demo mode) - accepting all requests");
    }

    if json_log {
        let timestamp: DateTime<Utc> = Utc::now();
        println!("{}", json!({
            "timestamp": timestamp.to_rfc3339(),
            "level": "info",
            "message": format!("Rate limit: {} requests per minute", rate_limit),
            "request_id": "",
            "endpoint": "",
            "duration_ms": 0,
        }));
        println!("{}", json!({
            "timestamp": timestamp.to_rfc3339(),
            "level": "info",
            "message": format!("Log level: {}", log_level),
            "request_id": "",
            "endpoint": "",
            "duration_ms": 0,
        }));
    } else {
        info!("Rate limit: {} requests per minute", rate_limit);
        info!("Log level: {}", log_level);
    }

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health))
        .route("/healthz", get(healthz))
        .route("/v1", get(openapi_handler))
        .route("/v1/decide", post(decide_handler))
        .route("/v1/decide/batch", post(decide_batch_handler))
        .route("/v1/audit", get(audit_handler))
        .route("/v1/audit/export", get(audit_export_handler))
        .route("/v1/audit", delete(audit_clear_handler))
        .route("/v1/stats", get(stats_handler))
        .route("/v1/metrics", get(metrics_handler))
        .route("/v1/rate-limit", get(rate_limit_handler))
        .route("/v1/webhook", post(webhook_register_handler))
        .route("/v1/webhooks", get(webhooks_list_handler))
        .route("/v1/webhooks/{id}", delete(webhook_delete_handler))
        .route("/v1/keys", post(api_key_create_handler))
        .route("/v1/keys", get(api_keys_list_handler))
        .route("/v1/keys/{id}", delete(api_key_delete_handler))
        .route("/v1/plugins", post(plugin_register_handler))
        .route("/v1/plugins", get(plugins_list_handler))
        .route("/v1/plugins/{id}", delete(plugin_delete_handler))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, std::time::Duration::from_secs(request_timeout_secs)))
        .with_state(state.clone());

    // Apply auth middleware only to /v1/decide when enabled
    let app = if auth_enabled {
        let api_routes = Router::new()
            .route("/decide", post(decide_handler))
            .route("/decide/batch", post(decide_batch_handler))
            .route("/audit", get(audit_handler))
            .route("/audit/export", get(audit_export_handler))
            .route("/audit", delete(audit_clear_handler))
            .route("/stats", get(stats_handler))
            .route("/metrics", get(metrics_handler))
            .route("/rate-limit", get(rate_limit_handler))
            .route("/webhook", post(webhook_register_handler))
            .route("/webhooks", get(webhooks_list_handler))
            .route("/webhooks/{id}", delete(webhook_delete_handler))
            .route("/keys", post(api_key_create_handler))
            .route("/keys", get(api_keys_list_handler))
            .route("/keys/{id}", delete(api_key_delete_handler))
            .route("/plugins", post(plugin_register_handler))
            .route("/plugins", get(plugins_list_handler))
            .route("/plugins/{id}", delete(plugin_delete_handler))
            .layer(middleware::from_fn(auth_middleware));

        Router::new()
            .route("/", get(root_handler))
            .route("/health", get(health))
            .route("/healthz", get(healthz))
            .route("/v1", get(openapi_handler))
            .nest("/v1", api_routes)
            .layer(TraceLayer::new_for_http())
            .layer(TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, std::time::Duration::from_secs(request_timeout_secs)))
            .with_state(state)
    } else {
        app
    };

    let addr: SocketAddr = format!("{}:{}", host, port).parse().expect("Invalid socket address");
    if json_log {
        let timestamp: DateTime<Utc> = Utc::now();
        println!("{}", json!({
            "timestamp": timestamp.to_rfc3339(),
            "level": "info",
            "message": format!("Kairo Decision Server starting on {}", addr),
            "request_id": "",
            "endpoint": "",
            "duration_ms": 0,
        }));
    } else {
        info!("Kairo Decision Server starting on {}", addr);
    }
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    // OpenTelemetry spans are created in handlers for tracing
    // Request ID middleware is applied via the TraceLayer from tower-http

    axum::serve(listener, app).await.unwrap();
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let uptime_secs = state.start_time.elapsed().as_secs();

    let (npm_status, npm_latency_ms) = check_endpoint_get("https://registry.npmjs.org/", &state.http_client).await;
    let (osv_status, osv_latency_ms) = check_endpoint_post("https://api.osv.dev/v1/query", &state.http_client).await;

    let stats = state.stats.read().unwrap();

    Json(serde_json::json!({
        "status": "ok",
        "uptime_seconds": uptime_secs,
        "stats": {
            "total_checks": stats.total_checks,
            "block_count": stats.block_count,
            "warn_count": stats.warn_count,
            "allow_count": stats.allow_count,
        },
        "dependencies": {
            "npm_registry": {
                "status": npm_status,
                "latency_ms": npm_latency_ms,
            },
            "osv_api": {
                "status": osv_status,
                "latency_ms": osv_latency_ms,
            }
        }
    }))
}

async fn check_endpoint_get(url: &str, client: &Client) -> (String, Option<u64>) {
    let start = std::time::Instant::now();
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let latency = start.elapsed().as_millis() as u64;
            ("ok".to_string(), Some(latency))
        }
        Ok(resp) => {
            let latency = start.elapsed().as_millis() as u64;
            (format!("error: HTTP {}", resp.status()), Some(latency))
        }
        Err(e) => {
            (format!("error: {}", e), None)
        }
    }
}

async fn check_endpoint_post(url: &str, client: &Client) -> (String, Option<u64>) {
    let start = std::time::Instant::now();
    #[derive(serde::Serialize)]
    struct EmptyQuery { package: &'static str, version: Option<&'static str>, ecosystem: &'static str }
    match client.post(url).json(&EmptyQuery { package: "test", version: None, ecosystem: "npm" }).send().await {
        Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 400 => {
            // OSV returns 400 for invalid queries but the service is up
            let latency = start.elapsed().as_millis() as u64;
            ("ok".to_string(), Some(latency))
        }
        Ok(resp) => {
            let latency = start.elapsed().as_millis() as u64;
            (format!("error: HTTP {}", resp.status()), Some(latency))
        }
        Err(e) => {
            (format!("error: {}", e), None)
        }
    }
}

async fn root_handler() -> Response {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kairo Decision API</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .endpoints { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .endpoint { padding: 10px; margin: 10px 0; background: #fafafa; border-left: 3px solid #007bff; }
        .method { display: inline-block; padding: 2px 8px; border-radius: 3px; font-weight: bold; margin-right: 10px; }
        .get { background: #28a745; color: white; }
        .post { background: #007bff; color: white; }
        a { color: #007bff; }
    </style>
</head>
<body>
    <h1>Kairo Decision API</h1>
    <p>Version 0.1.0</p>
    <div class="endpoints">
        <h2>Available Endpoints</h2>
        <div class="endpoint"><span class="method get">GET</span><a href="/health">/health</a> - Health check</div>
        <div class="endpoint"><span class="method get">GET</span><a href="/v1">/v1</a> - OpenAPI specification</div>
        <div class="endpoint"><span class="method post">POST</span><a href="/v1/decide">/v1/decide</a> - Make a decision on an action</div>
        <div class="endpoint"><span class="method get">GET</span><a href="/v1/audit">/v1/audit</a> - Get audit log</div>
        <div class="endpoint"><span class="method get">GET</span><a href="/v1/stats">/v1/stats</a> - Get aggregate statistics</div>
    </div>
</body>
</html>"#;
    Html(html).into_response()
}

async fn openapi_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "openapi": "3.0.0",
        "info": {
            "title": "Kairo Decision API",
            "version": "0.1.0",
            "description": "API for making decisions on package actions based on intelligence data"
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health check",
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": { "type": "string", "example": "ok" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/decide": {
                "post": {
                    "summary": "Make a decision on an action",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "ecosystem": { "type": "string", "enum": ["npm", "pnpm", "yarn", "bun", "pip", "cargo", "go", "docker"] },
                                        "package": { "type": "string", "example": "lodash" },
                                        "version": { "type": "string", "example": "4.17.21" },
                                        "action": { "type": "string", "enum": ["install", "publish", "test"] }
                                    },
                                    "required": ["ecosystem", "package", "action"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Decision returned successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "verdict": { "type": "string", "enum": ["Allow", "Block", "Warn"] },
                                            "risk_score": { "type": "integer", "minimum": 0, "maximum": 100 },
                                            "reason": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/audit": {
                "get": {
                    "summary": "Get audit log",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": { "type": "integer", "default": 100 },
                            "description": "Maximum number of entries to return"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Audit log entries",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "timestamp": { "type": "integer" },
                                                "package": { "type": "string" },
                                                "version": { "type": "string" },
                                                "ecosystem": { "type": "string" },
                                                "verdict": { "type": "string" },
                                                "risk_score": { "type": "integer" },
                                                "key_id": { "type": "string" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/stats": {
                "get": {
                    "summary": "Get aggregate statistics",
                    "responses": {
                        "200": {
                            "description": "Aggregate statistics",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "total_checks": { "type": "integer" },
                                            "block_count": { "type": "integer" },
                                            "warn_count": { "type": "integer" },
                                            "allow_count": { "type": "integer" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }))
}

async fn decide_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(action): Json<Action>,
) -> Result<Json<Verdict>, (StatusCode, Json<serde_json::Value>)> {
    let start = Instant::now();

    if let Some(_resp) = check_rate_limit(&state, &headers) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "error": "rate limit exceeded",
            "limit": state.rate_limit,
            "window_seconds": RATE_LIMIT_WINDOW_SECS,
        }))));
    }

    let package_name = action.package.clone().unwrap_or_default();
    let ecosystem = action.ecosystem;

    // Span for decision engine
    let tracer = opentelemetry::global::tracer("kairo-server");
    let mut span = tracer.start("decision_engine".to_string());
    span.set_attribute(KeyValue::new("package.name", package_name.clone()));
    span.set_attribute(KeyValue::new("ecosystem", format!("{:?}", ecosystem)));

    let intelligence = fetch_intelligence(&state.http_client, &action)
        .await
        .map_err(|e| {
            span.set_status(Status::error(format!("Failed to fetch intelligence: {}", e)));
            tracing::error!("Failed to fetch intelligence: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() })))
        })?;

    let verdict = decide(&action, &intelligence);
    span.set_attribute(KeyValue::new("verdict", format!("{:?}", verdict.verdict)));
    span.set_attribute(KeyValue::new("risk_score", verdict.risk_score as i64));

    // Run plugins after core decision engine - if any plugin returns a verdict, use it
    let verdict = run_plugins(&state.plugins, &action, &intelligence).await.unwrap_or(verdict);

    let duration_ms = start.elapsed().as_millis() as u64;
    state.request_duration.observe(duration_ms);

    // Log to audit log (non-blocking)
    let entry = AuditEntry {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        package: action.package.clone().unwrap_or_default(),
        version: action.version.clone(),
        ecosystem: action.ecosystem,
        verdict: verdict.verdict,
        risk_score: verdict.risk_score,
        key_id: None,
    };

    {
        let mut log = state.audit_log.write().unwrap();
        log.push(entry);
        if log.len() > 1000 {
            log.remove(0);
        }
    }

    // Update stats
    {
        let mut stats = state.stats.write().unwrap();
        stats.total_checks += 1;
        match verdict.verdict {
            VerdictType::Block => stats.block_count += 1,
            VerdictType::Warn => stats.warn_count += 1,
            VerdictType::Allow => stats.allow_count += 1,
        }
    }

    // Trigger webhooks for block/warn verdicts
    if matches!(verdict.verdict, VerdictType::Block | VerdictType::Warn) {
        trigger_webhooks(&state, &verdict, &action).await;
    }

    Ok(Json(verdict))
}

async fn decide_batch_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<BatchDecisionRequest>,
) -> Result<Json<BatchDecisionResponse>, (StatusCode, Json<serde_json::Value>)> {
    let start = Instant::now();

    if let Some(_resp) = check_rate_limit(&state, &headers) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "error": "rate limit exceeded",
            "limit": state.rate_limit,
            "window_seconds": RATE_LIMIT_WINDOW_SECS,
        }))));
    }

    let mut results = Vec::with_capacity(input.actions.len());

    for action in input.actions {
        let package_name = action.package.clone().unwrap_or_default();
        let version = action.version.clone();
        let ecosystem = action.ecosystem;

        let intelligence = match fetch_intelligence(&state.http_client, &action).await {
            Ok(intel) => intel,
            Err(e) => {
                tracing::error!("Failed to fetch intelligence for {}: {}", package_name, e);
                // Use default intelligence on error
                PackageIntelligence {
                    package: package_name.clone(),
                    version: version.clone(),
                    ecosystem,
                    publish_age_seconds: None,
                    has_postinstall_script: false,
                    has_prepare_script: false,
                    has_install_script: false,
                    osv_advisories: vec![],
                    has_provenance: false,
                    license: None,
                }
            }
        };

        let verdict = decide(&action, &intelligence);

        // Run plugins after core decision engine
        let verdict = run_plugins(&state.plugins, &action, &intelligence).await.unwrap_or(verdict);

        // Log to audit log
        let entry = AuditEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            package: package_name.clone(),
            version: version.clone(),
            ecosystem,
            verdict: verdict.verdict,
            risk_score: verdict.risk_score,
            key_id: None,
        };

        {
            let mut log = state.audit_log.write().unwrap();
            log.push(entry);
            if log.len() > 1000 {
                log.remove(0);
            }
        }

        // Update stats
        {
            let mut stats = state.stats.write().unwrap();
            stats.total_checks += 1;
            match verdict.verdict {
                VerdictType::Block => stats.block_count += 1,
                VerdictType::Warn => stats.warn_count += 1,
                VerdictType::Allow => stats.allow_count += 1,
            }
        }

        results.push(BatchDecisionResult {
            package: package_name,
            version,
            ecosystem,
            verdict,
        });
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    state.request_duration.observe(duration_ms);

    Ok(Json(BatchDecisionResponse { results }))
}

async fn audit_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditQuery>,
) -> Json<Vec<AuditEntry>> {
    use kairo_core::Ecosystem;

    let log = state.audit_log.read().unwrap();

    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    let filtered: Vec<AuditEntry> = log.iter()
        .rev()
        .filter(|entry| {
            if let Some(ref eco) = query.ecosystem {
                if Ecosystem::from_str(eco).map(|e| e != entry.ecosystem).unwrap_or(true) {
                    return false;
                }
            }
            if let Some(ref ver) = query.verdict {
                if entry.verdict.to_string().to_lowercase() != ver.to_lowercase() {
                    return false;
                }
            }
            true
        })
        .skip(offset)
        .take(limit)
        .cloned()
        .collect();

    Json(filtered)
}

async fn audit_export_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditExportQuery>,
) -> Response {
    let log = state.audit_log.read().unwrap();
    let entries: Vec<AuditEntry> = log.iter().cloned().collect();

    let format = query.format.as_deref().unwrap_or("json");

    if format == "csv" {
        let mut csv_output = String::new();
        csv_output.push_str("timestamp,package,version,ecosystem,verdict,risk_score,key_id\n");

        for entry in &entries {
            let version = entry.version.as_deref().unwrap_or("");
            let key_id = entry.key_id.as_deref().unwrap_or("");
            csv_output.push_str(&format!(
                "{},{},{},{:?},{:?},{},{}\n",
                entry.timestamp, entry.package, version, entry.ecosystem, entry.verdict, entry.risk_score, key_id
            ));
        }

        let mut resp = csv_output.into_response();
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/csv; charset=utf-8"),
        );
        resp
    } else {
        Json(entries).into_response()
    }
}

async fn audit_clear_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let confirm_header = headers
        .get("X-Confirm-Delete")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase());

    match confirm_header.as_deref() {
        Some("true" | "1" | "yes") => {
            let mut log = state.audit_log.write().unwrap();
            log.clear();
            Ok(StatusCode::NO_CONTENT)
        }
        _ => Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "missing required X-Confirm-Delete header (set to 'true', '1', or 'yes')"
        })))),
    }
}

async fn stats_handler(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let stats = state.stats.read().unwrap();
    Json(serde_json::json!({
        "total_checks": stats.total_checks,
        "block_count": stats.block_count,
        "warn_count": stats.warn_count,
        "allow_count": stats.allow_count,
    }))
}

async fn metrics_handler(
    State(state): State<Arc<AppState>>,
) -> Response {
    let stats = state.stats.read().unwrap();
    let buckets = state.request_duration.get_buckets();
    let sum = state.request_duration.get_sum();
    let count = state.request_duration.get_count();

    let mut output = String::new();

    // kairo_total_checks
    output.push_str("# HELP kairo_total_checks Total number of checks\n");
    output.push_str("# TYPE kairo_total_checks counter\n");
    output.push_str(&format!("kairo_total_checks {}\n\n", stats.total_checks));

    // kairo_block_count
    output.push_str("# HELP kairo_block_count Total BLOCK verdicts\n");
    output.push_str("# TYPE kairo_block_count counter\n");
    output.push_str(&format!("kairo_block_count {}\n\n", stats.block_count));

    // kairo_warn_count
    output.push_str("# HELP kairo_warn_count Total WARN verdicts\n");
    output.push_str("# TYPE kairo_warn_count counter\n");
    output.push_str(&format!("kairo_warn_count {}\n\n", stats.warn_count));

    // kairo_allow_count
    output.push_str("# HELP kairo_allow_count Total ALLOW verdicts\n");
    output.push_str("# TYPE kairo_allow_count counter\n");
    output.push_str(&format!("kairo_allow_count {}\n\n", stats.allow_count));

    // kairo_request_duration_ms histogram
    output.push_str("# HELP kairo_request_duration_ms Request duration in ms\n");
    output.push_str("# TYPE kairo_request_duration_ms histogram\n");

    let mut cumulative = 0u64;
    for (i, bucket) in buckets.iter().enumerate() {
        cumulative += bucket;
        output.push_str(&format!("kairo_request_duration_ms_bucket{{le=\"{}\"}} {}\n", HISTOGRAM_BUCKETS[i] as u64, cumulative));
    }
    // +Inf bucket
    output.push_str(&format!("kairo_request_duration_ms_bucket{{le=\"+Inf\"}} {}\n", count));

    output.push_str(&format!("kairo_request_duration_ms_sum {}\n", sum));
    output.push_str(&format!("kairo_request_duration_ms_count {}\n", count));

    let mut resp = output.into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}

async fn webhook_register_handler(
    State(state): State<Arc<AppState>>,
    Json(input): Json<WebhookCreate>,
) -> Result<Json<Webhook>, (StatusCode, Json<serde_json::Value>)> {
    if input.url.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "url is required"
        }))));
    }

    if input.events.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "events is required"
        }))));
    }

    for event in &input.events {
        if event != "*" && event != "block" && event != "warn" && event != "allow" {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "invalid event type, must be 'block', 'warn', 'allow', or '*'"
            }))));
        }
    }

    let webhook = Webhook {
        id: Uuid::new_v4().to_string(),
        url: input.url,
        events: input.events,
        secret: input.secret,
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };

    {
        let mut webhooks = state.webhooks.write().unwrap();
        webhooks.push(webhook.clone());
    }

    Ok(Json(webhook))
}

async fn webhooks_list_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<Webhook>> {
    let webhooks = state.webhooks.read().unwrap();
    Json(webhooks.clone())
}

async fn webhook_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let mut webhooks = state.webhooks.write().unwrap();
    let initial_len = webhooks.len();
    webhooks.retain(|w| w.id != id);

    if webhooks.len() == initial_len {
        Err((StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "webhook not found"
        }))))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

#[derive(Debug, serde::Serialize)]
struct ApiKeyCreatedResponse {
    id: String,
    name: String,
    key: String,
    created_at: i64,
}

async fn api_key_create_handler(
    State(state): State<Arc<AppState>>,
    Json(input): Json<ApiKeyCreate>,
) -> Result<Json<ApiKeyCreatedResponse>, (StatusCode, Json<serde_json::Value>)> {
    if input.name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "name is required"
        }))));
    }

    let raw_key = generate_api_key();
    let key_hash = bcrypt::hash(&raw_key, bcrypt::DEFAULT_COST)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("failed to hash key: {}", e)
        }))))?;

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let api_key = ApiKey {
        id: Uuid::new_v4().to_string(),
        name: input.name,
        key_hash,
        created_at,
        last_used_at: None,
    };

    {
        let mut api_keys = state.api_keys.write().unwrap();
        api_keys.push(api_key.clone());
    }

    Ok(Json(ApiKeyCreatedResponse {
        id: api_key.id,
        name: api_key.name,
        key: raw_key,
        created_at: api_key.created_at,
    }))
}

async fn api_keys_list_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<ApiKeyResponse>> {
    let api_keys = state.api_keys.read().unwrap();
    Json(api_keys.iter().map(ApiKeyResponse::from).collect())
}

async fn api_key_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let mut api_keys = state.api_keys.write().unwrap();
    let initial_len = api_keys.len();
    api_keys.retain(|k| k.id != id);

    if api_keys.len() == initial_len {
        Err((StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "api key not found"
        }))))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

async fn trigger_webhooks(
    state: &Arc<AppState>,
    verdict: &Verdict,
    action: &Action,
) {
    let verdict_event = match verdict.verdict {
        VerdictType::Block => "block",
        VerdictType::Warn => "warn",
        VerdictType::Allow => "allow",
    };

    let webhooks_to_fire: Vec<Webhook> = {
        let webhooks = state.webhooks.read().unwrap();
        webhooks.iter()
            .filter(|w| w.events.contains(&"*".to_string()) || w.events.iter().any(|e| e == verdict_event))
            .cloned()
            .collect()
    };

    for webhook in webhooks_to_fire {
        let payload = WebhookPayload {
            webhook_id: webhook.id.clone(),
            event: verdict_event.to_string(),
            verdict: verdict.clone(),
            action: action.clone(),
        };

        let client = state.http_client.clone();
        let url = webhook.url.clone();
        let secret = webhook.secret.clone();

        tokio::spawn(async move {
            let mut req = client.post(&url)
                .json(&payload);

            if !secret.is_empty() {
                req = req.header("X-Webhook-Secret", &secret);
            }

            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        tracing::info!("Webhook fired successfully: {} for event {}", url, verdict_event);
                    } else {
                        tracing::warn!("Webhook returned error: {} - HTTP {}", url, resp.status());
                    }
                }
                Err(e) => {
                    tracing::warn!("Webhook failed to fire: {} - {}", url, e);
                }
            }
        });
    }
}

async fn rate_limit_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let ip = get_client_ip(&headers);

    let (remaining, window) = {
        let limiter = state.rate_limiter.read().unwrap();
        limiter.get_status(&ip)
    };

    Json(serde_json::json!({
        "limit": state.rate_limit,
        "remaining": remaining,
        "window_seconds": window,
    })).into_response()
}

fn get_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn check_rate_limit(state: &Arc<AppState>, headers: &HeaderMap) -> Option<Response> {
    let ip = get_client_ip(headers);

    let (allowed, _remaining, window) = {
        let mut limiter = state.rate_limiter.write().unwrap();
        limiter.is_allowed(&ip)
    };

    if !allowed {
        Some((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "rate limit exceeded",
                "limit": state.rate_limit,
                "window_seconds": window,
            })),
        ).into_response())
    } else {
        None
    }
}

async fn run_plugins(
    registry: &PluginRegistry,
    action: &Action,
    intelligence: &PackageIntelligence,
) -> Option<Verdict> {
    let plugins = registry.get_plugins();
    for plugin in plugins {
        if let Some(verdict) = plugin.check(action.clone(), intelligence.clone()).await {
            tracing::info!("Plugin override: {} returned {:?}", plugin.name(), verdict.verdict);
            return Some(verdict);
        }
    }
    None
}

async fn plugin_register_handler(
    State(state): State<Arc<AppState>>,
    Json(config): Json<PluginConfig>,
) -> Result<Json<plugin::PluginResponse>, (StatusCode, Json<serde_json::Value>)> {
    if config.name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "name is required"
        }))));
    }

    let plugin = plugin::BuiltInPlugin::new(config.clone());
    let id = state.plugins.register(Box::new(plugin));

    Ok(Json(plugin::PluginResponse { id, name: config.name }))
}

async fn plugins_list_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<plugin::PluginInfo>> {
    let plugins = state.plugins.list();
    Json(plugins)
}

async fn plugin_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    if state.plugins.unregister(&id) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "plugin not found"
        }))))
    }
}

async fn fetch_intelligence(
    client: &Client,
    action: &Action,
) -> Result<PackageIntelligence, Box<dyn std::error::Error + Send + Sync>> {
    let ecosystem = action.ecosystem;
    let package = action.package.clone().unwrap_or_default();
    let version = action.version.clone();

    // Span for overall intelligence fetching
    let tracer = opentelemetry::global::tracer("kairo-server");
    let mut span = tracer.start("fetch_intelligence".to_string());
    span.set_attribute(KeyValue::new("package.name", package.clone()));
    span.set_attribute(KeyValue::new("ecosystem", format!("{:?}", ecosystem)));
    span.set_attribute(KeyValue::new("version", version.clone().unwrap_or_default()));

    let (npm_result, osv_result) = tokio::join!(
        fetch_npm_registry(client, &package, ecosystem),
        fetch_osv_advisories(client, &package, ecosystem, version.as_deref())
    );

    let (publish_age, has_postinstall, has_prepare, has_install, has_provenance, license) =
        npm_result.unwrap_or((None, false, false, false, false, None));
    let osv_advisories = osv_result.unwrap_or_default();

    span.set_attribute(KeyValue::new("npm.found", publish_age.is_some()));
    span.set_attribute(KeyValue::new("osv.advisory_count", osv_advisories.len() as i64));

    Ok(PackageIntelligence {
        package,
        version,
        ecosystem,
        publish_age_seconds: publish_age,
        has_postinstall_script: has_postinstall,
        has_prepare_script: has_prepare,
        has_install_script: has_install,
        osv_advisories,
        has_provenance,
        license,
    })
}

async fn fetch_npm_registry(
    client: &Client,
    package: &str,
    ecosystem: Ecosystem,
) -> Result<(Option<u64>, bool, bool, bool, bool, Option<String>), Box<dyn std::error::Error + Send + Sync>> {
    if !matches!(ecosystem, Ecosystem::npm | Ecosystem::pnpm | Ecosystem::yarn | Ecosystem::bun) {
        return Ok((None, false, false, false, false, None));
    }

    let tracer = opentelemetry::global::tracer("kairo-server");
    let mut span = tracer.start("npm_registry_lookup".to_string());
    span.set_attribute(KeyValue::new("package.name", package.to_string()));
    span.set_attribute(KeyValue::new("registry", "npm"));

    let url = format!("https://registry.npmjs.org/{}", package.replace('/', "%2F"));
    span.set_attribute(KeyValue::new("http.url", url.clone()));

    let resp = client.get(&url).send().await?;
    span.set_attribute(KeyValue::new("http.status_code", resp.status().as_u16() as i64));

    if !resp.status().is_success() {
        span.set_status(Status::error(format!("HTTP {}", resp.status())));
        return Ok((None, false, false, false, false, None));
    }

    let json: serde_json::Value = resp.json().await?;
    let publish_age = json
        .get("time")
        .and_then(|t| t.get("latest"))
        .and_then(|t| t.as_str())
        .and_then(|ts| {
            chrono::DateTime::parse_from_rfc3339(ts)
                .ok()
                .map(|dt| {
                    let now = chrono::Utc::now();
                    (now - dt.with_timezone(&chrono::Utc)).num_seconds() as u64
                })
        });

    let latest_version = json
        .get("dist-tags")
        .and_then(|t| t.get("latest"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "latest".to_string());

    let version_data = json.get("versions").and_then(|v| v.get(latest_version.as_str()));

    let has_postinstall = version_data
        .and_then(|v| v.get("scripts"))
        .and_then(|s| s.get("postinstall"))
        .and_then(|s| s.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let has_prepare = version_data
        .and_then(|v| v.get("scripts"))
        .and_then(|s| s.get("prepare"))
        .and_then(|s| s.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let has_install = version_data
        .and_then(|v| v.get("scripts"))
        .and_then(|s| s.get("install"))
        .and_then(|s| s.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let has_provenance = version_data
        .and_then(|v| v.get("dist"))
        .and_then(|d| d.get("integrity"))
        .is_some();

    let license = json
        .get("license")
        .and_then(|l| l.as_str())
        .map(|s| s.to_string());

    span.set_attribute(KeyValue::new("npm.latest_version", latest_version.clone()));
    span.set_attribute(KeyValue::new("npm.has_postinstall", has_postinstall));
    span.set_attribute(KeyValue::new("npm.has_provenance", has_provenance));

    Ok((publish_age, has_postinstall, has_prepare, has_install, has_provenance, license))
}

async fn fetch_osv_advisories(
    client: &Client,
    package: &str,
    ecosystem: Ecosystem,
    version: Option<&str>,
) -> Result<Vec<kairo_core::OsvAdvisory>, Box<dyn std::error::Error + Send + Sync>> {
    let osv_ecosystem = match ecosystem {
        Ecosystem::npm | Ecosystem::pnpm | Ecosystem::yarn | Ecosystem::bun => "npm",
        Ecosystem::pip => "PyPI",
        Ecosystem::cargo => "crates.io",
        Ecosystem::go => "Go",
        Ecosystem::docker => "Docker",
    };

    let package_name = if package.starts_with('@') {
        package.strip_prefix('@').unwrap_or(package)
    } else {
        package
    };

    let tracer = opentelemetry::global::tracer("kairo-server");
    let mut span = tracer.start("osv_advisory_lookup".to_string());
    span.set_attribute(KeyValue::new("package.name", package_name.to_string()));
    span.set_attribute(KeyValue::new("osv.ecosystem", osv_ecosystem));
    if let Some(v) = version {
        span.set_attribute(KeyValue::new("version", v.to_string()));
    }

    #[derive(serde::Serialize)]
    struct OsvQuery<'a> {
        package: &'a str,
        version: Option<&'a str>,
        ecosystem: &'a str,
    }

    let query = OsvQuery {
        package: package_name,
        version,
        ecosystem: osv_ecosystem,
    };

    let resp = client
        .post("https://api.osv.dev/v1/query")
        .json(&query)
        .send()
        .await?;

    span.set_attribute(KeyValue::new("http.status_code", resp.status().as_u16() as i64));

    if !resp.status().is_success() {
        span.set_status(Status::error(format!("HTTP {}", resp.status())));
        return Ok(vec![]);
    }

    #[derive(serde::Deserialize)]
    struct OsvResponse { vulns: Option<Vec<OsvVuln>> }

    #[derive(serde::Deserialize)]
    struct OsvVuln {
        id: String,
        summary: Option<String>,
        severity: Option<OsvSeverity>,
        modified: String,
    }

    #[derive(serde::Deserialize)]
    struct OsvSeverity { score: Option<String> }

    let osv_resp: OsvResponse = resp.json().await.unwrap_or(OsvResponse { vulns: None });

    let advisories: Vec<kairo_core::OsvAdvisory> = osv_resp
        .vulns
        .unwrap_or_default()
        .into_iter()
        .map(|v| kairo_core::OsvAdvisory {
            id: v.id,
            summary: v.summary.unwrap_or_default(),
            severity: v.severity.and_then(|s| s.score).unwrap_or_else(|| "unknown".to_string()),
            modified: v.modified,
        })
        .collect();

    span.set_attribute(KeyValue::new("osv.advisory_count", advisories.len() as i64));

    Ok(advisories)
}
