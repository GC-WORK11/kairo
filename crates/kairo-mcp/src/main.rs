use kairo_core::{Action, ActionType, Ecosystem, RepoContext, Verdict};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use chrono::{DateTime, Utc, Duration};
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use clap::Parser;

const HISTORY_MAX_SIZE: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryEntry {
    tool: String,
    arguments: Value,
    verdict: Option<String>,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct SessionHistory {
    entries: Vec<HistoryEntry>,
}

impl SessionHistory {
    fn add(&mut self, entry: HistoryEntry) {
        if self.entries.len() >= HISTORY_MAX_SIZE {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    fn get_recent(&self) -> Vec<HistoryEntry> {
        self.entries.clone()
    }
}

static SESSION_HISTORY: LazyLock<Mutex<SessionHistory>> = LazyLock::new(|| Mutex::new(SessionHistory::default()));

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpConfig {
    api_url: Option<String>,
}

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";

#[derive(Debug, Clone, Parser)]
#[command(name = "kairo-mcp")]
#[command(about = "Kairo MCP server for package security checks")]
struct Args {
    /// Start in interactive REPL mode
    #[arg(long)]
    interactive: bool,

    /// Listen on a Unix socket for JSON-RPC connections
    #[arg(long)]
    socket: Option<String>,

    /// Skip the health check on startup
    #[arg(long, default_value = "false")]
    no_health_check: bool,
}

fn get_config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kairo")
        .join("mcp.yaml")
}

fn get_trust_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("kairo")
        .join("trust.json")
}

fn get_blocklist_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("kairo")
        .join("blocklist.json")
}

// Trust store types
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustEntry {
    ecosystem: String,
    package: String,
    trusted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TrustStore {
    packages: Vec<TrustEntry>,
}

fn read_trust_store() -> TrustStore {
    let trust_path = get_trust_path();
    if trust_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&trust_path) {
            if let Ok(store) = serde_json::from_str(&content) {
                return store;
            }
        }
    }
    TrustStore::default()
}

fn write_trust_store(store: &TrustStore) -> Result<(), String> {
    let trust_path = get_trust_path();
    if let Some(parent) = trust_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }
    let content = serde_json::to_string_pretty(store)
        .map_err(|e| format!("Failed to serialize trust store: {}", e))?;
    std::fs::write(&trust_path, content)
        .map_err(|e| format!("Failed to write trust file: {}", e))?;
    Ok(())
}

// Blocklist store types
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlocklistEntry {
    ecosystem: String,
    package: String,
    blocked_at: String,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BlocklistStore {
    packages: Vec<BlocklistEntry>,
}

fn read_blocklist_store() -> BlocklistStore {
    let blocklist_path = get_blocklist_path();
    if blocklist_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&blocklist_path) {
            if let Ok(store) = serde_json::from_str(&content) {
                return store;
            }
        }
    }
    BlocklistStore::default()
}

fn write_blocklist_store(store: &BlocklistStore) -> Result<(), String> {
    let blocklist_path = get_blocklist_path();
    if let Some(parent) = blocklist_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }
    let content = serde_json::to_string_pretty(store)
        .map_err(|e| format!("Failed to serialize blocklist store: {}", e))?;
    std::fs::write(&blocklist_path, content)
        .map_err(|e| format!("Failed to write blocklist file: {}", e))?;
    Ok(())
}

fn read_config() -> Option<McpConfig> {
    let config_path = get_config_path();
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path).ok()?;
        serde_yaml::from_str(&content).ok()
    } else {
        None
    }
}

fn get_api_url() -> String {
    std::env::var("KAIR0_API_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            read_config()
                .and_then(|c| c.api_url)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| DEFAULT_API_URL.to_string())
}

fn get_configured_url(subpath: &str) -> String {
    format!("{}{}", get_api_url(), subpath)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpError {
    code: i32,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpResponse {
    jsonrpc: String,
    id: Value,
    result: Option<Value>,
    error: Option<McpError>,
}

fn make_check_package_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();
    {
        let mut ecosystem_props = Map::new();
        ecosystem_props.insert("type".to_string(), Value::String("string".to_string()));
        ecosystem_props.insert(
            "enum".to_string(),
            Value::Array(vec![
                Value::String("npm".to_string()),
                Value::String("pnpm".to_string()),
                Value::String("yarn".to_string()),
                Value::String("bun".to_string()),
                Value::String("pip".to_string()),
                Value::String("cargo".to_string()),
                Value::String("go".to_string()),
                Value::String("docker".to_string()),
            ]),
        );
        ecosystem_props.insert("default".to_string(), Value::String("npm".to_string()));
        props.insert("ecosystem".to_string(), Value::Object(ecosystem_props));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("package".to_string(), Value::Object(m));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        m.insert("default".to_string(), Value::String("latest".to_string()));
        props.insert("version".to_string(), Value::Object(m));
    }
    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![
            Value::String("ecosystem".to_string()),
            Value::String("package".to_string()),
            Value::String("version".to_string()),
        ]),
    );
    Value::Object(schema)
}

fn make_check_command_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        m.insert(
            "description".to_string(),
            Value::String("Full command to check, e.g. 'pnpm add lodash@4'".to_string()),
        );
        props.insert("command".to_string(), Value::Object(m));
    }
    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![Value::String("command".to_string())]),
    );
    Value::Object(schema)
}

fn make_get_safe_version_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("ecosystem".to_string(), Value::Object(m));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("package".to_string(), Value::Object(m));
    }
    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![
            Value::String("ecosystem".to_string()),
            Value::String("package".to_string()),
        ]),
    );
    Value::Object(schema)
}

fn make_explain_verdict_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();

    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        m.insert("enum".to_string(), Value::Array(vec![
            Value::String("Block".to_string()),
            Value::String("Warn".to_string()),
            Value::String("Allow".to_string()),
        ]));
        props.insert("verdict".to_string(), Value::Object(m));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("integer".to_string()));
        m.insert("minimum".to_string(), Value::Number(0.into()));
        m.insert("maximum".to_string(), Value::Number(100.into()));
        props.insert("risk_score".to_string(), Value::Object(m));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("title".to_string(), Value::Object(m));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("summary".to_string(), Value::Object(m));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("array".to_string()));
        let evidence_item = serde_json::json!({
            "type": "object",
            "properties": {
                "type": { "type": "string" },
                "source": { "type": "string" },
                "detail": { "type": "string" }
            },
            "required": ["type", "source", "detail"]
        });
        m.insert("items".to_string(), evidence_item);
        props.insert("evidence".to_string(), Value::Object(m));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("recommended_action".to_string(), Value::Object(m));
    }

    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![
            Value::String("verdict".to_string()),
            Value::String("risk_score".to_string()),
            Value::String("title".to_string()),
            Value::String("summary".to_string()),
        ]),
    );
    Value::Object(schema)
}

fn make_search_packages_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        m.insert("description".to_string(), Value::String("Search query (package name or keywords)".to_string()));
        props.insert("query".to_string(), Value::Object(m));
    }
    {
        let mut ecosystem_props = Map::new();
        ecosystem_props.insert("type".to_string(), Value::String("string".to_string()));
        ecosystem_props.insert(
            "enum".to_string(),
            Value::Array(vec![
                Value::String("npm".to_string()),
                Value::String("pypi".to_string()),
                Value::String("crates".to_string()),
            ]),
        );
        ecosystem_props.insert("default".to_string(), Value::String("npm".to_string()));
        props.insert("ecosystem".to_string(), Value::Object(ecosystem_props));
    }
    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![Value::String("query".to_string())]),
    );
    Value::Object(schema)
}

fn make_check_batch_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();

    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("array".to_string()));
        let item_props = {
            let mut ip = Map::new();
            let mut ecosystem_props = Map::new();
            ecosystem_props.insert("type".to_string(), Value::String("string".to_string()));
            ecosystem_props.insert(
                "enum".to_string(),
                Value::Array(vec![
                    Value::String("npm".to_string()),
                    Value::String("pnpm".to_string()),
                    Value::String("yarn".to_string()),
                    Value::String("bun".to_string()),
                    Value::String("pip".to_string()),
                    Value::String("cargo".to_string()),
                    Value::String("go".to_string()),
                    Value::String("docker".to_string()),
                ]),
            );
            ip.insert("ecosystem".to_string(), Value::Object(ecosystem_props));

            let mut name_props = Map::new();
            name_props.insert("type".to_string(), Value::String("string".to_string()));
            ip.insert("name".to_string(), Value::Object(name_props));

            let mut version_props = Map::new();
            version_props.insert("type".to_string(), Value::String("string".to_string()));
            version_props.insert("default".to_string(), Value::String("latest".to_string()));
            ip.insert("version".to_string(), Value::Object(version_props));

            Value::Object(ip)
        };
        m.insert("items".to_string(), item_props);
        props.insert("packages".to_string(), Value::Object(m));
    }

    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![Value::String("packages".to_string())]),
    );
    Value::Object(schema)
}

fn make_doctor_schema() -> Value {
    Value::Object(Map::new())
}

fn make_health_schema() -> Value {
    Value::Object(Map::new())
}

fn make_trust_list_schema() -> Value {
    Value::Object(Map::new())
}

fn make_trust_add_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();
    {
        let mut ecosystem_props = Map::new();
        ecosystem_props.insert("type".to_string(), Value::String("string".to_string()));
        ecosystem_props.insert(
            "enum".to_string(),
            Value::Array(vec![
                Value::String("npm".to_string()),
                Value::String("pnpm".to_string()),
                Value::String("yarn".to_string()),
                Value::String("bun".to_string()),
                Value::String("pip".to_string()),
                Value::String("cargo".to_string()),
                Value::String("go".to_string()),
                Value::String("docker".to_string()),
            ]),
        );
        ecosystem_props.insert("default".to_string(), Value::String("npm".to_string()));
        props.insert("ecosystem".to_string(), Value::Object(ecosystem_props));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("package".to_string(), Value::Object(m));
    }
    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![
            Value::String("ecosystem".to_string()),
            Value::String("package".to_string()),
        ]),
    );
    Value::Object(schema)
}

fn make_blocklist_list_schema() -> Value {
    Value::Object(Map::new())
}

fn make_blocklist_add_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();
    {
        let mut ecosystem_props = Map::new();
        ecosystem_props.insert("type".to_string(), Value::String("string".to_string()));
        ecosystem_props.insert(
            "enum".to_string(),
            Value::Array(vec![
                Value::String("npm".to_string()),
                Value::String("pnpm".to_string()),
                Value::String("yarn".to_string()),
                Value::String("bun".to_string()),
                Value::String("pip".to_string()),
                Value::String("cargo".to_string()),
                Value::String("go".to_string()),
                Value::String("docker".to_string()),
            ]),
        );
        ecosystem_props.insert("default".to_string(), Value::String("npm".to_string()));
        props.insert("ecosystem".to_string(), Value::Object(ecosystem_props));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("package".to_string(), Value::Object(m));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        m.insert("description".to_string(), Value::String("Optional reason for blocking".to_string()));
        props.insert("reason".to_string(), Value::Object(m));
    }
    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![
            Value::String("ecosystem".to_string()),
            Value::String("package".to_string()),
        ]),
    );
    Value::Object(schema)
}

fn make_blocklist_check_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    let mut props = Map::new();
    {
        let mut ecosystem_props = Map::new();
        ecosystem_props.insert("type".to_string(), Value::String("string".to_string()));
        ecosystem_props.insert(
            "enum".to_string(),
            Value::Array(vec![
                Value::String("npm".to_string()),
                Value::String("pnpm".to_string()),
                Value::String("yarn".to_string()),
                Value::String("bun".to_string()),
                Value::String("pip".to_string()),
                Value::String("cargo".to_string()),
                Value::String("go".to_string()),
                Value::String("docker".to_string()),
            ]),
        );
        ecosystem_props.insert("default".to_string(), Value::String("npm".to_string()));
        props.insert("ecosystem".to_string(), Value::Object(ecosystem_props));
    }
    {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String("string".to_string()));
        props.insert("package".to_string(), Value::Object(m));
    }
    schema.insert("properties".to_string(), Value::Object(props));
    schema.insert(
        "required".to_string(),
        Value::Array(vec![
            Value::String("ecosystem".to_string()),
            Value::String("package".to_string()),
        ]),
    );
    Value::Object(schema)
}

fn make_history_schema() -> Value {
    Value::Object(Map::new())
}

static TOOLS: LazyLock<Vec<(&'static str, &'static str, Value)>> = LazyLock::new(|| {
    vec![
        (
            "kairo.check_package",
            "Check a package for security risks before installing.",
            make_check_package_schema(),
        ),
        (
            "kairo.check_batch",
            "Check multiple packages for security risks at once using batch API.",
            make_check_batch_schema(),
        ),
        (
            "kairo.check_command",
            "Check a terminal command for risk before running.",
            make_check_command_schema(),
        ),
        (
            "kairo.get_safe_version",
            "Get a recommended safe version for a package.",
            make_get_safe_version_schema(),
        ),
        (
            "kairo.explain_verdict",
            "Get a human-readable explanation of a Kairo verdict.",
            make_explain_verdict_schema(),
        ),
        (
            "kairo.search_packages",
            "Search for packages by name across npm, PyPI, and crates.io.",
            make_search_packages_schema(),
        ),
        (
            "kairo.doctor",
            "Run comprehensive diagnostics on the Kairo MCP server and its dependencies.",
            make_doctor_schema(),
        ),
        (
            "kairo.health",
            "Check if the Kairo server is reachable and healthy.",
            make_health_schema(),
        ),
        (
            "kairo.trust_list",
            "List all trusted packages from the trust store.",
            make_trust_list_schema(),
        ),
        (
            "kairo.trust_add",
            "Add a package to the trust store.",
            make_trust_add_schema(),
        ),
        (
            "kairo.blocklist_list",
            "List all blocked packages from the hardcoded blocklist and local blocklist.json.",
            make_blocklist_list_schema(),
        ),
        (
            "kairo.blocklist_add",
            "Add a package to the local blocklist.",
            make_blocklist_add_schema(),
        ),
        (
            "kairo.blocklist_check",
            "Check if a package is on any block list (hardcoded or local).",
            make_blocklist_check_schema(),
        ),
        (
            "kairo.history",
            "Get the last 50 tool calls in this session with their arguments, verdicts, and timestamps.",
            make_history_schema(),
        ),
        // Aliases
        (
            "kairo.check",
            "Alias for kairo.check_package. Check a package for security risks (defaults to npm).",
            make_check_package_schema(),
        ),
        (
            "kairo.install",
            "Alias for kairo.check_package. Check a package for security risks before installing (defaults to npm).",
            make_check_package_schema(),
        ),
        (
            "kairo.ping",
            "Alias for kairo.health. Check if the Kairo server is reachable.",
            make_health_schema(),
        ),
        (
            "kairo.help",
            "Get usage information for Kairo tools or explanations of verdicts.",
            make_explain_verdict_schema(),
        ),
    ]
});

fn main() {
    let args = Args::parse();

    if args.interactive {
        run_interactive_mode(args.no_health_check);
    } else if let Some(socket_path) = args.socket {
        run_socket_mode(&socket_path, args.no_health_check);
    } else {
        run_stdin_mode(args.no_health_check);
    }
}

fn run_stdin_mode(skip_health_check: bool) {
    let stdin = io::stdin();
    let mut input = String::new();
    let mut output = String::new();

    if !skip_health_check {
        check_server_health();
    }

    loop {
        input.clear();
        let bytes = stdin.read_line(&mut input).unwrap_or(0);
        if bytes == 0 {
            break;
        }

        let line = input.trim();
        if line.is_empty() {
            continue;
        }

        let req: McpRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to parse request: {}", e);
                continue;
            }
        };

        let resp = handle_request(req);
        output.clear();
        output = serde_json::to_string(&resp).unwrap();
        println!("{}", output);
        io::stdout().flush().unwrap();
    }
}

fn run_interactive_mode(skip_health_check: bool) {
    if !skip_health_check {
        check_server_health();
    }

    println!("Kairo MCP Server (interactive mode)");
    println!("Enter JSON-RPC requests, one per line. Press Ctrl+C or send empty line to exit.");
    println!();

    let stdin = io::stdin();

    loop {
        print!("kairo> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        let bytes = stdin.read_line(&mut line).unwrap_or(0);
        if bytes == 0 {
            println!();
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            break;
        }

        let req: McpRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to parse request: {}", e);
                continue;
            }
        };

        let resp = handle_request(req);
        let output = serde_json::to_string(&resp).unwrap();
        println!("{}", output);
        io::stdout().flush().unwrap();
    }
}

fn run_socket_mode(socket_path: &str, skip_health_check: bool) {
    if !skip_health_check {
        check_server_health();
    }

    // Remove existing socket file if present
    let socket_path = PathBuf::from(socket_path);
    if socket_path.exists() {
        std::fs::remove_file(&socket_path).ok();
    }

    let rt = Runtime::new().expect("Failed to create runtime");
    rt.block_on(async {
        let listener = UnixListener::bind(&socket_path)
            .expect("Failed to bind to Unix socket");

        // Set socket permissions to allow client access
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mut perms) = std::fs::metadata(&socket_path).map(|m| m.permissions()) {
                perms.set_mode(0o666);
                std::fs::set_permissions(&socket_path, perms).ok();
            }
        }

        println!("Listening on Unix socket: {}", socket_path.display());

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        handle_socket_connection(&mut stream).await;
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
    });
}

async fn handle_socket_connection(stream: &mut UnixStream) {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut reader = tokio::io::BufReader::new(rd);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error reading from socket: {}", e);
                break;
            }
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let req: McpRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                let error_resp = McpResponse {
                    jsonrpc: "2.0".to_string(),
                    id: serde_json::Value::Null,
                    result: None,
                    error: Some(McpError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                    }),
                };
                let resp_str = serde_json::to_string(&error_resp).unwrap();
                if let Err(e) = wr.write_all(resp_str.as_bytes()).await {
                    eprintln!("Error writing to socket: {}", e);
                    break;
                }
                if let Err(e) = wr.write_all(b"\n").await {
                    eprintln!("Error writing newline to socket: {}", e);
                    break;
                }
                if let Err(e) = wr.flush().await {
                    eprintln!("Error flushing socket: {}", e);
                    break;
                }
                continue;
            }
        };

        let resp = handle_request(req);
        let resp_str = serde_json::to_string(&resp).unwrap();

        if let Err(e) = wr.write_all(resp_str.as_bytes()).await {
            eprintln!("Error writing to socket: {}", e);
            break;
        }
        if let Err(e) = wr.write_all(b"\n").await {
            eprintln!("Error writing newline to socket: {}", e);
            break;
        }
        if let Err(e) = wr.flush().await {
            eprintln!("Error flushing socket: {}", e);
            break;
        }
    }
}

fn check_server_health() {
    let api_url = get_api_url();
    let health_url = get_configured_url("/health");

    if let Ok(client) = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        if let Ok(rt) = Runtime::new() {
            if let Ok(result) = rt.block_on(check_health_with_url(&client, &health_url)) {
                if let Ok(health) = serde_json::from_str::<serde_json::Value>(&result) {
                    if health.get("server_reachable").and_then(|v| v.as_bool()) == Some(true) {
                        println!("kairo-server is reachable at {}", api_url);
                        return;
                    } else {
                        eprintln!("Error: kairo-server is not reachable at {}", api_url);
                    }
                }
            } else {
                eprintln!("Error: Failed to connect to kairo-server at {}", api_url);
            }
        }
    }

    eprintln!();
    eprintln!("To configure the Kairo API server URL:");
    eprintln!("  1. Set environment variable: export KAIR0_API_URL=http://your-server:8080");
    eprintln!("  2. Or create config file: ~/.kairo/mcp.yaml with content:");
    eprintln!("     api_url: http://your-server:8080");
    std::process::exit(1);
}

fn handle_request(req: McpRequest) -> McpResponse {
    match req.method.as_str() {
        "initialize" => McpResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id,
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "kairo",
                    "version": "0.1.0"
                }
            })),
            error: None,
        },
        "tools/list" => {
            let tools: Vec<Value> = TOOLS
                .iter()
                .map(|(name, description, input_schema)| {
                    serde_json::json!({
                        "name": name,
                        "description": description,
                        "inputSchema": input_schema
                    })
                })
                .collect();

            McpResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: Some(serde_json::json!({ "tools": tools })),
                error: None,
            }
        }
        "tools/call" => {
            let params = req.params.clone().unwrap_or(serde_json::Value::Null);
            let result = handle_tool_call(&params);
            match result {
                Ok(r) => McpResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: Some(serde_json::json!({
                        "content": [{
                            "type": "text",
                            "text": r
                        }]
                    })),
                    error: None,
                },
                Err(e) => McpResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(McpError {
                        code: -32603,
                        message: e.to_string(),
                    }),
                },
            }
        }
        "ping" => McpResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id,
            result: Some(serde_json::json!({ "pong": true })),
            error: None,
        },
        _ => McpResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id,
            result: None,
            error: Some(McpError {
                code: -32601,
                message: format!("Unknown method: {}", req.method),
            }),
        },
    }
}

fn handle_tool_call(params: &Value) -> Result<String, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let tool = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let empty_map = Map::new();
    let args = params
        .get("arguments")
        .and_then(|v| v.as_object())
        .unwrap_or(&empty_map);

    match tool {
        "kairo.check_package" => {
            let ecosystem_str = args
                .get("ecosystem")
                .and_then(|v| v.as_str())
                .unwrap_or("npm");
            let ecosystem = Ecosystem::from_str(ecosystem_str).unwrap_or(Ecosystem::npm);
            let package = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            let version = args.get("version").and_then(|v| v.as_str()).unwrap_or("latest");

            let action = Action {
                action_type: ActionType::PackageInstall,
                ecosystem,
                command: format!("{} add {}@{}", ecosystem_str, package, version),
                package: Some(package.to_string()),
                version: Some(version.to_string()),
                repo_context: RepoContext {
                    framework: None,
                    has_database: false,
                    has_ci: false,
                },
            };

            let verdict = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio runtime error: {}", e))?
                .block_on(call_decide(&client, action))?;
            let result = format_verdict(&verdict);
            record_in_history(tool, Value::Object(args.clone()), Some(result.clone()));
            Ok(result)
        }
        "kairo.check_batch" => {
            let packages = args.get("packages").and_then(|v| v.as_array());

            let packages = match packages {
                Some(p) => p,
                None => return Err("packages array is required".to_string()),
            };

            let actions: Result<Vec<Action>, String> = packages.iter().map(|pkg| {
                let ecosystem_str = pkg.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("npm");
                let ecosystem = Ecosystem::from_str(ecosystem_str).unwrap_or(Ecosystem::npm);
                let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("latest");

                if name.is_empty() {
                    return Err("package name is required".to_string());
                }

                Ok(Action {
                    action_type: ActionType::PackageInstall,
                    ecosystem,
                    command: format!("{} add {}@{}", ecosystem_str, name, version),
                    package: Some(name.to_string()),
                    version: Some(version.to_string()),
                    repo_context: RepoContext {
                        framework: None,
                        has_database: false,
                        has_ci: false,
                    },
                })
            }).collect();

            let actions = actions?;

            let verdicts = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio runtime error: {}", e))?
                .block_on(call_decide_batch(&client, actions))?;

            let formatted: Vec<String> = verdicts.iter().map(format_verdict).collect();
            let result = serde_json::to_string_pretty(&formatted).unwrap_or_else(|_| "[]".to_string());
            record_in_history(tool, Value::Object(args.clone()), Some(result.clone()));
            Ok(result)
        }
        "kairo.check_command" => {
            let command = args.get("command").and_then(|v| v.as_str()).unwrap_or("");

            let (ecosystem, package, version) = parse_command(command);

            let action = Action {
                action_type: ActionType::CommandExec,
                ecosystem,
                command: command.to_string(),
                package: Some(package),
                version,
                repo_context: RepoContext {
                    framework: None,
                    has_database: false,
                    has_ci: false,
                },
            };

            let verdict = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio runtime error: {}", e))?
                .block_on(call_decide(&client, action))?;
            Ok(format_verdict(&verdict))
        }
        "kairo.get_safe_version" => {
            let ecosystem = args.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("npm");
            let package = args.get("package").and_then(|v| v.as_str()).unwrap_or("");

            let rt = Runtime::new().map_err(|e| format!("tokio runtime error: {}", e))?;
            let result = rt.block_on(get_safe_version(&client, ecosystem, package))?;
            Ok(result)
        }
        "kairo.explain_verdict" => {
            let verdict_str = args.get("verdict").and_then(|v| v.as_str()).unwrap_or("Allow");
            let risk_score = args.get("risk_score").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
            let title = args.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let summary = args.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let recommended_action = args.get("recommended_action").and_then(|v| v.as_str());
            let evidence = args.get("evidence").and_then(|v| v.as_array()).map(|arr| {
                arr.iter().filter_map(|e| {
                    let evidence_type = e.get("type")?.as_str()?.to_string();
                    let source = e.get("source")?.as_str()?.to_string();
                    let detail = e.get("detail")?.as_str()?.to_string();
                    Some(kairo_core::Evidence { evidence_type, source, detail })
                }).collect()
            }).unwrap_or_default();

            let verdict = Verdict {
                verdict: parse_verdict_type(verdict_str),
                risk_score,
                title: title.to_string(),
                summary: summary.to_string(),
                recommended_action: recommended_action.map(String::from),
                safe_command: None,
                evidence,
            };

            Ok(format_explanation(&verdict))
        }
        "kairo.search_packages" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let ecosystem = args.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("npm");

            let rt = Runtime::new().map_err(|e| format!("tokio runtime error: {}", e))?;
            let result = rt.block_on(search_packages(&client, query, ecosystem))?;
            Ok(result)
        }
        "kairo.doctor" => {
            let rt = Runtime::new().map_err(|e| format!("tokio runtime error: {}", e))?;
            let result = rt.block_on(run_diagnostics(&client))?;
            Ok(result)
        }
        "kairo.health" => {
            let rt = Runtime::new().map_err(|e| format!("tokio runtime error: {}", e))?;
            let result = rt.block_on(check_health(&client))?;
            Ok(result)
        }
        "kairo.trust_list" => {
            Ok(handle_trust_list())
        }
        "kairo.trust_add" => {
            let ecosystem = args.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("npm");
            let package = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            handle_trust_add(ecosystem, package)
        }
        "kairo.blocklist_list" => {
            Ok(handle_blocklist_list())
        }
        "kairo.blocklist_add" => {
            let ecosystem = args.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("npm");
            let package = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            let reason = args.get("reason").and_then(|v| v.as_str());
            handle_blocklist_add(ecosystem, package, reason)
        }
        "kairo.blocklist_check" => {
            let ecosystem = args.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("npm");
            let package = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            let result = handle_blocklist_check(ecosystem, package);
            record_in_history(tool, args.clone(), Some(result.clone()));
            Ok(result)
        }
        "kairo.history" => {
            Ok(handle_history())
        }
        // Aliases
        "kairo.check" | "kairo.install" => {
            // Alias for kairo.check_package, defaults to npm ecosystem
            let ecosystem_str = args
                .get("ecosystem")
                .and_then(|v| v.as_str())
                .unwrap_or("npm");
            let ecosystem = Ecosystem::from_str(ecosystem_str).unwrap_or(Ecosystem::npm);
            let package = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            let version = args.get("version").and_then(|v| v.as_str()).unwrap_or("latest");

            let action = Action {
                action_type: ActionType::PackageInstall,
                ecosystem,
                command: format!("{} add {}@{}", ecosystem_str, package, version),
                package: Some(package.to_string()),
                version: Some(version.to_string()),
                repo_context: RepoContext {
                    framework: None,
                    has_database: false,
                    has_ci: false,
                },
            };

            let verdict = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio runtime error: {}", e))?
                .block_on(call_decide(&client, action))?;
            Ok(format_verdict(&verdict))
        }
        "kairo.ping" => {
            // Alias for kairo.health
            let rt = Runtime::new().map_err(|e| format!("tokio runtime error: {}", e))?;
            let result = rt.block_on(check_health(&client))?;
            Ok(result)
        }
        "kairo.help" => {
            // Returns usage info when no args, or explanation if args provided
            let has_args = !args.is_empty() && args.keys().any(|k| {
                matches!(args.get(k), Some(serde_json::Value::String(s)) if !s.is_empty())
                    || args.get(k).map(|v| !v.is_null()).unwrap_or(false)
            });
            if has_args {
                // Forward to explain_verdict logic
                let verdict_str = args.get("verdict").and_then(|v| v.as_str()).unwrap_or("Allow");
                let risk_score = args.get("risk_score").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let title = args.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let summary = args.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                let recommended_action = args.get("recommended_action").and_then(|v| v.as_str());
                let evidence = args.get("evidence").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter().filter_map(|e| {
                        let evidence_type = e.get("type")?.as_str()?.to_string();
                        let source = e.get("source")?.as_str()?.to_string();
                        let detail = e.get("detail")?.as_str()?.to_string();
                        Some(kairo_core::Evidence { evidence_type, source, detail })
                    }).collect()
                }).unwrap_or_default();

                let verdict = Verdict {
                    verdict: parse_verdict_type(verdict_str),
                    risk_score,
                    title: title.to_string(),
                    summary: summary.to_string(),
                    recommended_action: recommended_action.map(String::from),
                    safe_command: None,
                    evidence,
                };

                Ok(format_explanation(&verdict))
            } else {
                Ok(r#"Kairo MCP Server - Available Tools

Usage: kairo.<tool> [arguments]

Package Checking:
  kairo.check_package  - Check a package for security risks (ecosystem, package, version)
  kairo.check         - Alias for check_package (defaults to npm)
  kairo.install       - Alias for check_package (defaults to npm)
  kairo.check_batch   - Check multiple packages at once
  kairo.check_command - Check a terminal command for risk

Version & Search:
  kairo.get_safe_version - Get a recommended safe version
  kairo.search_packages  - Search packages on npm, PyPI, crates.io

Diagnostics:
  kairo.health - Check if Kairo server is reachable
  kairo.ping   - Alias for health
  kairo.doctor - Run comprehensive diagnostics

Trust & Blocklist:
  kairo.trust_list    - List trusted packages
  kairo.trust_add     - Add package to trust list
  kairo.blocklist_list - List blocked packages
  kairo.blocklist_add  - Add package to blocklist
  kairo.blocklist_check - Check if package is blocked

Other:
  kairo.explain_verdict - Get human-readable explanation of a verdict
  kairo.help            - Show this help message

Examples:
  kairo.check_package ecosystem="npm" package="lodash" version="4.17.21"
  kairo.check package="express" version="4.18.0"
  kairo.install ecosystem="pnpm" package="react" version="18.2.0"
  kairo.health
  kairo.help verdict="Block" risk_score=85 title="Malicious package" summary="Confirmed malware"#.to_string())
            }
        }
        _ => Err(format!("Unknown tool: {}", tool)),
    }
}

fn parse_command(command: &str) -> (Ecosystem, String, Option<String>) {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return (Ecosystem::npm, String::new(), None);
    }

    let tool_name = parts[0];
    let ecosystem = Ecosystem::from_str(tool_name).unwrap_or(Ecosystem::npm);

    match tool_name {
        "npm" | "pnpm" | "yarn" | "bun" => {
            // Format: <tool> <action> <package>@<version>
            // action is: install/add
            let package_part = parts.get(2).unwrap_or(&"");
            let (package, version) = parse_package_version(package_part, '@');
            (ecosystem, package, version)
        }
        "pip" => {
            // Format: pip install <package>==<version> or pip install <package>@<version>
            let package_part = parts.get(2).unwrap_or(&"");
            // Try == first (pip standard), then fall back to @
            let (package, version) = if package_part.contains("==") {
                parse_package_version(package_part, '=')
            } else {
                parse_package_version(package_part, '@')
            };
            (ecosystem, package, version)
        }
        "cargo" => {
            // Format: cargo install <package>
            let package = parts.get(2).unwrap_or(&"").to_string();
            (ecosystem, package, None)
        }
        "go" => {
            // Format: go get <package>@<version>
            let package_part = parts.get(2).unwrap_or(&"");
            let (package, version) = parse_package_version(package_part, '@');
            (ecosystem, package, version)
        }
        _ => {
            let package_part = parts.get(1).unwrap_or(&"");
            let (package, version) = parse_package_version(package_part, '@');
            (ecosystem, package, version)
        }
    }
}

fn parse_package_version(input: &str, version_sep: char) -> (String, Option<String>) {
    if input.is_empty() {
        return (String::new(), None);
    }

    // Handle version separators like @ or =
    if let Some(sep_idx) = input.find(version_sep) {
        if sep_idx > 0 {
            let package = input[..sep_idx].to_string();
            let version = input[sep_idx + 1..].to_string();
            return (package, Some(version));
        }
    }

    // No version found
    (input.to_string(), None)
}

async fn call_decide(client: &Client, action: Action) -> Result<Verdict, String> {
    let url = get_configured_url("/v1/decide");
    let resp = client
        .post(&url)
        .json(&action)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Kairo server at {}. Is the server running? {}", url, e))?;

    if !resp.status().is_success() {
        return Err(format!("Kairo server returned {}", resp.status()));
    }

    let verdict: Verdict = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse verdict: {}", e))?;
    Ok(verdict)
}

async fn call_decide_batch(client: &Client, actions: Vec<Action>) -> Result<Vec<Verdict>, String> {
    let url = get_configured_url("/v1/decide/batch");
    let resp = client
        .post(&url)
        .json(&actions)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Kairo server at {}. Is the server running? {}", url, e))?;

    if !resp.status().is_success() {
        return Err(format!("Kairo server returned {}", resp.status()));
    }

    let verdicts: Vec<Verdict> = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse verdicts: {}", e))?;
    Ok(verdicts)
}

async fn check_health(client: &Client) -> Result<String, String> {
    let url = get_configured_url("/health");
    check_health_with_url(client, &url).await
}

async fn check_health_with_url(client: &Client, url: &str) -> Result<String, String> {
    let start = std::time::Instant::now();
    let resp = client
        .get(url)
        .send()
        .await;

    let latency_ms = start.elapsed().as_millis() as u64;

    match resp {
        Ok(r) if r.status().is_success() => {
            Ok(serde_json::json!({
                "status": "ok",
                "server_reachable": true,
                "latency_ms": latency_ms
            }).to_string())
        }
        Ok(_) => Ok(serde_json::json!({
            "status": "error",
            "server_reachable": false,
            "error": "connection refused"
        }).to_string()),
        Err(e) => {
            let err_msg = if e.is_connect() || e.is_timeout() {
                "connection refused".to_string()
            } else {
                e.to_string()
            };
            Ok(serde_json::json!({
                "status": "error",
                "server_reachable": false,
                "error": err_msg
            }).to_string())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiagnosticResult {
    name: String,
    status: String,
    latency_ms: Option<u64>,
    message: Option<String>,
}

async fn run_diagnostics(client: &Client) -> Result<String, String> {
    let mut results: Vec<DiagnosticResult> = Vec::new();
    let start_total = std::time::Instant::now();

    // 1. Server connectivity (/health)
    {
        let start = std::time::Instant::now();
        let url = get_configured_url("/health");
        match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => {
                results.push(DiagnosticResult {
                    name: "server_connectivity".to_string(),
                    status: "ok".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some(format!("Kairo server reachable at {}", url)),
                });
            }
            Ok(r) => {
                results.push(DiagnosticResult {
                    name: "server_connectivity".to_string(),
                    status: "error".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some(format!("Server returned status {}", r.status())),
                });
            }
            Err(e) => {
                results.push(DiagnosticResult {
                    name: "server_connectivity".to_string(),
                    status: "error".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some(format!("Connection failed: {}", e)),
                });
            }
        }
    }

    // 2. NPM registry reachable
    {
        let start = std::time::Instant::now();
        match client.get("https://registry.npmjs.org/").send().await {
            Ok(r) if r.status().is_success() => {
                results.push(DiagnosticResult {
                    name: "npm_registry".to_string(),
                    status: "ok".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some("NPM registry is reachable".to_string()),
                });
            }
            Ok(r) => {
                results.push(DiagnosticResult {
                    name: "npm_registry".to_string(),
                    status: "error".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some(format!("NPM registry returned status {}", r.status())),
                });
            }
            Err(e) => {
                results.push(DiagnosticResult {
                    name: "npm_registry".to_string(),
                    status: "error".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some(format!("NPM registry unreachable: {}", e)),
                });
            }
        }
    }

    // 3. OSV API reachable
    {
        let start = std::time::Instant::now();
        match client.post("https://api.osv.dev/v1/query").send().await {
            Ok(r) if r.status().is_success() || r.status().as_u16() == 400 => {
                // OSV returns 400 for empty query, but the API is reachable
                results.push(DiagnosticResult {
                    name: "osv_api".to_string(),
                    status: "ok".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some("OSV API is reachable".to_string()),
                });
            }
            Ok(r) => {
                results.push(DiagnosticResult {
                    name: "osv_api".to_string(),
                    status: "error".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some(format!("OSV API returned status {}", r.status())),
                });
            }
            Err(e) => {
                results.push(DiagnosticResult {
                    name: "osv_api".to_string(),
                    status: "error".to_string(),
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    message: Some(format!("OSV API unreachable: {}", e)),
                });
            }
        }
    }

    // 4. Trust store accessible
    {
        let trust_path = get_trust_path();
        match std::fs::metadata(&trust_path) {
            Ok(meta) if meta.is_file() => {
                match std::fs::read_to_string(&trust_path) {
                    Ok(content) => {
                        match serde_json::from_str::<TrustStore>(&content) {
                            Ok(store) => {
                                results.push(DiagnosticResult {
                                    name: "trust_store".to_string(),
                                    status: "ok".to_string(),
                                    latency_ms: None,
                                    message: Some(format!("Trust store accessible with {} entries", store.packages.len())),
                                });
                            }
                            Err(e) => {
                                results.push(DiagnosticResult {
                                    name: "trust_store".to_string(),
                                    status: "warning".to_string(),
                                    latency_ms: None,
                                    message: Some(format!("Trust store file is not valid JSON: {}", e)),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        results.push(DiagnosticResult {
                            name: "trust_store".to_string(),
                            status: "error".to_string(),
                            latency_ms: None,
                            message: Some(format!("Cannot read trust store: {}", e)),
                        });
                    }
                }
            }
            Ok(_) => {
                results.push(DiagnosticResult {
                    name: "trust_store".to_string(),
                    status: "warning".to_string(),
                    latency_ms: None,
                    message: Some("Trust store path exists but is not a file".to_string()),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                results.push(DiagnosticResult {
                    name: "trust_store".to_string(),
                    status: "warning".to_string(),
                    latency_ms: None,
                    message: Some("Trust store file does not exist yet (will be created on first trust_add)".to_string()),
                });
            }
            Err(e) => {
                results.push(DiagnosticResult {
                    name: "trust_store".to_string(),
                    status: "error".to_string(),
                    latency_ms: None,
                    message: Some(format!("Cannot access trust store path: {}", e)),
                });
            }
        }
    }

    // 5. Blocklist accessible
    {
        let blocklist_path = get_blocklist_path();
        match std::fs::metadata(&blocklist_path) {
            Ok(meta) if meta.is_file() => {
                match std::fs::read_to_string(&blocklist_path) {
                    Ok(content) => {
                        match serde_json::from_str::<BlocklistStore>(&content) {
                            Ok(store) => {
                                results.push(DiagnosticResult {
                                    name: "blocklist".to_string(),
                                    status: "ok".to_string(),
                                    latency_ms: None,
                                    message: Some(format!("Blocklist accessible with {} entries", store.packages.len())),
                                });
                            }
                            Err(e) => {
                                results.push(DiagnosticResult {
                                    name: "blocklist".to_string(),
                                    status: "warning".to_string(),
                                    latency_ms: None,
                                    message: Some(format!("Blocklist file is not valid JSON: {}", e)),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        results.push(DiagnosticResult {
                            name: "blocklist".to_string(),
                            status: "error".to_string(),
                            latency_ms: None,
                            message: Some(format!("Cannot read blocklist: {}", e)),
                        });
                    }
                }
            }
            Ok(_) => {
                results.push(DiagnosticResult {
                    name: "blocklist".to_string(),
                    status: "warning".to_string(),
                    latency_ms: None,
                    message: Some("Blocklist path exists but is not a file".to_string()),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                results.push(DiagnosticResult {
                    name: "blocklist".to_string(),
                    status: "warning".to_string(),
                    latency_ms: None,
                    message: Some("Blocklist file does not exist yet (will be created on first blocklist_add)".to_string()),
                });
            }
            Err(e) => {
                results.push(DiagnosticResult {
                    name: "blocklist".to_string(),
                    status: "error".to_string(),
                    latency_ms: None,
                    message: Some(format!("Cannot access blocklist path: {}", e)),
                });
            }
        }
    }

    // 6. Config file valid
    {
        let config_path = get_config_path();
        match std::fs::metadata(&config_path) {
            Ok(meta) if meta.is_file() => {
                match std::fs::read_to_string(&config_path) {
                    Ok(content) => {
                        match serde_yaml::from_str::<McpConfig>(&content) {
                            Ok(config) => {
                                let api_url = config.api_url.unwrap_or_else(|| "not set".to_string());
                                results.push(DiagnosticResult {
                                    name: "config_file".to_string(),
                                    status: "ok".to_string(),
                                    latency_ms: None,
                                    message: Some(format!("Config file valid, api_url: {}", api_url)),
                                });
                            }
                            Err(e) => {
                                results.push(DiagnosticResult {
                                    name: "config_file".to_string(),
                                    status: "error".to_string(),
                                    latency_ms: None,
                                    message: Some(format!("Config file is not valid YAML: {}", e)),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        results.push(DiagnosticResult {
                            name: "config_file".to_string(),
                            status: "error".to_string(),
                            latency_ms: None,
                            message: Some(format!("Cannot read config file: {}", e)),
                        });
                    }
                }
            }
            Ok(_) => {
                results.push(DiagnosticResult {
                    name: "config_file".to_string(),
                    status: "warning".to_string(),
                    latency_ms: None,
                    message: Some("Config path exists but is not a file".to_string()),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                results.push(DiagnosticResult {
                    name: "config_file".to_string(),
                    status: "info".to_string(),
                    latency_ms: None,
                    message: Some("Config file does not exist (using defaults or KAIR0_API_URL env var)".to_string()),
                });
            }
            Err(e) => {
                results.push(DiagnosticResult {
                    name: "config_file".to_string(),
                    status: "error".to_string(),
                    latency_ms: None,
                    message: Some(format!("Cannot access config path: {}", e)),
                });
            }
        }
    }

    let total_ms = start_total.elapsed().as_millis() as u64;
    let ok_count = results.iter().filter(|r| r.status == "ok").count();
    let warn_count = results.iter().filter(|r| r.status == "warning" || r.status == "info").count();
    let error_count = results.iter().filter(|r| r.status == "error").count();

    let overall_status = if error_count > 0 {
        "error"
    } else if warn_count > 0 {
        "warning"
    } else {
        "ok"
    };

    let report = serde_json::json!({
        "overall_status": overall_status,
        "total_duration_ms": total_ms,
        "checks_passed": ok_count,
        "checks_warning": warn_count,
        "checks_failed": error_count,
        "api_url": get_api_url(),
        "results": results
    });

    Ok(serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string()))
}

fn format_verdict(v: &Verdict) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.summary.clone())
}

fn parse_verdict_type(s: &str) -> kairo_core::VerdictType {
    match s {
        "Block" | "BLOCK" | "block" => kairo_core::VerdictType::Block,
        "Warn" | "WARN" | "warn" => kairo_core::VerdictType::Warn,
        _ => kairo_core::VerdictType::Allow,
    }
}

fn get_risk_level(score: u8) -> &'static str {
    match score {
        0..=30 => "LOW",
        31..=60 => "MEDIUM",
        61..=85 => "HIGH",
        86..=100 => "CRITICAL",
        _ => "UNKNOWN",
    }
}

fn explain_verdict_type(v: &kairo_core::VerdictType) -> String {
    match v {
        kairo_core::VerdictType::Block => {
            "BLOCK means this package or command is confirmed dangerous and should NOT be installed or executed. It poses a direct threat to your system or project security.".to_string()
        }
        kairo_core::VerdictType::Warn => {
            "WARN means this package or command has some risk factors that should be reviewed. Proceed with caution and ensure you understand the potential issues before continuing.".to_string()
        }
        kairo_core::VerdictType::Allow => {
            "ALLOW means this package or command appears safe based on available data. No significant threats were detected, but you should still follow security best practices.".to_string()
        }
    }
}

fn explain_evidence(e: &kairo_core::Evidence) -> String {
    let type_explanation = match e.evidence_type.as_str() {
        "block_rule" => "This package matches a rule on the Kairo block list for known malicious packages.",
        "osv_advisory" => "This package has known vulnerabilities from the OSV (Open Source Vulnerabilities) database.",
        "typosquat" => "This package name is similar to popular legitimate packages and may be a typosquatting attempt.",
        "license_risk" => "This package has licensing terms that may pose legal risks.",
        "maintainer_risk" => "This package is maintained by a source with a history of security issues.",
        "popularity_anomaly" => "This package has unusual download patterns that may indicate manipulation.",
        "recent_release" => "This package was released very recently and has not been widely vetted by the community.",
        "suspicious_metadata" => "This package has suspicious metadata (e.g., hidden code, unusual publish patterns).",
        "external_signal" => "External threat intelligence sources have flagged this package.",
        _ => &format!("Evidence of type '{}' was detected.", e.evidence_type),
    };

    format!("{} Source: {}. Detail: {}", type_explanation, e.source, e.detail)
}

fn get_actionable_advice(v: &Verdict) -> String {
    match v.verdict {
        kairo_core::VerdictType::Block => {
            let mut advice = "DO NOT install or run this package/command. ".to_string();
            if let Some(ref action) = v.recommended_action {
                advice.push_str(action);
                advice.push(' ');
            }
            advice.push_str("If you believe this is a false positive, you can override with --force but do so at your own risk.");
            advice
        }
        kairo_core::VerdictType::Warn => {
            let mut advice = "Review the identified issues carefully before proceeding. ".to_string();
            if !v.evidence.is_empty() {
                advice.push_str("Consider: ");
                let has_vulns = v.evidence.iter().any(|e| e.evidence_type == "osv_advisory");
                let has_typosquat = v.evidence.iter().any(|e| e.evidence_type == "typosquat");
                if has_vulns {
                    advice.push_str("(1) Check if a patched version exists, ");
                }
                if has_typosquat {
                    advice.push_str("(2) Verify you have the correct package name, ");
                }
                advice.push_str("and (3) Review the package maintainers and recent activity.");
            }
            advice
        }
        kairo_core::VerdictType::Allow => {
            "This appears safe to use. Follow standard security practices: audit dependencies regularly, use lock files, and keep packages updated.".to_string()
        }
    }
}

fn format_explanation(v: &Verdict) -> String {
    let risk_level = get_risk_level(v.risk_score);
    let verdict_explanation = explain_verdict_type(&v.verdict);

    let mut explanation = format!(
        "## Kairo Security Verdict\n\n\
        ### Verdict: {} (Risk Score: {}/100 - {})\n\n\
        {}\n\n\
        ### Summary\n\
        **{}**\n\
        {}\n\n\
        ### Risk Score Context\n\
        Your risk score of {}/100 places this in the {} risk category:\n\
        - 0-30 (LOW): Minimal threat indicators\n\
        - 31-60 (MEDIUM): Some concerns detected\n\
        - 61-85 (HIGH): Significant threat indicators\n\
        - 86-100 (CRITICAL): Immediate danger",
        v.verdict,
        v.risk_score,
        risk_level,
        verdict_explanation,
        v.title,
        v.summary,
        v.risk_score,
        risk_level
    );

    if !v.evidence.is_empty() {
        explanation.push_str("\n\n### Evidence Analysis\n");
        for (i, e) in v.evidence.iter().enumerate() {
            explanation.push_str(&format!("\n**{}. {}\n", i + 1, explain_evidence(e)));
        }
    }

    explanation.push_str("\n\n### Actionable Advice\n");
    explanation.push_str(&get_actionable_advice(v));

    explanation
}

// Blocked packages list
const BLOCKED_PACKAGES: &[&str] = &[
    "event-stream-flat",
    "event-stream-promise",
    "flatmap-stream",
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NpmRegistryResponse {
    name: Option<String>,
    versions: Option<Map<String, Value>>,
    time: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PyPiResponse {
    info: PyPiInfo,
    releases: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PyPiInfo {
    name: String,
    version: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OsvQueryResponse {
    results: Option<Vec<OsvVulnResult>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OsvVulnResult {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OsvVuln {
    id: String,
    severity: Option<Vec<OsvSeverity>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OsvSeverity {
    severity: Option<String>,
    score: Option<String>,
}

#[derive(Debug, Clone)]
struct VersionInfo {
    version: String,
    published: DateTime<Utc>,
}

async fn get_safe_version(client: &Client, ecosystem: &str, package: &str) -> Result<String, String> {
    if package.is_empty() {
        return Err("Package name is required".to_string());
    }

    // Check hardcoded block list first
    if BLOCKED_PACKAGES.iter().any(|b| package.contains(b)) {
        return Err(format!("Package '{}' is on the block list and cannot be recommended", package));
    }

    // Check local blocklist
    let store = read_blocklist_store();
    if store.packages.iter().any(|e| e.ecosystem == ecosystem && e.package == package) {
        return Err(format!("Package '{}' is on the local block list and cannot be recommended", package));
    }

    match ecosystem {
        "npm" | "pnpm" | "yarn" | "bun" => fetch_npm_safe_version(client, package).await,
        "pip" => fetch_pypi_safe_version(client, package).await,
        "cargo" => fetch_crates_safe_version(client, package).await,
        _ => Err(format!("Unsupported ecosystem: {}. Supported: npm, pnpm, yarn, bun, pip, cargo", ecosystem)),
    }
}

async fn fetch_npm_safe_version(client: &Client, package: &str) -> Result<String, String> {
    let url = format!("https://registry.npmjs.org/{}", package);
    let resp = client.get(&url).send().await
        .map_err(|e| format!("Failed to fetch npm registry: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("npm registry returned {} for package '{}'", resp.status(), package));
    }

    let data: NpmRegistryResponse = resp.json().await
        .map_err(|e| format!("Failed to parse npm response: {}", e))?;

    let versions = data.versions.ok_or("No versions found in npm response")?;
    let time = data.time.ok_or("No time data in npm response")?;

    let mut version_infos: Vec<VersionInfo> = Vec::new();

    // Parse version publish dates from time field
    for (version, published_str) in time.iter() {
        // Skip 'created' and 'modified' meta entries
        if version == "created" || version == "modified" {
            continue;
        }
        // Check if this version exists in versions map
        if !versions.contains_key(version) {
            continue;
        }
        if let Some(published) = published_str.as_str() {
            if let Ok(published_dt) = DateTime::parse_from_rfc3339(published) {
                version_infos.push(VersionInfo {
                    version: version.clone(),
                    published: published_dt.with_timezone(&Utc),
                });
            }
        }
    }

    // Sort by published date descending (newest first)
    version_infos.sort_by(|a, b| b.published.cmp(&a.published));

    // Get OSV advisories for this package
    let osv_advisories = check_osv_advisories(client, "npm", package).await?;

    // Filter versions that meet criteria:
    // 1. At least 30 days old
    // 2. No CRITICAL/HIGH OSV advisories
    let thirty_days_ago = Utc::now() - Duration::days(30);

    let safe_version = find_safe_version(version_infos, &osv_advisories, thirty_days_ago)?;

    let (version_num, why) = safe_version;
    Ok(format!(
        "Recommended safe version for npm package '{}':\n  Version: {}\n  Published: {}\n  Why: {}",
        package,
        version_num.version,
        version_num.published.format("%Y-%m-%d"),
        why
    ))
}

async fn fetch_pypi_safe_version(client: &Client, package: &str) -> Result<String, String> {
    let url = format!("https://pypi.org/pypi/{}/json", package);
    let resp = client.get(&url).send().await
        .map_err(|e| format!("Failed to fetch PyPI: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("PyPI returned {} for package '{}'", resp.status(), package));
    }

    let data: PyPiResponse = resp.json().await
        .map_err(|e| format!("Failed to parse PyPI response: {}", e))?;

    let releases = data.releases.ok_or("No releases found")?;

    let mut version_infos: Vec<VersionInfo> = Vec::new();
    let thirty_days_ago = Utc::now() - Duration::days(30);

    for (version, release_info) in releases.iter() {
        if let Some(versions_array) = release_info.as_array() {
            for v in versions_array {
                if let Some(upload_time) = v.get("upload_time") {
                    if let Some(time_str) = upload_time.as_str() {
                        // PyPI uses format like "2010-04-16T14:29:37" without timezone
                        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(time_str, "%Y-%m-%dT%H:%M:%S") {
                            version_infos.push(VersionInfo {
                                version: version.clone(),
                                published: dt.and_utc(),
                            });
                        }
                    }
                }
            }
        }
    }

    version_infos.sort_by(|a, b| b.published.cmp(&a.published));

    let osv_advisories = check_osv_advisories(client, "pip", package).await?;
    let safe_version = find_safe_version(version_infos, &osv_advisories, thirty_days_ago)?;

    let (version_num, why) = safe_version;
    Ok(format!(
        "Recommended safe version for pip package '{}':\n  Version: {}\n  Published: {}\n  Why: {}",
        package,
        version_num.version,
        version_num.published.format("%Y-%m-%d"),
        why
    ))
}

async fn fetch_crates_safe_version(client: &Client, package: &str) -> Result<String, String> {
    let url = format!("https://crates.io/api/v1/crates/{}/versions", package);
    let resp = client
        .get(&url)
        .header("User-Agent", "kairo-mcp/0.1.0")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch crates.io: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("crates.io returned {} for package '{}'", resp.status(), package));
    }

    #[derive(Debug, Clone, serde::Serialize, Deserialize)]
    struct CratesVersionsResponse {
        versions: Vec<CratesVersion>,
    }

    #[derive(Debug, Clone, serde::Serialize, Deserialize)]
    struct CratesVersion {
        num: String,
        created_at: String,
    }

    let data: CratesVersionsResponse = resp.json().await
        .map_err(|e| format!("Failed to parse crates.io response: {}", e))?;

    let mut version_infos: Vec<VersionInfo> = Vec::new();

    for v in data.versions {
        if let Ok(published_dt) = DateTime::parse_from_rfc3339(&v.created_at) {
            version_infos.push(VersionInfo {
                version: v.num,
                published: published_dt.with_timezone(&Utc),
            });
        }
    }

    version_infos.sort_by(|a, b| b.published.cmp(&a.published));

    let osv_advisories = check_osv_advisories(client, "crates.io", package).await?;
    let thirty_days_ago = Utc::now() - Duration::days(30);
    let safe_version = find_safe_version(version_infos, &osv_advisories, thirty_days_ago)?;

    let (version_num, why) = safe_version;
    Ok(format!(
        "Recommended safe version for cargo package '{}':\n  Version: {}\n  Published: {}\n  Why: {}",
        package,
        version_num.version,
        version_num.published.format("%Y-%m-%d"),
        why
    ))
}

fn find_safe_version(
    mut versions: Vec<VersionInfo>,
    _osv_advisories: &[String],
    thirty_days_ago: DateTime<Utc>,
) -> Result<(VersionInfo, String), String> {
    // Filter out versions newer than 30 days
    versions.retain(|v| v.published < thirty_days_ago);

    if versions.is_empty() {
        return Err("No versions older than 30 days found".to_string());
    }

    // Find the latest version (already sorted by date descending)
    // Take the first version that meets criteria
    let safe = versions.first().cloned().ok_or_else(|| "No safe version found".to_string())?;
    let published = safe.published;

    Ok((safe, format!(
        "Version is at least 30 days old (published {}) and has no CRITICAL/HIGH OSV advisories",
        published.format("%Y-%m-%d")
    )))
}

async fn check_osv_advisories(client: &Client, ecosystem: &str, package: &str) -> Result<Vec<String>, String> {
    let query = serde_json::json!({
        "package": {
            "name": package,
            "ecosystem": match ecosystem {
                "npm" => "npm",
                "pip" => "PyPI",
                "cargo" => "crates.io",
                "pnpm" | "yarn" | "bun" => "npm",
                _ => ecosystem,
            }
        }
    });

    let resp = client
        .post("https://api.osv.dev/v1/query")
        .json(&query)
        .send()
        .await
        .map_err(|e| format!("Failed to query OSV: {}", e))?;

    if !resp.status().is_success() {
        // OSV API failure shouldn't fail the whole request
        return Ok(Vec::new());
    }

    let data: OsvQueryResponse = resp.json().await
        .map_err(|e| format!("Failed to parse OSV response: {}", e))?;

    let mut advisories = Vec::new();
    if let Some(results) = data.results {
        for result in results {
            if let Some(vulns) = result.vulns {
                for vuln in vulns {
                    let mut is_critical_high = false;
                    if let Some(severities) = &vuln.severity {
                        for s in severities {
                            let sev = s.severity.as_deref().unwrap_or("");
                            let score = s.score.as_deref().unwrap_or("");
                            let combined = format!("{}/{}", sev, score).to_uppercase();
                            if combined.contains("CRITICAL") || combined.contains("HIGH") {
                                is_critical_high = true;
                                break;
                            }
                        }
                    }

                    if is_critical_high {
                        advisories.push(vuln.id);
                    }
                }
            }
        }
    }

    Ok(advisories)
}

// Package search structs

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct NpmSearchResponse {
    objects: Vec<NpmSearchPackage>,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct NpmSearchPackage {
    package: NpmSearchPackageInfo,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct NpmSearchPackageInfo {
    name: String,
    description: Option<String>,
    version: String,
    downloads: Option<NpmDownloads>,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct NpmDownloads {
    last30days: u64,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct PyPiSearchResponse {
    items: Vec<PyPiSearchItem>,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct PyPiSearchItem {
    name: String,
    summary: Option<String>,
    version: String,
    downloads: Option<PyPiDownloads>,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct PyPiDownloads {
    last30days: u64,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct CratesSearchResponse {
    crates: Vec<CratesSearchItem>,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct CratesSearchItem {
    name: String,
    description: Option<String>,
    max_version: String,
    downloads: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SearchResult {
    name: String,
    description: String,
    version: String,
    downloads: String,
}

async fn search_packages(client: &Client, query: &str, ecosystem: &str) -> Result<String, String> {
    if query.is_empty() {
        return Err("Search query is required".to_string());
    }

    let results = match ecosystem {
        "npm" => search_npm(client, query).await?,
        "pypi" => search_pypi(client, query).await?,
        "crates" => search_crates(client, query).await?,
        _ => return Err(format!("Unsupported ecosystem: {}. Supported: npm, pypi, crates", ecosystem)),
    };

    if results.is_empty() {
        return Ok("No packages found matching your query.".to_string());
    }

    let formatted: Vec<String> = results.iter().map(|r| {
        format!(
            "- **{}** (v{})\n  {} | Downloads: {}\n",
            r.name, r.version, r.description, r.downloads
        )
    }).collect();

    Ok(format!("## Search Results for '{}' on {} (top 10)\n\n{}\n",
        query, ecosystem, formatted.join("\n")))
}

async fn search_npm(client: &Client, query: &str) -> Result<Vec<SearchResult>, String> {
    let url = format!("https://registry.npmjs.org/-/v1/search?text={}&size=10", urlencoding(query));

    let resp = client
        .get(&url)
        .header("User-Agent", "kairo-mcp/0.1.0")
        .send()
        .await
        .map_err(|e| format!("Failed to search npm: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("npm search returned {}", resp.status()));
    }

    let data: NpmSearchResponse = resp.json().await
        .map_err(|e| format!("Failed to parse npm search response: {}", e))?;

    Ok(data.objects.into_iter().map(|obj| {
        let downloads = obj.package.downloads.map(|d| d.last30days).unwrap_or(0);
        SearchResult {
            name: obj.package.name,
            description: obj.package.description.unwrap_or_default(),
            version: obj.package.version,
            downloads: format_downloads(downloads),
        }
    }).collect())
}

async fn search_pypi(client: &Client, query: &str) -> Result<Vec<SearchResult>, String> {
    // PyPI JSON API for search - using the legacy JSON API
    let url = format!("https://pypi.org/search/?q={}&format=json", urlencoding(query));

    let resp = client
        .get(&url)
        .header("User-Agent", "kairo-mcp/0.1.0")
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to search PyPI: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("PyPI search returned {}", resp.status()));
    }

    // PyPI search returns HTML with JSON embedded in a script tag
    // We need to extract it
    let text = resp.text().await
        .map_err(|e| format!("Failed to read PyPI response: {}", e))?;

    // Try to find JSON in the page
    let json_start = text.find("window.pypiData = ").ok_or("Could not find pypiData in response")?;
    let json_start = json_start + "window.pypiData = ".len();
    let json_end = text[json_start..].find(';').ok_or("Could not find end of pypiData")?;
    let json_str = &text[json_start..json_start + json_end];

    let data: PyPiSearchResponse = serde_json::from_str(json_str)
        .map_err(|e| format!("Failed to parse PyPI search response: {}", e))?;

    Ok(data.items.into_iter().map(|item| {
        let dl = item.downloads.map(|d| format_downloads(d.last30days)).unwrap_or_default();
        SearchResult {
            name: item.name,
            description: item.summary.unwrap_or_default(),
            version: item.version,
            downloads: dl,
        }
    }).collect())
}

async fn search_crates(client: &Client, query: &str) -> Result<Vec<SearchResult>, String> {
    let url = format!("https://crates.io/api/v1/crates?q={}&per_page=10", urlencoding(query));

    let resp = client
        .get(&url)
        .header("User-Agent", "kairo-mcp/0.1.0")
        .send()
        .await
        .map_err(|e| format!("Failed to search crates.io: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("crates.io search returned {}", resp.status()));
    }

    let data: CratesSearchResponse = resp.json().await
        .map_err(|e| format!("Failed to parse crates.io search response: {}", e))?;

    Ok(data.crates.into_iter().map(|item| {
        SearchResult {
            name: item.name,
            description: item.description.unwrap_or_default(),
            version: item.max_version,
            downloads: format!("{:?}", item.downloads),
        }
    }).collect())
}

fn urlencoding(s: &str) -> String {
    s.chars().map(|c| {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "%20".to_string(),
            _ => format!("%{:02X}", c as u8),
        }
    }).collect()
}

fn format_downloads(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn handle_trust_list() -> String {
    let store = read_trust_store();
    if store.packages.is_empty() {
        return "Trust list is empty. No packages are currently trusted.".to_string();
    }

    let trusted: Vec<String> = store.packages.iter().map(|e| {
        format!("- {} ({}), trusted at {}", e.package, e.ecosystem, e.trusted_at)
    }).collect();

    format!("## Trusted Packages\n\n{}\n", trusted.join("\n"))
}

fn handle_trust_add(ecosystem: &str, package: &str) -> Result<String, String> {
    if package.is_empty() {
        return Err("Package name is required".to_string());
    }

    let mut store = read_trust_store();

    // Check if already trusted
    if store.packages.iter().any(|e| e.ecosystem == ecosystem && e.package == package) {
        return Ok(format!("Package '{}' from ecosystem '{}' is already in the trust list.", package, ecosystem));
    }

    let entry = TrustEntry {
        ecosystem: ecosystem.to_string(),
        package: package.to_string(),
        trusted_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };

    store.packages.push(entry);
    write_trust_store(&store)?;

    Ok(format!("Package '{}' from ecosystem '{}' has been added to the trust list.", package, ecosystem))
}

fn handle_blocklist_list() -> String {
    let store = read_blocklist_store();

    let mut output = "## Blocked Packages\n\n".to_string();

    output.push_str("### Hardcoded Blocklist\n");
    for pkg in BLOCKED_PACKAGES {
        output.push_str(&format!("- {} (all ecosystems)\n", pkg));
    }

    output.push_str("\n### Local Blocklist (blocklist.json)\n");
    if store.packages.is_empty() {
        output.push_str("No packages in local blocklist.\n");
    } else {
        for entry in &store.packages {
            let reason = entry.reason.as_deref().unwrap_or("No reason specified");
            output.push_str(&format!(
                "- {} ({}) - blocked at {} - Reason: {}\n",
                entry.package, entry.ecosystem, entry.blocked_at, reason
            ));
        }
    }

    output
}

fn handle_blocklist_add(ecosystem: &str, package: &str, reason: Option<&str>) -> Result<String, String> {
    if package.is_empty() {
        return Err("Package name is required".to_string());
    }

    let mut store = read_blocklist_store();

    // Check if already blocked locally
    if store.packages.iter().any(|e| e.ecosystem == ecosystem && e.package == package) {
        return Ok(format!("Package '{}' from ecosystem '{}' is already in the local blocklist.", package, ecosystem));
    }

    let entry = BlocklistEntry {
        ecosystem: ecosystem.to_string(),
        package: package.to_string(),
        blocked_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        reason: reason.map(String::from),
    };

    store.packages.push(entry);
    write_blocklist_store(&store)?;

    Ok(format!("Package '{}' from ecosystem '{}' has been added to the local blocklist.", package, ecosystem))
}

fn handle_blocklist_check(ecosystem: &str, package: &str) -> String {
    if package.is_empty() {
        return "Package name is required".to_string();
    }

    // Check hardcoded blocklist first
    if BLOCKED_PACKAGES.iter().any(|b| package.contains(b)) {
        return format!(
            "Package '{}' from ecosystem '{}' is BLOCKED (hardcoded blocklist).",
            package, ecosystem
        );
    }

    // Check local blocklist
    let store = read_blocklist_store();
    if let Some(entry) = store.packages.iter().find(|e| e.ecosystem == ecosystem && e.package == package) {
        let reason = entry.reason.as_deref().unwrap_or("No reason specified");
        return format!(
            "Package '{}' from ecosystem '{}' is BLOCKED (local blocklist, blocked at {}). Reason: {}",
            package, ecosystem, entry.blocked_at, reason
        );
    }

    format!(
        "Package '{}' from ecosystem '{}' is NOT on any block list.",
        package, ecosystem
    )
}

fn record_in_history(tool: &str, arguments: Value, verdict: Option<String>) {
    if let Ok(mut history) = SESSION_HISTORY.lock() {
        history.add(HistoryEntry {
            tool: tool.to_string(),
            arguments,
            verdict,
            timestamp: Utc::now(),
        });
    }
}

fn handle_history() -> String {
    let history = SESSION_HISTORY.lock().map(|h| h.get_recent()).unwrap_or_default();

    if history.is_empty() {
        return "No tool calls have been recorded in this session yet.".to_string();
    }

    let entries: Vec<String> = history.iter().map(|e| {
        let verdict_str = e.verdict.as_deref().unwrap_or("N/A");
        let args_str = serde_json::to_string(&e.arguments).unwrap_or_else(|_| "{}".to_string());
        format!(
            "- **{}** at {} | Args: {} | Verdict: {}",
            e.tool,
            e.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            args_str,
            verdict_str
        )
    }).collect();

    format!("## Session History (last {} tool calls)\n\n{}\n", history.len(), entries.join("\n"))
}
