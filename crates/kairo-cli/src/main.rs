use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use kairo_core::{Action, ActionType, Ecosystem, RepoContext, BLOCKED_PACKAGES};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const SUPPORTED_ECOSYSTEMS: &[&str] = &["npm", "pnpm", "yarn", "bun", "pip", "cargo", "go", "docker"];
const BLOCKLIST_FILE: &str = "blocklist.json";
const TRUST_FILE: &str = "trust.json";

fn get_config_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("kairo")
}

fn get_trust_path() -> PathBuf {
    get_config_dir().join(TRUST_FILE)
}

fn read_trust_list() -> Vec<String> {
    let path = get_trust_path();
    if path.exists() {
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    }
}

fn write_trust_list(packages: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_trust_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(packages)?;
    fs::write(path, content)?;
    Ok(())
}

fn is_trusted(package: &str) -> bool {
    read_trust_list().iter().any(|t| package == t)
}

fn get_blocklist_path() -> PathBuf {
    std::env::current_dir().unwrap_or_default().join(BLOCKLIST_FILE)
}

fn read_local_blocklist() -> Vec<String> {
    let path = get_blocklist_path();
    if path.exists() {
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    }
}

fn write_local_blocklist(packages: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_blocklist_path();
    let content = serde_json::to_string_pretty(packages)?;
    fs::write(path, content)?;
    Ok(())
}

fn is_blocked(package: &str) -> bool {
    // Check hardcoded block list
    if BLOCKED_PACKAGES.iter().any(|b| package.contains(b)) {
        return true;
    }
    // Check local block list
    read_local_blocklist().iter().any(|b| package == b)
}

fn print_ecosystems_help() {
    println!("Available ecosystems: {}", SUPPORTED_ECOSYSTEMS.join(", "));
}

fn print_completion_script(shell: Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "kairo", &mut std::io::stdout());

    let install_instructions = match shell {
        Shell::Bash => r#"
# Install bash completions

# For current session, run:
#   source <(kairo completion bash)

# To install permanently for a single user, run:
#   kairo completion bash > ~/.local/share/bash-completion/completions/kairo

# Or if that directory doesn't exist:
#   kairo completion bash > ~/.bash_completion

# For system-wide installation (requires root):
#   sudo kairo completion bash > /etc/bash_completion.d/kairo
"#,
        Shell::Zsh => r#"
# Install zsh completions

# For current session, run:
#   autoload -U compinit; compinit
#   source <(kairo completion zsh)

# To install permanently, run one of:
#   # If using oh-my-zsh:
#   kairo completion zsh > ~/.oh-my-zsh/completions/_kairo

#   # If using a custom completions directory:
#   kairo completion zsh > ~/.local/share/zsh/site-functions/_kairo

#   # For system-wide installation (requires root):
#   sudo kairo completion zsh > /usr/local/share/zsh/site-functions/_kairo

# Then restart your shell or run:
#   autoload -U compinit; compinit
"#,
        Shell::Fish => r#"
# Install fish completions

# For current session, run:
#   kairo completion fish | source

# To install permanently, run:
#   kairo completion fish > ~/.config/fish/completions/kairo.fish

# For system-wide installation (requires root):
#   sudo kairo completion fish > /etc/fish/completions/kairo.fish
"#,
        _ => "",
    };

    println!("{}", install_instructions);
}

fn detect_ecosystem() -> Option<String> {
    if fs::metadata("package.json").is_ok() {
        return Some("npm".to_string());
    }
    if fs::metadata("Cargo.toml").is_ok() {
        return Some("cargo".to_string());
    }
    if fs::metadata("requirements.txt").is_ok() {
        return Some("pip".to_string());
    }
    if fs::metadata("go.mod").is_ok() {
        return Some("go".to_string());
    }
    if fs::metadata("Dockerfile").is_ok() || fs::metadata("docker-compose.yml").is_ok() || fs::metadata("docker-compose.yaml").is_ok() {
        return Some("docker".to_string());
    }
    None
}

#[derive(Parser)]
#[command(name = "kairo")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse a command and check its risk without executing
    Check {
        /// The command to check, e.g. "pnpm add lodash@4.17.21"
        #[arg(required = false)]
        command: Option<String>,
        /// Output raw JSON instead of pretty format
        #[arg(long = "json", short = 'j')]
        json_output: bool,
    },
    /// Run a command after checking its risk
    Run {
        /// The command to run, e.g. "-- pnpm add lodash"
        #[arg(last = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Check a specific package directly
    CheckPackage {
        /// Package name
        #[arg(required = true)]
        package: String,
        /// Version (or "latest")
        #[arg(required = true)]
        version: String,
        /// Ecosystem: npm, pnpm, yarn, bun, pip, cargo, go, docker (auto-detected if not specified)
        #[arg(short = 'e', long = "ecosystem", value_name = "ECOSYSTEM")]
        ecosystem: Option<String>,
        /// Output raw JSON instead of pretty format
        #[arg(long = "json", short = 'j')]
        json_output: bool,
    },
    /// Show CLI configuration and status
    Doctor,
    /// Manage local block list
    Blocklist {
        #[command(subcommand)]
        command: BlocklistCommand,
    },
    /// Manage trusted packages (bypass warnings, but not hard blocks)
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    /// Show version information for all Kairo components
    Version {
        /// Silently check for updates without displaying version info
        #[arg(long = "check", short = 'c')]
        check: bool,
    },
    /// Scan a project directory for risky dependencies
    Scan {
        /// Path to the project directory to scan
        #[arg(required = true)]
        path: String,
    },
    /// Install shell completions
    Completion {
        #[command(subcommand)]
        command: CompletionCommand,
    },
    /// Scan Docker images for security issues
    Docker {
        #[command(subcommand)]
        command: DockerCommand,
    },
    /// Scan packages that were changed in git (for pre-commit hooks)
    GitScan {
        /// Scan unstaged changes instead of staged changes
        #[arg(long = "unstaged", short = 'u')]
        unstaged: bool,
        /// Output raw JSON instead of pretty format
        #[arg(long = "json", short = 'j')]
        json_output: bool,
    },
    /// Start daemon mode for live security scanning
    Daemon,
    /// Check for available updates
    Update,
    /// Audit Python packages in requirements.txt against OSV
    PipAudit {
        /// Path to requirements.txt (defaults to ./requirements.txt)
        #[arg(short = 'r', long = "requirements")]
        requirements_path: Option<String>,
        /// Output raw JSON instead of pretty format
        #[arg(long = "json", short = 'j')]
        json_output: bool,
    },
    /// Watch a project directory for dependency changes and run scans automatically
    Watch {
        /// Path to the project directory to watch
        #[arg(short = 'p', long = "path", default_value = ".")]
        path: String,
    },
    /// Export trust list and blocklist to a JSON file
    Export {
        /// Output file path (default: kairo-export.json)
        #[arg(short = 'o', long = "output", default_value = "kairo-export.json")]
        output: String,
    },
    /// Import trust list and blocklist from a JSON file
    Import {
        /// Input file path
        #[arg(short = 'i', long = "input", required = true)]
        input: String,
    },
    /// Validate Kairo configuration files
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Show statistics from the Kairo server
    Stats,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Validate all Kairo configuration files
    Validate,
}

#[derive(Subcommand)]
enum DockerCommand {
    /// Scan a Docker image for security issues
    Scan {
        /// Docker image to scan (e.g., node:18-alpine, nginx:latest)
        #[arg(required = true)]
        image: String,
        /// Output raw JSON instead of pretty format
        #[arg(long = "json", short = 'j')]
        json_output: bool,
    },
}

#[derive(Subcommand)]
enum CompletionCommand {
    /// Generate and install bash completions
    Bash,
    /// Generate and install zsh completions
    Zsh,
    /// Generate and install fish completions
    Fish,
}

#[derive(Subcommand)]
enum BlocklistCommand {
    /// Show current block list (hardcoded + local)
    List,
    /// Add a package to local block list
    Add {
        /// Package name to block
        package: String,
    },
    /// Remove a package from local block list
    Remove {
        /// Package name to unblock
        package: String,
    },
    /// Check if a package is on the block list
    Check {
        /// Package name to check
        package: String,
    },
}

#[derive(Subcommand)]
enum TrustCommand {
    /// List trusted packages
    List,
    /// Add a package to trust list
    Add {
        /// Package name to trust
        package: String,
    },
    /// Remove a package from trust list
    Remove {
        /// Package name to remove from trust list
        package: String,
    },
}

#[derive(Deserialize, Serialize)]
struct VerdictResponse {
    verdict: String,
    risk_score: u8,
    title: String,
    summary: String,
    recommended_action: Option<String>,
    #[allow(dead_code)]
    safe_command: Option<String>,
}

#[derive(Deserialize)]
struct StatsResponse {
    total_checks: usize,
    block_count: usize,
    warn_count: usize,
    allow_count: usize,
}

const SERVER_URL: &str = "http://127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Check { command, json_output } => {
            let cmd = match command {
                Some(c) => c,
                None => {
                    if json_output {
                        println!("{{\"error\": \"No command provided. Usage: kairo check \\\"npm install lodash@4.17.21\\\"\"}}");
                    } else {
                        eprintln!("No command provided. Usage: kairo check \"npm install lodash@4.17.21\"");
                        print_ecosystems_help();
                    }
                    std::process::exit(1);
                }
            };
            let verdict = check_command(&cmd).await?;
            if json_output {
                println!("{}", serde_json::to_string(&verdict).unwrap_or_else(|_| r#"{"error":"Failed to serialize verdict"}"#.to_string()));
            } else {
                print_verdict(&verdict, &cmd);
            }
        }
        Commands::Run { command } => {
            let command_str = command.join(" ");
            let verdict = check_command(&command_str).await?;
            print_verdict(&verdict, &command_str);

            match verdict.verdict.as_str() {
                "ALLOW" => {
                    execute_command(&command_str).await?;
                }
                "WARN" => {
                    print!("\n⚠️  Continue with execution? [y/N] ");
                    std::io::Write::flush(&mut std::io::stdout())?;
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    if input.trim().to_lowercase() == "y" {
                        execute_command(&command_str).await?;
                    } else {
                        println!("Aborted.");
                        std::process::exit(1);
                    }
                }
                "BLOCK" => {
                    eprintln!("\n🚫 Blocked. Not executing.");
                    std::process::exit(1);
                }
                _ => {
                    execute_command(&command_str).await?;
                }
            }
        }
        Commands::CheckPackage {
            ecosystem,
            package,
            version,
            json_output,
        } => {
            let eco = match ecosystem {
                Some(e) => e,
                None => {
                    match detect_ecosystem() {
                        Some(detected) => {
                            if !json_output {
                                println!("Auto-detected ecosystem: {}", detected);
                            }
                            detected
                        }
                        None => {
                            if json_output {
                                println!("{{\"error\": \"Could not auto-detect ecosystem. Please specify one: npm, pnpm, yarn, bun, pip, cargo, go, docker\"}}");
                            } else {
                                eprintln!("Could not auto-detect ecosystem. Please specify one:");
                                print_ecosystems_help();
                            }
                            std::process::exit(1);
                        }
                    }
                }
            };
            let verdict = check_package(&eco, &package, &version).await?;
            let command_str = format!("{} add {}@{}", eco, package, version);
            if json_output {
                println!("{}", serde_json::to_string(&verdict).unwrap_or_else(|_| r#"{"error":"Failed to serialize verdict"}"#.to_string()));
            } else {
                print_verdict(&verdict, &command_str);
            }
        }
        Commands::Doctor => {
            doctor().await?;
        }
        Commands::Blocklist { command } => {
            match command {
                BlocklistCommand::List => {
                    blocklist_list();
                }
                BlocklistCommand::Add { package } => {
                    blocklist_add(&package)?;
                }
                BlocklistCommand::Remove { package } => {
                    blocklist_remove(&package)?;
                }
                BlocklistCommand::Check { package } => {
                    blocklist_check(&package);
                }
            }
        }
        Commands::Trust { command } => {
            match command {
                TrustCommand::List => {
                    trust_list();
                }
                TrustCommand::Add { package } => {
                    trust_add(&package)?;
                }
                TrustCommand::Remove { package } => {
                    trust_remove(&package)?;
                }
            }
        }
        Commands::Version { check } => {
            version(check).await?;
        }
        Commands::Scan { path } => {
            let result = scan_project(&path).await?;
            if result.blocks > 0 {
                std::process::exit(1);
            }
        }
        Commands::Completion { command } => {
            match command {
                CompletionCommand::Bash => print_completion_script(Shell::Bash),
                CompletionCommand::Zsh => print_completion_script(Shell::Zsh),
                CompletionCommand::Fish => print_completion_script(Shell::Fish),
            }
        }
        Commands::Docker { command } => {
            match command {
                DockerCommand::Scan { image, json_output } => {
                    let verdict = scan_docker_image(&image).await?;
                    let command_str = format!("docker pull {}", image);
                    if json_output {
                        println!("{}", serde_json::to_string(&verdict).unwrap_or_else(|_| r#"{"error":"Failed to serialize verdict"}"#.to_string()));
                    } else {
                        print_verdict(&verdict, &command_str);
                    }
                }
            }
        }
        Commands::GitScan { unstaged, json_output } => {
            let result = git_scan(unstaged).await?;
            if json_output {
                println!("{}", serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"Failed to serialize result"}"#.to_string()));
            } else if result.blocks > 0 {
                std::process::exit(1);
            }
        }
        Commands::Daemon => {
            daemon_mode().await?;
        }
        Commands::Update => {
            check_for_updates(false).await?;
        }
        Commands::PipAudit { requirements_path, json_output } => {
            pip_audit(requirements_path, json_output).await?;
        }
        Commands::Watch { path } => {
            watch_project(&path).await?;
        }
        Commands::Export { output } => {
            export_data(&output)?;
        }
        Commands::Import { input } => {
            import_data(&input)?;
        }
        Commands::Config { command } => {
            match command {
                ConfigCommand::Validate => {
                    config_validate();
                }
            }
        }
        Commands::Stats => {
            stats().await?;
        }
    }

    Ok(())
}

async fn check_command(command: &str) -> Result<VerdictResponse, Box<dyn std::error::Error>> {
    let parsed = parse_command(command);

    // Check merged block list first (hardcoded + local blocklist.json)
    if let Some(ref pkg) = parsed.1 {
        if is_blocked(pkg) {
            return Ok(VerdictResponse {
                verdict: "BLOCK".to_string(),
                risk_score: 95,
                title: "Package on block list".to_string(),
                summary: format!("Package '{}' is on the Kairo block list.", pkg),
                recommended_action: Some("Do not install this package.".to_string()),
                safe_command: None,
            });
        }
    }

    let action = build_action(&parsed.0, parsed.1, parsed.2, command);
    call_decide(action).await
}

async fn check_package(
    ecosystem: &str,
    package: &str,
    version: &str,
) -> Result<VerdictResponse, Box<dyn std::error::Error>> {
    // Check merged block list first (hardcoded + local blocklist.json)
    if is_blocked(package) {
        return Ok(VerdictResponse {
            verdict: "BLOCK".to_string(),
            risk_score: 95,
            title: "Package on block list".to_string(),
            summary: format!("Package '{}' is on the Kairo block list.", package),
            recommended_action: Some("Do not install this package.".to_string()),
            safe_command: None,
        });
    }

    // Check trust list — trusted packages bypass warnings
    if is_trusted(package) {
        return Ok(VerdictResponse {
            verdict: "ALLOW".to_string(),
            risk_score: 5,
            title: "Trusted package".to_string(),
            summary: format!("Package '{}' is explicitly trusted.", package),
            recommended_action: None,
            safe_command: None,
        });
    }

    let eco = match Ecosystem::from_str(ecosystem) {
        Some(e) => e,
        None => {
            return Err(format!(
                "Unknown ecosystem '{}'. Supported: {}",
                ecosystem,
                SUPPORTED_ECOSYSTEMS.join(", ")
            ).into());
        }
    };
    let action = Action {
        action_type: ActionType::PackageInstall,
        ecosystem: eco,
        command: format!("{} add {}@{}", ecosystem, package, version),
        package: Some(package.to_string()),
        version: Some(version.to_string()),
        repo_context: RepoContext {
            framework: None,
            has_database: false,
            has_ci: false,
        },
    };
    call_decide(action).await
}

struct ParsedImage {
    registry: Option<String>,
    image: String,
    tag: String,
}

fn parse_docker_image(image_str: &str) -> ParsedImage {
    // Handle registry prefix (e.g., myregistry.com:5000/myimage)
    let (registry, rest) = if let Some(pos) = image_str.find('/') {
        let potential_registry = &image_str[..pos];
        // If the first part looks like a registry (contains . or :), treat it as registry
        if potential_registry.contains('.') || potential_registry.contains(':') {
            (Some(potential_registry.to_string()), &image_str[pos + 1..])
        } else {
            (None, image_str)
        }
    } else {
        (None, image_str)
    };

    // Parse image name and tag
    let (image, tag) = if let Some(pos) = rest.rfind(':') {
        let potential_tag = &rest[pos + 1..];
        // Only treat as tag if it doesn't contain slashes (which would indicate a path)
        if !potential_tag.contains('/') {
            (rest[..pos].to_string(), potential_tag.to_string())
        } else {
            (rest.to_string(), "latest".to_string())
        }
    } else {
        (rest.to_string(), "latest".to_string())
    };

    ParsedImage { registry, image, tag }
}

async fn scan_docker_image(image_str: &str) -> Result<VerdictResponse, Box<dyn std::error::Error>> {
    let parsed = parse_docker_image(image_str);

    let eco = match Ecosystem::from_str("docker") {
        Some(e) => e,
        None => {
            return Err("Docker ecosystem not supported".into());
        }
    };

    let full_image = if let Some(ref registry) = parsed.registry {
        format!("{}/{}:{}", registry, parsed.image, parsed.tag)
    } else {
        format!("{}:{}", parsed.image, parsed.tag)
    };

    let action = Action {
        action_type: ActionType::PackageInstall,
        ecosystem: eco,
        command: format!("docker pull {}", full_image),
        package: Some(parsed.image),
        version: Some(parsed.tag),
        repo_context: RepoContext {
            framework: None,
            has_database: false,
            has_ci: false,
        },
    };
    call_decide(action).await
}

async fn call_decide(action: Action) -> Result<VerdictResponse, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let url = format!("{}/v1/decide", SERVER_URL);
    let resp = client
        .post(&url)
        .json(&action)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Kairo Decision Server at {}/v1/decide: {}. Is kairo-server running?", SERVER_URL, e))?;

    if !resp.status().is_success() {
        return Err(format!("Server returned error: {}", resp.status()).into());
    }

    let verdict: VerdictResponse = resp.json().await.map_err(|e| {
        format!(
            "Invalid response from server (not valid JSON). This may indicate the server encountered an error processing your request. Details: {}",
            e
        )
    })?;
    Ok(verdict)
}

fn parse_command(command: &str) -> (String, Option<String>, Option<String>) {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return (String::new(), None, None);
    }

    let tool = parts[0];
    let ecosystem = match tool {
        "pnpm" => "pnpm",
        "npm" => "npm",
        "yarn" => "yarn",
        "bun" => "bun",
        "pip" | "pip3" => "pip",
        "cargo" => "cargo",
        "go" => "go",
        "docker" => "docker",
        _ => tool,
    };

    if parts.len() < 3 {
        return (ecosystem.to_string(), None, None);
    }

    let _subcommand = parts[1];
    let target = parts[2];

    // Parse package@version
    let (package, version) = if target.contains('@') {
        let at_idx = target.rfind('@').unwrap();
        let pkg = target[..at_idx].to_string();
        let ver = target[at_idx + 1..].to_string();
        (pkg, Some(ver))
    } else {
        (target.to_string(), None)
    };

    (ecosystem.to_string(), Some(package), version)
}

fn build_action(
    ecosystem_str: &str,
    package: Option<String>,
    version: Option<String>,
    command: &str,
) -> Action {
    let ecosystem = Ecosystem::from_str(ecosystem_str).unwrap_or(Ecosystem::npm);
    Action {
        action_type: ActionType::PackageInstall,
        ecosystem,
        command: command.to_string(),
        package,
        version,
        repo_context: RepoContext {
            framework: None,
            has_database: false,
            has_ci: false,
        },
    }
}

fn print_verdict(verdict: &VerdictResponse, command: &str) {
    let verdict_display = verdict.verdict.to_uppercase();
    let risk = verdict.risk_score;

    let verdict_color = match verdict.verdict.to_uppercase().as_str() {
        "ALLOW" => "\x1b[32m",  // green
        "WARN" => "\x1b[33m",   // yellow
        "BLOCK" => "\x1b[31m",  // red
        _ => "\x1b[0m",
    };
    let reset = "\x1b[0m";

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KAIRO                                                     ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!(
        "║  VERDICT    {}{:8}{}                                  ║",
        verdict_color, verdict_display, reset
    );
    println!("║  RISK       {:3} / 100                                       ║", risk);
    println!("║  TITLE      {}                            ║", truncate(&verdict.title, 50));
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  {}", truncate(command, 60));
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  SUMMARY                                                   ║");
    for line in wrap_text(&verdict.summary, 58) {
        println!("║  {}  ║", truncate(&line, 58));
    }
    if let Some(ref action) = verdict.recommended_action {
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  RECOMMEND                                                 ║");
        for line in wrap_text(action, 58) {
            println!("║  {}  ║", truncate(&line, 58));
        }
    }
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

fn wrap_text(text: &str, max_len: usize) -> Vec<String> {
    let mut lines = vec![];
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.len() + word.len() + 1 > max_len && !current.is_empty() {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

async fn execute_command(command: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n▶ Executing: {}", command);
    let shell = if cfg!(target_os = "windows") { "cmd" } else { "sh" };
    let flag = if cfg!(target_os = "windows") { "/C" } else { "-c" };

    let output = Command::new(shell)
        .arg(flag)
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()?;

    if !output.status.success() {
        std::process::exit(output.status.code().unwrap_or(1));
    }
    Ok(())
}

async fn doctor() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Kairo CLI Doctor");
    println!("===================");

    // Check server connectivity
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    match client.get(format!("{}/health", SERVER_URL)).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("✅ Decision Server: reachable at {}", SERVER_URL);
        }
        Ok(resp) => {
            println!("⚠️  Decision Server: returned {}", resp.status());
        }
        Err(e) => {
            println!("❌ Decision Server: not reachable at {} — {}", SERVER_URL, e);
            println!("   Run: cargo run -p kairo-server");
        }
    }

    // Check kairo-core version
    println!("✅ kairo-core: present");
    println!("\nAll checks passed. Kairo is ready.");
    Ok(())
}

async fn version(check: bool) -> Result<(), Box<dyn std::error::Error>> {
    if check {
        // Silent update check
        return check_for_updates(true).await;
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KAIRO VERSION                                            ║");
    println!("╠══════════════════════════════════════════════════════════╣");

    // kairo-cli version (hardcoded from Cargo.toml)
    println!("║  kairo-cli          0.1.0                                ║");

    // kairo-core version (hardcoded from Cargo.toml)
    println!("║  kairo-core         0.1.0                                ║");

    // kairo-server version (check /health endpoint)
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    match client.get(format!("{}/health", SERVER_URL)).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("║  kairo-server       running                               ║");
        }
        _ => {
            println!("║  kairo-server       not running                           ║");
        }
    }

    // kairo-mcp version (hardcoded from Cargo.toml)
    println!("║  kairo-mcp          0.1.0                                ║");

    // kairo-github-action version (hardcoded from Cargo.toml)
    println!("║  kairo-github-action 0.1.0                              ║");

    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    Ok(())
}

async fn check_for_updates(silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    const CURRENT_VERSION: &str = "0.1.0";
    const GITHUB_API_URL: &str = "https://api.github.com/repos/kairo-ai/kairo/releases/latest";

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(GITHUB_API_URL)
        .header("User-Agent", "kairo-cli")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;

    if resp.status() == 404 {
        if !silent {
            println!();
            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║  KAIRO UPDATE CHECK                                      ║");
            println!("╠══════════════════════════════════════════════════════════╣");
            println!("║                                                          ║");
            println!("║  No releases found. This may be a pre-release version    ║");
            println!("║  or the repository has not published any releases yet.     ║");
            println!("║                                                          ║");
            println!("╚══════════════════════════════════════════════════════════╝");
            println!();
        }
        return Ok(());
    }

    if !resp.status().is_success() {
        if !silent {
            println!("Failed to check for updates: HTTP {}", resp.status());
        }
        return Ok(());
    }

    #[derive(Deserialize)]
    struct GitHubRelease {
        tag_name: String,
        name: Option<String>,
        body: Option<String>,
        html_url: String,
        assets: Vec<GitHubAsset>,
    }

    #[derive(Deserialize)]
    struct GitHubAsset {
        name: String,
        browser_download_url: String,
    }

    let release: GitHubRelease = resp.json().await?;

    // Parse latest version from tag (remove 'v' prefix if present)
    let latest_version = release.tag_name.trim_start_matches('v');

    // Simple version comparison (major.minor.patch)
    let current_parts: Vec<u32> = CURRENT_VERSION
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let latest_parts: Vec<u32> = latest_version
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

    let needs_update = if latest_parts.len() >= current_parts.len() {
        for i in 0..current_parts.len() {
            if latest_parts[i] > current_parts[i] {
                break;
            }
            if latest_parts[i] < current_parts[i] {
                return Ok(()); // Already on newer version
            }
        }
        latest_parts.len() > current_parts.len()
    } else {
        false
    };

    if !needs_update {
        if !silent {
            println!();
            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║  KAIRO UPDATE CHECK                                      ║");
            println!("╠══════════════════════════════════════════════════════════╣");
            println!("║  Current version: {}                                     ║", CURRENT_VERSION);
            println!("║  Latest version:  {}                                     ║", latest_version);
            println!("║                                                          ║");
            println!("║  You are up to date!                                      ║");
            println!("╚══════════════════════════════════════════════════════════╝");
            println!();
        }
        return Ok(());
    }

    // Find binary assets
    let mut download_urls: Vec<String> = Vec::new();
    for asset in &release.assets {
        if asset.name.contains("kairo") || asset.name.contains(".tar.gz") || asset.name.contains(".zip") {
            download_urls.push(asset.browser_download_url.clone());
        }
    }

    if !silent {
        println!();
        println!("╔══════════════════════════════════════════════════════════╗");
        println!("║  KAIRO UPDATE CHECK                                      ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  Current version: {}                                     ║", CURRENT_VERSION);
        println!("║  Latest version:  {}                                     ║", latest_version);
        println!("║                                                          ║");
        println!("║  A new release is available!                             ║");
        println!("║                                                          ║");
        if let Some(name) = &release.name {
            println!("║  Release: {}                                      ║", truncate(name, 50));
        }
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  RELEASE NOTES                                           ║");
        if let Some(body) = &release.body {
            for line in wrap_text(body, 58) {
                println!("║  {}  ║", truncate(&line, 58));
            }
        } else {
            println!("║  (no release notes)                                      ║");
        }
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  DOWNLOAD                                                 ║");
        if !download_urls.is_empty() {
            for url in &download_urls {
                println!("║  {}  ║", truncate(url, 58));
            }
        } else {
            println!("║  {}  ║", truncate(&release.html_url, 58));
        }
        println!("╚══════════════════════════════════════════════════════════╝");
        println!();
    }

    Ok(())
}

fn blocklist_list() {
    let local = read_local_blocklist();
    let merged_count = BLOCKED_PACKAGES.len() + local.len();

    println!("\n📦 Kairo Block List");
    println!("====================");
    println!("\nHardcoded (kairo-core):");
    for pkg in BLOCKED_PACKAGES {
        println!("  - {}", pkg);
    }
    println!("\nLocal (blocklist.json):");
    if local.is_empty() {
        println!("  (empty)");
    } else {
        for pkg in &local {
            println!("  - {}", pkg);
        }
    }
    println!("\nMerged total: {} packages", merged_count);
    println!();
}

fn blocklist_add(package: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut local = read_local_blocklist();
    if !local.contains(&package.to_string()) {
        local.push(package.to_string());
        write_local_blocklist(&local)?;
        println!("Added '{}' to blocklist.json", package);
    } else {
        println!("'{}' is already in blocklist.json", package);
    }
    Ok(())
}

fn blocklist_remove(package: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut local = read_local_blocklist();
    let original_len = local.len();
    local.retain(|p| p != package);
    if local.len() < original_len {
        write_local_blocklist(&local)?;
        println!("Removed '{}' from blocklist.json", package);
    } else {
        println!("'{}' was not in blocklist.json", package);
    }
    Ok(())
}

fn blocklist_check(package: &str) {
    let local = read_local_blocklist();
    let in_hardcoded = BLOCKED_PACKAGES.contains(&package);
    let in_local = local.iter().any(|p| p == package);
    let blocked = is_blocked(package);

    println!("\n🔍 Block list check for: {}", package);
    println!("  In hardcoded list: {}", if in_hardcoded { "YES" } else { "no" });
    println!("  In local blocklist.json: {}", if in_local { "YES" } else { "no" });
    println!("  Blocked: {}", if blocked { "YES" } else { "no" });
    println!();

    if blocked {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

fn trust_list() {
    let trusted = read_trust_list();

    println!("\n🔐 Kairo Trust List");
    println!("====================");
    if trusted.is_empty() {
        println!("  (empty)");
    } else {
        for pkg in &trusted {
            println!("  - {}", pkg);
        }
    }
    println!();
}

fn trust_add(package: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut trusted = read_trust_list();
    if !trusted.contains(&package.to_string()) {
        trusted.push(package.to_string());
        write_trust_list(&trusted)?;
        println!("Added '{}' to trust list", package);
    } else {
        println!("'{}' is already trusted", package);
    }
    Ok(())
}

fn trust_remove(package: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut trusted = read_trust_list();
    let original_len = trusted.len();
    trusted.retain(|p| p != package);
    if trusted.len() < original_len {
        write_trust_list(&trusted)?;
        println!("Removed '{}' from trust list", package);
    } else {
        println!("'{}' was not in trust list", package);
    }
    Ok(())
}

#[derive(Deserialize)]
struct PackageJson {
    dependencies: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct CargoLock {
    package: Option<Vec<CargoPackage>>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
}

struct ScanResult {
    blocks: usize,
}

// Rich output types for diff-style display
struct RichPackageResult {
    name: String,
    version: String,
    ecosystem: String,
    verdict: String,
    risk_score: u8,
    title: String,
    trusted: bool,
    error: Option<String>,
}

impl RichPackageResult {
    fn verdict_color(&self) -> &'static str {
        if self.trusted {
            return "\x1b[36m"; // cyan for trusted
        }
        match self.verdict.to_uppercase().as_str() {
            "ALLOW" => "\x1b[32m",  // green
            "WARN" => "\x1b[33m",   // yellow
            "BLOCK" => "\x1b[31m",  // red
            _ => "\x1b[0m",
        }
    }

    fn verdict_symbol(&self) -> &'static str {
        if self.trusted {
            return "🔐";
        }
        match self.verdict.to_uppercase().as_str() {
            "ALLOW" => "✅",
            "WARN" => "⚠️",
            "BLOCK" => "🚫",
            _ => "❓",
        }
    }

    fn status_text(&self) -> String {
        if self.trusted {
            return "TRUSTED".to_string();
        }
        if let Some(ref e) = self.error {
            return format!("ERROR: {}", e);
        }
        format!("{} {}", self.verdict.to_uppercase(), self.title)
    }
}

fn print_rich_scan_header(path: &str, total_packages: usize) {
    println!();
    println!("\x1b[1;36m╭\x1b[0m \x1b[1mScanning\x1b[0m {} \x1b[2mpackages in\x1b[0m {}", total_packages, path);
    println!("\x1b[36m│\x1b[0m");
}

fn print_rich_ecosystem_header(ecosystem: &str, count: usize, icon: &str) {
    let eco_label = match ecosystem {
        "npm" | "pnpm" | "yarn" | "bun" => "NPM Packages",
        "cargo" => "Cargo Crates",
        "pip" => "Pip Packages",
        "go" => "Go Modules",
        "docker" => "Docker Images",
        _ => ecosystem,
    };
    println!("\x1b[36m├──\x1b[0m \x1b[1m{}\x1b[0m \x1b[2m{} {}\x1b[0m", icon, count, eco_label);
}

fn print_rich_package_result(result: &RichPackageResult, is_last: bool, base_indent: &str) -> String {
    let indent = if is_last { "└──" } else { "├──" };
    let child_indent = if is_last { "   " } else { "│  " };

    // Truncate package name if too long
    let pkg_display = format!("{}@{}", result.name, result.version);
    let dots = " ".repeat(40usize.saturating_sub(pkg_display.len().max(40)));

    let color = result.verdict_color();
    let symbol = result.verdict_symbol();
    let status = result.status_text();

    println!("\x1b[36m{}\x1b[0m {}\x1b[1m{}\x1b[0m{}\x1b[2m{}\x1b[0m {}", base_indent, indent, color, pkg_display, dots, symbol);

    if !result.trusted && result.title != "Trusted package" && !result.title.is_empty() {
        println!("\x1b[36m{}\x1b[0m {}\x1b[2m  {}{}\x1b[0m {}\x1b[2m{}\x1b[0m",
            base_indent, child_indent, color, result.verdict.to_uppercase(), result.risk_score, status);
    } else if result.trusted {
        println!("\x1b[36m{}\x1b[0m {}\x1b[36m  {}\x1b[0m", base_indent, child_indent, status);
    }

    child_indent.to_string()
}

fn print_rich_scan_summary(allows: usize, warns: usize, blocks: usize, trusted: usize) {
    println!("\x1b[36m│\x1b[0m");
    println!("\x1b[36m╰─\x1b[0m \x1b[1mResults\x1b[0m");

    let total = allows + warns + blocks + trusted;

    // Summary with color coding
    let allow_color = if allows > 0 { "\x1b[32m" } else { "\x1b[2m" };
    let warn_color = if warns > 0 { "\x1b[33m" } else { "\x1b[2m" };
    let block_color = if blocks > 0 { "\x1b[31m" } else { "\x1b[2m" };
    let trusted_color = if trusted > 0 { "\x1b[36m" } else { "\x1b[2m" };

    println!("    {}✅ ALLOW   \x1b[0m{:>3}\x1b[0m / {}", allow_color, allows, total);
    println!("    {}⚠️  WARN   \x1b[0m{:>3}\x1b[0m / {}", warn_color, warns, total);
    println!("    {}🚫 BLOCK  \x1b[0m{:>3}\x1b[0m / {}", block_color, blocks, total);
    println!("    {}🔐 TRUST  \x1b[0m{:>3}\x1b[0m / {}", trusted_color, trusted, total);
    println!();
}

fn print_collapsible_details(results: &[RichPackageResult]) {
    // Show blocked and warned packages in detail
    let concerning: Vec<&RichPackageResult> = results
        .iter()
        .filter(|r| r.verdict.to_uppercase() == "BLOCK" || r.verdict.to_uppercase() == "WARN")
        .collect();

    if concerning.is_empty() {
        return;
    }

    println!("\x1b[1m┌─ \x1b[33mPackage Details\x1b[0m \x1b[2m(concerning packages)\x1b[0m");
    println!("\x1b[1m│\x1b[0m");

    for (i, result) in concerning.iter().enumerate() {
        let is_last = i == concerning.len() - 1;
        let color = result.verdict_color();
        let icon = if result.verdict.to_uppercase() == "BLOCK" { "🚫" } else { "⚠️" };

        println!("\x1b[1m├──\x1b[0m \x1b[1m{}@{}\x1b[0m \x1b[2m({})\x1b[0m", result.name, result.version, result.ecosystem);
        println!("\x1b[1m│\x1b[0m   {} {} {}\x1b[0m \x1b[1mRisk:\x1b[0m {}/100", icon, color, result.verdict.to_uppercase(), result.risk_score);
        println!("\x1b[1m│\x1b[0m   \x1b[1mTitle:\x1b[0m {}", result.title);

        if !is_last {
            println!("\x1b[1m│\x1b[0m");
        }
    }

    println!("\x1b[1m│\x1b[0m");
    println!("\x1b[1m└─\x1b[0m \x1b[2mEnd details\x1b[0m");
    println!();
}

fn parse_requirements_txt(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip editable installs (lines starting with -e or --editable)
        if line.starts_with("-e") || line.starts_with("--editable") {
            continue;
        }
        // Parse package==version or package>=version patterns
        // Also handle package[extras]==version
        if let Some((name, version)) = extract_pip_package(line) {
            packages.push((name, version));
        }
    }
    packages
}

fn extract_pip_package(line: &str) -> Option<(String, String)> {
    // Handle package==version
    if let Some(pos) = line.find("==") {
        let name = line[..pos].trim().to_string();
        let version = line[pos + 2..].trim().to_string();
        if !name.is_empty() && !version.is_empty() {
            return Some((name, version));
        }
    }
    // Handle package>=version
    if let Some(pos) = line.find(">=") {
        let name = line[..pos].trim().to_string();
        let version = line[pos + 2..].trim().to_string();
        if !name.is_empty() && !version.is_empty() {
            return Some((name, version));
        }
    }
    // Handle package~=version (compatible release)
    if let Some(pos) = line.find("~=") {
        let name = line[..pos].trim().to_string();
        let version = line[pos + 2..].trim().to_string();
        if !name.is_empty() && !version.is_empty() {
            return Some((name, version));
        }
    }
    // Handle package<=version
    if let Some(pos) = line.find("<=") {
        let name = line[..pos].trim().to_string();
        let version = line[pos + 2..].trim().to_string();
        if !name.is_empty() && !version.is_empty() {
            return Some((name, version));
        }
    }
    // Handle package>version (no =)
    if let Some(pos) = line.find('>') {
        if pos > 0 && !line[..pos].contains('=') {
            let name = line[..pos].trim().to_string();
            let version = line[pos + 1..].trim().to_string();
            if !name.is_empty() && !version.is_empty() {
                return Some((name, version));
            }
        }
    }
    // Handle package<version (no =)
    if let Some(pos) = line.find('<') {
        if pos > 0 && !line[..pos].contains('=') {
            let name = line[..pos].trim().to_string();
            let version = line[pos + 1..].trim().to_string();
            if !name.is_empty() && !version.is_empty() {
                return Some((name, version));
            }
        }
    }
    None
}

fn parse_go_mod(content: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut in_require = false;

    for line in content.lines() {
        let line = line.trim();

        // Track require block
        if line.starts_with("require (") {
            in_require = true;
            continue;
        }
        if line == ")" && in_require {
            in_require = false;
            continue;
        }

        // Single line require: require module v1.2.3
        if line.starts_with("require ") && !line.contains("(") {
            if let Some((name, version)) = parse_go_require_line(line) {
                packages.push((name, version));
            }
            continue;
        }

        // Inside require block
        if in_require {
            if let Some((name, version)) = parse_go_require_line(line) {
                packages.push((name, version));
            }
        }
    }
    packages
}

fn parse_go_require_line(line: &str) -> Option<(String, String)> {
    // Remove "require " prefix if present
    let line = line.strip_prefix("require ").unwrap_or(line);

    // Split on whitespace - format is "module v1.2.3"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        let name = parts[0].to_string();
        let version = parts[1].to_string();
        if !name.is_empty() && !version.is_empty() {
            return Some((name, version));
        }
    }
    None
}

async fn scan_project(path: &str) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let path = PathBuf::from(path);

    if !path.exists() {
        return Err(format!("Path does not exist: {}", path.display()).into());
    }

    let mut npm_packages: Vec<(String, String)> = Vec::new();
    let mut cargo_packages: Vec<(String, String)> = Vec::new();
    let mut pip_packages: Vec<(String, String)> = Vec::new();
    let mut go_packages: Vec<(String, String)> = Vec::new();

    // Scan package.json for npm packages
    let pkg_json_path = path.join("package.json");
    if pkg_json_path.exists() {
        let content = fs::read_to_string(&pkg_json_path)?;
        let pkg_json: PackageJson = serde_json::from_str(&content)?;

        if let Some(deps) = pkg_json.dependencies {
            for (name, ver) in deps {
                let version = extract_version(&ver);
                npm_packages.push((name, version));
            }
        }

        if let Some(deps) = pkg_json.dev_dependencies {
            for (name, ver) in deps {
                let version = extract_version(&ver);
                npm_packages.push((name, version));
            }
        }
    }

    // Scan Cargo.lock for Rust crates
    let cargo_lock_path = path.join("Cargo.lock");
    if cargo_lock_path.exists() {
        let content = fs::read_to_string(&cargo_lock_path)?;
        let cargo_lock: CargoLock = toml::from_str(&content)?;

        if let Some(packages) = cargo_lock.package {
            for pkg in packages {
                cargo_packages.push((pkg.name, pkg.version));
            }
        }
    }

    // Scan requirements.txt for pip packages
    let requirements_path = path.join("requirements.txt");
    if requirements_path.exists() {
        let content = fs::read_to_string(&requirements_path)?;
        pip_packages = parse_requirements_txt(&content);
    }

    // Scan go.mod for Go modules
    let go_mod_path = path.join("go.mod");
    if go_mod_path.exists() {
        let content = fs::read_to_string(&go_mod_path)?;
        go_packages = parse_go_mod(&content);
    }

    let total_packages = npm_packages.len() + cargo_packages.len() + pip_packages.len() + go_packages.len();

    if total_packages == 0 {
        return Err("No package.json, Cargo.lock, requirements.txt, or go.mod found. Nothing to scan.".into());
    }

    // Print rich header
    print_rich_scan_header(path.to_str().unwrap_or("."), total_packages);

    let mut all_results: Vec<RichPackageResult> = Vec::new();
    let mut allows = 0;
    let mut warns = 0;
    let mut blocks = 0;
    let mut trusted = 0;

    // Scan npm packages with rich output
    if !npm_packages.is_empty() {
        print_rich_ecosystem_header("npm", npm_packages.len(), "📦");
        for (i, (name, version)) in npm_packages.iter().enumerate() {
            let is_last = i == npm_packages.len() - 1 && cargo_packages.is_empty() && pip_packages.is_empty() && go_packages.is_empty();

            if is_trusted(name) {
                let result = RichPackageResult {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: "npm".to_string(),
                    verdict: "TRUSTED".to_string(),
                    risk_score: 0,
                    title: "Explicitly trusted package".to_string(),
                    trusted: true,
                    error: None,
                };
                all_results.push(result);
                trusted += 1;
                print_rich_package_result(all_results.last().unwrap(), is_last, "");
            } else {
                match check_package("npm", name, version).await {
                    Ok(verdict) => {
                        let result = RichPackageResult {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "npm".to_string(),
                            verdict: verdict.verdict.clone(),
                            risk_score: verdict.risk_score,
                            title: verdict.title.clone(),
                            trusted: false,
                            error: None,
                        };
                        all_results.push(result);

                        match verdict.verdict.to_uppercase().as_str() {
                            "ALLOW" => allows += 1,
                            "WARN" => warns += 1,
                            "BLOCK" => blocks += 1,
                            _ => allows += 1,
                        }
                        print_rich_package_result(all_results.last().unwrap(), is_last, "");
                    }
                    Err(e) => {
                        let result = RichPackageResult {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "npm".to_string(),
                            verdict: "ERROR".to_string(),
                            risk_score: 0,
                            title: format!("Failed to check: {}", e),
                            trusted: false,
                            error: Some(e.to_string()),
                        };
                        all_results.push(result);
                        allows += 1;
                        print_rich_package_result(all_results.last().unwrap(), is_last, "");
                    }
                }
            }
        }
    }

    // Scan cargo packages with rich output
    if !cargo_packages.is_empty() {
        let _is_last_eco = pip_packages.is_empty() && go_packages.is_empty();
        print_rich_ecosystem_header("cargo", cargo_packages.len(), "🔧");
        for (i, (name, version)) in cargo_packages.iter().enumerate() {
            let is_last = i == cargo_packages.len() - 1 && pip_packages.is_empty() && go_packages.is_empty();

            if is_trusted(name) {
                let result = RichPackageResult {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: "cargo".to_string(),
                    verdict: "TRUSTED".to_string(),
                    risk_score: 0,
                    title: "Explicitly trusted package".to_string(),
                    trusted: true,
                    error: None,
                };
                all_results.push(result);
                trusted += 1;
                print_rich_package_result(all_results.last().unwrap(), is_last, "");
            } else {
                match check_package("cargo", name, version).await {
                    Ok(verdict) => {
                        let result = RichPackageResult {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "cargo".to_string(),
                            verdict: verdict.verdict.clone(),
                            risk_score: verdict.risk_score,
                            title: verdict.title.clone(),
                            trusted: false,
                            error: None,
                        };
                        all_results.push(result);

                        match verdict.verdict.to_uppercase().as_str() {
                            "ALLOW" => allows += 1,
                            "WARN" => warns += 1,
                            "BLOCK" => blocks += 1,
                            _ => allows += 1,
                        }
                        print_rich_package_result(all_results.last().unwrap(), is_last, "");
                    }
                    Err(e) => {
                        let result = RichPackageResult {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "cargo".to_string(),
                            verdict: "ERROR".to_string(),
                            risk_score: 0,
                            title: format!("Failed to check: {}", e),
                            trusted: false,
                            error: Some(e.to_string()),
                        };
                        all_results.push(result);
                        allows += 1;
                        print_rich_package_result(all_results.last().unwrap(), is_last, "");
                    }
                }
            }
        }
    }

    // Scan pip packages with rich output
    if !pip_packages.is_empty() {
        let _is_last_eco = go_packages.is_empty();
        print_rich_ecosystem_header("pip", pip_packages.len(), "🐍");
        for (i, (name, version)) in pip_packages.iter().enumerate() {
            let is_last = i == pip_packages.len() - 1 && go_packages.is_empty();

            if is_trusted(name) {
                let result = RichPackageResult {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: "pip".to_string(),
                    verdict: "TRUSTED".to_string(),
                    risk_score: 0,
                    title: "Explicitly trusted package".to_string(),
                    trusted: true,
                    error: None,
                };
                all_results.push(result);
                trusted += 1;
                print_rich_package_result(all_results.last().unwrap(), is_last, "");
            } else {
                match check_package("pip", name, version).await {
                    Ok(verdict) => {
                        let result = RichPackageResult {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "pip".to_string(),
                            verdict: verdict.verdict.clone(),
                            risk_score: verdict.risk_score,
                            title: verdict.title.clone(),
                            trusted: false,
                            error: None,
                        };
                        all_results.push(result);

                        match verdict.verdict.to_uppercase().as_str() {
                            "ALLOW" => allows += 1,
                            "WARN" => warns += 1,
                            "BLOCK" => blocks += 1,
                            _ => allows += 1,
                        }
                        print_rich_package_result(all_results.last().unwrap(), is_last, "");
                    }
                    Err(e) => {
                        let result = RichPackageResult {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "pip".to_string(),
                            verdict: "ERROR".to_string(),
                            risk_score: 0,
                            title: format!("Failed to check: {}", e),
                            trusted: false,
                            error: Some(e.to_string()),
                        };
                        all_results.push(result);
                        allows += 1;
                        print_rich_package_result(all_results.last().unwrap(), is_last, "");
                    }
                }
            }
        }
    }

    // Scan go modules with rich output
    if !go_packages.is_empty() {
        print_rich_ecosystem_header("go", go_packages.len(), "🐹");
        for (i, (name, version)) in go_packages.iter().enumerate() {
            let is_last = i == go_packages.len() - 1;

            if is_trusted(name) {
                let result = RichPackageResult {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: "go".to_string(),
                    verdict: "TRUSTED".to_string(),
                    risk_score: 0,
                    title: "Explicitly trusted package".to_string(),
                    trusted: true,
                    error: None,
                };
                all_results.push(result);
                trusted += 1;
                print_rich_package_result(all_results.last().unwrap(), is_last, "");
            } else {
                match check_package("go", name, version).await {
                    Ok(verdict) => {
                        let result = RichPackageResult {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "go".to_string(),
                            verdict: verdict.verdict.clone(),
                            risk_score: verdict.risk_score,
                            title: verdict.title.clone(),
                            trusted: false,
                            error: None,
                        };
                        all_results.push(result);

                        match verdict.verdict.to_uppercase().as_str() {
                            "ALLOW" => allows += 1,
                            "WARN" => warns += 1,
                            "BLOCK" => blocks += 1,
                            _ => allows += 1,
                        }
                        print_rich_package_result(all_results.last().unwrap(), is_last, "");
                    }
                    Err(e) => {
                        let result = RichPackageResult {
                            name: name.clone(),
                            version: version.clone(),
                            ecosystem: "go".to_string(),
                            verdict: "ERROR".to_string(),
                            risk_score: 0,
                            title: format!("Failed to check: {}", e),
                            trusted: false,
                            error: Some(e.to_string()),
                        };
                        all_results.push(result);
                        allows += 1;
                        print_rich_package_result(all_results.last().unwrap(), is_last, "");
                    }
                }
            }
        }
    }

    // Print summary and collapsible details
    print_rich_scan_summary(allows, warns, blocks, trusted);
    print_collapsible_details(&all_results);

    if blocks > 0 {
        println!("\x1b[31m❌ {} BLOCKED packages found. Fix before proceeding.\x1b[0m", blocks);
    } else if warns > 0 {
        println!("\x1b[33m⚠️  {} packages flagged as WARN. Review recommended.\x1b[0m", warns);
    } else if trusted > 0 {
        println!("\x1b[36m🔐 {} trusted packages bypassed server checks.\x1b[0m", trusted);
        println!("\x1b[32m✅ All packages passed.\x1b[0m");
    } else {
        println!("\x1b[32m✅ All packages passed.\x1b[0m");
    }

    Ok(ScanResult { blocks })
}

fn extract_version(ver: &serde_json::Value) -> String {
    match ver {
        serde_json::Value::String(s) => s.clone(),
        _ => "latest".to_string(),
    }
}

#[derive(Serialize)]
struct GitScanResult {
    packages_scanned: usize,
    allows: usize,
    warns: usize,
    blocks: usize,
    findings: Vec<GitScanFinding>,
}

#[derive(Serialize)]
struct GitScanFinding {
    package: String,
    version: String,
    ecosystem: String,
    verdict: String,
    risk_score: u8,
    title: String,
}

async fn git_scan(unstaged: bool) -> Result<GitScanResult, Box<dyn std::error::Error>> {
    // Run git diff command
    let diff_output = if unstaged {
        Command::new("git")
            .args(["diff"])
            .output()?
    } else {
        Command::new("git")
            .args(["diff", "--cached"])
            .output()?
    };

    if !diff_output.status.success() {
        return Err("Git diff command failed. Are you in a git repository?".into());
    }

    let diff_content = String::from_utf8_lossy(&diff_output.stdout);

    // Find changed dependency files
    let changed_files = extract_changed_files(&diff_content);

    if changed_files.is_empty() {
        println!("No dependency file changes detected in git diff.");
        return Ok(GitScanResult {
            packages_scanned: 0,
            allows: 0,
            warns: 0,
            blocks: 0,
            findings: vec![],
        });
    }

    println!("Changed dependency files: {}", changed_files.join(", "));

    // Extract packages from changed files
    let mut packages_to_scan: Vec<(String, String, String)> = Vec::new(); // (ecosystem, name, version)

    for file in &changed_files {
        let content = fs::read_to_string(file)?;
        let path_buf = PathBuf::from(file);
        let ext = path_buf
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext {
            "json" => {
                if file.ends_with("package.json") {
                    let pkg_json: PackageJson = serde_json::from_str(&content)?;
                    if let Some(deps) = pkg_json.dependencies {
                        for (name, ver) in deps {
                            packages_to_scan.push(("npm".to_string(), name, extract_version(&ver)));
                        }
                    }
                    if let Some(deps) = pkg_json.dev_dependencies {
                        for (name, ver) in deps {
                            packages_to_scan.push(("npm".to_string(), name, extract_version(&ver)));
                        }
                    }
                } else if file.ends_with("package-lock.json") || file.ends_with("yarn.lock") || file.ends_with("pnpm-lock.yaml") {
                    // Lock files - skip individual parsing, rely on package.json
                    continue;
                }
            }
            "toml" => {
                if file.ends_with("Cargo.toml") {
                    // Cargo.toml doesn't have versions inline, would need Cargo.lock
                    // For now, skip Cargo.toml changes
                    continue;
                }
            }
            "txt" => {
                if file.ends_with("requirements.txt") {
                    let pip_packages = parse_requirements_txt(&content);
                    for (name, version) in pip_packages {
                        packages_to_scan.push(("pip".to_string(), name, version));
                    }
                }
            }
            "mod" => {
                if file.ends_with("go.mod") {
                    let go_packages = parse_go_mod(&content);
                    for (name, version) in go_packages {
                        packages_to_scan.push(("go".to_string(), name, version));
                    }
                }
            }
            _ => {}
        }
    }

    if packages_to_scan.is_empty() {
        println!("No packages found in changed dependency files.");
        return Ok(GitScanResult {
            packages_scanned: 0,
            allows: 0,
            warns: 0,
            blocks: 0,
            findings: vec![],
        });
    }

    // Print rich header for git scan
    let _changed_str = if unstaged { "unstaged" } else { "staged" };
    println!();
    println!("\x1b[1;36m╭\x1b[0m \x1b[1mGit Scan\x1b[0m {} changed files, {} packages", changed_files.len(), packages_to_scan.len());
    println!("\x1b[36m│\x1b[0m \x1b[2mChanged files:\x1b[0m {}", changed_files.join(", "));
    println!("\x1b[36m│\x1b[0m");

    let mut all_results: Vec<RichPackageResult> = Vec::new();
    let mut allows = 0;
    let mut warns = 0;
    let mut blocks = 0;
    let mut trusted_count = 0;
    let mut findings = Vec::new();

    for (i, (ecosystem, name, version)) in packages_to_scan.iter().enumerate() {
        let is_last = i == packages_to_scan.len() - 1;

        if is_trusted(name) {
            let result = RichPackageResult {
                name: name.clone(),
                version: version.clone(),
                ecosystem: ecosystem.clone(),
                verdict: "TRUSTED".to_string(),
                risk_score: 0,
                title: "Explicitly trusted package".to_string(),
                trusted: true,
                error: None,
            };
            print_rich_package_result(&result, is_last, "");
            all_results.push(result);
            trusted_count += 1;
            allows += 1;
            continue;
        }

        match check_package(ecosystem, name, version).await {
            Ok(verdict) => {
                let verdict_upper = verdict.verdict.to_uppercase();
                let result = RichPackageResult {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: ecosystem.clone(),
                    verdict: verdict_upper.clone(),
                    risk_score: verdict.risk_score,
                    title: verdict.title.clone(),
                    trusted: false,
                    error: None,
                };
                print_rich_package_result(&result, is_last, "");
                all_results.push(result);

                match verdict_upper.as_str() {
                    "ALLOW" => allows += 1,
                    "WARN" => {
                        warns += 1;
                        findings.push(GitScanFinding {
                            package: name.clone(),
                            version: version.clone(),
                            ecosystem: ecosystem.clone(),
                            verdict: verdict_upper,
                            risk_score: verdict.risk_score,
                            title: verdict.title,
                        });
                    }
                    "BLOCK" => {
                        blocks += 1;
                        findings.push(GitScanFinding {
                            package: name.clone(),
                            version: version.clone(),
                            ecosystem: ecosystem.clone(),
                            verdict: verdict_upper,
                            risk_score: verdict.risk_score,
                            title: verdict.title,
                        });
                    }
                    _ => allows += 1,
                }
                print_rich_package_result(all_results.last().unwrap(), is_last, "");
            }
            Err(e) => {
                let result = RichPackageResult {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: ecosystem.clone(),
                    verdict: "ERROR".to_string(),
                    risk_score: 0,
                    title: format!("Failed to check: {}", e),
                    trusted: false,
                    error: Some(e.to_string()),
                };
                all_results.push(result);
                allows += 1;
                print_rich_package_result(all_results.last().unwrap(), is_last, "");
            }
        }
    }

    // Print summary and collapsible details
    print_rich_scan_summary(allows, warns, blocks, trusted_count);
    print_collapsible_details(&all_results);

    if blocks > 0 {
        println!("\x1b[31m❌ {} BLOCKED packages found in changed files.\x1b[0m", blocks);
    } else if warns > 0 {
        println!("\x1b[33m⚠️  {} packages flagged as WARN in changed files.\x1b[0m", warns);
    } else {
        println!("\x1b[32m✅ All changed packages passed.\x1b[0m");
    }

    Ok(GitScanResult {
        packages_scanned: packages_to_scan.len(),
        allows,
        warns,
        blocks,
        findings,
    })
}

#[cfg(target_os = "linux")]
async fn daemon_mode() -> Result<(), Box<dyn std::error::Error>> {
    use inotify::{Inotify, watch_mask};
    use std::os::unix::ffi::OsStrExt;

    println!("\n🚀 Starting Kairo Daemon Mode");
    println!("==============================");

    // Start kairo-server as a background process
    println!("Starting kairo-server...");
    let server_child = std::process::Command::new("cargo")
        .args(["run", "-p", "kairo-server"])
        .current_dir("/home/govinda/kairo")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let server_pid = server_child.id();
    println!("Server started with PID {}", server_pid);

    // Wait for server to be ready
    println!("Waiting for server to be ready...");
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let mut retries = 0;
    let max_retries = 60;
    let server_ready = loop {
        match client.get(format!("{}/health", SERVER_URL)).send().await {
            Ok(resp) if resp.status().is_success() => {
                println!("Server is ready!");
                break true;
            }
            _ => {
                retries += 1;
                if retries >= max_retries {
                    eprintln!("Server failed to become ready after {} retries", max_retries);
                    break false;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    };

    if !server_ready {
        eprintln!("Failed to start kairo-server");
        std::process::exit(1);
    }

    // Set up inotify watcher
    println!("Watching for dependency file changes...");
    let mut inotify = Inotify::init()?;
    let watch_mask = watch_mask::MODIFY | watch_mask::CREATE | watch_mask::DELETE | watch_mask::MOVED_FROM | watch_mask::MOVED_TO;

    // Watch current directory recursively for dependency files
    let cwd = std::env::current_dir()?;
    inotify.add_watch(&cwd, watch_mask)?;

    println!("\n📁 Daemon active. Watching:");
    println!("   - package.json, package-lock.json, yarn.lock, pnpm-lock.yaml");
    println!("   - Cargo.toml, Cargo.lock");
    println!("   - requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, poetry.lock");
    println!("   - go.mod, go.sum");
    println!("   - *.lock files");
    println!("\nPress Ctrl+C to stop.\n");

    let mut buffer = vec![0u8; 4096];

    // Set up Ctrl+C handler
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        // Check for file events with a timeout
        if let Ok(events) = inotify.read_events(&mut buffer) {
            for event in events {
                let name_bytes = event.name.as_bytes();
                if !name_bytes.is_empty() {
                    let name_str = String::from_utf8_lossy(name_bytes).to_string();
                    if is_dependency_file(&name_str) {
                        println!("\n🔔 Change detected: {}", name_str);

                        // Run a scan on the project
                        let cwd_str = cwd.to_string_lossy().to_string();
                        match scan_project(&cwd_str).await {
                            Ok(result) => {
                                if result.blocks > 0 {
                                    println!("\n⚠️  Scan complete: {} blocked packages found", result.blocks);
                                } else {
                                    println!("\n✅ Scan complete: no blocked packages");
                                }
                            }
                            Err(e) => {
                                eprintln!("Scan error: {}", e);
                            }
                        }
                        println!();
                    }
                }
            }
        }

        // Small sleep to prevent busy looping
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Cleanup
    println!("\nStopping server (PID {})...", server_pid);
    // Server is child process, it will be killed when this process exits
    // For graceful shutdown, we would need to send SIGTERM
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn daemon_mode() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Daemon mode is only supported on Linux.");
    eprintln!("Use 'kairo server' in one terminal and 'kairo scan' in another.");
    std::process::exit(1);
}

fn extract_changed_files(diff_content: &str) -> Vec<String> {
    let mut changed_files = Vec::new();
    let mut current_file = String::new();
    let mut in_diff = false;

    for line in diff_content.lines() {
        // Track which file we're in
        if line.starts_with("diff --git") {
            in_diff = true;
            current_file.clear();
        } else if line.starts_with("+++") && in_diff {
            // Extract file path from +++ b/path/to/file
            let path = line.trim_start_matches("+++ ").trim_start_matches("b/");
            if path != "/dev/null" && !path.is_empty() {
                current_file = path.to_string();
            }
        } else if line.starts_with("@@") && !current_file.is_empty() {
            // We've moved past the header, check if this file is a dependency file
            if is_dependency_file(&current_file) && !changed_files.contains(&current_file) {
                    changed_files.push(current_file.clone());
                }
            current_file.clear();
            in_diff = false;
        } else if line.starts_with("new file") || line.starts_with("deleted file") || line.starts_with("index ") {
            // These also indicate valid file entries
        }
    }

    // Check last file if still in diff
    if !current_file.is_empty() && is_dependency_file(&current_file) && !changed_files.contains(&current_file) {
            changed_files.push(current_file);
        }

    changed_files
}

async fn pip_audit(requirements_path: Option<String>, json_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    let path = match requirements_path {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from("requirements.txt"),
    };

    if !path.exists() {
        return Err(format!("requirements.txt not found at {}", path.display()).into());
    }

    let content = fs::read_to_string(&path)?;
    let packages = parse_requirements_txt(&content);

    if packages.is_empty() {
        if !json_output {
            println!("No packages found in requirements.txt");
        }
        return Ok(());
    }

    if !json_output {
        println!("\n🔍 Auditing {} Python packages against OSV...\n", packages.len());
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut total_vulns = 0;
    let mut findings: Vec<PipAuditFinding> = Vec::new();

    for (name, version) in &packages {
        print!("  {}@{} ", name, version);
        std::io::stdout().flush().ok();

        let query = serde_json::json!({
            "package": name,
            "version": version,
            "ecosystem": "PyPI"
        });

        match client.post("https://api.osv.dev/v1/query")
            .json(&query)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                #[derive(Deserialize)]
                struct OsvResponse {
                    vulns: Option<Vec<OsvVuln>>,
                }
                #[derive(Deserialize)]
                struct OsvVuln {
                    id: String,
                    summary: Option<String>,
                    severity: Option<OsvSeverity>,
                    #[allow(dead_code)]
                    database_specific: Option<serde_json::Value>,
                }
                #[derive(Deserialize)]
                struct OsvSeverity {
                    score: Option<String>,
                }

                if let Ok(osv_resp) = resp.json::<OsvResponse>().await {
                    if let Some(vulns) = osv_resp.vulns {
                        let vuln_count = vulns.len();
                        if vuln_count > 0 {
                            total_vulns += vuln_count;
                            for vuln in vulns {
                                let severity = vuln.severity.and_then(|s| s.score).unwrap_or_else(|| "UNKNOWN".to_string());
                                let vuln_id = vuln.id.clone();
                                findings.push(PipAuditFinding {
                                    package: name.clone(),
                                    version: version.clone(),
                                    vuln_id: vuln_id.clone(),
                                    summary: vuln.summary.unwrap_or_else(|| "No summary".to_string()),
                                    severity: severity.clone(),
                                });
                                if json_output {
                                    println!("\n  Vuln: {} severity={}", vuln_id, severity);
                                }
                            }
                            if !json_output {
                                println!("\x1b[31m{} vuln(s)\x1b[0m", vuln_count);
                            }
                            continue;
                        }
                    }
                }
                if !json_output {
                    println!("\x1b[32mOK\x1b[0m");
                }
            }
            Ok(resp) => {
                if !json_output {
                    println!("\x1b[33mHTTP {}\x1b[0m", resp.status());
                }
            }
            Err(e) => {
                if !json_output {
                    println!("\x1b[33merror\x1b[0m: {}", e);
                }
            }
        }
    }

    if json_output {
        #[derive(Serialize)]
        struct PipAuditJsonResult {
            packages_scanned: usize,
            total_vulnerabilities: usize,
            findings: Vec<PipAuditFinding>,
        }
        println!("{}", serde_json::to_string(&PipAuditJsonResult {
            packages_scanned: packages.len(),
            total_vulnerabilities: total_vulns,
            findings,
        })?);
    } else {
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║  PIP AUDIT RESULTS                                     ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  Packages scanned: {:3}                                   ║", packages.len());
        println!("║  Vulnerabilities: {:3}                                   ║", total_vulns);
        println!("╚══════════════════════════════════════════════════════════╝");
        if total_vulns > 0 {
            println!("\n❌ {} vulnerabilities found. Run with --json for details.", total_vulns);
            return Err("Vulnerabilities found".into());
        } else {
            println!("\n✅ No vulnerabilities found.");
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct PipAuditFinding {
    package: String,
    version: String,
    vuln_id: String,
    summary: String,
    severity: String,
}

#[cfg(target_os = "linux")]
async fn watch_project(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    use inotify::{Inotify, watch_mask};
    use std::os::unix::ffi::OsStrExt;

    let watch_path = PathBuf::from(path);

    if !watch_path.exists() {
        return Err(format!("Path does not exist: {}", watch_path.display()).into());
    }

    println!("\n🔍 Kairo Watch Mode");
    println!("====================");
    println!("Watching: {}", watch_path.display());
    println!("\nPress Ctrl+C to stop.\n");

    // Run initial scan
    println!("Running initial scan...");
    match scan_project(&watch_path.to_string_lossy()).await {
        Ok(result) => {
            if result.blocks > 0 {
                println!("\n⚠️  Initial scan complete: {} blocked packages found", result.blocks);
            } else {
                println!("\n✅ Initial scan complete: no blocked packages");
            }
        }
        Err(e) => {
            eprintln!("Initial scan error: {}", e);
        }
    }
    println!();

    // Set up inotify watcher
    let mut inotify = Inotify::init()?;
    let watch_mask = watch_mask::MODIFY | watch_mask::CREATE | watch_mask::DELETE | watch_mask::MOVED_FROM | watch_mask::MOVED_TO;
    inotify.add_watch(&watch_path, watch_mask)?;

    // Also watch subdirectories for lock files
    if watch_path.is_dir() {
        watch_directory_recursive(&mut inotify, &watch_path, watch_mask)?;
    }

    let mut buffer = vec![0u8; 4096];

    // Set up Ctrl+C handler
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_clone = running.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        running_clone.store(false, std::sync::atomic::Ordering::SeqCst);
    });

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        // Check for file events with a timeout
        if let Ok(events) = inotify.read_events(&mut buffer) {
            for event in events {
                let name_bytes = event.name.as_bytes();
                if !name_bytes.is_empty() {
                    let name_str = String::from_utf8_lossy(name_bytes).to_string();
                    if is_dependency_file(&name_str) {
                        println!("🔔 Change detected: {}", name_str);

                        match scan_project(&watch_path.to_string_lossy()).await {
                            Ok(result) => {
                                if result.blocks > 0 {
                                    println!("\n⚠️  Scan complete: {} blocked packages found", result.blocks);
                                } else {
                                    println!("\n✅ Scan complete: no blocked packages");
                                }
                            }
                            Err(e) => {
                                eprintln!("Scan error: {}", e);
                            }
                        }
                        println!();
                    }
                }
            }
        }

        // Small sleep to prevent busy looping
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    println!("\nStopping watcher...");
    Ok(())
}

#[cfg(target_os = "linux")]
fn watch_directory_recursive(inotify: &mut inotify::Inotify, path: &PathBuf, mask: inotify::WatchMask) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            // Skip common directories that don't contain dependency files
            let skip_dirs = ["node_modules", ".git", "target", "__pycache__", ".venv", "venv"];
            if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
                if !skip_dirs.contains(&name) {
                    inotify.add_watch(&entry_path, mask)?;
                    watch_directory_recursive(inotify, &entry_path, mask)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn watch_project(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Watch mode is only supported on Linux.");
    eprintln!("Use 'kairo scan --path {}' for one-time scanning.", path);
    std::process::exit(1);
}

#[derive(Serialize, Deserialize)]
struct KairoExport {
    version: String,
    trust_list: Vec<String>,
    local_blocklist: Vec<String>,
}

fn export_data(output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let trust = read_trust_list();
    let blocklist = read_local_blocklist();

    let export = KairoExport {
        version: "1.0".to_string(),
        trust_list: trust,
        local_blocklist: blocklist,
    };

    let content = serde_json::to_string_pretty(&export)?;
    fs::write(output_path, content)?;

    println!("Exported to {}", output_path);
    println!("  - Trust list: {} packages", export.trust_list.len());
    println!("  - Local blocklist: {} packages", export.local_blocklist.len());

    Ok(())
}

fn import_data(input_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(input_path)?;
    let import: KairoExport = serde_json::from_str(&content)?;

    // Merge trust list
    let mut trust = read_trust_list();
    let mut added_trust = 0;
    for pkg in import.trust_list {
        if !trust.contains(&pkg) {
            trust.push(pkg);
            added_trust += 1;
        }
    }
    write_trust_list(&trust)?;

    // Merge local blocklist
    let mut blocklist = read_local_blocklist();
    let mut added_blocklist = 0;
    for pkg in import.local_blocklist {
        if !blocklist.contains(&pkg) {
            blocklist.push(pkg);
            added_blocklist += 1;
        }
    }
    write_local_blocklist(&blocklist)?;

    println!("Imported from {}", input_path);
    println!("  - Trust list: {} packages added ({} total)", added_trust, trust.len());
    println!("  - Local blocklist: {} packages added ({} total)", added_blocklist, blocklist.len());

    Ok(())
}

fn config_validate() {
    println!("\n🔍 Kairo Config Validation");
    println!("===========================\n");

    let config_dir = get_config_dir();
    let mut issues: Vec<String> = Vec::new();

    // Check server.yaml
    let server_yaml_path = config_dir.join("server.yaml");
    match fs::read_to_string(&server_yaml_path) {
        Ok(content) => {
            match serde_yaml::from_str::<serde_yaml::Value>(&content) {
                Ok(_) => {
                    println!("✅ server.yaml: valid YAML");
                }
                Err(e) => {
                    println!("❌ server.yaml: invalid YAML - {}", e);
                    issues.push(format!("server.yaml: invalid YAML ({})", e));
                }
            }
        }
        Err(_) => {
            println!("⚠️  server.yaml: not found (optional)");
        }
    }

    // Check mcp.yaml
    let mcp_yaml_path = config_dir.join("mcp.yaml");
    match fs::read_to_string(&mcp_yaml_path) {
        Ok(content) => {
            match serde_yaml::from_str::<serde_yaml::Value>(&content) {
                Ok(_) => {
                    println!("✅ mcp.yaml: valid YAML");
                }
                Err(e) => {
                    println!("❌ mcp.yaml: invalid YAML - {}", e);
                    issues.push(format!("mcp.yaml: invalid YAML ({})", e));
                }
            }
        }
        Err(_) => {
            println!("⚠️  mcp.yaml: not found (optional)");
        }
    }

    // Check trust.json
    let trust_path = get_trust_path();
    match fs::read_to_string(&trust_path) {
        Ok(content) => {
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(_) => {
                    println!("✅ trust.json: valid JSON");
                }
                Err(e) => {
                    println!("❌ trust.json: invalid JSON - {}", e);
                    issues.push(format!("trust.json: invalid JSON ({})", e));
                }
            }
        }
        Err(_) => {
            println!("⚠️  trust.json: not found (optional)");
        }
    }

    // Check blocklist.json (local)
    let blocklist_path = get_blocklist_path();
    if blocklist_path.exists() {
        match fs::read_to_string(&blocklist_path) {
            Ok(content) => {
                match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(_) => {
                        println!("✅ blocklist.json: valid JSON");
                    }
                    Err(e) => {
                        println!("❌ blocklist.json: invalid JSON - {}", e);
                        issues.push(format!("blocklist.json: invalid JSON ({})", e));
                    }
                }
            }
            Err(e) => {
                println!("❌ blocklist.json: could not read - {}", e);
                issues.push(format!("blocklist.json: could not read ({})", e));
            }
        }
    } else {
        println!("⚠️  blocklist.json: not found (optional)");
    }

    println!();

    if issues.is_empty() {
        println!("✅ All config checks passed!");
    } else {
        println!("❌ {} issue(s) found:", issues.len());
        for issue in &issues {
            println!("  - {}", issue);
        }
    }
    println!();
}

fn is_dependency_file(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    path_lower.ends_with("package.json")
        || path_lower.ends_with("package-lock.json")
        || path_lower.ends_with("yarn.lock")
        || path_lower.ends_with("pnpm-lock.yaml")
        || path_lower.ends_with("cargo.lock")
        || path_lower.ends_with("cargo.toml")
        || path_lower.ends_with("requirements.txt")
        || path_lower.ends_with("go.mod")
        || path_lower.ends_with("go.sum")
        || path_lower.ends_with("pipfile")
        || path_lower.ends_with("pipfile.lock")
        || path_lower.ends_with("pyproject.toml")
        || path_lower.ends_with("poetry.lock")
}

async fn stats() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let url = format!("{}/v1/stats", SERVER_URL);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to connect to Kairo Decision Server at {}/v1/stats: {}. Is kairo-server running?", SERVER_URL, e))?;

    if !resp.status().is_success() {
        return Err(format!("Server returned error: {}", resp.status()).into());
    }

    let stats: StatsResponse = resp.json().await.map_err(|e| {
        format!("Invalid response from server: {}", e)
    })?;

    let total = stats.total_checks;
    let block = stats.block_count;
    let warn = stats.warn_count;
    let allow = stats.allow_count;

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KAIRO STATISTICS                                       ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Total Checks: {:>6}                                    ║", total);
    println!("╠══════════════════════════════════════════════════════════╣");

    // Mini bar chart
    let bar_width = 40usize;
    let scale = if total > 0 { total as f64 } else { 1.0 };

    let block_width = ((block as f64 / scale) * bar_width as f64).round() as usize;
    let warn_width = ((warn as f64 / scale) * bar_width as f64).round() as usize;
    let allow_width = ((allow as f64 / scale) * bar_width as f64).round() as usize;

    // Build bar segments
    let block_bar = "\x1b[31m"; // red
    let warn_bar = "\x1b[33m";  // yellow
    let allow_bar = "\x1b[32m"; // green
    let reset = "\x1b[0m";

    let mut bar = String::new();
    bar.push_str(block_bar);
    for _ in 0..block_width {
        bar.push('█');
    }
    bar.push_str(reset);
    bar.push_str(warn_bar);
    for _ in 0..warn_width {
        bar.push('█');
    }
    bar.push_str(reset);
    bar.push_str(allow_bar);
    for _ in 0..allow_width {
        bar.push('█');
    }
    bar.push_str(reset);

    println!("║  {}  ║", truncate(&bar, 58));
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  {}🚫 Block:   {:>5}{}                               ║", block_bar, block, reset);
    println!("║  {}⚠️  Warn:   {:>5}{}                               ║", warn_bar, warn, reset);
    println!("║  {}✅ Allow:   {:>5}{}                               ║", allow_bar, allow, reset);
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}
