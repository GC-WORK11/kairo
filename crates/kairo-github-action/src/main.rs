use clap::{Parser, Subcommand};
use kairo_core::{Action, ActionType, Ecosystem, RepoContext};
use reqwest::Client;
use serde::Deserialize;
use std::env;

#[derive(Parser)]
#[command(name = "kairo")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run Kairo check as a GitHub Action
    GithubAction {
        policy: String,
        github_token: String,
        api_url: String,
        fail_on: String,
    },
    /// Run Kairo check locally with a diff file (for testing)
    LocalCheck {
        #[arg(long)]
        diff_file: String,
        #[arg(long)]
        api_url: String,
        #[arg(long)]
        fail_on: String,
    },
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VerdictResponse {
    verdict: String,
    #[allow(dead_code)]
    risk_score: u8,
    title: String,
    summary: String,
    #[allow(dead_code)]
    recommended_action: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GithubAction {
            policy,
            github_token,
            api_url,
            fail_on,
        } => {
            run_github_action(&policy, &github_token, &api_url, &fail_on).await?;
        }
        Commands::LocalCheck {
            diff_file,
            api_url,
            fail_on,
        } => {
            run_local_check(&diff_file, &api_url, &fail_on).await?;
        }
    }
    Ok(())
}

#[derive(Clone)]
struct ChangedFile {
    filename: String,
    diff: String,
}

async fn run_github_action(
    _policy: &str,
    github_token: &str,
    api_url: &str,
    fail_on: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let event_name = env::var("GITHUB_EVENT_NAME").unwrap_or_default();
    let event_path = env::var("GITHUB_EVENT_PATH").unwrap_or_default();
    let _workspace = env::var("GITHUB_WORKSPACE").unwrap_or_default();
    let repository = env::var("GITHUB_REPOSITORY").unwrap_or_default();

    if event_name != "pull_request" {
        println!("Kairo: Not a pull request event ({}), skipping.", event_name);
        return Ok(());
    }

    let event_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&event_path)?)?;

    let pr = event_json
        .get("pull_request")
        .ok_or("No pull_request in event")?;
    let pr_number = pr
        .get("number")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let base_ref = pr
        .get("base")
        .and_then(|v| v.get("ref"))
        .and_then(|v| v.as_str())
        .unwrap_or("main");
    let head_ref = pr
        .get("head")
        .and_then(|v| v.get("ref"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    println!(
        "Kairo: Checking PR #{} ({} <- {})",
        pr_number, base_ref, head_ref
    );

    let changed_files = get_changed_files(github_token, &repository, pr_number).await?;
    println!("Kairo: {} files changed", changed_files.len());

    let risky_patterns = identify_risky_files(&changed_files);
    if risky_patterns.is_empty() {
        println!("Kairo: No risky files detected.");
        post_success(github_token, &repository, &pr_number, "No risky actions detected.").await?;
        return Ok(());
    }

    println!("Kairo: Checking {} risky file patterns...", risky_patterns.len());

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut block_count = 0;
    let mut warn_count = 0;
    let mut results = vec![];

    for pattern in &risky_patterns {
        let verdict = check_pattern(&client, api_url, pattern).await?;
        if verdict.verdict == "BLOCK" {
            block_count += 1;
        } else if verdict.verdict == "WARN" {
            warn_count += 1;
        }
        results.push(format!(
            "{}: [{}] {} — {}",
            pattern.filename, verdict.verdict, verdict.title, verdict.summary
        ));
    }

    let summary = format!(
        "Kairo checked {} risky items: {} BLOCK, {} WARN",
        risky_patterns.len(),
        block_count,
        warn_count
    );

    let comment_body = format!(
        "## Kairo Risk Check\n\n{}\n\n### Details\n{}\n\n---\n*Checked by [Kairo](https://kairo.ai)*",
        summary,
        results.iter().map(|r| format!("- {}", r)).collect::<Vec<_>>().join("\n")
    );

    post_pr_comment(github_token, &repository, pr_number, &comment_body).await?;

    let (status_state, status_desc) = if block_count > 0 {
        ("error", &summary)
    } else if warn_count > 0 {
        ("warning", &summary)
    } else {
        ("success", &summary)
    };

    post_commit_status(github_token, &repository, head_ref, status_state, status_desc).await?;

    let should_fail = match fail_on {
        "block" => block_count > 0,
        "warn" => warn_count > 0 || block_count > 0,
        _ => false,
    };

    if should_fail {
        eprintln!("Kairo: FAILED — {}", summary);
        std::process::exit(1);
    }

    println!("Kairo: {}", summary);
    Ok(())
}

async fn get_changed_files(
    token: &str,
    repo: &str,
    pr_number: u32,
) -> Result<Vec<ChangedFile>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.github.com/repos/{}/pulls/{}/files",
        repo, pr_number
    );

    let resp = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "kairo-github-action")
        .send()
        .await?;

    #[derive(Deserialize)]
    struct FileResponse {
        filename: String,
        #[allow(dead_code)]
        status: String,
        patch: Option<String>,
    }

    let files: Vec<FileResponse> = resp.json().await?;
    Ok(files
        .into_iter()
        .map(|f| ChangedFile {
            filename: f.filename,
            diff: f.patch.unwrap_or_default(),
        })
        .collect())
}

fn identify_risky_files(files: &[ChangedFile]) -> Vec<ChangedFile> {
    files
        .iter()
        .filter(|f| {
            let fname = f.filename.as_str();
            fname.contains("package.json")
                || fname.contains("package-lock.json")
                || fname.contains("pnpm-lock.yaml")
                || fname.contains("yarn.lock")
                || fname.contains("bun.lock")
                || fname.contains("requirements.txt")
                || fname.contains("Cargo.toml")
                || fname.contains("Cargo.lock")
                || fname.contains(".github/workflows")
                || fname.contains("Dockerfile")
                || fname.contains("docker-compose")
                || fname.contains(".tf")
                || fname.contains("prisma/")
                || fname.contains("migrations/")
                || fname.contains(".env")
        })
        .cloned()
        .collect()
}

async fn check_pattern(
    client: &Client,
    api_url: &str,
    file: &ChangedFile,
) -> Result<VerdictResponse, Box<dyn std::error::Error>> {
    let pattern = &file.filename;
    let diff_content = &file.diff;

    let (action_type, ecosystem, package_hint, version_hint) = if pattern.contains("package")
        || pattern.contains("lock")
    {
        let (pkg, ver) = extract_package_from_lock(pattern, diff_content);
        (ActionType::PackageInstall, Ecosystem::npm, pkg, ver)
    } else if pattern.contains(".github/workflows") {
        (ActionType::CiChange, Ecosystem::npm, None, None)
    } else if pattern.contains("Dockerfile") {
        let (img, tag) = extract_docker_image(diff_content);
        (ActionType::PackageInstall, Ecosystem::docker, img, tag)
    } else if pattern.contains("prisma") || pattern.contains("migrations") {
        (ActionType::Migration, Ecosystem::npm, None, None)
    } else if pattern.contains("Cargo.toml") || pattern.contains("Cargo.lock") {
        let (pkg, ver) = extract_cargo_crate(diff_content);
        (ActionType::PackageInstall, Ecosystem::cargo, pkg, ver)
    } else if pattern.contains("requirements.txt") {
        let (pkg, ver) = extract_pip_package(diff_content);
        (ActionType::PackageInstall, Ecosystem::pip, pkg, ver)
    } else if pattern.contains("go.mod") {
        let (pkg, ver) = extract_go_module(diff_content);
        (ActionType::PackageInstall, Ecosystem::go, pkg, ver)
    } else {
        (ActionType::CommandExec, Ecosystem::npm, None, None)
    };

    let action = Action {
        action_type,
        ecosystem,
        command: format!("Checking file: {}", pattern),
        package: package_hint,
        version: version_hint,
        repo_context: RepoContext {
            framework: None,
            has_database: pattern.contains("prisma") || pattern.contains("migrations"),
            has_ci: pattern.contains(".github/workflows"),
        },
    };

    let resp = client
        .post(format!("{}/v1/decide", api_url))
        .json(&action)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(VerdictResponse {
            verdict: "ALLOW".to_string(),
            risk_score: 0,
            title: "Check unavailable".to_string(),
            summary: format!("Kairo server returned {}", resp.status()),
            recommended_action: None,
        });
    }

    let verdict: VerdictResponse = resp.json().await?;
    Ok(verdict)
}

fn extract_package_from_lock(filename: &str, diff_content: &str) -> (Option<String>, Option<String>) {
    let is_lock_file = filename.contains("package-lock.json")
        || filename.contains("pnpm-lock.yaml")
        || filename.contains("yarn.lock")
        || filename.contains("bun.lock");

    // For plain package.json, we still want to extract packages from the diff
    let is_package_json = filename == "package.json" || filename.ends_with("/package.json");

    if !is_lock_file && !is_package_json {
        return (None, None);
    }

    // Parse added lines (lines starting with + that aren't +++ or +{)
    for line in diff_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip diff header lines
        if trimmed.starts_with("+++") || trimmed.starts_with("diff --git") || trimmed.starts_with("@@") {
            continue;
        }

        // Only process added lines
        let content = if let Some(stripped) = trimmed.strip_prefix('+') {
            stripped
        } else {
            continue;
        };

        // Skip empty lines after +
        if content.is_empty() {
            continue;
        }

        // Try to extract package@version pattern
        // For package-lock.json and pnpm-lock.yaml: "package-name": "version" or package-name@version
        // For yarn.lock: pkgname@version
        // For package.json dependencies: "package": "version"

        // Try regex-like pattern matching for package@version
        if let Some((pkg, ver)) = extract_package_version(content) {
            return (Some(pkg), Some(ver));
        }
    }

    (None, None)
}

fn extract_package_version(content: &str) -> Option<(String, String)> {
    let content = content.trim();

    // Pattern 1: "package": "version" (package.json format)
    // Find quoted package name followed by colon and quoted version
    if let Some(start) = content.find('"') {
        if let Some(quote_end) = content[start + 1..].find('"') {
            let pkg_name = &content[start + 1..start + 1 + quote_end];
            let after_name = &content[start + 1 + quote_end + 1..];
            if after_name.trim().starts_with(':') || after_name.trim().starts_with(',') {
                if let Some(version_start) = after_name.find('"') {
                    if let Some(version_end) = after_name[version_start + 1..].find('"') {
                        let version = &after_name[version_start + 1..version_start + 1 + version_end];
                        if !version.is_empty() && !pkg_name.is_empty() {
                            // Clean up version (remove ^ ~ >= etc for npm)
                            let clean_version = version.trim_start_matches(['^', '~', '>', '<', '=']);
                            return Some((pkg_name.to_string(), clean_version.to_string()));
                        }
                    }
                }
            }
        }
    }

    // Pattern 2: package-name@version (yarn.lock, npm format in diffs)
    // Look for @version at the end of a package name
    if let Some(at_pos) = content.find('@') {
        if at_pos > 0 {
            let pkg_name = &content[..at_pos];
            let after_at = &content[at_pos + 1..];
            // Version is typically until space, newline, or end
            let version = after_at.split(|c: char| c.is_whitespace() || c == ',' || c == ')').next()?;
            if !pkg_name.is_empty() && !version.is_empty() && !version.contains('/') {
                return Some((pkg_name.to_string(), version.to_string()));
            }
        }
    }

    // Pattern 3: "package@version" in quotes
    if let Some(at_pos) = content.find('@') {
        if at_pos > 0 {
            // Check if there's a quote before the @
            let before_at = &content[..at_pos];
            if let Some(quote_start) = before_at.rfind('"') {
                let pkg_name = &content[quote_start + 1..at_pos];
                let after_at = &content[at_pos + 1..];
                if let Some(quote_end) = after_at.find('"') {
                    let version = &after_at[..quote_end];
                    if !pkg_name.is_empty() && !version.is_empty() {
                        return Some((pkg_name.to_string(), version.to_string()));
                    }
                }
            }
        }
    }

    None
}

fn extract_cargo_crate(diff_content: &str) -> (Option<String>, Option<String>) {
    let mut in_dependencies = false;
    let mut in_dev_dependencies = false;

    for line in diff_content.lines() {
        let trimmed = line.trim();

        // Skip diff headers
        if trimmed.starts_with("+++") || trimmed.starts_with("diff --git") || trimmed.starts_with("@@") {
            continue;
        }

        // Track section headers
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = trimmed.trim_start_matches('[').trim_end_matches(']');
            in_dependencies = section == "dependencies";
            in_dev_dependencies = section == "dev-dependencies";
            continue;
        }

        // Only process added lines
        let content = if let Some(stripped) = trimmed.strip_prefix('+') {
            stripped
        } else {
            continue;
        };

        // Skip empty lines and comments
        if content.is_empty() || content.starts_with('#') {
            continue;
        }

        // Only process if we're in dependencies section
        if !in_dependencies && !in_dev_dependencies {
            continue;
        }

        // Parse crate = "version" pattern
        if let Some(eq_pos) = content.find('=') {
            let name_part = content[..eq_pos].trim();
            if name_part.is_empty() || !name_part.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                continue;
            }

            let value_part = content[eq_pos + 1..].trim();

            // Handle simple version: crate = "1.0"
            if let Some(stripped) = value_part.strip_prefix('"') {
                if let Some(end_quote) = stripped.find('"') {
                    let version = &stripped[..end_quote];
                    if !version.is_empty() {
                        return (Some(name_part.to_string()), Some(version.to_string()));
                    }
                }
            }

            // Handle table format: crate = { version = "1.0", ... }
            if value_part.starts_with('{') {
                if let Some(version_pos) = value_part.find("version") {
                    let after_version = &value_part[version_pos + 7..];
                    if let Some(eq_pos) = after_version.find('=') {
                        let after_eq = after_version[eq_pos + 1..].trim();
                        if let Some(stripped) = after_eq.strip_prefix('"') {
                            if let Some(end_quote) = stripped.find('"') {
                                let version = &stripped[..end_quote];
                                if !version.is_empty() {
                                    return (Some(name_part.to_string()), Some(version.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (None, None)
}

fn extract_pip_package(diff_content: &str) -> (Option<String>, Option<String>) {
    for line in diff_content.lines() {
        let trimmed = line.trim();

        // Skip diff headers
        if trimmed.starts_with("+++") || trimmed.starts_with("diff --git") || trimmed.starts_with("@@") {
            continue;
        }

        // Only process added lines
        let content = if let Some(stripped) = trimmed.strip_prefix('+') {
            stripped
        } else {
            continue;
        };

        if content.is_empty() {
            continue;
        }

        let content = content.trim();

        // Parse package==version format
        if let Some(eq_pos) = content.find("==") {
            let pkg = content[..eq_pos].trim();
            let version = content[eq_pos + 2..].trim();
            if !pkg.is_empty() && !version.is_empty() && !pkg.starts_with('#') {
                return (Some(pkg.to_string()), Some(version.to_string()));
            }
        }

        // Handle >=, <=, ~, !=, >, < operators
        for op in &[">=", "<=", "~=", "!=", ">", "<", "="] {
            if let Some(pos) = content.find(op) {
                let pkg = content[..pos].trim();
                let version = content[pos + op.len()..].trim();
                if !pkg.is_empty() && !version.is_empty() && !pkg.starts_with('#') {
                    let version = version.split(|c: char| c.is_whitespace() || c == ',').next().unwrap_or(version);
                    return (Some(pkg.to_string()), Some(version.to_string()));
                }
            }
        }
    }

    (None, None)
}

fn extract_go_module(diff_content: &str) -> (Option<String>, Option<String>) {
    for line in diff_content.lines() {
        let trimmed = line.trim();

        // Skip diff headers
        if trimmed.starts_with("+++") || trimmed.starts_with("diff --git") || trimmed.starts_with("@@") {
            continue;
        }

        // Only process added lines
        let content = if let Some(stripped) = trimmed.strip_prefix('+') {
            stripped
        } else {
            continue;
        };

        let content = content.trim();

        if content.is_empty() || content.starts_with("//") {
            continue;
        }

        // Parse require directive: require module version
        if content.starts_with("require") {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 3 {
                let module = parts[1];
                let version = parts[2].trim_start_matches('v');
                if !module.is_empty() && !version.is_empty() && !module.starts_with('/') {
                    return (Some(module.to_string()), Some(version.to_string()));
                }
            }
        }

        // Handle replace directive: replace module => other
        if content.starts_with("replace") {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 4 && parts[2] == "=>" {
                let module = parts[1];
                if !module.is_empty() && !module.starts_with('/') {
                    return (Some(module.to_string()), Some("replace".to_string()));
                }
            }
        }

        // Handle go 1.21 format: module v1.0.0
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 2 {
            let first = parts[0];
            let second = parts[1];
            if (first.contains('.') || first.starts_with("gopkg")) && !first.starts_with('.') {
                let version = second.trim_start_matches('v');
                return (Some(first.to_string()), Some(version.to_string()));
            }
        }
    }

    (None, None)
}

fn extract_docker_image(diff_content: &str) -> (Option<String>, Option<String>) {
    for line in diff_content.lines() {
        let trimmed = line.trim();

        // Skip diff headers
        if trimmed.starts_with("+++") || trimmed.starts_with("diff --git") || trimmed.starts_with("@@") {
            continue;
        }

        // Only process added lines
        let content = if let Some(stripped) = trimmed.strip_prefix('+') {
            stripped
        } else {
            continue;
        };

        let content = content.trim();

        // Look for FROM instruction
        if let Some(from_pos) = content.find("FROM") {
            let after_from = content[from_pos + 4..].trim();
            // Parse image:tag or image@digest
            // Handle FROM image:tag format
            if let Some(colon_pos) = after_from.find(':') {
                let image = &after_from[..colon_pos];
                let rest = &after_from[colon_pos + 1..];
                // Tag is until space or end
                let tag = rest.split_whitespace().next().unwrap_or(rest);
                if !image.is_empty() && !tag.is_empty() && !tag.contains('@') {
                    return (Some(image.to_string()), Some(tag.to_string()));
                }
            }
            // Handle image@digest (no tag)
            if let Some(at_pos) = after_from.find('@') {
                let image = &after_from[..at_pos];
                if !image.is_empty() {
                    return (Some(image.to_string()), Some("latest".to_string()));
                }
            }
            // Plain image without tag
            let image = after_from.split_whitespace().next().unwrap_or(after_from);
            if !image.is_empty() && !image.contains(':') {
                return (Some(image.to_string()), Some("latest".to_string()));
            }
        }
    }
    (None, None)
}

async fn post_pr_comment(
    token: &str,
    repo: &str,
    pr_number: u32,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.github.com/repos/{}/issues/{}/comments",
        repo, pr_number
    );

    reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "kairo-github-action")
        .json(&serde_json::json!({ "body": body }))
        .send()
        .await?;

    Ok(())
}

async fn post_commit_status(
    token: &str,
    repo: &str,
    sha: &str,
    state: &str,
    description: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.github.com/repos/{}/statuses/{}",
        repo,
        std::env::var("GITHUB_SHA").unwrap_or_else(|_| sha.to_string())
    );

    reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "kairo-github-action")
        .json(&serde_json::json!({
            "state": state,
            "description": description,
            "context": "kairo/check"
        }))
        .send()
        .await?;

    Ok(())
}

async fn post_success(
    token: &str,
    repo: &str,
    _pr_number: &u32,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    post_commit_status(token, repo, "", "success", message).await
}

async fn run_local_check(
    diff_file: &str,
    api_url: &str,
    fail_on: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let changed_files = parse_diff_file(diff_file)?;
    println!("Kairo: {} files changed", changed_files.len());

    let risky_patterns = identify_risky_files(&changed_files);
    if risky_patterns.is_empty() {
        println!("Kairo: No risky files detected.");
        return Ok(());
    }

    println!("Kairo: Checking {} risky file patterns...", risky_patterns.len());

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut block_count = 0;
    let mut warn_count = 0;

    for pattern in &risky_patterns {
        let verdict = check_pattern(&client, api_url, pattern).await?;
        if verdict.verdict == "BLOCK" {
            block_count += 1;
        } else if verdict.verdict == "WARN" {
            warn_count += 1;
        }
        println!("{}: [{}] {} — {}", pattern.filename, verdict.verdict, verdict.title, verdict.summary);
    }

    let summary = format!(
        "Kairo checked {} risky items: {} BLOCK, {} WARN",
        risky_patterns.len(),
        block_count,
        warn_count
    );

    let should_fail = match fail_on {
        "block" => block_count > 0,
        "warn" => warn_count > 0 || block_count > 0,
        _ => false,
    };

    if should_fail {
        eprintln!("Kairo: FAILED — {}", summary);
        std::process::exit(1);
    }

    println!("Kairo: {}", summary);
    Ok(())
}

fn parse_diff_file(diff_file: &str) -> Result<Vec<ChangedFile>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(diff_file)?;
    let mut files = Vec::new();
    let mut current_file = String::new();
    let mut current_diff = String::new();

    for line in content.lines() {
        if line.starts_with("diff --git a/") {
            // Save previous file if exists
            if !current_file.is_empty() {
                files.push(ChangedFile {
                    filename: current_file.clone(),
                    diff: current_diff.clone(),
                });
                current_diff.clear();
            }
            // Extract the filename from "diff --git a/X b/X"
            if let Some(path) = line.strip_prefix("diff --git a/") {
                if let Some(space_idx) = path.find(" b/") {
                    current_file = path[..space_idx].to_string();
                }
            }
        }
        // Accumulate diff content
        if !current_file.is_empty() {
            current_diff.push_str(line);
            current_diff.push('\n');
        }
    }

    // Don't forget the last file
    if !current_file.is_empty() {
        files.push(ChangedFile {
            filename: current_file,
            diff: current_diff,
        });
    }

    Ok(files)
}
