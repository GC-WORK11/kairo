use clap::{Parser, Subcommand};
use kairo_ingest::{
    GithubAdvisoriesSource, IntelligenceSource, IntelligenceStore, NpmRegistrySource,
    OsvSource, DepsDevSource,
};
use std::env;

#[derive(Parser)]
#[command(name = "kairo-ingest")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Cache TTL in seconds (default: 3600)
    #[arg(long, default_value = "3600")]
    cache_ttl: u64,
    /// Maximum number of cache entries (default: 10000)
    #[arg(long, default_value = "10000")]
    cache_max_entries: usize,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch intelligence for a specific package
    Fetch {
        /// Package name
        package: String,
        /// Ecosystem (npm, pnpm, cargo, pip, etc.)
        ecosystem: String,
    },
    /// Start background refresh loop
    Worker {
        /// Interval in seconds between refresh cycles
        #[arg(long, default_value = "300")]
        interval: u64,
    },
    /// Show cache statistics
    Stats,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let store = IntelligenceStore::new(cli.cache_max_entries, cli.cache_ttl);
    println!("Cache: max_entries={}, ttl={}s", cli.cache_max_entries, cli.cache_ttl);

    let gh_token = env::var("GITHUB_TOKEN").ok();

    match cli.command {
        Commands::Fetch { package, ecosystem } => {
            let osv = OsvSource::new();
            let npm = NpmRegistrySource::new();
            let gh = GithubAdvisoriesSource::new(gh_token);
            let deps = DepsDevSource::new();

            println!("Fetching intelligence for {} ({})...", package, ecosystem);

            let results = tokio::join!(
                osv.fetch(&package, &ecosystem),
                npm.fetch(&package, &ecosystem),
                gh.fetch(&package, &ecosystem),
                deps.fetch(&package, &ecosystem),
            );

            let mut all = vec![];
            for result in [results.0, results.1, results.2, results.3] {
                match result {
                    Ok(advisories) => all.extend(advisories),
                    Err(e) => eprintln!("Source error: {}", e),
                }
            }

            println!("\nFound {} advisories:", all.len());
            for adv in &all {
                println!(
                    "  [{}] {} — {} (severity: {:?})",
                    adv.source,
                    adv.id,
                    adv.summary.chars().take(60).collect::<String>(),
                    adv.severity
                );
            }

            // Cache results
            store.set_advisories(&package, &ecosystem, all, cli.cache_ttl).await;
            println!("\nCached results for {} seconds.", cli.cache_ttl);
        }
        Commands::Worker { interval } => {
            println!("Starting intelligence worker (refresh every {}s)...", interval);
            loop {
                println!("[{}] Refresh cycle started", chrono::Utc::now());
                let stats = store.cache_stats().await;
                println!(
                    "Cache: {} total ({} fresh, {} stale)",
                    stats.total_entries, stats.fresh_entries, stats.stale_entries
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
            }
        }
        Commands::Stats => {
            let stats = store.cache_stats().await;
            println!(
                "Intelligence cache: {} entries ({} fresh, {} stale)",
                stats.total_entries, stats.fresh_entries, stats.stale_entries
            );
        }
    }

    Ok(())
}
