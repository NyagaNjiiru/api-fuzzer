use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::{fs, path::Path};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name="api-fuzzkit", version, about="Sandbox API fuzzing toolkit")]
struct Args {
    /// Path to target profile TOML
    #[arg(short, long, default_value = "profiles/kra-sandbox.toml")]
    profile: String,

    /// Require sandbox mode
    #[arg(long, default_value_t = true)]
    sandbox: bool,

    /// Dry run (don’t send requests)
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct Limits {
    concurrency: usize,
    rate_per_sec: u32,
    request_budget: u32,
    max_rate_per_sec: u32,
    allowed_methods: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Timeouts { connect_ms: u64, read_ms: u64 }

#[derive(Debug, Deserialize)]
struct Safety {
    require_sandbox_flag: bool,
    allowlist_hosts: Vec<String>,
    #[serde(default)] // key->value map for forced headers (optional in v1)
    force_headers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Profile {
    name: String,
    base_url: String,
    endpoint: String,
    method: String,
    limits: Limits,
    timeouts: Timeouts,
    safety: Safety,
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

fn load_profile(path: &str) -> Result<Profile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read profile: {path}"))?;
    let p: Profile = toml::from_str(&raw).context("invalid TOML in profile")?;
    Ok(p)
}

fn enforce_guardrails(p: &Profile, args: &Args) -> Result<()> {
    // 1) Sandbox flag
    if p.safety.require_sandbox_flag && !args.sandbox {
        bail!("sandbox flag required: re-run with --sandbox");
    }

    // 2) Host allowlist
    let host = url::Url::parse(&p.base_url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .ok_or_else(|| anyhow::anyhow!("invalid base_url: {}", p.base_url))?;
    if !p.safety.allowlist_hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
        bail!("base_url host not in allowlist: {host}");
    }

    // 3) Method safety
    if !p.limits.allowed_methods.iter().any(|m| m.eq_ignore_ascii_case(&p.method)) {
        bail!("HTTP method '{}' not allowed by policy", p.method);
    }

    // 4) Rate ceiling
    if p.limits.rate_per_sec > p.limits.max_rate_per_sec {
        bail!("rate_per_sec exceeds policy ceiling");
    }

    // 5) Request budget > 0
    if p.limits.request_budget == 0 {
        bail!("request_budget must be > 0");
    }
    Ok(())
}

fn main() -> Result<()> {
    init_logging();
    let args = Args::parse();
    let profile = load_profile(&args.profile)?;

    enforce_guardrails(&profile, &args)?;

    // v1: just show planned session; no networking yet
    tracing::info!(target = "session",
        name = %profile.name,
        base = %profile.base_url,
        endpoint = %profile.endpoint,
        method = %profile.method,
        budget = profile.limits.request_budget,
        rate = profile.limits.rate_per_sec,
        concurrency = profile.limits.concurrency,
        "guardrails OK; {} mode",
        if args.dry_run { "dry-run" } else { "execution" }
    );

    if args.dry_run {
        println!("(dry-run) Ready to plan test cases. No requests will be sent.");
    } else {
        println!("Execution would start here (transport not wired yet).");
    }
    Ok(())
}
