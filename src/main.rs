use anyhow::{Context, Result, ensure};
use chrono::Utc;
use clap::{Parser, Subcommand};
use domain_review_harness::{
    Row,
    assessment::{AssessmentConfig, assess_lead_with_progress},
    changes, evidence, io,
};
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    name = "bankai",
    version,
    about = "Review domain security and website trust signals"
)]
struct Cli {
    /// Domain to review. Supplying this confirms you are authorized for the scope in docs/scope.md.
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,
    /// Root directory where Bankai retains every review run.
    #[arg(long, default_value = "reports", value_name = "DIRECTORY")]
    reports: PathBuf,
    /// Local dashboard port. The dashboard is available at http://127.0.0.1:PORT.
    #[arg(long, default_value_t = 8787, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// Timeout per network operation for the one-line review command.
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=120))]
    timeout: u64,
    /// Retries per network operation for the one-line review command.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(0..=3))]
    retries: u32,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Open a read-only local dashboard for saved runs.
    Serve {
        #[arg(long, default_value = "reports")]
        reports: PathBuf,
        #[arg(long, default_value_t = 8787, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
    },
    /// Run active checks on a domain and related discovered hosts. See docs/scope.md.
    Review {
        domain: String,
        /// Confirm permission for the target and the scope documented in docs/scope.md.
        #[arg(long)]
        authorized: bool,
        #[arg(long, default_value = "reports/latest")]
        output: PathBuf,
        /// Timeout per network operation, not for the whole review.
        #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=120))]
        timeout: u64,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(0..=3))]
        retries: u32,
    },
    /// Compare two assessment CSV files without network access.
    Diff {
        #[arg(long)]
        previous: PathBuf,
        #[arg(long)]
        current: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
fn target(value: &str) -> Result<String> {
    let raw = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let url = url::Url::parse(&raw).context("invalid domain or URL")?;
    ensure!(
        ["http", "https"].contains(&url.scheme()),
        "only HTTP(S) targets are supported"
    );
    ensure!(
        url.host_str().is_some() && url.username().is_empty() && url.password().is_none(),
        "target must have a host and no credentials"
    );
    ensure!(
        url.port().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "provide a domain or root URL without a custom port, path, query, or fragment"
    );
    Ok(url.to_string())
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(
        !(cli.domain.is_some() && cli.command.is_some()),
        "--domain cannot be used with a subcommand"
    );
    if let Some(domain) = cli.domain {
        return bankai_review(domain, cli.reports, cli.port, cli.timeout, cli.retries);
    }
    match cli
        .command
        .context("provide --domain DOMAIN or a subcommand; use --help for usage")?
    {
        Command::Serve { reports, port } => {
            domain_review_harness::dashboard::serve(&reports, port)?
        }
        Command::Review {
            domain,
            authorized,
            output,
            timeout,
            retries,
        } => {
            ensure!(
                authorized,
                "review requires --authorized; read docs/scope.md and confirm permission for the full scope"
            );
            let website = target(&domain)?;
            ensure!(
                !output.exists(),
                "output directory already exists; choose a new path to preserve previous evidence"
            );
            write_review(&website, &output, timeout, retries)?;
            eprintln!("Review saved to {}", output.display());
        }
        Command::Diff {
            previous,
            current,
            output,
        } => {
            ensure!(
                previous.is_file() && current.is_file(),
                "both assessment CSV files must exist"
            );
            ensure!(!output.exists(), "diff output already exists");
            io::write_jsonl(
                output,
                &changes::compare(&io::read_csv(previous)?, &io::read_csv(current)?),
            )?;
        }
    }
    Ok(())
}

fn bankai_review(
    domain: String,
    reports: PathBuf,
    port: u16,
    timeout: u64,
    retries: u32,
) -> Result<()> {
    let website = target(&domain)?;
    std::fs::create_dir_all(&reports)?;
    domain_review_harness::dashboard::start(reports.clone(), port)?;
    let domain_slug = domain_review_harness::normalize::slug(
        url::Url::parse(&website)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .as_deref()
            .unwrap_or("domain"),
    );
    let run_name = format!(
        "{}-{}",
        if domain_slug.is_empty() {
            "domain"
        } else {
            &domain_slug
        },
        Utc::now().format("%Y%m%dT%H%M%SZ")
    );
    let output = reports.join(run_name);
    ensure!(
        !output.exists(),
        "run directory already exists; rerun the command"
    );
    std::fs::create_dir_all(&output)?;
    write_run_status(&output, &domain, "running")?;
    eprintln!("Bankai dashboard: http://127.0.0.1:{port}");
    eprintln!(
        "Starting review of {domain}. This confirms you are authorized for the scope in docs/scope.md."
    );
    if let Err(error) = write_review(&website, &output, timeout, retries) {
        let _ = write_run_status(&output, &domain, "failed");
        return Err(error);
    }
    write_run_status(&output, &domain, "complete")?;
    eprintln!("Review saved to {}", output.display());
    eprintln!(
        "The dashboard remains available at http://127.0.0.1:{port}. Press Ctrl-C when you are done reviewing results."
    );
    loop {
        std::thread::park();
    }
}

fn write_run_status(output: &std::path::Path, domain: &str, state: &str) -> Result<()> {
    let started_at = std::fs::read(output.join("run.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value["started_at"].as_str().map(str::to_owned))
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    std::fs::write(
        output.join("run.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "domain": domain,
            "state": state,
            "started_at": started_at,
            "updated_at": Utc::now().to_rfc3339(),
        }))?,
    )?;
    Ok(())
}

fn write_review(website: &str, output: &std::path::Path, timeout: u64, retries: u32) -> Result<()> {
    std::fs::create_dir_all(output)?;
    let row = assess_lead_with_progress(
        &Row::from([("website".into(), website.to_string())]),
        &AssessmentConfig {
            timeout: Duration::from_secs(timeout),
            retries: retries as usize,
        },
        |stage| eprintln!("{stage}"),
    );
    io::write_csv(output.join("assessment.csv"), std::slice::from_ref(&row))?;
    io::write_jsonl(output.join("evidence.jsonl"), &evidence::records(&row))?;
    std::fs::write(
        output.join("assessment.json"),
        serde_json::to_vec_pretty(&row)?,
    )?;
    let findings = domain_review_harness::findings::prioritized_findings(&row);
    let mut report = format!(
        "# Domain review\n\nDomain: {}\n\nChecked: {}\n\nRisk: {}\n\nThese automated observations require human verification. Inspect assessment.json for errors and incomplete checks.\n\n## Findings\n\n",
        domain_review_harness::text(&row, "domain"),
        domain_review_harness::text(&row, "checked_at"),
        domain_review_harness::text(&row, "risk_level")
    );
    for finding in findings {
        report.push_str(&format!("- {}\n", finding.replace(['\n', '\r'], " ")));
    }
    std::fs::write(output.join("report.md"), report)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_target_before_network_work() {
        assert_eq!(target("example.com").unwrap(), "https://example.com/");
        for invalid in [
            "file:///etc/passwd",
            "https://u:p@example.com",
            "https://example.com/path",
            "https://example.com:8080",
            "https://example.com/?q=x",
        ] {
            assert!(target(invalid).is_err(), "{invalid}");
        }
    }
    #[test]
    fn run_status_preserves_its_original_start_time() {
        let temp = tempfile::tempdir().unwrap();
        write_run_status(temp.path(), "example.com", "running").unwrap();
        let first: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temp.path().join("run.json")).unwrap()).unwrap();
        write_run_status(temp.path(), "example.com", "complete").unwrap();
        let final_status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temp.path().join("run.json")).unwrap()).unwrap();
        assert_eq!(first["started_at"], final_status["started_at"]);
        assert_eq!(final_status["state"], "complete");
    }
}
