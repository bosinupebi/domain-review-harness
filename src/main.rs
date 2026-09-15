use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use domain_review_harness::{
    Row,
    assessment::{AssessmentConfig, assess_lead_with_progress},
    changes, evidence, io,
};
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    name = "domain-review",
    version,
    about = "Review domain security and website trust signals"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
    match Cli::parse().command {
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
            std::fs::create_dir_all(&output)?;
            let row = assess_lead_with_progress(
                &Row::from([("website".into(), website)]),
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
}
