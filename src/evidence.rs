use crate::findings::classify_finding_severity;
use crate::{Row, text};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const SEVERITY_ORDER: &[&str] = &["critical", "high", "medium", "low"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub finding_id: String,
    pub domain: String,
    pub company: String,
    pub severity: String,
    pub confidence: String,
    pub finding: String,
    pub evidence_url: String,
    pub observed_at: String,
    pub http_status: String,
    pub response_sha256: String,
    pub detection_method: String,
    pub manual_review_status: String,
}

pub fn records(row: &Row) -> Vec<Evidence> {
    let severity = classify_finding_severity(row);
    let domain = text(row, "domain");
    let checked_at = text(row, "checked_at");
    let final_url = [
        text(row, "final_url"),
        text(row, "homepage_final_url"),
        text(row, "website"),
    ]
    .into_iter()
    .find(|value| !value.is_empty())
    .unwrap_or_default();
    let confirmed_markers = [
        "source control metadata",
        "environment file url",
        "backup or database file path",
        "form action appears to submit over plain http",
    ];
    let heuristic_markers = [
        "secret-like",
        "html injection",
        "admin or login path",
        "missing trust/page signal",
    ];
    let mut output = Vec::new();
    for level in SEVERITY_ORDER {
        for finding in severity.get(*level).into_iter().flatten() {
            let normalized = finding.to_lowercase();
            let confidence = if confirmed_markers
                .iter()
                .any(|marker| normalized.contains(marker))
            {
                "confirmed"
            } else if heuristic_markers
                .iter()
                .any(|marker| normalized.contains(marker))
            {
                "heuristic"
            } else {
                "probable"
            };
            let evidence_url = evidence_url_for_finding(row, finding, &final_url);
            let fingerprint_source =
                [domain.as_str(), level, finding, evidence_url.as_str()].join("\n");
            output.push(Evidence {
                finding_id: hex_sha256(fingerprint_source.as_bytes())[..16].into(),
                domain: domain.clone(),
                company: text(row, "company"),
                severity: (*level).into(),
                confidence: confidence.into(),
                finding: finding.clone(),
                evidence_url,
                observed_at: checked_at.clone(),
                http_status: {
                    let status = text(row, "http_status");
                    if status.is_empty() {
                        text(row, "homepage_status")
                    } else {
                        status
                    }
                },
                response_sha256: text(row, "homepage_body_sha256"),
                detection_method: detection_method(finding),
                manual_review_status: {
                    let status = text(row, "manual_review_status");
                    if !status.is_empty() {
                        status
                    } else if matches!(*level, "critical" | "high") {
                        "pending".into()
                    } else {
                        "not_required".into()
                    }
                },
            });
        }
    }
    output
}

pub fn annotations(row: &Row) -> Row {
    let records = records(row);
    let highest = SEVERITY_ORDER
        .iter()
        .find(|level| records.iter().any(|record| record.severity == **level))
        .copied()
        .unwrap_or("");
    let confidence = records
        .iter()
        .map(|record| record.confidence.as_str())
        .max_by_key(|value| confidence_rank(value))
        .unwrap_or("unknown");
    let manual_required = records.iter().any(|record| {
        matches!(record.severity.as_str(), "critical" | "high") && record.confidence != "confirmed"
    });
    let status = {
        let status = text(row, "manual_review_status").trim().to_lowercase();
        if status.is_empty() {
            if manual_required {
                "pending".into()
            } else {
                "not_required".into()
            }
        } else {
            status
        }
    };
    let serializable: Vec<BTreeMap<String, String>> = records.iter().map(evidence_map).collect();
    let json = serde_json::to_string(&serializable).unwrap_or_else(|_| "[]".into());
    Row::from([
        ("evidence_count".into(), records.len().to_string()),
        ("evidence_fingerprint".into(), hex_sha256(json.as_bytes())),
        ("highest_finding_severity".into(), highest.into()),
        ("finding_confidence".into(), confidence.into()),
        ("manual_review_required".into(), manual_required.to_string()),
        ("manual_review_status".into(), status),
        ("evidence_json".into(), json),
    ])
}

pub fn annotate(row: &mut Row) {
    row.extend(annotations(row));
}

pub fn evidence_is_fresh(row: &Row, max_age_days: i64) -> bool {
    let checked_at = text(row, "checked_at");
    if checked_at.is_empty() {
        return true;
    }
    let Ok(observed) = DateTime::parse_from_rfc3339(&checked_at) else {
        return false;
    };
    Utc::now()
        .signed_duration_since(observed.with_timezone(&Utc))
        .num_days()
        <= max_age_days
}

pub fn manual_review_allows_review(row: &Row) -> bool {
    if !text(row, "manual_review_required").eq_ignore_ascii_case("true") {
        return true;
    }
    matches!(
        text(row, "manual_review_status").to_lowercase().as_str(),
        "confirmed" | "approved"
    )
}

pub fn evidence_url_for_finding(row: &Row, finding: &str, fallback: &str) -> String {
    let lower = finding.to_lowercase();
    for (field, marker) in [
        ("env_files_found", "environment file"),
        ("backup_files_found", "backup or database"),
        ("admin_panels_found", "admin or login"),
        ("ftp_webroot_paths_accessible", "anonymous ftp"),
        ("api_documentation_urls", "api documentation"),
        ("apis_leaking_data", "api response"),
        ("unauthenticated_apis", "api endpoint"),
        ("wordpress_unsafe_write_apis", "wordpress rest write"),
    ] {
        let value = text(row, field);
        if lower.contains(marker) && !value.trim().is_empty() {
            return value.split(';').next().unwrap_or("").trim().into();
        }
    }
    fallback.into()
}

pub fn detection_method(finding: &str) -> String {
    let lower = finding.to_lowercase();
    if lower.contains("public dns") || lower.contains("dmarc") || lower.contains("spf") {
        "dns_record".into()
    } else if lower.contains("tls") || lower.contains("https") {
        "tls_http_observation".into()
    } else if lower.contains("javascript") || lower.contains("html") {
        "public_source_pattern".into()
    } else if lower.contains("path") || lower.contains("source control") {
        "content_confirmed_public_get".into()
    } else {
        "public_http_observation".into()
    }
}

fn confidence_rank(value: &str) -> u8 {
    match value {
        "heuristic" => 1,
        "probable" => 2,
        "confirmed" => 3,
        _ => 0,
    }
}

fn evidence_map(record: &Evidence) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("company".into(), record.company.clone()),
        ("confidence".into(), record.confidence.clone()),
        ("detection_method".into(), record.detection_method.clone()),
        ("domain".into(), record.domain.clone()),
        ("evidence_url".into(), record.evidence_url.clone()),
        ("finding".into(), record.finding.clone()),
        ("finding_id".into(), record.finding_id.clone()),
        ("http_status".into(), record.http_status.clone()),
        (
            "manual_review_status".into(),
            record.manual_review_status.clone(),
        ),
        ("observed_at".into(), record.observed_at.clone()),
        ("response_sha256".into(), record.response_sha256.clone()),
        ("severity".into(), record.severity.clone()),
    ])
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
