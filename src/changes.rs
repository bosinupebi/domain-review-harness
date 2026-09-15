use crate::evidence;
use crate::{Row, text};
use serde::Serialize;
use std::collections::BTreeMap;

const TRACKED_FIELDS: &[&str] = &[
    "reachable",
    "https",
    "tls_valid",
    "tls_days_remaining",
    "hsts",
    "csp",
    "x_frame_options",
    "spf_record",
    "dmarc_record",
    "mta_sts_record",
    "tls_rpt_record",
    "caa_records",
    "dnssec",
    "dkim_selectors_found",
    "source_control_exposed",
    "env_files_found",
    "backup_files_found",
    "admin_panels_found",
    "api_endpoints_discovered",
    "js_source_map_seen",
    "js_secret_like_details",
    "representative_page_urls",
    "header_consistency",
    "score",
    "risk_level",
];

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Change {
    pub domain: String,
    pub company: String,
    pub change_type: String,
    pub checked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_changed: Option<bool>,
    pub fields: BTreeMap<String, BTreeMap<String, String>>,
}

pub fn compare(previous: &[Row], current: &[Row]) -> Vec<Change> {
    let previous_by_domain: BTreeMap<String, &Row> = previous
        .iter()
        .filter(|row| !text(row, "domain").is_empty())
        .map(|row| (text(row, "domain"), row))
        .collect();
    current
        .iter()
        .filter_map(|row| {
            let domain = text(row, "domain");
            let Some(before) = previous_by_domain.get(&domain) else {
                return Some(Change {
                    domain,
                    company: text(row, "company"),
                    change_type: "new_assessment".into(),
                    checked_at: text(row, "checked_at"),
                    evidence_changed: None,
                    fields: BTreeMap::new(),
                });
            };
            let fields: BTreeMap<_, _> = TRACKED_FIELDS
                .iter()
                .filter_map(|field| {
                    let old = text(before, field);
                    let new = text(row, field);
                    (old != new).then(|| {
                        (
                            (*field).to_string(),
                            BTreeMap::from([("after".into(), new), ("before".into(), old)]),
                        )
                    })
                })
                .collect();
            let previous_fingerprint = text(&evidence::annotations(before), "evidence_fingerprint");
            let current_fingerprint = text(&evidence::annotations(row), "evidence_fingerprint");
            let evidence_changed = previous_fingerprint != current_fingerprint;
            (!fields.is_empty() || evidence_changed).then(|| Change {
                domain,
                company: text(row, "company"),
                change_type: "changed".into(),
                checked_at: text(row, "checked_at"),
                evidence_changed: Some(evidence_changed),
                fields,
            })
        })
        .collect()
}
