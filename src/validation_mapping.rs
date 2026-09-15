use crate::{Row, int_value, text};
use chrono::{DateTime, Utc};

pub fn public_validation_to_assessment_fields(row: &Row) -> Row {
    let homepage = !text(row, "homepage_status").trim().is_empty();
    let human_verification = text(row, "validation_notes")
        .to_lowercase()
        .starts_with("human verification");
    let dns = [
        "spf_record",
        "dmarc_record",
        "mx_records",
        "dnssec_enabled",
        "mta_sts_record",
        "tls_rpt_record",
    ]
    .iter()
    .any(|field| !text(row, field).trim().is_empty());
    let mut mapped = Row::from([
        (
            "checked_at".into(),
            epoch_to_iso(&text(row, "checked_at_epoch")),
        ),
        ("company".into(), text(row, "company")),
        ("website".into(), text(row, "website")),
        ("domain".into(), text(row, "domain")),
        (
            "assessment_profile_version".into(),
            crate::models::ASSESSMENT_PROFILE_VERSION.into(),
        ),
        (
            "reachable".into(),
            if human_verification {
                "unknown".into()
            } else {
                homepage.to_string()
            },
        ),
        ("final_url".into(), text(row, "homepage_final_url")),
        ("http_status".into(), text(row, "homepage_status")),
        (
            "https".into(),
            if human_verification {
                "unknown".into()
            } else {
                text(row, "homepage_final_url")
                    .to_lowercase()
                    .starts_with("https://")
                    .to_string()
            },
        ),
        (
            "redirects_to_https".into(),
            if human_verification {
                "unknown".into()
            } else {
                text(row, "redirect_to_https")
            },
        ),
        (
            "tls_valid".into(),
            if human_verification {
                "unknown".into()
            } else {
                text(row, "cert_valid")
            },
        ),
        (
            "tls_days_remaining".into(),
            text(row, "cert_days_remaining"),
        ),
        (
            "hsts".into(),
            (!text(row, "hsts_header").trim().is_empty()).to_string(),
        ),
        (
            "csp".into(),
            (!text(row, "csp_header").trim().is_empty()).to_string(),
        ),
        (
            "x_frame_options".into(),
            (!text(row, "x_frame_options").trim().is_empty()).to_string(),
        ),
        (
            "referrer_policy".into(),
            (!text(row, "referrer_policy").trim().is_empty()).to_string(),
        ),
        (
            "permissions_policy".into(),
            (!text(row, "permissions_policy").trim().is_empty()).to_string(),
        ),
        ("server_header".into(), text(row, "server_header")),
        ("x_powered_by_header".into(), text(row, "x_powered_by")),
        (
            "set_cookie_seen".into(),
            (int_value(row, "set_cookie_count") > 0).to_string(),
        ),
        (
            "secure_cookie_seen".into(),
            cookie_count_ok(row, "cookies_missing_secure").to_string(),
        ),
        (
            "httponly_cookie_seen".into(),
            cookie_count_ok(row, "cookies_missing_httponly").to_string(),
        ),
        (
            "samesite_cookie_seen".into(),
            cookie_count_ok(row, "cookies_missing_samesite").to_string(),
        ),
        ("security_txt".into(), text(row, "security_txt_found")),
        (
            "privacy_policy_seen".into(),
            text(row, "privacy_policy_found"),
        ),
        ("contact_page_seen".into(), text(row, "contact_page_found")),
        ("robots_txt".into(), text(row, "robots_txt_found")),
        ("forms_count".into(), text(row, "forms_count")),
        (
            "password_field_seen".into(),
            (int_value(row, "password_fields_seen") > 0).to_string(),
        ),
        ("forms_over_https".into(), forms_over_https(row)),
        (
            "inline_script_count".into(),
            text(row, "inline_script_count"),
        ),
        (
            "external_script_hosts".into(),
            text(row, "external_script_hosts"),
        ),
        (
            "external_scripts_without_sri".into(),
            text(row, "scripts_without_sri"),
        ),
        (
            "admin_link_hints_seen".into(),
            (!text(row, "admin_paths_found").trim().is_empty()).to_string(),
        ),
        (
            "api_endpoint_hints_seen".into(),
            (!text(row, "js_api_endpoints").trim().is_empty()).to_string(),
        ),
        ("js_files_checked".into(), text(row, "js_files_checked")),
        (
            "js_source_map_seen".into(),
            (!text(row, "source_map_references").trim().is_empty()).to_string(),
        ),
        (
            "js_secret_like_terms".into(),
            secret_terms(&text(row, "js_secrets_found")),
        ),
        (
            "js_secret_like_terms_seen".into(),
            (!text(row, "js_secrets_found").trim().is_empty()).to_string(),
        ),
        (
            "js_secret_like_details".into(),
            text(row, "js_secrets_found"),
        ),
        (
            "js_secret_like_details_seen".into(),
            (!text(row, "js_secrets_found").trim().is_empty()).to_string(),
        ),
        (
            "js_html_injection_sinks".into(),
            if text(row, "dom_xss_sinks_found").to_lowercase() == "true" {
                "DOM XSS sink pattern".into()
            } else {
                String::new()
            },
        ),
        (
            "js_html_injection_sinks_seen".into(),
            text(row, "dom_xss_sinks_found"),
        ),
        (
            "js_debug_terms_seen".into(),
            (!text(row, "js_debug_terms").trim().is_empty()).to_string(),
        ),
        ("technology_hints".into(), text(row, "technology_hints")),
        ("generator_meta".into(), text(row, "generator_meta")),
        ("backup_files_found".into(), text(row, "backup_files_found")),
        ("source_control_exposed".into(), text(row, "git_exposed")),
        (
            "env_files_found".into(),
            if !text(row, "env_files_found").trim().is_empty() {
                text(row, "env_files_found").trim().into()
            } else {
                (text(row, "env_exposed").trim().to_lowercase() == "true").to_string()
            },
        ),
        ("admin_panels_found".into(), text(row, "admin_paths_found")),
        (
            "api_endpoints_discovered".into(),
            text(row, "js_api_endpoints"),
        ),
        (
            "error".into(),
            if human_verification || !homepage {
                text(row, "validation_notes")
            } else {
                String::new()
            },
        ),
    ]);
    if !homepage {
        for field in HOMEPAGE_FIELDS {
            mapped.remove(*field);
        }
    }
    if dns {
        mapped.extend([
            (
                "spf".into(),
                (!text(row, "spf_record").trim().is_empty()).to_string(),
            ),
            ("spf_record".into(), text(row, "spf_record")),
            (
                "dmarc".into(),
                (!text(row, "dmarc_record").trim().is_empty()).to_string(),
            ),
            ("dmarc_record".into(), text(row, "dmarc_record")),
            ("dmarc_policy".into(), text(row, "dmarc_policy")),
            ("mx_hosts".into(), text(row, "mx_records")),
            ("dnssec".into(), text(row, "dnssec_enabled")),
            (
                "mta_sts".into(),
                (!text(row, "mta_sts_record").trim().is_empty()).to_string(),
            ),
            ("mta_sts_record".into(), text(row, "mta_sts_record")),
            (
                "tls_rpt".into(),
                (!text(row, "tls_rpt_record").trim().is_empty()).to_string(),
            ),
            ("tls_rpt_record".into(), text(row, "tls_rpt_record")),
        ]);
    }
    mapped
}

const HOMEPAGE_FIELDS: &[&str] = &[
    "reachable",
    "final_url",
    "http_status",
    "https",
    "redirects_to_https",
    "tls_valid",
    "tls_days_remaining",
    "hsts",
    "csp",
    "x_frame_options",
    "referrer_policy",
    "permissions_policy",
    "server_header",
    "x_powered_by_header",
    "set_cookie_seen",
    "secure_cookie_seen",
    "httponly_cookie_seen",
    "samesite_cookie_seen",
    "security_txt",
    "privacy_policy_seen",
    "contact_page_seen",
    "robots_txt",
    "forms_count",
    "password_field_seen",
    "forms_over_https",
    "inline_script_count",
    "external_script_hosts",
    "external_scripts_without_sri",
    "admin_link_hints_seen",
    "api_endpoint_hints_seen",
    "js_files_checked",
    "js_source_map_seen",
    "js_secret_like_terms",
    "js_secret_like_terms_seen",
    "js_secret_like_details",
    "js_secret_like_details_seen",
    "js_html_injection_sinks",
    "js_html_injection_sinks_seen",
    "js_debug_terms_seen",
    "technology_hints",
    "generator_meta",
    "backup_files_found",
    "source_control_exposed",
    "env_files_found",
    "admin_panels_found",
    "api_endpoints_discovered",
];

pub fn epoch_to_iso(value: &str) -> String {
    value
        .parse::<i64>()
        .ok()
        .and_then(|timestamp| DateTime::<Utc>::from_timestamp(timestamp, 0))
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, false))
        .unwrap_or_default()
}

pub fn cookie_count_ok(row: &Row, field: &str) -> bool {
    int_value(row, "set_cookie_count") > 0 && int_value(row, field) == 0
}

pub fn forms_over_https(row: &Row) -> String {
    if int_value(row, "forms_count") == 0 {
        "no_forms_seen".into()
    } else if int_value(row, "forms_without_https") > 0 {
        "insecure_form_action".into()
    } else {
        "likely_ok".into()
    }
}

pub fn secret_terms(details: &str) -> String {
    let mut terms = Vec::new();
    for detail in details.split(';') {
        let name = detail.split('=').next().unwrap_or("").trim().to_string();
        if !name.is_empty() && !terms.contains(&name) {
            terms.push(name);
        }
    }
    terms.join("; ")
}
