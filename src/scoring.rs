use crate::{Row, int_value, is_true, text};

pub fn compute_score(row: &Row) -> (i64, String, String, String) {
    let mut score = 100_i64;
    let mut notes: Vec<&str> = Vec::new();
    let mut offer = "Website security trust snapshot";
    let missing = |field: &str| {
        matches!(
            text(row, field).trim().to_lowercase().as_str(),
            "" | "false" | "missing" | "unknown"
        )
    };

    if text(row, "reachable").to_lowercase() != "true" {
        score -= 40;
        notes.push("website did not respond during public check");
        offer = "Website uptime and security review";
    }
    if text(row, "https").to_lowercase() != "true" {
        score -= 25;
        notes.push("site did not load over HTTPS");
        offer = "HTTPS and trust hardening";
    }
    if text(row, "tls_valid").to_lowercase() == "false" {
        score -= 25;
        notes.push("TLS certificate was not valid");
        offer = "HTTPS and trust hardening";
    }
    for (field, penalty, note) in [
        ("hsts", 8, "HSTS header not seen"),
        ("csp", 7, "Content-Security-Policy header not seen"),
        (
            "x_frame_options",
            5,
            "clickjacking protection header not seen",
        ),
    ] {
        if missing(field) {
            score -= penalty;
            notes.push(note);
        }
    }
    if missing("spf") {
        score -= 10;
        notes.push("SPF email protection not seen");
        offer = "Email fraud protection setup";
    }
    if missing("dmarc") {
        score -= 15;
        notes.push("DMARC email protection not seen");
        offer = "Email fraud protection setup";
    }
    if text(row, "dmarc_policy").trim().to_lowercase() == "none" {
        score -= 5;
        notes.push("DMARC policy is monitoring-only");
        offer = "Email fraud protection setup";
    }
    let dmarc_pct = text(row, "dmarc_pct");
    if !dmarc_pct.trim().is_empty() && dmarc_pct.trim() != "100" {
        score -= 2;
        notes.push("DMARC policy does not appear to apply to all mail");
        offer = "Email fraud protection setup";
    }
    if is_true(row, "set_cookie_seen") {
        if !is_true(row, "secure_cookie_seen") {
            score -= 3;
            notes.push("Set-Cookie header was seen without a Secure flag");
        }
        if !is_true(row, "httponly_cookie_seen") {
            score -= 3;
            notes.push("Set-Cookie header was seen without an HttpOnly flag");
        }
        if !is_true(row, "samesite_cookie_seen") {
            score -= 2;
            notes.push("Set-Cookie header was seen without a SameSite flag");
        }
    }
    for (field, penalty, note) in [
        (
            "privacy_policy_seen",
            4,
            "privacy policy link not seen on homepage",
        ),
        (
            "meta_description_seen",
            2,
            "homepage meta description not seen",
        ),
        ("h1_seen", 2, "homepage H1 not seen"),
        ("viewport_meta_seen", 2, "mobile viewport metadata not seen"),
        ("security_txt", 2, "security.txt not seen"),
    ] {
        if missing(field) {
            score -= penalty;
            notes.push(note);
        }
    }
    if text(row, "forms_over_https").to_lowercase() == "insecure_form_action" {
        score -= 20;
        notes.push("form action appears to submit over HTTP");
        offer = "Website form security review";
    }
    if int_value(row, "mixed_content_refs") > 0 {
        score -= 10;
        notes.push("homepage source references HTTP assets");
        offer = "Website security trust snapshot";
    }
    if is_true(row, "password_field_seen") {
        score -= 5;
        notes.push("password field visible on homepage");
        offer = "Website form security review";
    }
    if is_true(row, "external_form_action_seen") {
        score -= 5;
        notes.push("homepage form posts to an external host");
        offer = "Website form security review";
    }
    let sri = int_value(row, "external_scripts_without_sri");
    if sri > 0 {
        score -= (sri * 2).min(6);
        notes.push("external scripts without Subresource Integrity were seen");
    }
    if int_value(row, "vulnerable_script_count") > 0 {
        score -= 12;
        notes.push("public JavaScript references known vulnerability advisories");
        offer = "Website source exposure review";
    }
    for (field, penalty, note) in [
        (
            "js_source_map_seen",
            5,
            "JavaScript source map reference was seen",
        ),
        (
            "js_html_injection_sinks_seen",
            10,
            "public JavaScript uses HTML injection sinks",
        ),
        (
            "js_secret_like_terms_seen",
            12,
            "secret-like terms were seen in public JavaScript",
        ),
        (
            "js_secret_like_details_seen",
            12,
            "secret-like variable/value pairs were seen in public JavaScript",
        ),
    ] {
        if is_true(row, field) {
            score -= penalty;
            notes.push(note);
            offer = "Website source exposure review";
        }
    }
    if is_true(row, "js_debug_terms_seen") {
        score -= 3;
        notes.push("debug terms were seen in public JavaScript");
    }
    if !text(row, "html_comment_risk_terms").trim().is_empty() {
        score -= 5;
        notes.push("risk-related terms were seen in HTML comments");
        offer = "Website source exposure review";
    }
    if is_true(row, "admin_link_hints_seen") {
        score -= 2;
        notes.push("admin/login link hints were visible in homepage source");
    }
    if is_true(row, "source_control_exposed") {
        score -= 35;
        notes.push("source control metadata was publicly reachable");
        offer = "Website source exposure review";
    }
    let env = text(row, "env_files_found").trim().to_lowercase();
    if !env.is_empty() && !matches!(env.as_str(), "false" | "unknown") {
        score -= 35;
        notes.push("environment file path was publicly reachable");
        offer = "Website source exposure review";
    }
    if !text(row, "backup_files_found").trim().is_empty() {
        score -= 25;
        notes.push("backup or database file path was publicly reachable");
        offer = "Website source exposure review";
    }
    if !text(row, "admin_panels_found").trim().is_empty() {
        score -= 8;
        notes.push("admin or login paths were publicly reachable");
        offer = "Website access surface review";
    }
    if int_value(row, "api_endpoints_discovered") > 0 {
        score -= 4;
        notes.push("client-side code exposed API endpoint paths");
    }
    if !text(row, "x_powered_by_header").trim().is_empty() {
        score -= 2;
        notes.push("X-Powered-By technology header was exposed");
    }
    if is_true(row, "outdated_copyright") {
        score -= 2;
        notes.push("visible copyright year appears outdated");
    }
    if is_true(row, "wordpress_visible") {
        notes.push("WordPress indicators seen; maintenance review may be relevant");
    }
    score = score.clamp(0, 100);
    let risk = if score >= 80 {
        "low"
    } else if score >= 60 {
        "medium"
    } else {
        "high"
    };
    if notes.is_empty() {
        notes.push("no major public trust gaps were detected");
    }
    (score, risk.into(), notes.join(" | "), offer.into())
}
