use crate::{Row, int_value, is_true, text};
use std::collections::BTreeMap;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedFinding {
    pub category: String,
    pub finding: String,
    pub observation: String,
    pub severity: String,
    pub priority_score: i64,
    pub likelihood: i64,
    pub impact: i64,
    pub confidence: String,
    pub evidence_field: String,
    pub evidence_value: String,
    pub standard_basis: String,
}

pub fn specific_findings(row: &Row) -> String {
    let findings = review_findings(row);
    if findings.is_empty() {
        "No customer-facing observation is ready; review the internal evidence before review."
            .into()
    } else {
        findings.join(" | ")
    }
}

pub fn has_env_exposure(row: &Row) -> bool {
    let value = text(row, "env_files_found");
    !value.trim().is_empty() && !matches!(value.trim().to_lowercase().as_str(), "false" | "unknown")
}

pub fn env_exposure_finding(row: &Row) -> String {
    let value = text(row, "env_files_found");
    if value.trim().eq_ignore_ascii_case("true") {
        "Environment file path was publicly reachable".into()
    } else {
        format!(
            "Environment file URL(s) were content-confirmed as publicly reachable: {}",
            value.trim()
        )
    }
}

pub fn opening_observation(row: &Row) -> String {
    let domain = nonempty(&[text(row, "domain"), text(row, "website")], "");
    if text(row, "reachable") == "false" {
        return format!(
            "{domain} did not respond during the public website check and should be verified from another network."
        );
    }
    if text(row, "reachable") == "unknown" {
        return format!(
            "{domain} presented a human-verification interstitial, so no homepage availability or browser-control finding should be reported until manual review."
        );
    }
    if let Some(finding) = ranked_review_findings(row)
        .into_iter()
        .find(opener_safe_finding)
    {
        return finding.observation.clone();
    }
    format!("{domain} was reviewed with a public website and email trust snapshot.")
}

fn opener_safe_finding(finding: &RankedFinding) -> bool {
    !matches!(
        finding.category.as_str(),
        "transport_security"
            | "browser_hardening"
            | "cookie_hardening"
            | "disclosure_process"
            | "cms_maintenance"
    )
}

pub fn email_authentication_findings(row: &Row) -> Vec<String> {
    let mut findings = Vec::new();
    if text(row, "spf") == "false" {
        findings.push("no SPF record".into());
    }
    if text(row, "dmarc") == "false" {
        findings.push("no DMARC record".into());
    } else if text(row, "dmarc_policy")
        .trim()
        .eq_ignore_ascii_case("none")
    {
        findings.push("DMARC set to p=none monitoring mode".into());
    }
    let pct = text(row, "dmarc_pct");
    if !pct.trim().is_empty() && pct.trim() != "100" {
        findings.push(format!("DMARC pct={} instead of 100", pct.trim()));
    }
    findings
}

pub fn missing_header_findings(row: &Row) -> Vec<String> {
    [
        ("hsts", "HSTS"),
        ("csp", "Content-Security-Policy"),
        ("x_frame_options", "X-Frame-Options"),
        ("referrer_policy", "Referrer-Policy"),
        ("permissions_policy", "Permissions-Policy"),
    ]
    .into_iter()
    .filter(|(field, _)| text(row, field) == "false")
    .map(|(_, label)| label.to_string())
    .take(3)
    .collect()
}

pub fn missing_cookie_findings(row: &Row) -> Vec<String> {
    if text(row, "set_cookie_seen") != "true" {
        return Vec::new();
    }
    [
        ("secure_cookie_seen", "Secure cookie flag"),
        ("httponly_cookie_seen", "HttpOnly cookie flag"),
        ("samesite_cookie_seen", "SameSite cookie flag"),
    ]
    .into_iter()
    .filter(|(field, _)| text(row, field) == "false")
    .map(|(_, label)| label.to_string())
    .collect()
}

pub fn trust_signal_findings(row: &Row) -> Vec<String> {
    [
        ("privacy_policy_seen", "a homepage privacy policy link"),
        ("contact_page_seen", "a homepage contact link"),
        ("security_txt", "security.txt"),
        ("meta_description_seen", "a homepage meta description"),
        ("h1_seen", "a homepage H1"),
        ("viewport_meta_seen", "mobile viewport metadata"),
    ]
    .into_iter()
    .filter(|(field, _)| text(row, field) == "false")
    .map(|(_, label)| label.to_string())
    .take(3)
    .collect()
}

pub fn classify_finding_severity(row: &Row) -> BTreeMap<String, Vec<String>> {
    let mut critical = Vec::new();
    let mut high = Vec::new();
    let mut medium = Vec::new();
    let mut low = Vec::new();
    let domain = nonempty(&[text(row, "domain"), text(row, "website")], "domain");
    if is_true(row, "source_control_exposed") {
        critical.push("Source control metadata path was publicly reachable".into());
    }
    if has_env_exposure(row) {
        critical.push(env_exposure_finding(row));
    }
    for (field, prefix) in [
        (
            "backup_files_found",
            "Backup or database file path(s) were publicly reachable",
        ),
        (
            "admin_panels_found",
            "Admin or login path(s) were publicly reachable",
        ),
        (
            "ftp_webroot_paths_accessible",
            "Anonymous FTP allowed access to likely webroot path(s)",
        ),
    ] {
        let value = text(row, field);
        if !value.is_empty() {
            critical.push(format!("{prefix}: {value}"));
        }
    }
    for (field, prefix) in [
        (
            "apis_leaking_data",
            "API response matched data-exposure heuristics",
        ),
        (
            "api_documentation_urls",
            "Public API documentation URL(s) were found",
        ),
        (
            "unauthenticated_apis",
            "Meaningful API endpoint(s) responded without authentication",
        ),
        (
            "wordpress_unsafe_write_apis",
            "WordPress REST write route accepted an unauthenticated write request",
        ),
    ] {
        let value = text(row, field);
        if !value.is_empty()
            && (field != "unauthenticated_apis"
                || has_strong_unauthenticated_api_evidence(row, &value))
        {
            high.push(format!("{prefix}: {value}"));
        }
    }
    if is_true(row, "graphql_introspection") {
        high.push("GraphQL introspection was reachable".into());
    }
    let secrets = split_terms(&text(row, "js_secret_like_details"));
    if !secrets.is_empty() {
        critical.push(format!(
            "Public JavaScript exposes these secret-like variable/value pairs: {}",
            secrets.join("; ")
        ));
    }
    let sector = text(row, "sector").to_lowercase();
    if ["finance", "bank", "health", "hospital", "clinic", "payment"]
        .iter()
        .any(|marker| sector.contains(marker))
        && text(row, "dmarc") == "false"
    {
        critical.push(format!(
            "Missing DMARC on sensitive sector domain: {domain}"
        ));
    }
    if is_true(row, "js_source_map_seen") {
        high.push(
            "JavaScript source map reference is public, which can expose the original source tree"
                .into(),
        );
    }
    if text(row, "dmarc") == "false" || text(row, "dmarc_policy").to_lowercase() == "none" {
        high.push("Weak email authentication: SPF or DMARC p=none".into());
    }
    if text(row, "forms_over_https") == "insecure_form_action" {
        high.push("Homepage form action appears to submit over plain HTTP".into());
    }
    if int_value(row, "mixed_content_refs") > 0 {
        high.push(format!(
            "Homepage source includes {} HTTP asset/link reference(s)",
            text(row, "mixed_content_refs")
        ));
    }
    medium.extend(
        missing_header_findings(row)
            .into_iter()
            .map(|finding| format!("Missing browser header: {finding}")),
    );
    if text(row, "security_txt") == "false" {
        medium.push(format!("No security.txt contact file seen for {domain}"));
    }
    low.extend(
        trust_signal_findings(row)
            .into_iter()
            .map(|finding| format!("Missing trust/page signal: {finding}")),
    );
    BTreeMap::from([
        ("critical".into(), critical),
        ("high".into(), high),
        ("medium".into(), medium),
        ("low".into(), low),
    ])
}

pub fn prioritized_findings(row: &Row) -> Vec<String> {
    review_findings(row)
}

pub fn review_findings(row: &Row) -> Vec<String> {
    let ranked = ranked_review_findings(row);
    if !ranked.is_empty() {
        return ranked.into_iter().map(|finding| finding.finding).collect();
    }
    legacy_review_findings(row)
}

pub fn ranked_review_findings(row: &Row) -> Vec<RankedFinding> {
    let mut findings = Vec::new();
    let domain = nonempty(
        &[text(row, "domain"), text(row, "website")],
        "the public website",
    );
    if has_env_exposure(row) {
        let value = text(row, "env_files_found");
        findings.push(ranked(
            "configuration_exposure",
            "Public configuration file path needs urgent confirmation; redact and rotate any credentials found",
            &format!(
                "The public review for {domain} found a reachable configuration-file path. If it contains database usernames, passwords, tokens, or mail credentials, those secrets should be rotated after confirmation."
            ),
            "critical",
            10,
            sector_impact(row, 10),
            "confirmed",
            "env_files_found",
            &value,
            "OWASP likelihood x impact; NIST confidentiality impact",
        ));
    }
    if is_true(row, "source_control_exposed") {
        findings.push(ranked(
            "source_control_exposure",
            "Source-control metadata path was publicly reachable",
            &format!(
                "The public review for {domain} found source-control metadata reachable from the web, which can expose application history, source paths, and secrets."
            ),
            "critical",
            10,
            sector_impact(row, 9),
            "confirmed",
            "source_control_exposed",
            "true",
            "OWASP likelihood x impact; exposure of implementation details and credentials",
        ));
    }
    for (field, category, label, observation, base_impact) in [
        (
            "backup_files_found",
            "backup_file_exposure",
            "Backup or database file path(s) were publicly reachable",
            "backup or database file path(s) reachable from the public web",
            9,
        ),
        (
            "admin_panels_found",
            "admin_surface_exposure",
            "Admin or login path(s) were publicly reachable",
            "admin or login surfaces reachable from the public web",
            8,
        ),
        (
            "ftp_webroot_paths_accessible",
            "ftp_webroot_exposure",
            "Anonymous FTP allowed access to likely webroot path(s)",
            "anonymous FTP access to likely webroot directories",
            9,
        ),
    ] {
        let value = text(row, field);
        if !value.trim().is_empty() {
            if field == "admin_panels_found" && is_broad_probe_spray(&value) {
                findings.push(ranked(
                    "admin_surface_candidate",
                    &format!(
                        "Public review mapped admin/login path candidates for manual confirmation: {}",
                        summarize_list(&value, 3)
                    ),
                    &format!(
                        "The public review for {domain} mapped a broad set of admin/login path candidates. Because broad matches can come from catch-all routing, this should be manually confirmed before it is used as the lead review claim."
                    ),
                    "medium",
                    4,
                    sector_impact(row, 5),
                    "heuristic",
                    field,
                    &value,
                    "OWASP likelihood x impact; catch-all route false-positive guard",
                ));
                continue;
            }
            findings.push(ranked(
                category,
                &format!("{label}: {}", summarize_list(&value, 3)),
                &format!(
                    "The public review for {domain} found {observation}: {}. {}",
                    summarize_list(&value, 3),
                    access_surface_context(field),
                ),
                "critical",
                9,
                sector_impact(row, base_impact),
                "confirmed",
                field,
                &value,
                "OWASP likelihood x impact; externally reachable access surface",
            ));
        }
    }
    for (field, category, label, observation, confidence, impact) in [
        (
            "apis_leaking_data",
            "api_data_exposure",
            "API response matched data-exposure heuristics",
            "API response patterns that may expose business or member/customer data",
            "probable",
            10,
        ),
        (
            "graphql_introspection",
            "graphql_schema_exposure",
            "GraphQL introspection was reachable",
            "GraphQL introspection reachable from the public internet",
            "probable",
            8,
        ),
        (
            "wordpress_unsafe_write_apis",
            "wordpress_unsafe_write_access",
            "WordPress REST write route accepted an unauthenticated write request",
            "an unauthenticated WordPress REST write route accepting requests",
            "confirmed",
            10,
        ),
        (
            "api_documentation_urls",
            "api_documentation_exposure",
            "Public API documentation surface was found",
            "public API documentation or Swagger/OpenAPI surface",
            "probable",
            8,
        ),
        (
            "unauthenticated_apis",
            "unauthenticated_api_surface",
            "Meaningful API endpoint responded without authentication",
            "meaningful API endpoint(s) responding without authentication",
            "probable",
            7,
        ),
    ] {
        let value = text(row, field);
        let active = if field == "graphql_introspection" {
            value.eq_ignore_ascii_case("true")
        } else if field == "unauthenticated_apis" {
            has_strong_unauthenticated_api_evidence(row, &value)
        } else {
            !value.trim().is_empty()
        };
        if active {
            let evidence = if field == "graphql_introspection" {
                "/graphql".to_string()
            } else {
                summarize_list(&value, 3)
            };
            findings.push(ranked(
                category,
                &format!("{label}: {evidence}"),
                &format!(
                    "The public review for {domain} found {observation}: {evidence}. This should be validated for authorization, exposed operations, and data returned before review."
                ),
                if impact >= 9 { "critical" } else { "high" },
                8,
                sector_impact(row, impact),
                confidence,
                field,
                &value,
                "OWASP API Security Top 10 2023; OWASP likelihood x impact",
            ));
        }
    }
    let endpoint_urls = text(row, "api_endpoint_urls");
    if !endpoint_urls.trim().is_empty() {
        if default_wordpress_rest_read_urls_only(&endpoint_urls)
            && text(row, "wordpress_unsafe_write_apis").trim().is_empty()
        {
            let write_probe = text(row, "wordpress_write_probe_results");
            findings.push(ranked(
                "wordpress_rest_read_inventory",
                &format!(
                    "WordPress REST read routes were visible: {}",
                    summarize_list(&endpoint_urls, 3)
                ),
                &format!(
                    "The public review for {domain} found default WordPress REST read routes. That is normal for many WordPress sites; review should focus on whether unauthenticated write actions or sensitive data exposure are possible."
                ),
                "medium",
                3,
                sector_impact(row, 4),
                "probable",
                if write_probe.trim().is_empty() {
                    "api_endpoint_urls"
                } else {
                    "wordpress_write_probe_results"
                },
                if write_probe.trim().is_empty() {
                    &endpoint_urls
                } else {
                    &write_probe
                },
                "WordPress REST API default-read-route guard; non-destructive write probe",
            ));
        } else if has_reportable_api_surface_inventory(&endpoint_urls) {
            findings.push(ranked(
                "api_surface_inventory",
                &format!(
                    "Public review mapped API endpoint URL(s): {}",
                    summarize_list(&endpoint_urls, 3)
                ),
                &format!(
                    "The public review for {domain} mapped API endpoint URLs worth confirming: {}.",
                    summarize_list(&endpoint_urls, 3)
                ),
                "high",
                7,
                sector_impact(row, 7),
                "probable",
                "api_endpoint_urls",
                &endpoint_urls,
                "OWASP API Security Top 10 2023; attack-surface inventory",
            ));
        } else {
            findings.push(ranked(
                "api_surface_inventory",
                &format!(
                    "Public review mapped API candidate URL(s): {}",
                    summarize_list(&endpoint_urls, 3)
                ),
                &format!(
                    "The public review for {domain} mapped API candidate URLs that need review before review: {}.",
                    summarize_list(&endpoint_urls, 3)
                ),
                "medium",
                4,
                sector_impact(row, 4),
                "heuristic",
                "api_endpoint_urls",
                &endpoint_urls,
                "Attack-surface inventory; requires URL evidence review before escalation",
            ));
        }
    } else if int_value(row, "api_endpoints_discovered") > 0 {
        findings.push(ranked(
            "api_surface_inventory",
            &format!(
                "Public review mapped {} API endpoint candidate(s)",
                text(row, "api_endpoints_discovered")
            ),
            &format!(
                "The public review for {domain} mapped {} API endpoint candidate(s). The endpoint URLs should be reviewed before this is used in review.",
                text(row, "api_endpoints_discovered")
            ),
            "medium",
            5,
            sector_impact(row, 5),
            "heuristic",
            "api_endpoints_discovered",
            &text(row, "api_endpoints_discovered"),
            "Attack-surface inventory; requires URL evidence before high-confidence review",
        ));
    }
    let secrets = split_terms(&text(row, "js_secret_like_details"));
    if !secrets.is_empty() {
        if actionable_secret_details(&secrets) {
            findings.push(ranked(
                "client_side_secret_pattern",
                "Public JavaScript contains credential-like patterns that require manual confirmation",
                &format!(
                    "The public source review for {domain} found credential-like patterns in JavaScript. The review copy intentionally redacts values until a human confirms what is real."
                ),
                "critical",
                7,
                sector_impact(row, 8),
                "heuristic",
                "js_secret_like_details",
                &text(row, "js_secret_like_details"),
                "OWASP likelihood x impact; client-side secret exposure heuristic",
            ));
        } else {
            findings.push(ranked(
                "client_side_secret_terms",
                "Public JavaScript contains token/password-related code terms that need manual confirmation",
                &format!(
                    "The public source review for {domain} found token/password-related code terms, but they look like framework or client-side state patterns. Treat this as a review cue, not a primary review claim."
                ),
                "medium",
                4,
                sector_impact(row, 5),
                "heuristic",
                "js_secret_like_details",
                &text(row, "js_secret_like_details"),
                "OWASP likelihood x impact; false-positive guard for common frontend terms",
            ));
        }
    } else if is_true(row, "js_secret_like_terms_seen") {
        findings.push(ranked(
            "client_side_secret_terms",
            "Public JavaScript contains credential-related terms that require manual confirmation",
            &format!(
                "The public source review for {domain} found credential-related terms in JavaScript. This needs manual confirmation before quoting any detail."
            ),
            "high",
            5,
            sector_impact(row, 6),
            "heuristic",
            "js_secret_like_terms",
            &text(row, "js_secret_like_terms"),
            "OWASP likelihood x impact; client-side secret exposure heuristic",
        ));
    }
    if is_true(row, "js_source_map_seen") {
        findings.push(ranked(
            "source_map_exposure",
            "A public JavaScript source map may reveal application structure and internal paths",
            &format!(
                "The public source review for {domain} found a source-map reference, which can reveal original file paths and application structure behind minified code."
            ),
            "high",
            6,
            sector_impact(row, 6),
            "probable",
            "js_source_map_seen",
            "true",
            "OWASP likelihood x impact; information disclosure",
        ));
    }
    if !split_terms(&text(row, "js_html_injection_sinks")).is_empty() {
        findings.push(ranked(
            "client_side_injection_sink",
            "Client-side code uses browser APIs that warrant review for unsafe HTML injection",
            &format!(
                "The public source review for {domain} found HTML injection sink patterns in JavaScript. This should be reviewed with the application context before remediation."
            ),
            "high",
            5,
            sector_impact(row, 6),
            "heuristic",
            "js_html_injection_sinks",
            &text(row, "js_html_injection_sinks"),
            "OWASP likelihood x impact; injection-prone client-side APIs",
        ));
    }
    if int_value(row, "mixed_content_refs") > 0 {
        findings.push(ranked(
            "mixed_content",
            "The homepage references resources over insecure HTTP",
            &format!(
                "The public source review for {domain} found {} HTTP asset/link reference(s).",
                text(row, "mixed_content_refs")
            ),
            "high",
            5,
            sector_impact(row, 5),
            "probable",
            "mixed_content_refs",
            &text(row, "mixed_content_refs"),
            "Transport integrity and browser trust baseline",
        ));
    }
    if int_value(row, "external_scripts_without_sri") > 0 {
        findings.push(ranked(
            "third_party_script_integrity",
            "Some third-party scripts load without integrity checks",
            &format!(
                "The public source review for {domain} found third-party scripts loading without Subresource Integrity."
            ),
            "medium",
            4,
            sector_impact(row, 4),
            "probable",
            "external_scripts_without_sri",
            &text(row, "external_scripts_without_sri"),
            "Supply-chain hardening; browser script integrity control",
        ));
    }
    if int_value(row, "vulnerable_script_count") > 0 {
        let evidence = text(row, "vulnerable_script_evidence");
        findings.push(ranked(
            "known_vulnerable_client_library",
            &format!(
                "Included JavaScript library version(s) appear to match known vulnerability advisories: {}",
                nonempty(&[text(row, "vulnerable_script_libraries")], "review evidence")
            ),
            &format!(
                "The public source review for {domain} matched a client-side library version to known advisories. Evidence: {}",
                nonempty(std::slice::from_ref(&evidence), &text(row, "vulnerable_script_libraries"))
            ),
            "high",
            6,
            sector_impact(row, 6),
            "probable",
            "vulnerable_script_evidence",
            &evidence,
            "Known-vulnerability exposure; OWASP likelihood x impact",
        ));
    }
    if text(row, "forms_over_https") == "insecure_form_action" {
        findings.push(ranked(
            "insecure_form_transport",
            "Homepage form action appears to submit over plain HTTP",
            &format!(
                "The homepage form review for {domain} found a form action that appears to submit over plain HTTP."
            ),
            "high",
            7,
            sector_impact(row, 7),
            "probable",
            "forms_over_https",
            "insecure_form_action",
            "OWASP likelihood x impact; user-submitted data transport risk",
        ));
    }
    findings.extend(
        email_authentication_findings(row)
            .into_iter()
            .map(|finding| {
                let severity = if finding.contains("DMARC") { "high" } else { "medium" };
                ranked(
                    "email_authentication",
                    &format!("Public DNS shows {finding}"),
                    &format!(
                        "Public DNS for {domain} showed {finding}. This matters for spoofing and payment/trust conversations because monitoring-only or missing enforcement may not reject impersonation attempts."
                    ),
                    severity,
                    if finding.contains("DMARC") { 7 } else { 5 },
                    sector_impact(row, if finding.contains("DMARC") { 7 } else { 5 }),
                    "probable",
                    if finding.contains("DMARC") { "dmarc_policy" } else { "spf" },
                    &finding,
                    "CISA/DHS email security baseline; OWASP business impact",
                )
            }),
    );
    if text(row, "https") == "false" {
        findings.push(ranked(
            "transport_security",
            "The final page did not load over HTTPS",
            &format!("The public browser check for {domain} showed the final page did not load over HTTPS."),
            "high",
            6,
            sector_impact(row, 6),
            "probable",
            "https",
            "false",
            "CISA/DHS web security baseline; transport confidentiality/integrity",
        ));
    }
    if text(row, "tls_valid") == "false" {
        findings.push(ranked(
            "transport_security",
            "The TLS certificate did not validate",
            &format!(
                "The public browser check for {domain} showed the TLS certificate did not validate."
            ),
            "medium",
            4,
            sector_impact(row, 5),
            "probable",
            "tls_valid",
            "false",
            "Transport security baseline; lower review priority than concrete exposure evidence",
        ));
    }
    if text(row, "redirects_to_https") == "false" {
        findings.push(ranked(
            "transport_security",
            "HTTP traffic did not redirect to HTTPS",
            &format!("The public browser check for {domain} showed HTTP traffic did not redirect to HTTPS."),
            "medium",
            4,
            sector_impact(row, 5),
            "probable",
            "redirects_to_https",
            "false",
            "Transport security baseline; lower review priority than concrete exposure evidence",
        ));
    }
    findings.extend(missing_header_findings(row).into_iter().map(|finding| {
        ranked(
            "browser_hardening",
            &format!("Missing browser protection: {finding}"),
            &format!("{domain} is online, but the response did not show {finding}."),
            "medium",
            3,
            sector_impact(row, 4),
            "probable",
            "security_headers",
            &finding,
            "CISA/DHS web security baseline; browser hardening",
        )
    }));
    findings.extend(missing_cookie_findings(row).into_iter().map(|finding| {
        ranked(
            "cookie_hardening",
            &format!("Missing cookie protection: {finding}"),
            &format!("{domain} set cookies, but the response did not show {finding}."),
            "medium",
            3,
            sector_impact(row, 4),
            "probable",
            "cookie_flags",
            &finding,
            "Session hardening baseline; browser cookie controls",
        )
    }));
    if text(row, "security_txt") == "false" {
        findings.push(ranked(
            "disclosure_process",
            &format!("No security.txt contact file was found for {domain}"),
            &format!("{domain} was missing security.txt in the public homepage check."),
            "low",
            2,
            sector_impact(row, 3),
            "probable",
            "security_txt",
            "false",
            "RFC 9116 vulnerability disclosure contact signal",
        ));
    }
    if is_true(row, "wordpress_visible") {
        findings.push(ranked(
            "cms_maintenance",
            "WordPress indicators visible on homepage",
            &format!("{domain} appears to run WordPress, which usually benefits from routine patching and monitoring."),
            "low",
            2,
            sector_impact(row, 3),
            "heuristic",
            "wordpress_visible",
            "true",
            "Operational maintenance and patch cadence signal",
        ));
    }
    findings.sort_by(|left, right| {
        right
            .priority_score
            .cmp(&left.priority_score)
            .then_with(|| severity_rank(&right.severity).cmp(&severity_rank(&left.severity)))
            .then_with(|| {
                confidence_rank(&right.confidence).cmp(&confidence_rank(&left.confidence))
            })
            .then_with(|| left.category.cmp(&right.category))
    });
    dedupe_ranked_findings(findings)
}

fn legacy_review_findings(row: &Row) -> Vec<String> {
    let mut findings = Vec::new();
    let domain = nonempty(
        &[text(row, "domain"), text(row, "website")],
        "the public website",
    );
    match text(row, "recommended_offer").as_str() {
        "Website source exposure review" => findings.extend(review_source_findings(row)),
        "Website form security review" => findings.extend(form_security_findings(row)),
        _ => {}
    }
    if text(row, "reachable") == "false" {
        findings.push(
            "The public website did not respond during the check and should be verified from another network"
                .into(),
        );
    }
    if text(row, "reachable") == "unknown" {
        findings.push(
            "The site presented a browser-verification page, so its homepage controls need manual review"
                .into(),
        );
    }
    if text(row, "https") == "false" {
        findings.push("The final page did not load over HTTPS".into());
    }
    if text(row, "tls_valid") == "false" {
        findings.push("The TLS certificate did not validate".into());
    }
    if text(row, "redirects_to_https") == "false" {
        findings.push("HTTP traffic did not redirect to HTTPS".into());
    }
    findings.extend(
        email_authentication_findings(row)
            .into_iter()
            .map(|finding| format!("Public DNS shows {finding}")),
    );
    findings.extend(
        missing_header_findings(row)
            .into_iter()
            .map(|finding| format!("Missing browser protection: {finding}")),
    );
    findings.extend(
        missing_cookie_findings(row)
            .into_iter()
            .map(|finding| format!("Missing cookie protection: {finding}")),
    );
    if text(row, "security_txt") == "false" {
        findings.push(format!(
            "No security.txt contact file was found for {domain}"
        ));
    }
    dedupe_preserve_order(findings)
}

#[allow(clippy::too_many_arguments)]
fn ranked(
    category: &str,
    finding: &str,
    observation: &str,
    severity: &str,
    likelihood: i64,
    impact: i64,
    confidence: &str,
    evidence_field: &str,
    evidence_value: &str,
    standard_basis: &str,
) -> RankedFinding {
    RankedFinding {
        category: category.into(),
        finding: finding.into(),
        observation: observation.into(),
        severity: severity.into(),
        priority_score: likelihood * impact + confidence_bonus(confidence),
        likelihood,
        impact,
        confidence: confidence.into(),
        evidence_field: evidence_field.into(),
        evidence_value: evidence_value.into(),
        standard_basis: standard_basis.into(),
    }
}

fn sector_impact(row: &Row, base: i64) -> i64 {
    let sector = text(row, "sector").to_lowercase();
    let sensitive = [
        "bank",
        "finance",
        "payment",
        "insurance",
        "hospital",
        "clinic",
        "health",
        "school",
        "education",
        "government",
        "membership",
    ]
    .iter()
    .any(|marker| sector.contains(marker));
    if sensitive { (base + 1).min(10) } else { base }
}

fn confidence_bonus(confidence: &str) -> i64 {
    match confidence {
        "confirmed" => 3,
        "probable" => 2,
        "heuristic" => 0,
        _ => 0,
    }
}

fn confidence_rank(confidence: &str) -> i64 {
    match confidence {
        "confirmed" => 3,
        "probable" => 2,
        "heuristic" => 1,
        _ => 0,
    }
}

fn severity_rank(severity: &str) -> i64 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn dedupe_ranked_findings(findings: Vec<RankedFinding>) -> Vec<RankedFinding> {
    let mut output = Vec::new();
    for finding in findings {
        if !output
            .iter()
            .any(|existing: &RankedFinding| existing.finding == finding.finding)
        {
            output.push(finding);
        }
    }
    output
}

fn summarize_list(value: &str, limit: usize) -> String {
    let values = split_terms(value);
    values
        .into_iter()
        .take(limit)
        .collect::<Vec<_>>()
        .join("; ")
}

fn access_surface_context(field: &str) -> &'static str {
    match field {
        "admin_panels_found" => {
            "The first step is to confirm whether these URLs are intentionally public, protected by the right access controls, and owned by your team."
        }
        "backup_files_found" => {
            "The first step is to confirm whether the file is intentionally public and whether it contains deployment, database, or configuration data."
        }
        "ftp_webroot_paths_accessible" => {
            "The first step is to confirm whether anonymous access is intended and whether those directories expose deployment or uploaded content."
        }
        _ => {
            "The first step is to confirm the exposure, remove false positives, and agree the remediation order."
        }
    }
}

pub fn has_strong_unauthenticated_api_evidence(row: &Row, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    let urls = split_terms(value);
    if !urls.is_empty()
        && urls
            .iter()
            .all(|url| is_default_wordpress_rest_read_url(url))
    {
        return !text(row, "wordpress_unsafe_write_apis").trim().is_empty();
    }
    if !text(row, "api_documentation_urls").trim().is_empty()
        || !text(row, "apis_leaking_data").trim().is_empty()
        || !text(row, "wordpress_unsafe_write_apis").trim().is_empty()
    {
        return true;
    }
    !is_broad_probe_spray(value) && urls.iter().any(|url| is_api_like_url(url))
}

pub fn default_wordpress_rest_read_urls_only(value: &str) -> bool {
    let urls = split_terms(value);
    !urls.is_empty()
        && urls
            .iter()
            .all(|url| is_default_wordpress_rest_read_url(url))
}

pub fn has_reportable_api_surface_inventory(value: &str) -> bool {
    let urls = split_terms(value);
    !urls.is_empty()
        && urls
            .iter()
            .any(|url| !is_default_wordpress_rest_read_url(url) && is_api_like_url(url))
}

fn is_default_wordpress_rest_read_url(value: &str) -> bool {
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    let path = parsed.path().trim_end_matches('/').to_lowercase();
    matches!(
        path.as_str(),
        "/wp-json"
            | "/wp-json/wp/v2"
            | "/wp-json/wp/v2/posts"
            | "/wp-json/wp/v2/pages"
            | "/wp-json/wp/v2/media"
            | "/wp-json/wp/v2/menu-items"
    )
}

fn is_broad_probe_spray(value: &str) -> bool {
    split_terms(value).len() > 20
}

fn is_api_like_url(value: &str) -> bool {
    let lower = value.to_lowercase();
    [
        "api.",
        "/api",
        "/graphql",
        "/wp-json",
        "/jsonapi",
        "/rest",
        "/swagger",
        "/openapi",
        "/api-docs",
        "/health",
        "/metrics",
        "/actuator",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn actionable_secret_details(values: &[String]) -> bool {
    values.iter().any(|value| {
        let lower = value.to_lowercase();
        if lower.contains("__secret_internals_do_not_use")
            || lower.contains("canceltoken")
            || lower.contains("metatokens")
            || lower.contains("withxsrftoken")
            || lower.contains("withxsrf")
            || lower.contains("password=!0")
            || lower.contains("token=new ")
        {
            return false;
        }
        lower.contains("api")
            || lower.contains("secret")
            || lower.contains("private")
            || lower.contains("key=")
            || lower.contains("token=")
            || lower.contains("password=")
            || lower.contains("passwd=")
            || lower.contains("pwd=")
    })
}

pub fn review_source_findings(row: &Row) -> Vec<String> {
    let mut findings = Vec::new();
    if is_true(row, "source_control_exposed") {
        findings.push(
            "A source-control metadata path appeared publicly reachable and needs prompt confirmation"
                .into(),
        );
    }
    if has_env_exposure(row) {
        findings.push(
            "A configuration-file path appeared publicly reachable and needs prompt confirmation"
                .into(),
        );
    }
    if !text(row, "backup_files_found").is_empty() {
        findings.push(
            "A backup or database-file path appeared publicly reachable and needs prompt confirmation"
                .into(),
        );
    }
    if is_true(row, "js_secret_like_details_seen") {
        findings.push(
            "Public JavaScript contains credential-like patterns that require manual confirmation"
                .into(),
        );
    } else if is_true(row, "js_secret_like_terms_seen") {
        findings.push(
            "Public JavaScript contained credential-related patterns that require manual confirmation"
                .into(),
        );
    }
    if is_true(row, "js_source_map_seen") {
        findings.push(
            "A public JavaScript source map may reveal application structure and internal paths"
                .into(),
        );
    }
    if !split_terms(&text(row, "js_html_injection_sinks")).is_empty() {
        findings.push(
            "Client-side code uses browser APIs that warrant review for unsafe HTML injection"
                .into(),
        );
    }
    if int_value(row, "mixed_content_refs") > 0 {
        findings.push("The homepage references resources over insecure HTTP".into());
    }
    if int_value(row, "external_scripts_without_sri") > 0 {
        findings.push("Some third-party scripts load without integrity checks".into());
    }
    if is_true(row, "admin_link_hints_seen") {
        findings.push("Public page source exposes administrative or login-path hints".into());
    }
    if is_true(row, "api_endpoint_hints_seen") {
        findings.push("Public page source exposes application endpoint hints".into());
    }
    findings
}

pub fn form_security_findings(row: &Row) -> Vec<String> {
    let mut findings = Vec::new();
    if text(row, "forms_over_https") == "insecure_form_action" {
        findings.push("Homepage form action appears to submit over plain HTTP".into());
    }
    if is_true(row, "password_field_seen") {
        findings.push("Password field visible in homepage source".into());
    }
    if is_true(row, "external_form_action_seen") {
        findings.push("Homepage form action posts to an external host".into());
    }
    findings
}

pub fn source_exposure_findings(row: &Row) -> Vec<String> {
    let mut findings = Vec::new();
    if int_value(row, "mixed_content_refs") > 0 {
        findings.push(format!(
            "Homepage source includes {} HTTP asset/link reference(s)",
            text(row, "mixed_content_refs")
        ));
    }
    if int_value(row, "external_scripts_without_sri") > 0 {
        findings.push(format!(
            "{} external script(s) without Subresource Integrity",
            text(row, "external_scripts_without_sri")
        ));
    }
    append_source_details(row, &mut findings);
    findings
}

pub fn all_findings(row: &Row) -> Vec<String> {
    let mut findings = Vec::new();
    let domain = nonempty(&[text(row, "domain"), text(row, "website")], "domain");
    for (field, value) in [
        (
            "reachable",
            "Website did not respond during the public check; verify availability from another network",
        ),
        ("https", "Final page did not load over HTTPS"),
        ("tls_valid", "TLS certificate check did not validate"),
        ("redirects_to_https", "HTTP did not redirect to HTTPS"),
    ] {
        if text(row, field) == "false" {
            findings.push(value.into());
        }
    }
    findings.extend(
        email_authentication_findings(row)
            .into_iter()
            .map(|finding| format!("Public DNS: {finding}")),
    );
    findings.extend(form_security_findings(row));
    if int_value(row, "mixed_content_refs") > 0 {
        findings.push(format!(
            "Homepage source includes {} HTTP asset/link reference(s)",
            text(row, "mixed_content_refs")
        ));
    }
    findings.extend(
        missing_header_findings(row)
            .into_iter()
            .map(|finding| format!("Missing browser header: {finding}")),
    );
    findings.extend(
        missing_cookie_findings(row)
            .into_iter()
            .map(|finding| format!("Missing cookie attribute: {finding}")),
    );
    findings.extend(
        trust_signal_findings(row)
            .into_iter()
            .map(|finding| format!("Missing trust/page signal: {finding}")),
    );
    for (field, prefix) in [
        (
            "x_powered_by_header",
            "Technology header exposed: X-Powered-By=",
        ),
        ("generator_meta", "Generator metadata visible: "),
        ("technology_hints", "Technology hints visible: "),
    ] {
        let value = text(row, field);
        if !value.is_empty() {
            findings.push(format!("{prefix}{value}"));
        }
    }
    if int_value(row, "external_scripts_without_sri") > 0 {
        findings.push(format!(
            "{} external script(s) without Subresource Integrity",
            text(row, "external_scripts_without_sri")
        ));
    }
    let external_hosts = text(row, "external_script_hosts");
    if !external_hosts.is_empty() {
        findings.push(format!("External script hosts visible: {external_hosts}"));
    }
    if is_true(row, "html_comments_seen") {
        findings.push("HTML comments visible in homepage source".into());
    }
    append_source_details(row, &mut findings);
    if int_value(row, "js_files_checked") > 0 {
        findings.push(format!(
            "{} same-origin JavaScript file(s) inspected",
            text(row, "js_files_checked")
        ));
    }
    if is_true(row, "wordpress_visible") {
        findings.push("WordPress indicators visible on homepage".into());
    }
    if is_true(row, "outdated_copyright") {
        findings.push("Visible copyright year appears outdated".into());
    }
    if text(row, "security_txt") == "false" {
        findings.push(format!("No security.txt contact file seen for {domain}"));
    }
    dedupe_preserve_order(findings)
}

fn append_source_details(row: &Row, findings: &mut Vec<String>) {
    if is_true(row, "js_source_map_seen") {
        findings.push("JavaScript source map reference is public, which can expose the original source tree, function names, comments, and internal endpoint paths behind minified code".into());
    }
    let secrets = split_terms(&text(row, "js_secret_like_details"));
    if !secrets.is_empty() {
        findings.push(format!("Public JavaScript exposes these secret-like variable/value pairs: {}. These should not be present in client-side code because they can expose credentials, API access, or private material", secrets.join("; ")));
    } else {
        let terms = text(row, "js_secret_like_terms");
        if !terms.trim().is_empty() {
            let parsed = split_terms(&terms);
            findings.push(format!(
                "Public JavaScript contains these secret-like terms: {}. These can indicate embedded API keys, tokens, passwords, or private keys",
                if parsed.is_empty() { terms } else { parsed.join(", ") }
            ));
        }
    }
    if is_true(row, "js_secret_like_terms_seen") && secrets.is_empty() {
        findings.push("Public JavaScript contains secret-like terms".into());
    }
    let sinks = split_terms(&text(row, "js_html_injection_sinks"));
    if !sinks.is_empty() {
        findings.push(format!("Public JavaScript uses HTML injection sink(s): {}. If user-controlled data reaches these functions, it can become HTML injection or XSS", sinks.join(", ")));
    }
    if is_true(row, "js_debug_terms_seen") {
        findings.push("Debug terms visible in public JavaScript".into());
    }
    let comments = split_terms(&text(row, "html_comment_risk_terms"));
    if !comments.is_empty() {
        findings.push(format!(
            "HTML comments exposed these terms in page source: {}",
            comments.join(", ")
        ));
    }
    for (field, label) in [
        (
            "admin_link_hints_seen",
            "Admin/login link hints visible in homepage source",
        ),
        (
            "api_endpoint_hints_seen",
            "API endpoint hints visible in homepage source",
        ),
        (
            "source_control_exposed",
            "Source control metadata path was publicly reachable",
        ),
    ] {
        if is_true(row, field) {
            findings.push(label.into());
        }
    }
    if has_env_exposure(row) {
        findings.push(env_exposure_finding(row));
    }
    for (field, prefix) in [
        (
            "backup_files_found",
            "Backup or database file path(s) were publicly reachable",
        ),
        (
            "admin_panels_found",
            "Admin or login path(s) were publicly reachable",
        ),
        (
            "ftp_webroot_paths_accessible",
            "Anonymous FTP allowed access to likely webroot path(s)",
        ),
        (
            "api_endpoint_urls",
            "Public review mapped API endpoint URL(s)",
        ),
        (
            "api_documentation_urls",
            "Public API documentation URL(s) were found",
        ),
        (
            "unauthenticated_apis",
            "Meaningful API endpoint(s) responded without authentication",
        ),
        (
            "api_endpoints_discovered",
            "Client-side code exposed API endpoint path(s)",
        ),
    ] {
        let value = text(row, field);
        if !value.is_empty() && (field != "api_endpoints_discovered" || int_value(row, field) > 0) {
            findings.push(format!("{prefix}: {value}"));
        }
    }
}

pub fn split_terms(value: &str) -> Vec<String> {
    dedupe_preserve_order(
        value
            .split([';', ','])
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

pub fn dedupe_preserve_order(values: Vec<String>) -> Vec<String> {
    let mut result = Vec::new();
    for value in values {
        let normalized = value.trim().to_string();
        if !normalized.is_empty() && !result.contains(&normalized) {
            result.push(normalized);
        }
    }
    result
}

pub fn join_findings(findings: &[String]) -> String {
    match findings {
        [] => String::new(),
        [one] => one.clone(),
        [one, two] => format!("{one} and {two}"),
        _ => format!(
            "{}, and {}",
            findings[..findings.len() - 1].join(", "),
            findings.last().unwrap()
        ),
    }
}

fn nonempty(values: &[String], fallback: &str) -> String {
    values
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| fallback.into())
}
