use crate::Row;
use crate::evidence;
use crate::normalize::{domain_from_url, normalize_website};
use crate::scoring::compute_score;
use anyhow::Result;
use base64::Engine;
use chrono::{NaiveDateTime, Utc};
use regex::Regex;
use reqwest::Method;
use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::SystemTime;
use std::time::{Duration, Instant};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, connect};
use url::Url;

const USER_AGENT: &str = "DomainReviewHarness/0.1";
const MAX_BODY_BYTES: usize = 500_000;
const MAX_JS_FILES: usize = 12;
const MAX_REPRESENTATIVE_PAGES: usize = 8;
const SENSITIVE_PATHS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.env",
    "/.env.local",
    "/.hg/hgrc",
    "/.env.production",
    "/config.php.bak",
    "/config.php.old",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/db.sql",
    "/site.zip",
    "/backup.zip",
    "/backup.tar.gz",
    "/.htaccess.bak",
    "/.htpasswd",
    "/admin",
    "/administrator",
    "/admin/login",
    "/login",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/pma",
    "/myadmin",
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/graphql",
    "/openapi.json",
    "/swagger.json",
    "/.well-known/security.txt",
    "/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
];
const API_DISCOVERY_PATHS: &[&str] = &[
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/swagger",
    "/swagger/index.html",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui.html",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/documentation",
    "/graphql",
    "/graphiql",
    "/playground",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/jsonapi",
    "/api/json",
    "/wp-json",
    "/wp-json/wp/v2",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/media",
    "/wp-json/wp/v2/menu-items",
    "/users",
    "/auth",
    "/login",
    "/register",
    "/oauth",
    "/token",
    "/admin/api",
    "/internal/api",
    "/dev/api",
    "/staging/api",
    "/webhooks",
    "/callbacks",
    "/hooks",
    "/graphql/v1",
    "/graphql/v2",
    "/api/graphql",
    "/api/graphiql",
    "/health",
    "/healthz",
    "/status",
    "/ready",
    "/alive",
    "/metrics",
    "/prometheus",
    "/actuator",
    "/actuator/health",
    "/info",
    "/version",
    "/build",
    "/config",
    "/env",
    "/environment",
    "/debug",
    "/trace",
    "/dump",
    "/heapdump",
    "/upload",
    "/uploads",
    "/files",
    "/file",
    "/storage",
    "/assets",
    "/media",
    "/attachments",
    "/download",
    "/exports",
    "/search",
    "/query",
    "/find",
    "/lookup",
    "/index",
    "/es",
    "/elastic",
    "/internal",
    "/private",
    "/backend",
    "/service",
    "/services",
    "/rpc",
    "/grpc",
    "/soap",
    "/xmlrpc",
];
const HUMAN_VERIFICATION_MARKERS: &[&str] = &[
    "verify you are human",
    "checking your browser",
    "performing security verification",
    "attention required! | cloudflare",
    "cf-chl-",
    "challenge-platform",
    "captcha",
];
const ACCESS_DENIED_MARKERS: &[&str] = &[
    "403 forbidden",
    "access denied",
    "request blocked",
    "gateway error",
    "not authorized",
    "not authorised",
    "permission denied",
    "you don't have permission",
    "you do not have permission",
];
const NOT_FOUND_MARKERS: &[&str] = &[
    "404 not found",
    "page not found",
    "route not found",
    "cannot get /",
    "no route matches",
    "this page could not be found",
    "nothing here",
    "terminal with no rails",
    "take the train home",
];

#[derive(Debug, Clone)]
pub struct AssessmentConfig {
    pub timeout: Duration,
    pub retries: usize,
}

impl Default for AssessmentConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            retries: 1,
        }
    }
}

#[derive(Debug, Clone)]
struct Fetch {
    ok: bool,
    status: u16,
    final_url: String,
    headers: HeaderMap,
    body: String,
    elapsed_ms: u128,
    error: String,
}

#[derive(Debug, Clone, Copy)]
struct OpenSslHttpVariant {
    label: &'static str,
    http_version: &'static str,
    quiet: bool,
    ignore_eof: bool,
    connection_close: bool,
}

const OPENSSL_HTTP_VARIANTS: &[OpenSslHttpVariant] = &[
    OpenSslHttpVariant {
        label: "http10_quiet",
        http_version: "HTTP/1.0",
        quiet: true,
        ignore_eof: false,
        connection_close: false,
    },
    OpenSslHttpVariant {
        label: "http10_ign_eof",
        http_version: "HTTP/1.0",
        quiet: false,
        ignore_eof: true,
        connection_close: false,
    },
    OpenSslHttpVariant {
        label: "http11_ign_eof",
        http_version: "HTTP/1.1",
        quiet: false,
        ignore_eof: true,
        connection_close: true,
    },
    OpenSslHttpVariant {
        label: "http11_quiet",
        http_version: "HTTP/1.1",
        quiet: true,
        ignore_eof: false,
        connection_close: true,
    },
];

pub fn assess_lead(lead: &Row, config: &AssessmentConfig) -> Row {
    assess_lead_with_progress(lead, config, |_| {})
}

pub fn assess_lead_with_progress<F>(lead: &Row, config: &AssessmentConfig, mut progress: F) -> Row
where
    F: FnMut(&str),
{
    let started = Instant::now();
    let mut timings = BTreeMap::new();
    let website = lead.get("website").cloned().unwrap_or_default();
    let normalized = normalize_website(&website);
    let domain = domain_from_url(&normalized);
    let now = Utc::now();
    let mut row: Row = crate::models::ASSESSMENT_FIELDS
        .iter()
        .chain(crate::models::RAW_VALIDATION_FIELDS)
        .map(|field| ((*field).into(), String::new()))
        .collect();
    row.extend(lead.clone());
    row.extend([
        (
            "checked_at".into(),
            now.to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        ),
        ("normalized_url".into(), normalized.clone()),
        ("domain".into(), domain.clone()),
        (
            "assessment_mode".into(),
            "proactive-security-reconnaissance".into(),
        ),
        (
            "assessment_profile_version".into(),
            crate::models::ASSESSMENT_PROFILE_VERSION.into(),
        ),
        ("validation_mode".into(), "deep".into()),
        ("campaign".into(), text_value(lead, "campaign")),
        ("checked_at_epoch".into(), now.timestamp().to_string()),
    ]);
    if normalized.is_empty() || domain.is_empty() {
        row.insert("error".into(), "missing website or domain".into());
        finalize(&mut row, started, timings);
        return row;
    }

    let client = match Client::builder()
        .user_agent(USER_AGENT)
        .timeout(config.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            row.insert("error".into(), error.to_string());
            finalize(&mut row, started, timings);
            return row;
        }
    };

    progress("homepage and TLS reconnaissance");
    let stage = Instant::now();
    let (homepage, redirects) = fetch_with_redirects(&client, &normalized, config, 10);
    timings.insert("homepage", stage.elapsed().as_millis());
    let human_verification = homepage.error.starts_with("human verification");
    row.insert(
        "reachable".into(),
        if human_verification {
            "unknown".into()
        } else {
            homepage.ok.to_string()
        },
    );
    row.insert("http_status".into(), status_text(homepage.status));
    row.insert("homepage_status".into(), status_text(homepage.status));
    row.insert("final_url".into(), homepage.final_url.clone());
    row.insert("homepage_final_url".into(), homepage.final_url.clone());
    row.insert("page_load_ms".into(), homepage.elapsed_ms.to_string());
    row.insert("page_size_bytes".into(), homepage.body.len().to_string());
    row.insert("error".into(), homepage.error.clone());
    row.insert(
        "redirect_count".into(),
        redirects.len().saturating_sub(1).to_string(),
    );
    row.insert(
        "redirect_chain_length".into(),
        redirects.len().saturating_sub(1).to_string(),
    );
    row.insert(
        "redirect_chain".into(),
        serde_json::to_string(&redirects).unwrap_or_default(),
    );
    row.insert(
        "https".into(),
        if human_verification {
            "unknown".into()
        } else {
            (homepage.ok && homepage.final_url.starts_with("https://")).to_string()
        },
    );
    row.insert(
        "tls_valid".into(),
        if human_verification {
            "unknown".into()
        } else {
            (homepage.ok && homepage.final_url.starts_with("https://")).to_string()
        },
    );
    row.insert(
        "homepage_body_sha256".into(),
        format!("{:x}", Sha256::digest(homepage.body.as_bytes())),
    );
    if human_verification {
        analyze_headers(&mut row, &homepage.headers);
        row.insert("redirects_to_https".into(), "unknown".into());
        row.insert("redirect_to_https".into(), "unknown".into());
        finalize(&mut row, started, timings);
        return row;
    }
    if !homepage.ok {
        row.insert("validation_notes".into(), homepage.error);
        progress("fallback sensitive-path reconnaissance");
        let stage = Instant::now();
        let bases = sensitive_path_base_urls(&normalized, &row, true);
        probe_sensitive_paths(&mut row, &client, &bases, config, &mut progress, true);
        timings.insert("sensitive_paths", stage.elapsed().as_millis());
        finalize(&mut row, started, timings);
        return row;
    }

    progress("HTTP redirect reconnaissance");
    let stage = Instant::now();
    let (http_result, _) = fetch_with_redirects(&client, &format!("http://{domain}/"), config, 10);
    let redirects_to_https =
        (http_result.ok && http_result.final_url.starts_with("https://")).to_string();
    row.insert("redirects_to_https".into(), redirects_to_https.clone());
    row.insert("redirect_to_https".into(), redirects_to_https);
    timings.insert("http_redirect", stage.elapsed().as_millis());

    progress("homepage analysis");
    let stage = Instant::now();
    analyze_headers(&mut row, &homepage.headers);
    analyze_html(&mut row, &homepage.body, &homepage.final_url);
    let header_values: BTreeMap<String, String> = homepage
        .headers
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.as_str().into(), value.into()))
        })
        .collect();
    row.insert(
        "technology_hints".into(),
        crate::public_checks::technology_hints(&header_values, &homepage.body).join("; "),
    );
    timings.insert("homepage_analysis", stage.elapsed().as_millis());

    progress("DNS reconnaissance");
    let stage = Instant::now();
    analyze_dns(&mut row, &domain);
    timings.insert("dns", stage.elapsed().as_millis());

    progress("JavaScript reconnaissance");
    let stage = Instant::now();
    analyze_javascript(
        &mut row,
        &client,
        &homepage.body,
        &homepage.final_url,
        config,
        &mut progress,
    );
    timings.insert("javascript", stage.elapsed().as_millis());

    progress("representative-page reconnaissance");
    let stage = Instant::now();
    analyze_representative_pages(
        &mut row,
        &client,
        &homepage.body,
        &homepage.final_url,
        config,
        &mut progress,
    );
    timings.insert("representative_pages", stage.elapsed().as_millis());

    progress("sensitive-path reconnaissance");
    let stage = Instant::now();
    let bases = sensitive_path_base_urls(&homepage.final_url, &row, false);
    probe_sensitive_paths(&mut row, &client, &bases, config, &mut progress, false);
    timings.insert("sensitive_paths", stage.elapsed().as_millis());

    progress("HTTP method and header-variant reconnaissance");
    let stage = Instant::now();
    analyze_http_methods_and_headers(&mut row, &client, &homepage.final_url, config);
    timings.insert("method_and_header_variants", stage.elapsed().as_millis());

    progress("certificate transparency and subdomain reconnaissance");
    let cert_stage = Instant::now();
    analyze_certificate_and_subdomains(&mut row, &client, &domain, config, &mut progress);
    timings.insert(
        "certificate_and_subdomains",
        cert_stage.elapsed().as_millis(),
    );

    progress("FTP surface reconnaissance");
    let ftp_stage = Instant::now();
    analyze_ftp_surface(&mut row, &domain, config);
    timings.insert("ftp_surface", ftp_stage.elapsed().as_millis());

    progress("API reconnaissance");
    let stage = Instant::now();
    analyze_deep_api(
        &mut row,
        &client,
        &homepage.body,
        &homepage.final_url,
        config,
        &mut progress,
    );
    timings.insert("deep_api", stage.elapsed().as_millis());

    row.insert(
        "validation_notes".into(),
        "comprehensive active public reconnaissance; non-destructive; no exploitation".into(),
    );
    fill_missing_contact_email(&mut row, &domain);
    progress("validation mapping, scoring, and evidence");
    finalize(&mut row, started, timings);
    row
}

fn finalize(row: &mut Row, started: Instant, timings: BTreeMap<&str, u128>) {
    let (score, risk, notes, offer) = compute_score(row);
    row.insert("score".into(), score.to_string());
    row.insert("risk_level".into(), risk);
    row.insert("risk_notes".into(), notes);
    row.insert("recommended_offer".into(), offer);
    row.insert(
        "assessment_duration_ms".into(),
        started.elapsed().as_millis().to_string(),
    );
    row.insert(
        "assessment_stage_timings".into(),
        serde_json::to_string(&timings).unwrap_or_default(),
    );
    evidence::annotate(row);
}

fn fetch(client: &Client, url: &str, config: &AssessmentConfig) -> Fetch {
    let started = Instant::now();
    let mut last_error = String::new();
    for attempt in 0..=config.retries {
        match client.get(url).send() {
            Ok(response) => {
                let status = response.status().as_u16();
                let final_url = response.url().to_string();
                let headers = response.headers().clone();
                match response.bytes() {
                    Ok(bytes) => {
                        let bounded = &bytes[..bytes.len().min(MAX_BODY_BYTES)];
                        let mut result = Fetch {
                            ok: true,
                            status,
                            final_url,
                            headers,
                            body: String::from_utf8_lossy(bounded).into_owned(),
                            elapsed_ms: started.elapsed().as_millis(),
                            error: String::new(),
                        };
                        if human_verification_needed(status, &result.body) {
                            if let Some(browser) =
                                browser_fetch(url, config.timeout, MAX_BODY_BYTES)
                            {
                                result = browser;
                            } else {
                                result.ok = false;
                                result.error =
                                    "human verification remained after browser navigation".into();
                            }
                        }
                        if is_transient_status(status) && attempt < config.retries {
                            std::thread::sleep(Duration::from_millis(250 * (attempt as u64 + 1)));
                            continue;
                        }
                        return result;
                    }
                    Err(error) => last_error = error.to_string(),
                }
            }
            Err(error) => last_error = error.to_string(),
        }
        if attempt < config.retries {
            std::thread::sleep(Duration::from_millis(250 * (attempt as u64 + 1)));
        }
    }
    Fetch {
        ok: false,
        status: 0,
        final_url: url.into(),
        headers: HeaderMap::new(),
        body: String::new(),
        elapsed_ms: started.elapsed().as_millis(),
        error: last_error,
    }
}

fn fetch_sensitive_path(
    client: &Client,
    url: &str,
    path: &str,
    config: &AssessmentConfig,
    prefer_openssl: bool,
) -> (Fetch, &'static str) {
    if prefer_openssl && openssl_primary_sensitive_path(path, url) {
        let openssl_timeout = config
            .timeout
            .min(Duration::from_secs(8))
            .max(Duration::from_secs(5));
        let openssl_result = fetch_https_with_openssl(url, openssl_timeout);
        if openssl_result.ok {
            return (openssl_result, "openssl_s_client");
        }
        let reqwest_result = fetch(client, url, config);
        if reqwest_result.ok {
            return (reqwest_result, "openssl_s_client; reqwest");
        }
        if let Some(browser_result) = browser_fetch(url, openssl_timeout, MAX_BODY_BYTES)
            && browser_result.ok
        {
            return (browser_result, "openssl_s_client; reqwest; browser");
        }
        return (openssl_result, "openssl_s_client");
    }
    (fetch(client, url, config), "reqwest")
}

fn openssl_primary_sensitive_path(path: &str, url: &str) -> bool {
    url.to_lowercase().starts_with("https://")
        && (path.contains(".env")
            || path.contains(".git")
            || path.contains(".svn")
            || path.contains("wp-config")
            || path.contains(".htpasswd"))
}

fn fetch_https_with_openssl(url: &str, timeout: Duration) -> Fetch {
    let started = Instant::now();
    let mut current = url.to_string();
    for _ in 0..=2 {
        let result = fetch_https_with_openssl_cli_once(&current, timeout, started);
        let location = header_value(&result.headers, "location");
        if matches!(result.status, 301 | 302 | 303 | 307 | 308)
            && !location.is_empty()
            && let Some(next) = redirect_url(&current, &location)
        {
            current = next;
            continue;
        }
        return result;
    }
    failed_fetch(url, started, "too many redirects")
}

fn fetch_https_with_openssl_cli_once(url: &str, timeout: Duration, started: Instant) -> Fetch {
    let mut last_error = String::new();
    for command in openssl_command_candidates() {
        for variant in OPENSSL_HTTP_VARIANTS {
            match fetch_https_with_openssl_cli_once_result(
                url, timeout, started, &command, *variant,
            ) {
                Ok(result) => return result,
                Err(error) => last_error = error,
            }
        }
    }
    failed_fetch(url, started, last_error)
}

fn openssl_command_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(value) = std::env::var("DOMAIN_REVIEW_OPENSSL") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            candidates.push(trimmed.to_string());
        }
    }
    candidates.push("/usr/bin/openssl".into());
    candidates.push("openssl".into());
    crate::findings::dedupe_preserve_order(candidates)
}

fn fetch_https_with_openssl_cli_once_result(
    url: &str,
    timeout: Duration,
    started: Instant,
    openssl_command: &str,
    variant: OpenSslHttpVariant,
) -> std::result::Result<Fetch, String> {
    let parsed = Url::parse(url).map_err(|error| error.to_string())?;
    if parsed.scheme() != "https" {
        return Err("OpenSSL transport only supports HTTPS URLs".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "HTTPS URL did not include a host".to_string())?;
    let port = parsed.port().unwrap_or(443);
    let mut target = parsed.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }
    let host_header = if parsed.port().is_some() {
        format!("{host}:{port}")
    } else {
        host.to_string()
    };
    let connect = format!("{host}:{port}");
    let mut args = vec!["s_client", "-connect", &connect, "-servername", host];
    if variant.ignore_eof {
        args.push("-ign_eof");
    }
    if variant.quiet {
        args.push("-quiet");
    }
    let mut child = Command::new(openssl_command)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("{error} using {openssl_command}"))?;
    let connection = if variant.connection_close {
        "Connection: close\r\n"
    } else {
        ""
    };
    let request = format!(
        "GET {target} {}\r\nHost: {host_header}\r\nUser-Agent: {USER_AGENT}\r\nAccept: text/plain,application/json,*/*;q=0.8\r\nAccept-Encoding: identity\r\n{connection}\r\n",
        variant.http_version
    );
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "OpenSSL stdin was unavailable".to_string())?
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    drop(child.stdin.take());
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "OpenSSL stdout was unavailable".to_string())?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if sender.send(buffer[..count].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let mut bytes = Vec::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && bytes.len() < MAX_BODY_BYTES + 65_536 {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(chunk) => {
                bytes.extend_from_slice(&chunk);
                if http_response_complete(&bytes) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return parse_openssl_http_response(url, &bytes, started.elapsed().as_millis());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if child
                    .try_wait()
                    .map_err(|error| error.to_string())?
                    .is_some()
                {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }
    interrupt_child(&mut child);
    drain_openssl_output(&receiver, &mut bytes);
    if bytes.is_empty() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "OpenSSL transport returned no HTTP bytes using {} with {}",
            variant.label, openssl_command
        ));
    }
    parse_openssl_http_response(url, &bytes, started.elapsed().as_millis())
        .map_err(|error| format!("{error} using {} with {}", variant.label, openssl_command))
}

fn interrupt_child(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(child.id() as i32, libc::SIGINT);
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let deadline = Instant::now() + Duration::from_millis(750);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn drain_openssl_output(receiver: &mpsc::Receiver<Vec<u8>>, bytes: &mut Vec<u8>) {
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline && bytes.len() < MAX_BODY_BYTES + 65_536 {
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(chunk) => bytes.extend_from_slice(&chunk),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn parse_openssl_http_response(
    url: &str,
    bytes: &[u8],
    elapsed_ms: u128,
) -> std::result::Result<Fetch, String> {
    let start =
        find_subslice(bytes, b"HTTP/").ok_or_else(|| "HTTP response line not found".to_string())?;
    let response = &bytes[start..];
    let (header_end, separator_len) =
        http_header_end(response).ok_or_else(|| "HTTP header terminator not found".to_string())?;
    let head = String::from_utf8_lossy(&response[..header_end]);
    let body_bytes = &response[header_end + separator_len..];
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "HTTP status code not found".to_string())?;
    let mut headers = HeaderMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let Ok(name) = reqwest::header::HeaderName::from_bytes(name.trim().as_bytes()) else {
            continue;
        };
        let Ok(value) = reqwest::header::HeaderValue::from_str(value.trim()) else {
            continue;
        };
        headers.insert(name, value);
    }
    let body = if header_value(&headers, "transfer-encoding")
        .to_lowercase()
        .contains("chunked")
    {
        decode_chunked_body(body_bytes).unwrap_or_else(|| body_bytes.to_vec())
    } else {
        body_bytes.to_vec()
    };
    Ok(Fetch {
        ok: true,
        status,
        final_url: url.into(),
        headers,
        body: String::from_utf8_lossy(&body[..body.len().min(MAX_BODY_BYTES)]).into_owned(),
        elapsed_ms,
        error: String::new(),
    })
}

fn http_response_complete(bytes: &[u8]) -> bool {
    let Some((header_end, separator_len)) = http_header_end(bytes) else {
        return false;
    };
    let head = String::from_utf8_lossy(&bytes[..header_end]);
    let body = &bytes[header_end + separator_len..];
    for line in head.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length")
            && let Ok(length) = value.trim().parse::<usize>()
        {
            return body.len() >= length;
        }
        if name.trim().eq_ignore_ascii_case("transfer-encoding")
            && value.to_lowercase().contains("chunked")
        {
            return body.windows(5).any(|window| window == b"\r\n0\r\n")
                || body.windows(7).any(|window| window == b"\r\n0\r\n\r\n");
        }
    }
    false
}

fn failed_fetch(url: &str, started: Instant, error: impl Into<String>) -> Fetch {
    Fetch {
        ok: false,
        status: 0,
        final_url: url.into(),
        headers: HeaderMap::new(),
        body: String::new(),
        elapsed_ms: started.elapsed().as_millis(),
        error: error.into(),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn redirect_url(current: &str, location: &str) -> Option<String> {
    let next = Url::parse(current).ok()?.join(location).ok()?;
    (next.scheme() == "https").then(|| next.to_string())
}

fn http_header_end(bytes: &[u8]) -> Option<(usize, usize)> {
    find_subslice(bytes, b"\r\n\r\n")
        .map(|index| (index, 4))
        .or_else(|| find_subslice(bytes, b"\n\n").map(|index| (index, 2)))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_chunked_body(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut cursor = 0_usize;
    loop {
        let line_end = find_subslice(&bytes[cursor..], b"\r\n")? + cursor;
        let size_text = std::str::from_utf8(&bytes[cursor..line_end])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        if cursor + size > bytes.len() {
            return None;
        }
        output.extend_from_slice(&bytes[cursor..cursor + size]);
        cursor += size;
        if bytes.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor += 2;
        }
    }
    Some(output)
}

fn human_verification_needed(status: u16, body: &str) -> bool {
    if std::env::var("DOMAIN_REVIEW_BROWSER_FALLBACK")
        .ok()
        .is_some_and(|value| matches!(value.trim().to_lowercase().as_str(), "0" | "false" | "no"))
    {
        return false;
    }
    human_verification_response(status, body)
}

fn human_verification_response(status: u16, body: &str) -> bool {
    matches!(status, 403 | 429 | 503)
        && contains_any_marker(&body.to_lowercase(), HUMAN_VERIFICATION_MARKERS)
}

fn gated_or_denied_response(status: u16, body: &str) -> bool {
    if human_verification_response(status, body) {
        return true;
    }
    if not_found_response(status, body) {
        return true;
    }
    status == 403
        && (body.trim().is_empty()
            || contains_any_marker(&body.to_lowercase(), ACCESS_DENIED_MARKERS))
}

fn not_found_response(status: u16, body: &str) -> bool {
    if status == 404 {
        return true;
    }
    if !(200..300).contains(&status) {
        return false;
    }
    let visible = visible_page_text(body).to_lowercase();
    visible == "404"
        || visible.starts_with("404 ")
        || contains_any_marker(&visible, NOT_FOUND_MARKERS)
}

fn visible_page_text(body: &str) -> String {
    let without_scripts = Regex::new(
        r"(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<noscript[^>]*>.*?</noscript>",
    )
    .unwrap()
    .replace_all(body, " ");
    let without_tags = Regex::new(r"(?is)<[^>]+>")
        .unwrap()
        .replace_all(&without_scripts, " ");
    without_tags
        .split_whitespace()
        .take(160)
        .collect::<Vec<_>>()
        .join(" ")
}

fn contains_any_marker(lower_body: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| lower_body.contains(marker))
}

fn browser_fetch(url: &str, timeout: Duration, max_bytes: usize) -> Option<Fetch> {
    let executable = chromium_executable()?;

    let started = Instant::now();
    let profile = std::env::temp_dir().join(format!(
        "domain_review-chromium-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_nanos()
    ));
    fs::create_dir_all(&profile).ok()?;
    let child = Command::new(executable)
        .args([
            "--headless=new",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--remote-debugging-port=0",
            "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            &format!("--user-data-dir={}", profile.display()),
            "about:blank",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut browser = BrowserProcess { child, profile };
    let deadline = Instant::now() + timeout;
    let stderr = browser.child.stderr.take()?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("DevTools listening on ") {
                let _ = sender.send(line);
                break;
            }
        }
    });
    let remaining = deadline.saturating_duration_since(Instant::now());
    let listening = receiver.recv_timeout(remaining).ok()?;
    let browser_ws = listening.split("DevTools listening on ").nth(1)?.trim();
    let debug_port = Url::parse(browser_ws).ok()?.port()?;
    let endpoint = format!("http://127.0.0.1:{debug_port}/json/new?about%3Ablank");
    let target: serde_json::Value = Client::builder()
        .timeout(deadline.saturating_duration_since(Instant::now()))
        .build()
        .ok()?
        .put(endpoint)
        .send()
        .ok()?
        .json()
        .ok()?;
    let websocket_url = target.get("webSocketDebuggerUrl")?.as_str()?;
    let (mut socket, _) = connect(websocket_url).ok()?;
    if let MaybeTlsStream::Plain(stream) = socket.get_mut() {
        let read_timeout = Some(Duration::from_millis(250));
        stream.set_read_timeout(read_timeout).ok()?;
        stream.set_write_timeout(read_timeout).ok()?;
    }
    send_cdp(&mut socket, 1, "Network.enable", serde_json::json!({}))?;
    send_cdp(&mut socket, 2, "Page.enable", serde_json::json!({}))?;
    send_cdp(
        &mut socket,
        3,
        "Page.navigate",
        serde_json::json!({"url": url}),
    )?;
    let mut document_response: Option<serde_json::Value> = None;
    let mut document_request_id: Option<String> = None;
    let mut loaded = false;
    while Instant::now() < deadline && !loaded {
        if let Some(message) = read_cdp(&mut socket) {
            if message.get("method").and_then(|value| value.as_str())
                == Some("Network.responseReceived")
                && message
                    .pointer("/params/type")
                    .and_then(|value| value.as_str())
                    == Some("Document")
            {
                document_response = message.pointer("/params/response").cloned();
                document_request_id = message
                    .pointer("/params/requestId")
                    .and_then(|value| value.as_str())
                    .map(str::to_string);
            }
            loaded = message.get("method").and_then(|value| value.as_str())
                == Some("Page.loadEventFired");
        }
    }
    let mut body = String::new();
    if let Some(request_id) = document_request_id {
        send_cdp(
            &mut socket,
            4,
            "Network.getResponseBody",
            serde_json::json!({"requestId": request_id}),
        )?;
        while Instant::now() < deadline {
            let Some(message) = read_cdp(&mut socket) else {
                continue;
            };
            if message.get("id").and_then(|value| value.as_u64()) == Some(4) {
                let raw = message
                    .pointer("/result/body")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                body = if message
                    .pointer("/result/base64Encoded")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    base64::engine::general_purpose::STANDARD
                        .decode(raw)
                        .ok()
                        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                        .unwrap_or_default()
                } else {
                    raw.to_string()
                }
                .chars()
                .take(max_bytes)
                .collect();
                break;
            }
        }
    }
    if body.is_empty() {
        send_cdp(
            &mut socket,
            5,
            "Runtime.evaluate",
            serde_json::json!({
                "expression": "document.documentElement.outerHTML",
                "returnByValue": true
            }),
        )?;
    }
    while Instant::now() < deadline {
        if !body.is_empty() {
            break;
        }
        let Some(message) = read_cdp(&mut socket) else {
            continue;
        };
        if message.get("id").and_then(|value| value.as_u64()) == Some(5) {
            body = message
                .pointer("/result/result/value")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .chars()
                .take(max_bytes)
                .collect();
            break;
        }
    }
    let response = document_response.unwrap_or_default();
    let status = response
        .get("status")
        .and_then(|value| value.as_f64())
        .map(|value| value as u16)
        .unwrap_or(200);
    let final_url = response
        .get("url")
        .and_then(|value| value.as_str())
        .unwrap_or(url)
        .to_string();
    let mut headers = HeaderMap::new();
    if let Some(values) = response.get("headers").and_then(|value| value.as_object()) {
        for (name, value) in values {
            let Ok(name) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let text = value
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| value.to_string());
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&text) {
                headers.insert(name, value);
            }
        }
    }
    let _ = socket.close(None);
    if body.is_empty() {
        return None;
    }
    let verification_remained = HUMAN_VERIFICATION_MARKERS
        .iter()
        .any(|marker| body.to_lowercase().contains(marker));
    Some(Fetch {
        ok: !verification_remained,
        status,
        final_url,
        headers,
        body,
        elapsed_ms: started.elapsed().as_millis(),
        error: if verification_remained {
            "human verification remained after browser navigation".into()
        } else {
            String::new()
        },
    })
}

fn chromium_executable() -> Option<String> {
    [
        std::env::var("DOMAIN_REVIEW_CHROMIUM_PATH").ok(),
        Some("chromium".into()),
        Some("chromium-browser".into()),
        Some("google-chrome".into()),
        Some("google-chrome-stable".into()),
        Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
        Some("/Applications/Chromium.app/Contents/MacOS/Chromium".into()),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

struct BrowserProcess {
    child: Child,
    profile: PathBuf,
}

impl Drop for BrowserProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.profile);
    }
}

fn send_cdp(
    socket: &mut tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
    id: u64,
    method: &str,
    params: serde_json::Value,
) -> Option<()> {
    socket
        .send(Message::Text(
            serde_json::json!({"id": id, "method": method, "params": params})
                .to_string()
                .into(),
        ))
        .ok()
}

fn read_cdp(
    socket: &mut tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
) -> Option<serde_json::Value> {
    match socket.read() {
        Ok(Message::Text(text)) => serde_json::from_str(text.as_ref()).ok(),
        Ok(_) => None,
        Err(tungstenite::Error::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            None
        }
        Err(_) => None,
    }
}

fn fetch_with_redirects(
    client: &Client,
    url: &str,
    config: &AssessmentConfig,
    max_redirects: usize,
) -> (Fetch, Vec<BTreeMap<String, String>>) {
    let mut current = url.to_string();
    let mut chain = Vec::new();
    let mut result = fetch(client, &current, config);
    for _ in 0..max_redirects {
        chain.push(BTreeMap::from([
            ("url".into(), current.clone()),
            ("status".into(), status_text(result.status)),
        ]));
        if !matches!(result.status, 301 | 302 | 303 | 307 | 308) {
            break;
        }
        let Some(location) = result
            .headers
            .get("location")
            .and_then(|value| value.to_str().ok())
        else {
            break;
        };
        let Some(next) = Url::parse(&current)
            .ok()
            .and_then(|base| base.join(location).ok())
        else {
            break;
        };
        current = next.to_string();
        result = fetch(client, &current, config);
    }
    (result, chain)
}

fn analyze_headers(row: &mut Row, headers: &HeaderMap) {
    let has = |name: &str| headers.contains_key(name);
    row.insert("hsts".into(), has("strict-transport-security").to_string());
    row.insert("csp".into(), has("content-security-policy").to_string());
    let hsts = header_text(headers, "strict-transport-security");
    row.insert("hsts_header".into(), hsts.clone());
    row.insert(
        "hsts_max_age".into(),
        crate::public_checks::extract_hsts_max_age(&hsts),
    );
    row.insert(
        "hsts_preload".into(),
        hsts.to_lowercase().contains("preload").to_string(),
    );
    row.insert(
        "hsts_subdomains".into(),
        hsts.to_lowercase()
            .contains("includesubdomains")
            .to_string(),
    );
    let csp = header_text(headers, "content-security-policy");
    row.insert(
        "csp_header".into(),
        if csp.is_empty() {
            header_text(headers, "content-security-policy-report-only")
        } else {
            csp.clone()
        },
    );
    row.insert(
        "csp_report_only".into(),
        has("content-security-policy-report-only").to_string(),
    );
    row.insert(
        "csp_unsafe_inline".into(),
        csp.to_lowercase().contains("'unsafe-inline'").to_string(),
    );
    row.insert(
        "csp_unsafe_eval".into(),
        csp.to_lowercase().contains("'unsafe-eval'").to_string(),
    );
    row.insert("x_frame_options".into(), has("x-frame-options").to_string());
    row.insert("referrer_policy".into(), has("referrer-policy").to_string());
    row.insert(
        "permissions_policy".into(),
        has("permissions-policy").to_string(),
    );
    row.insert("server_header".into(), header_text(headers, "server"));
    let powered_by = header_text(headers, "x-powered-by");
    row.insert("x_powered_by_header".into(), powered_by.clone());
    row.insert("x_powered_by".into(), powered_by);
    row.insert(
        "x_content_type_options".into(),
        header_text(headers, "x-content-type-options"),
    );
    row.insert(
        "cross_origin_embedder_policy".into(),
        header_text(headers, "cross-origin-embedder-policy"),
    );
    row.insert(
        "cross_origin_opener_policy".into(),
        header_text(headers, "cross-origin-opener-policy"),
    );
    row.insert(
        "cross_origin_resource_policy".into(),
        header_text(headers, "cross-origin-resource-policy"),
    );
    let cors = header_text(headers, "access-control-allow-origin");
    row.insert("cors_origin_wildcard".into(), (cors == "*").to_string());
    row.insert(
        "cors_creds_allowed".into(),
        header_text(headers, "access-control-allow-credentials")
            .eq_ignore_ascii_case("true")
            .to_string(),
    );
    row.insert(
        "cors_origin_reflected".into(),
        (!cors.is_empty() && cors != "*").to_string(),
    );
    let cookies: Vec<String> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_string))
        .collect();
    let joined = cookies.join("\n").to_lowercase();
    row.insert("set_cookie_count".into(), cookies.len().to_string());
    row.insert(
        "cookies_missing_secure".into(),
        cookies
            .iter()
            .filter(|cookie| !cookie.to_lowercase().contains("secure"))
            .count()
            .to_string(),
    );
    row.insert(
        "cookies_missing_httponly".into(),
        cookies
            .iter()
            .filter(|cookie| !cookie.to_lowercase().contains("httponly"))
            .count()
            .to_string(),
    );
    row.insert(
        "cookies_missing_samesite".into(),
        cookies
            .iter()
            .filter(|cookie| !cookie.to_lowercase().contains("samesite"))
            .count()
            .to_string(),
    );
    row.insert("set_cookie_seen".into(), (!cookies.is_empty()).to_string());
    row.insert(
        "secure_cookie_seen".into(),
        joined.contains("secure").to_string(),
    );
    row.insert(
        "httponly_cookie_seen".into(),
        joined.contains("httponly").to_string(),
    );
    row.insert(
        "samesite_cookie_seen".into(),
        joined.contains("samesite").to_string(),
    );
}

fn analyze_html(row: &mut Row, body: &str, final_url: &str) {
    let lower = body.to_lowercase();
    let same_origin_links = crate::deep_validation::same_origin_links(body, final_url);
    row.insert(
        "same_origin_links_seen".into(),
        same_origin_links.len().to_string(),
    );
    row.insert(
        "same_origin_query_urls_seen".into(),
        same_origin_links
            .iter()
            .filter(|value| {
                Url::parse(value)
                    .ok()
                    .is_some_and(|url| url.query().is_some())
            })
            .count()
            .to_string(),
    );
    row.insert(
        "privacy_policy_seen".into(),
        crate::public_checks::sees_privacy_policy(body).to_string(),
    );
    row.insert(
        "privacy_policy_found".into(),
        crate::public_checks::sees_privacy_policy(body).to_string(),
    );
    row.insert(
        "contact_page_seen".into(),
        crate::public_checks::sees_contact_page(body).to_string(),
    );
    row.insert(
        "contact_page_found".into(),
        crate::public_checks::sees_contact_page(body).to_string(),
    );
    row.insert(
        "title_seen".into(),
        crate::public_checks::sees_title(body).to_string(),
    );
    row.insert(
        "meta_description_seen".into(),
        crate::public_checks::sees_meta_description(body).to_string(),
    );
    row.insert(
        "h1_seen".into(),
        crate::public_checks::sees_h1(body).to_string(),
    );
    row.insert(
        "viewport_meta_seen".into(),
        crate::public_checks::sees_viewport_meta(body).to_string(),
    );
    row.insert(
        "canonical_seen".into(),
        crate::public_checks::sees_canonical(body).to_string(),
    );
    row.insert(
        "linkedin_seen".into(),
        lower.contains("linkedin.com").to_string(),
    );
    row.insert(
        "wordpress_visible".into(),
        (lower.contains("wp-content") || lower.contains("wp-json")).to_string(),
    );
    row.insert(
        "wordpress_version".into(),
        crate::public_checks::extract_wordpress_version(body),
    );
    row.insert(
        "outdated_copyright".into(),
        crate::public_checks::outdated_copyright(body, crate::public_checks::current_year())
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    row.insert(
        "public_email_seen".into(),
        crate::public_checks::sees_public_email(body).to_string(),
    );
    fill_contact_email_from_candidates(row, crate::public_checks::public_role_emails(body));
    row.insert(
        "social_links_seen".into(),
        crate::public_checks::social_links_seen(&lower).join("; "),
    );
    row.insert(
        "generator_meta".into(),
        crate::public_checks::generator_meta(body),
    );
    row.extend(crate::public_checks::analyze_forms(body, final_url));
    let deep_forms = crate::deep_validation::extract_forms(body, final_url);
    let base_host = Url::parse(final_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string));
    row.insert(
        "external_form_action_seen".into(),
        deep_forms
            .iter()
            .any(|form| {
                Url::parse(&form.action)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_string))
                    != base_host
            })
            .to_string(),
    );
    row.insert(
        "password_fields_seen".into(),
        deep_forms
            .iter()
            .filter(|form| form.has_password)
            .count()
            .to_string(),
    );
    row.insert(
        "csrf_tokens_seen".into(),
        deep_forms
            .iter()
            .filter(|form| form.has_csrf)
            .count()
            .to_string(),
    );
    row.insert(
        "password_field_seen".into(),
        Regex::new(r#"(?is)<input\b[^>]*type\s*=\s*["']?password"#)
            .unwrap()
            .is_match(body)
            .to_string(),
    );
    let mixed = Regex::new(r#"(?i)(?:src|href|action)\s*=\s*["']http://"#)
        .unwrap()
        .find_iter(body)
        .count();
    row.insert("mixed_content_refs".into(), mixed.to_string());
    let script_re = Regex::new(r"(?is)<script\b([^>]*)>").unwrap();
    let script_sources: Vec<(String, String)> = script_re
        .captures_iter(body)
        .map(|capture| {
            let attrs = capture.get(1).unwrap().as_str().to_string();
            let source = crate::public_checks::attr_value(&attrs, "src");
            (attrs, source)
        })
        .collect();
    row.insert(
        "external_script_hosts".into(),
        crate::public_checks::external_script_hosts(&script_sources, final_url).join(";"),
    );
    row.insert(
        "inline_script_count".into(),
        script_sources
            .iter()
            .filter(|(_, source)| source.is_empty())
            .count()
            .to_string(),
    );
    let without_sri =
        crate::public_checks::external_scripts_without_sri(&script_sources, final_url).to_string();
    row.insert("external_scripts_without_sri".into(), without_sri.clone());
    row.insert("scripts_without_sri".into(), without_sri);
    row.insert(
        "sql_error_patterns".into(),
        crate::deep_validation::sql_error_text_seen(body).to_string(),
    );
    let comments: Vec<String> = Regex::new(r"(?is)<!--(.*?)-->")
        .unwrap()
        .captures_iter(body)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
        .collect();
    row.insert(
        "html_comments_seen".into(),
        (!comments.is_empty()).to_string(),
    );
    row.insert(
        "html_comment_risk_terms".into(),
        crate::public_checks::risk_terms_seen(&comments.join(" "), false).join("; "),
    );
    row.insert(
        "admin_link_hints_seen".into(),
        crate::public_checks::admin_link_hints_seen(body).to_string(),
    );
    row.insert(
        "api_endpoint_hints_seen".into(),
        crate::public_checks::api_endpoint_hints_seen(body).to_string(),
    );
}

fn fill_contact_email_from_candidates(row: &mut Row, candidates: Vec<String>) {
    if !text_value(row, "contact_email").trim().is_empty() || candidates.is_empty() {
        return;
    }
    row.insert(
        "contact_email".into(),
        unique_preserving_order(candidates).join("; "),
    );
}

fn fill_missing_contact_email(row: &mut Row, domain: &str) {
    if !text_value(row, "contact_email").trim().is_empty() {
        return;
    }
    fill_contact_email_from_candidates(row, crate::public_checks::inferred_role_emails(domain));
}

fn analyze_dns(row: &mut Row, domain: &str) {
    let txt = dig("TXT", domain);
    let spf = txt
        .into_iter()
        .find(|value| value.to_lowercase().contains("v=spf1"))
        .unwrap_or_default();
    let dmarc = dig("TXT", &format!("_dmarc.{domain}"))
        .into_iter()
        .find(|value| value.to_lowercase().contains("v=dmarc1"))
        .unwrap_or_default();
    let mta_sts = dig("TXT", &format!("_mta-sts.{domain}"))
        .into_iter()
        .find(|value| value.to_lowercase().contains("v=stsv1"))
        .unwrap_or_default();
    let tls_rpt = dig("TXT", &format!("_smtp._tls.{domain}"))
        .into_iter()
        .find(|value| value.to_lowercase().contains("v=tlsrptv1"))
        .unwrap_or_default();
    row.insert("spf".into(), (!spf.is_empty()).to_string());
    row.insert("spf_record".into(), spf);
    row.insert(
        "spf_dns_lookups".into(),
        crate::public_checks::count_spf_dns_lookups(&[text_value(row, "spf_record")]).to_string(),
    );
    row.insert("dmarc".into(), (!dmarc.is_empty()).to_string());
    row.insert("dmarc_policy".into(), tag_value(&dmarc, "p"));
    row.insert("dmarc_pct".into(), tag_value(&dmarc, "pct"));
    row.insert(
        "dmarc_alignment_s".into(),
        dmarc.to_lowercase().contains("aspf=r").to_string(),
    );
    row.insert("dmarc_record".into(), dmarc);
    row.insert("mta_sts".into(), (!mta_sts.is_empty()).to_string());
    row.insert("mta_sts_record".into(), mta_sts);
    row.insert("tls_rpt".into(), (!tls_rpt.is_empty()).to_string());
    row.insert("tls_rpt_record".into(), tls_rpt);
    let mx = dig("MX", domain);
    let mx_text = mx.join("; ");
    row.insert("mx_hosts".into(), mx_text.clone());
    row.insert("mx_records".into(), mx_text);
    row.insert("mx_count".into(), mx.len().to_string());
    row.insert("mx_provider".into(), mx_provider(&mx));
    row.insert("caa_records".into(), dig("CAA", domain).join("; "));
    row.insert(
        "caa".into(),
        (!text_value(row, "caa_records").is_empty()).to_string(),
    );
    row.insert(
        "caa_critical".into(),
        (text_value(row, "caa_records").contains("128")
            || text_value(row, "caa_records")
                .to_lowercase()
                .contains("critical"))
        .to_string(),
    );
    let dnssec = (!dig("DNSKEY", domain).is_empty()).to_string();
    row.insert("dnssec".into(), dnssec.clone());
    row.insert("dnssec_enabled".into(), dnssec);
    let selectors = [
        "google",
        "selector1",
        "selector2",
        "default",
        "mail",
        "s1",
        "s2",
        "sendgrid",
        "zoho",
    ];
    let found: Vec<_> = selectors
        .into_iter()
        .filter(|selector| !dig("TXT", &format!("{selector}._domainkey.{domain}")).is_empty())
        .collect();
    row.insert("dkim_selectors_found".into(), found.join("; "));
}

fn mx_provider(records: &[String]) -> String {
    let hosts: Vec<String> = records
        .iter()
        .filter_map(|record| record.trim_end_matches('.').split_whitespace().last())
        .map(|host| host.to_lowercase().trim_end_matches('.').to_string())
        .filter(|host| !host.is_empty())
        .collect();
    let joined = hosts.join(" ");
    for (token, provider) in [
        ("google", "Google Workspace"),
        ("aspmx.l.google.com", "Google Workspace"),
        ("protection.outlook.com", "Microsoft 365"),
        ("mail.protection.outlook.com", "Microsoft 365"),
        ("zoho", "Zoho Mail"),
        ("secureserver.net", "GoDaddy"),
        ("privateemail.com", "Namecheap Private Email"),
        ("registrar-servers.com", "Namecheap Private Email"),
        ("titan.email", "Titan Email"),
        ("yahoodns.net", "Yahoo Mail"),
        ("protonmail", "Proton Mail"),
        ("mimecast", "Mimecast"),
        ("proofpoint", "Proofpoint"),
    ] {
        if joined.contains(token) {
            return provider.into();
        }
    }
    hosts.first().cloned().unwrap_or_default()
}

fn analyze_javascript(
    row: &mut Row,
    client: &Client,
    body: &str,
    final_url: &str,
    config: &AssessmentConfig,
    progress: &mut dyn FnMut(&str),
) {
    let urls: Vec<_> = crate::deep_validation::same_origin_script_urls(body, final_url)
        .into_iter()
        .take(MAX_JS_FILES)
        .collect();
    let mut checked = 0;
    let mut source_maps = Vec::new();
    let mut secrets = Vec::new();
    let mut debug = Vec::new();
    let mut endpoints = Vec::new();
    let mut sinks = Vec::new();
    let mut bodies = Vec::new();
    for (index, url) in urls.iter().enumerate() {
        progress(&format!(
            "JavaScript reconnaissance {}/{}",
            index + 1,
            urls.len()
        ));
        let result = fetch(client, url, config);
        if !result.ok || result.body.is_empty() {
            continue;
        }
        checked += 1;
        source_maps.extend(crate::deep_validation::source_map_references(&result.body));
        secrets.extend(crate::public_checks::secret_like_assignment_details(
            &result.body,
        ));
        debug.extend(crate::deep_validation::debug_terms_in_js(&result.body));
        endpoints.extend(crate::deep_validation::extract_api_endpoints(&result.body));
        sinks.extend(crate::public_checks::html_injection_sink_terms(
            &result.body,
        ));
        bodies.push(result.body);
    }
    let source_maps = unique(source_maps);
    let secrets = unique(secrets);
    let debug = unique(debug);
    let endpoints = unique(endpoints);
    let sinks = unique(sinks);
    row.insert("js_files_checked".into(), checked.to_string());
    row.insert("source_map_references".into(), source_maps.join("; "));
    row.insert(
        "js_source_map_seen".into(),
        (!source_maps.is_empty()).to_string(),
    );
    row.insert("js_secrets_found".into(), secrets.join("; "));
    row.insert(
        "js_secret_like_details".into(),
        text_value(row, "js_secrets_found"),
    );
    row.insert(
        "js_secret_like_details_seen".into(),
        (!text_value(row, "js_secret_like_details").is_empty()).to_string(),
    );
    row.insert(
        "js_secret_like_terms".into(),
        crate::validation_mapping::secret_terms(&text_value(row, "js_secret_like_details")),
    );
    row.insert(
        "js_secret_like_terms_seen".into(),
        (!text_value(row, "js_secret_like_details").is_empty()).to_string(),
    );
    row.insert("js_debug_terms".into(), debug.join("; "));
    row.insert(
        "js_debug_terms_seen".into(),
        (!text_value(row, "js_debug_terms").is_empty()).to_string(),
    );
    row.insert("js_api_endpoints".into(), endpoints.join("; "));
    row.insert(
        "api_endpoints_discovered".into(),
        text_value(row, "js_api_endpoints"),
    );
    row.insert("js_html_injection_sinks".into(), sinks.join("; "));
    row.insert(
        "js_html_injection_sinks_seen".into(),
        (!text_value(row, "js_html_injection_sinks").is_empty()).to_string(),
    );
    let cloud = crate::deep_validation::extract_cloud_assets(&bodies.join("\n"));
    for (field, key) in [
        ("s3_buckets_found", "s3_buckets"),
        ("gcs_buckets_found", "gcs_buckets"),
        ("azure_blobs_found", "azure_blobs"),
        ("firebase_endpoints", "firebase"),
        ("cloudfront_endpoints", "cloudfront"),
        ("websocket_endpoints", "websockets"),
        ("internal_refs_found", "internal_urls"),
        ("js_api_keys_found", "api_keys"),
        ("js_tokens_found", "tokens"),
    ] {
        row.insert(
            field.into(),
            cloud.get(key).cloned().unwrap_or_default().join("; "),
        );
    }
}

fn analyze_representative_pages(
    row: &mut Row,
    client: &Client,
    body: &str,
    final_url: &str,
    config: &AssessmentConfig,
    progress: &mut dyn FnMut(&str),
) {
    let mut candidates = same_origin_links(body, final_url);
    let sitemap = fetch(client, &join_url(final_url, "/sitemap.xml"), config);
    if sitemap.ok {
        candidates.extend(sitemap_urls(&sitemap.body, final_url));
        candidates = unique(candidates);
    }
    candidates.sort_by_key(|url| representative_priority(url));
    candidates.truncate(MAX_REPRESENTATIVE_PAGES);
    let mut checked = Vec::new();
    let mut header_signatures = Vec::new();
    let mut errors = Vec::new();
    let mut public_role_emails = Vec::new();
    let total = candidates.len();
    for (index, url) in candidates.into_iter().enumerate() {
        progress(&format!(
            "representative-page reconnaissance {}/{}",
            index + 1,
            total
        ));
        let result = fetch(client, &url, config);
        if result.ok {
            checked.push(result.final_url.clone());
            header_signatures.push(security_header_signature(&result.headers));
            public_role_emails.extend(crate::public_checks::public_role_emails(&result.body));
        } else {
            errors.push(format!("{url}: {}", result.error));
        }
    }
    let consistency = if header_signatures.is_empty() {
        "unknown"
    } else if header_signatures
        .iter()
        .all(|value| value == &header_signatures[0])
    {
        "consistent"
    } else {
        "varies"
    };
    row.insert(
        "representative_pages_checked".into(),
        checked.len().to_string(),
    );
    row.insert("representative_page_urls".into(), checked.join("; "));
    row.insert("representative_page_errors".into(), errors.join("; "));
    row.insert("header_consistency".into(), consistency.into());
    fill_contact_email_from_candidates(row, public_role_emails);
}

fn probe_sensitive_paths(
    row: &mut Row,
    client: &Client,
    base_urls: &[String],
    config: &AssessmentConfig,
    progress: &mut dyn FnMut(&str),
    high_signal_only: bool,
) {
    let mut git = false;
    let mut svn = false;
    let mut env = Vec::new();
    let mut backups = Vec::new();
    let mut admins = Vec::new();
    let mut apis = Vec::new();
    let mut checked = 0_usize;
    let mut transports = Vec::new();
    let mut probe_errors = Vec::new();
    let paths: Vec<&str> = if high_signal_only {
        high_signal_sensitive_paths()
    } else {
        SENSITIVE_PATHS.to_vec()
    };
    let total = base_urls.len().saturating_mul(paths.len()).max(1);
    'probe: for base_url in base_urls {
        for (index, path) in paths.iter().enumerate() {
            checked += 1;
            if checked == 1 || index % 5 == 0 {
                progress(&format!("sensitive-path reconnaissance {checked}/{total}"));
            }
            let Ok(url) = Url::parse(base_url).and_then(|base| base.join(path)) else {
                continue;
            };
            let (result, transport) =
                fetch_sensitive_path(client, url.as_str(), path, config, high_signal_only);
            transports.push(transport);
            if !result.ok && records_sensitive_probe_error(path) {
                probe_errors.push(format!(
                    "{} via {}: {}",
                    url,
                    transport,
                    nonempty_error(&result.error, "request failed")
                ));
            }
            let confirmed = confirmed_exposure(path, url.as_str(), &result);
            let admin_surface = reportable_admin_surface(path, url.as_str(), &result);
            let api_surface = reportable_api_surface(path, url.as_str(), &result);
            match *path {
                value if value.contains(".git") && confirmed => git = true,
                value if value.contains(".svn") && confirmed => svn = true,
                value if value.contains(".env") && confirmed => env.push(url.to_string()),
                value
                    if confirmed
                        && (value.ends_with(".sql")
                            || value.ends_with(".bak")
                            || value.contains(".old")
                            || value.contains("wp-config")) =>
                {
                    backups.push(url.to_string())
                }
                value if admin_surface && (value.contains("admin") || value.contains("login")) => {
                    admins.push(url.to_string())
                }
                value
                    if api_surface
                        && (value.contains("api")
                            || value.contains("graphql")
                            || value.contains("openapi")
                            || value.contains("swagger")) =>
                {
                    apis.push(url.to_string())
                }
                _ => {}
            }
            if high_signal_only && confirmed && records_sensitive_probe_error(path) {
                break 'probe;
            }
        }
    }
    row.insert("git_exposed".into(), git.to_string());
    row.insert("svn_exposed".into(), svn.to_string());
    row.insert("source_control_exposed".into(), (git || svn).to_string());
    let env = unique(env);
    let backups = unique(backups.into_iter().chain(env.clone()).collect());
    let admins = unique(admins);
    let apis = unique(apis);
    let env_text = env.join("; ");
    let backup_text = backups.join("; ");
    let admin_text = admins.join("; ");
    row.insert("sensitive_path_probe_bases".into(), base_urls.join("; "));
    row.insert(
        "sensitive_path_probe_transports".into(),
        unique(transports.into_iter().map(str::to_string).collect()).join("; "),
    );
    row.insert("sensitive_paths_checked".into(), checked.to_string());
    row.insert(
        "sensitive_path_probe_errors".into(),
        unique(probe_errors).join("; "),
    );
    row.insert("env_files_found".into(), env_text);
    row.insert("env_exposed".into(), (!env.is_empty()).to_string());
    row.insert("backup_files_found".into(), backup_text);
    row.insert("admin_panels_found".into(), admin_text.clone());
    row.insert("admin_paths_found".into(), admin_text);
    row.insert(
        "wp_login_found".into(),
        admins
            .iter()
            .any(|url| url.contains("wp-login"))
            .to_string(),
    );
    let mut security_txt = false;
    let mut security_contact = String::new();
    if !high_signal_only {
        for base_url in base_urls {
            for path in SENSITIVE_PATHS
                .iter()
                .filter(|path| path.contains("security.txt"))
            {
                let url = join_url(base_url, path);
                let result = fetch(client, &url, config);
                if result.ok
                    && result.status == 200
                    && result.body.to_lowercase().contains("contact:")
                {
                    security_txt = true;
                    security_contact = result
                        .body
                        .lines()
                        .find(|line| line.trim().to_lowercase().starts_with("contact:"))
                        .map(|line| line.trim().to_string())
                        .unwrap_or_default();
                    break;
                }
            }
            if security_txt {
                break;
            }
        }
    }
    row.insert("security_txt".into(), security_txt.to_string());
    row.insert("security_txt_found".into(), security_txt.to_string());
    fill_contact_email_from_candidates(
        row,
        crate::public_checks::public_role_emails(&security_contact),
    );
    row.insert("security_txt_contact".into(), security_contact);
    if !high_signal_only {
        let primary_base = base_urls
            .first()
            .cloned()
            .unwrap_or_else(|| text_value(row, "normalized_url"));
        let robots = fetch(client, &join_url(&primary_base, "/robots.txt"), config);
        let sitemap = fetch(client, &join_url(&primary_base, "/sitemap.xml"), config);
        row.insert(
            "robots_txt".into(),
            (robots.ok && robots.status == 200).to_string(),
        );
        row.insert(
            "robots_txt_found".into(),
            (robots.ok && robots.status == 200).to_string(),
        );
        row.insert(
            "sitemap_xml".into(),
            (sitemap.ok && sitemap.status == 200).to_string(),
        );
    }
    let existing = text_value(row, "api_endpoints_discovered");
    row.insert(
        "api_endpoints_discovered".into(),
        unique(
            existing
                .split(';')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .chain(apis)
                .collect(),
        )
        .join("; "),
    );
}

fn analyze_http_methods_and_headers(
    row: &mut Row,
    client: &Client,
    final_url: &str,
    config: &AssessmentConfig,
) {
    for (method, field) in [
        (Method::OPTIONS, "options_method_allowed"),
        (Method::TRACE, "trace_method_allowed"),
        (Method::PUT, "put_method_allowed"),
        (Method::DELETE, "delete_method_allowed"),
    ] {
        let allowed = client
            .request(method, final_url)
            .timeout(config.timeout.min(Duration::from_secs(5)))
            .send()
            .map(|response| !matches!(response.status().as_u16(), 400 | 403 | 404 | 405 | 501))
            .unwrap_or(false);
        row.insert(field.into(), allowed.to_string());
    }
    let marker = "domain_review-header-probe.invalid";
    let response = client
        .get(final_url)
        .header("X-Forwarded-Host", marker)
        .timeout(config.timeout.min(Duration::from_secs(5)))
        .send()
        .and_then(|response| response.text());
    row.insert(
        "x_forwarded_host_reflected".into(),
        response
            .map(|body| body.contains(marker))
            .unwrap_or(false)
            .to_string(),
    );
    let host_response = client
        .get(final_url)
        .header("Host", marker)
        .timeout(config.timeout.min(Duration::from_secs(5)))
        .send()
        .and_then(|response| response.text());
    row.insert(
        "host_header_injection".into(),
        host_response
            .map(|body| body.contains(marker))
            .unwrap_or(false)
            .to_string(),
    );
}

fn analyze_deep_api(
    row: &mut Row,
    client: &Client,
    homepage_body: &str,
    final_url: &str,
    config: &AssessmentConfig,
    progress: &mut dyn FnMut(&str),
) {
    let mut discovered = Vec::new();
    let mut documentation_urls = Vec::new();
    let mut documentation = false;
    let mut open_cors = Vec::new();
    let mut unauthenticated = Vec::new();
    let mut leaks = Vec::new();
    let mut auth_required = Vec::new();
    let homepage_fingerprint = content_fingerprint(homepage_body);
    let bases = api_base_urls(final_url, row);
    let total = bases.len().saturating_mul(API_DISCOVERY_PATHS.len()).max(1);
    let mut checked = 0;
    for base in bases {
        let empty_shell = fetch(
            client,
            &join_url(&base, "/domain_review-empty-shell-probe-20260626"),
            &AssessmentConfig {
                timeout: config.timeout.min(Duration::from_secs(4)),
                retries: config.retries,
            },
        );
        let empty_shell_fingerprint = if empty_shell.ok {
            Some(content_fingerprint(&empty_shell.body))
        } else {
            None
        };
        for path in API_DISCOVERY_PATHS {
            checked += 1;
            if checked % 8 == 1 {
                progress(&format!("API reconnaissance {checked}/{total}"));
            }
            let url = join_url(&base, path);
            let result = fetch(
                client,
                &url,
                &AssessmentConfig {
                    timeout: config.timeout.min(Duration::from_secs(4)),
                    retries: config.retries,
                },
            );
            if !result.ok
                || !matches!(result.status, 200 | 201 | 401 | 405)
                || gated_or_denied_response(result.status, &result.body)
            {
                continue;
            }
            let headers: BTreeMap<String, String> = result
                .headers
                .iter()
                .filter_map(|(key, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (key.as_str().into(), value.into()))
                })
                .collect();
            let content_type =
                crate::deep_validation::get_header(&headers, "Content-Type").to_lowercase();
            let body: String = result.body.chars().take(4000).collect();
            let kind = crate::deep_validation::classify_api_response(&content_type, &body);
            let meaningful = meaningful_api_response(
                &url,
                result.status,
                &content_type,
                &body,
                &homepage_fingerprint,
                empty_shell_fingerprint.as_deref(),
                &kind,
            );
            if !meaningful && !matches!(result.status, 401 | 405) {
                continue;
            }
            if kind == "documentation" {
                documentation = true;
                documentation_urls.push(url.clone());
            }
            if crate::deep_validation::check_cors_open(&headers) && meaningful {
                open_cors.push(url.clone());
            }
            if result.status == 401 {
                auth_required.push(url.clone());
            } else if meaningful
                && result.status != 405
                && !is_default_wordpress_rest_read_url(&url)
            {
                unauthenticated.push(url.clone());
            }
            if meaningful && crate::deep_validation::indicates_data_leak(&body, &content_type) {
                leaks.push(url.clone());
            }
            discovered.push(url);
        }
    }
    let (wordpress_write_probe_results, wordpress_unsafe_write_apis) =
        probe_wordpress_write_access(client, final_url, &discovered, config);
    row.insert(
        "api_endpoints_discovered".into(),
        discovered.len().to_string(),
    );
    row.insert(
        "api_endpoint_urls".into(),
        crate::findings::dedupe_preserve_order(discovered).join("; "),
    );
    row.insert("api_documentation_found".into(), documentation.to_string());
    row.insert(
        "api_documentation_urls".into(),
        crate::findings::dedupe_preserve_order(documentation_urls).join("; "),
    );
    row.insert("open_cors_apis".into(), open_cors.join("; "));
    row.insert("unauthenticated_apis".into(), unauthenticated.join("; "));
    row.insert("apis_leaking_data".into(), leaks.join("; "));
    row.insert(
        "wordpress_write_probe_results".into(),
        wordpress_write_probe_results.join("; "),
    );
    row.insert(
        "wordpress_unsafe_write_apis".into(),
        wordpress_unsafe_write_apis.join("; "),
    );

    let graphql = join_url(final_url, "/graphql");
    let payload = serde_json::json!({"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields { name description type { name kind } } } } }"});
    let graphql_result = client
        .post(&graphql)
        .timeout(config.timeout.min(Duration::from_secs(4)))
        .json(&payload)
        .send()
        .and_then(|response| response.text());
    if let Ok(body) = graphql_result {
        row.insert(
            "graphql_introspection".into(),
            body.contains("__schema").to_string(),
        );
        row.insert(
            "graphql_types_count".into(),
            crate::deep_validation::extract_type_count(&body).to_string(),
        );
    } else {
        row.insert("graphql_introspection".into(), "false".into());
        row.insert("graphql_types_count".into(), "0".into());
    }

    let mut bypass_findings = Vec::new();
    for endpoint in auth_required.iter().take(3) {
        let baseline = request_sample(client, endpoint, Method::GET, None, config);
        let _ = request_sample(client, endpoint, Method::HEAD, None, config);
        let _ = request_sample(client, endpoint, Method::OPTIONS, None, config);
        for (name, value) in [
            ("X-HTTP-Method-Override", "GET"),
            ("X-Original-Method", "GET"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Host", "127.0.0.1"),
            ("X-Forwarded-Host", "127.0.0.1"),
        ] {
            let variant =
                request_sample(client, endpoint, Method::GET, Some((name, value)), config);
            if (200..300).contains(&variant.status)
                && !variant.body.is_empty()
                && variant.sha256 != baseline.sha256
                && crate::deep_validation::response_contains_protected_data(
                    &variant.body,
                    &variant.content_type,
                )
            {
                bypass_findings.push(format!("{endpoint} (header:{name})"));
            }
        }
    }
    row.insert(
        "auth_bypass_endpoints_tested".into(),
        auth_required.len().min(3).to_string(),
    );
    row.insert("auth_bypass_findings".into(), bypass_findings.join("; "));

    let query_link = crate::deep_validation::same_origin_links(homepage_body, final_url)
        .into_iter()
        .find(|url| {
            Url::parse(url)
                .ok()
                .is_some_and(|url| url.query().is_some())
        });
    if let Some(query_link) = query_link {
        let reflection_url = crate::deep_validation::reflection_probe_url(&query_link);
        let reflected = fetch(client, &reflection_url, config);
        row.insert("benign_reflection_url".into(), reflection_url);
        row.insert(
            "benign_reflection_seen".into(),
            reflected
                .body
                .contains("domain_review_probe_20260614")
                .to_string(),
        );
        row.insert(
            "dom_xss_sinks_found".into(),
            crate::deep_validation::dom_xss_sinks_seen(&reflected.body).to_string(),
        );
    }
}

fn api_base_urls(final_url: &str, row: &Row) -> Vec<String> {
    let mut bases = Vec::new();
    if let Some(origin) = origin_from_url(final_url) {
        bases.push(origin);
    }
    let domain = text_value(row, "domain");
    if !domain.is_empty() {
        bases.push(format!("https://api.{domain}/"));
    }
    for field in ["ct_subdomain_sample", "subdomain_sample"] {
        for host in text_value(row, field).split(';').map(str::trim) {
            let host = host.trim_start_matches("*.").trim();
            if host.is_empty() {
                continue;
            }
            let lower = host.to_lowercase();
            if lower.starts_with("api.") || lower.contains(".api.") {
                bases.push(format!("https://{host}/"));
            }
        }
    }
    crate::findings::dedupe_preserve_order(bases)
        .into_iter()
        .take(4)
        .collect()
}

fn probe_wordpress_write_access(
    client: &Client,
    final_url: &str,
    discovered: &[String],
    config: &AssessmentConfig,
) -> (Vec<String>, Vec<String>) {
    let mut bases = Vec::new();
    if discovered
        .iter()
        .any(|url| is_default_wordpress_rest_read_url(url))
    {
        if let Some(origin) = origin_from_url(final_url) {
            bases.push(origin);
        }
        for url in discovered {
            if is_default_wordpress_rest_read_url(url)
                && let Some(origin) = origin_from_url(url)
            {
                bases.push(origin);
            }
        }
    }
    let mut results = Vec::new();
    let mut unsafe_write = Vec::new();
    for base in crate::findings::dedupe_preserve_order(bases)
        .into_iter()
        .take(3)
    {
        let url = join_url(&base, "/wp-json/wp/v2/posts");
        let sample = request_sample(client, &url, Method::POST, None, config);
        let status = if sample.status == 0 {
            "request_failed".into()
        } else {
            sample.status.to_string()
        };
        results.push(format!("POST {url} -> {status}"));
        if matches!(sample.status, 200 | 201) {
            unsafe_write.push(format!("POST {url} ({})", sample.status));
        }
    }
    (results, unsafe_write)
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

fn sensitive_path_base_urls(
    primary_url: &str,
    row: &Row,
    include_domain_variants: bool,
) -> Vec<String> {
    let mut bases = Vec::new();
    if let Some(origin) = origin_from_url(primary_url) {
        bases.push(origin);
    }
    let normalized = text_value(row, "normalized_url");
    if let Some(origin) = origin_from_url(&normalized) {
        bases.push(origin);
    }
    let domain = text_value(row, "domain");
    if include_domain_variants && !domain.is_empty() {
        bases.push(format!("https://{domain}/"));
        if !domain.starts_with("www.") {
            bases.push(format!("https://www.{domain}/"));
        }
    }
    crate::findings::dedupe_preserve_order(bases)
}

fn origin_from_url(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    Some(format!("{}://{}/", parsed.scheme(), parsed.host_str()?))
}

fn records_sensitive_probe_error(path: &str) -> bool {
    path.contains(".env")
        || path.contains(".git")
        || path.contains(".svn")
        || path.contains("wp-config")
}

fn high_signal_sensitive_paths() -> Vec<&'static str> {
    [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/.git/HEAD",
        "/.git/config",
        "/.svn/entries",
        "/.htpasswd",
    ]
    .into()
}

fn nonempty_error(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.into()
    } else {
        trimmed.into()
    }
}

fn meaningful_api_response(
    url: &str,
    status: u16,
    content_type: &str,
    body: &str,
    homepage_fingerprint: &str,
    empty_shell_fingerprint: Option<&str>,
    kind: &str,
) -> bool {
    if matches!(status, 401 | 405) {
        return true;
    }
    let trimmed = body.trim();
    if trimmed.len() < 20 {
        return false;
    }
    if content_fingerprint(trimmed) == homepage_fingerprint {
        return false;
    }
    if empty_shell_fingerprint
        .is_some_and(|fingerprint| content_fingerprint(trimmed) == fingerprint)
    {
        return false;
    }
    if looks_like_empty_shell(trimmed) {
        return false;
    }
    let lower_url = url.to_lowercase();
    let lower_body = trimmed.to_lowercase();
    let looks_html = content_type.contains("html")
        || lower_body.starts_with("<!doctype")
        || lower_body.starts_with("<html")
        || lower_body.contains("<html");
    if looks_html {
        let doc_path = [
            "/swagger",
            "/openapi",
            "/api-docs",
            "/docs",
            "/graphql",
            "/graphiql",
        ]
        .iter()
        .any(|marker| lower_url.contains(marker));
        let doc_body = ["swagger-ui", "swagger", "openapi", "redoc", "graphql"]
            .iter()
            .any(|marker| lower_body.contains(marker));
        if !(doc_path && doc_body) {
            return false;
        }
    }
    if !api_probe_path_is_api_like(url)
        && !crate::deep_validation::indicates_data_leak(trimmed, content_type)
    {
        return false;
    }
    if kind != "unknown" {
        return true;
    }
    let looks_like_api_path = [
        "/api", "/graphql", "/swagger", "/openapi", "/wp-json", "/jsonapi", "/rest",
    ]
    .iter()
    .any(|marker| lower_url.contains(marker));
    let looks_like_structured = content_type.contains("json")
        || content_type.contains("xml")
        || trimmed.starts_with('{')
        || trimmed.starts_with('[');
    let not_html_fallback = !lower_body.contains("<html") && !lower_body.contains("<!doctype");
    looks_like_api_path && looks_like_structured && not_html_fallback
}

fn api_probe_path_is_api_like(value: &str) -> bool {
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

fn looks_like_empty_shell(body: &str) -> bool {
    let normalized = body
        .split_whitespace()
        .take(80)
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    [
        "page not found",
        "404 not found",
        "not found",
        "route not found",
        "cannot get /",
        "no route matches",
        "this page could not be found",
        "nothing here",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn content_fingerprint(value: &str) -> String {
    let normalized: String = value
        .split_whitespace()
        .take(200)
        .collect::<Vec<_>>()
        .join(" ");
    format!("{:x}", Sha256::digest(normalized.as_bytes()))
}

#[derive(Default)]
struct RequestSample {
    status: u16,
    body: String,
    sha256: String,
    content_type: String,
}

fn request_sample(
    client: &Client,
    url: &str,
    method: Method,
    header: Option<(&str, &str)>,
    config: &AssessmentConfig,
) -> RequestSample {
    let mut request = client
        .request(method, url)
        .timeout(config.timeout.min(Duration::from_secs(3)));
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }
    let Ok(response) = request.send() else {
        return RequestSample::default();
    };
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let bytes = response.bytes().unwrap_or_default();
    let bounded = &bytes[..bytes.len().min(20_000)];
    RequestSample {
        status,
        body: String::from_utf8_lossy(bounded)
            .chars()
            .take(2000)
            .collect(),
        sha256: format!("{:x}", Sha256::digest(bounded)),
        content_type,
    }
}

fn analyze_certificate_and_subdomains(
    row: &mut Row,
    client: &Client,
    domain: &str,
    config: &AssessmentConfig,
    progress: &mut dyn FnMut(&str),
) {
    let openssl = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("{domain}:443"),
            "-servername",
            domain,
            "-showcerts",
        ])
        .output();
    if let Ok(output) = openssl {
        let certificate = String::from_utf8_lossy(&output.stdout);
        let handshake = format!(
            "{}\n{}",
            certificate,
            String::from_utf8_lossy(&output.stderr)
        );
        let tls_version = first_capture(
            &handshake,
            &[
                r"(?im)^\s*Protocol\s*:\s*(\S+)",
                r"(?im)^\s*Protocol version:\s*(\S+)",
                r"(?im)^New,\s*(TLSv[0-9.]+),",
            ],
        );
        let tls_cipher = first_capture(
            &handshake,
            &[
                r"(?im)^\s*Cipher\s*:\s*(\S+)",
                r"(?im)^\s*Ciphersuite:\s*(\S+)",
                r"(?im)^New,\s*TLSv[0-9.]+,\s*Cipher is\s*(\S+)",
            ],
        );
        row.insert("tls_version".into(), tls_version.clone());
        row.insert("tls_cipher".into(), tls_cipher.clone());
        row.insert(
            "tls_weak_ciphers".into(),
            (matches!(tls_version.as_str(), "TLSv1" | "TLSv1.0" | "TLSv1.1")
                || ["RC4", "3DES", "DES", "NULL", "EXPORT"]
                    .iter()
                    .any(|marker| tls_cipher.to_uppercase().contains(marker)))
            .to_string(),
        );
        row.insert(
            "tls_forward_secrecy".into(),
            (tls_version == "TLSv1.3"
                || tls_cipher.to_uppercase().contains("ECDHE")
                || tls_cipher.to_uppercase().contains("DHE"))
            .to_string(),
        );
        if let Ok(mut child) = Command::new("openssl")
            .args([
                "x509",
                "-noout",
                "-dates",
                "-issuer",
                "-ext",
                "subjectAltName",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(certificate.as_bytes());
            }
            if let Ok(details_output) = child.wait_with_output() {
                let details_ok = details_output.status.success();
                let details = String::from_utf8_lossy(&details_output.stdout);
                row.insert(
                    "tls_certificate_details".into(),
                    details.chars().take(2000).collect(),
                );
                let issuer = details
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("issuer="))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let sans = details
                    .lines()
                    .filter(|line| line.contains("DNS:"))
                    .flat_map(|line| line.split(','))
                    .filter_map(|part| part.trim().strip_prefix("DNS:"))
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                let days_remaining = details
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("notAfter="))
                    .and_then(|value| {
                        NaiveDateTime::parse_from_str(value.trim(), "%b %e %H:%M:%S %Y GMT").ok()
                    })
                    .map(|expires| {
                        expires
                            .signed_duration_since(Utc::now().naive_utc())
                            .num_days()
                    });
                let valid = details_ok && days_remaining.is_some_and(|remaining| remaining >= 0);
                row.insert("cert_valid".into(), valid.to_string());
                row.insert("tls_valid".into(), valid.to_string());
                row.insert(
                    "cert_days_remaining".into(),
                    days_remaining
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                );
                row.insert(
                    "tls_days_remaining".into(),
                    text_value(row, "cert_days_remaining"),
                );
                row.insert("cert_issuer".into(), issuer);
                row.insert("cert_sans".into(), sans.join("; "));
            }
        }
    }
    let crt_url = format!("https://crt.sh/?q=%.{domain}&output=json");
    if let Ok(response) = client
        .get(crt_url)
        .timeout(config.timeout.min(Duration::from_secs(10)))
        .send()
        .and_then(|response| response.json::<serde_json::Value>())
    {
        let mut names = BTreeSet::new();
        for entry in response.as_array().into_iter().flatten() {
            for candidate in entry["name_value"].as_str().unwrap_or("").lines() {
                let candidate = candidate
                    .trim()
                    .to_lowercase()
                    .trim_start_matches("*.")
                    .to_string();
                if !candidate.is_empty() && !candidate.contains('*') {
                    names.insert(candidate);
                }
            }
        }
        row.insert("ct_subdomains_found".into(), names.len().to_string());
        row.insert(
            "ct_subdomain_sample".into(),
            names
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    let common = [
        "www", "mail", "ftp", "admin", "portal", "api", "app", "dev", "staging", "test", "blog",
        "shop",
    ];
    let found: Vec<String> = common
        .iter()
        .enumerate()
        .filter_map(|prefix| {
            let (index, prefix) = prefix;
            progress(&format!(
                "common-subdomain reconnaissance {}/{}",
                index + 1,
                common.len()
            ));
            let name = format!("{prefix}.{domain}");
            (!dig("A", &name).is_empty()).then_some(name)
        })
        .collect();
    row.insert("subdomains_found".into(), found.len().to_string());
    row.insert(
        "subdomain_sample".into(),
        found
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("; "),
    );
    row.insert(
        "wildcard_dns".into(),
        (!dig("A", &format!("thisdoesnotexist12345.{domain}")).is_empty()).to_string(),
    );
}

fn confirmed_exposure(path: &str, requested_url: &str, result: &Fetch) -> bool {
    if !result.ok
        || result.status != 200
        || normalize_path(&result.final_url) != normalize_path(requested_url)
    {
        return false;
    }
    let body = result.body.trim();
    let lower = body.to_lowercase();
    let content_type = header_text(&result.headers, "content-type").to_lowercase();
    if body.is_empty()
        || content_type.contains("text/html")
        || contains_any_marker(&lower, HUMAN_VERIFICATION_MARKERS)
    {
        return false;
    }
    if path.ends_with("/HEAD") {
        return lower.starts_with("ref: refs/")
            || Regex::new(r"^[0-9a-f]{40}$").unwrap().is_match(body);
    }
    if path.contains(".git/config") {
        return lower.contains("[core]") && lower.contains("repositoryformatversion");
    }
    if path.contains(".svn") {
        return lower.contains("svn")
            || body
                .lines()
                .next()
                .is_some_and(|line| line.trim().parse::<u64>().is_ok());
    }
    if path.contains(".env") {
        return Regex::new(r"(?m)^[A-Z][A-Z0-9_]{1,63}\s*=\s*[^\r\n]+$")
            .unwrap()
            .find_iter(body)
            .count()
            >= 2;
    }
    if path.ends_with(".sql") {
        return ["create table", "insert into", "sql dump", "database dump"]
            .iter()
            .any(|marker| lower.contains(marker));
    }
    if path.contains(".bak") || path.contains(".old") || path.contains("wp-config") {
        return ["<?php", "db_name", "db_password", "database"]
            .iter()
            .any(|marker| lower.contains(marker));
    }
    false
}

fn reportable_admin_surface(path: &str, requested_url: &str, result: &Fetch) -> bool {
    if !(path.contains("admin") || path.contains("login"))
        || !direct_probe_response(requested_url, result)
        || !(200..300).contains(&result.status)
        || gated_or_denied_response(result.status, &result.body)
    {
        return false;
    }
    let lower = result.body.to_lowercase();
    [
        "<form",
        "type=\"password",
        "type='password",
        "sign in",
        "log in",
        "login",
        "wp-login",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn reportable_api_surface(path: &str, requested_url: &str, result: &Fetch) -> bool {
    if !(path.contains("api")
        || path.contains("graphql")
        || path.contains("openapi")
        || path.contains("swagger"))
        || !direct_probe_response(requested_url, result)
        || !matches!(result.status, 200 | 201 | 401 | 405)
        || gated_or_denied_response(result.status, &result.body)
    {
        return false;
    }
    api_surface_response_has_value(path, result)
}

fn api_surface_response_has_value(path: &str, result: &Fetch) -> bool {
    if matches!(result.status, 401 | 405) {
        return true;
    }

    let body = result.body.trim();
    if body.len() < 20 {
        return false;
    }

    let content_type = header_text(&result.headers, "content-type").to_lowercase();
    let lower_path = path.to_lowercase();
    let lower_body = body.to_lowercase();
    let looks_html = content_type.contains("text/html")
        || lower_body.starts_with("<!doctype")
        || lower_body.starts_with("<html")
        || lower_body.contains("<html");
    let doc_markers = ["swagger-ui", "swagger", "openapi", "redoc", "graphql"];

    if looks_html {
        return ["swagger", "openapi", "graphql"]
            .iter()
            .any(|marker| lower_path.contains(marker))
            && doc_markers.iter().any(|marker| lower_body.contains(marker));
    }

    if looks_like_empty_shell(body) {
        return false;
    }

    if content_type.contains("json") || body.starts_with('{') || body.starts_with('[') {
        return serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .is_some_and(|value| match value {
                serde_json::Value::Object(map) => !map.is_empty(),
                serde_json::Value::Array(items) => !items.is_empty(),
                _ => false,
            });
    }

    if content_type.contains("xml") || body.starts_with("<?xml") {
        return lower_body.contains('<')
            && lower_body.contains('>')
            && !lower_body.contains("<html");
    }

    let kind = crate::deep_validation::classify_api_response(&content_type, body);
    kind != "unknown"
}

fn direct_probe_response(requested_url: &str, result: &Fetch) -> bool {
    if !result.ok || normalize_path(&result.final_url) != normalize_path(requested_url) {
        return false;
    }
    true
}

fn dig(record_type: &str, name: &str) -> Vec<String> {
    Command::new("dig")
        .args(["+time=2", "+tries=1", "+short", record_type, name])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|line| {
                    line.replace("\" \"", "")
                        .replace('"', "")
                        .trim()
                        .to_string()
                })
                .filter(|line| !line.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn same_origin_links(body: &str, final_url: &str) -> Vec<String> {
    let Ok(base) = Url::parse(final_url) else {
        return Vec::new();
    };
    let base_host = base.host_str().map(str::to_string);
    let regex = Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*["']([^"'#]+)["']"#).unwrap();
    unique(
        regex
            .captures_iter(body)
            .filter_map(|capture| base.join(capture.get(1)?.as_str()).ok())
            .filter(|url| url.host_str().map(str::to_string) == base_host && url.query().is_none())
            .map(|url| url.to_string())
            .collect(),
    )
}

fn sitemap_urls(body: &str, final_url: &str) -> Vec<String> {
    let Ok(base) = Url::parse(final_url) else {
        return Vec::new();
    };
    let base_host = base.host_str().map(str::to_string);
    Regex::new(r"(?is)<loc>\s*([^<]+)\s*</loc>")
        .unwrap()
        .captures_iter(body)
        .filter_map(|capture| Url::parse(capture.get(1)?.as_str().trim()).ok())
        .filter(|url| url.host_str().map(str::to_string) == base_host)
        .map(|url| url.to_string())
        .collect()
}

fn representative_priority(url: &str) -> usize {
    let lower = url.to_lowercase();
    [
        "login", "account", "contact", "enquiry", "apply", "privacy", "about",
    ]
    .iter()
    .position(|keyword| lower.contains(keyword))
    .unwrap_or(20)
}

fn security_header_signature(headers: &HeaderMap) -> String {
    [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]
    .into_iter()
    .filter(|name| headers.contains_key(*name))
    .collect::<Vec<_>>()
    .join(",")
}

fn header_text(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn tag_value(record: &str, name: &str) -> String {
    Regex::new(&format!(
        r"(?i)(?:^|;)\s*{}\s*=\s*([^;\s]+)",
        regex::escape(name)
    ))
    .ok()
    .and_then(|regex| regex.captures(record))
    .and_then(|capture| capture.get(1).map(|value| value.as_str().to_lowercase()))
    .unwrap_or_default()
}

fn unique(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn unique_preserving_order(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            output.push(value);
        }
    }
    output
}

fn normalize_path(value: &str) -> String {
    Url::parse(value)
        .ok()
        .map(|url| url.path().trim_end_matches('/').to_lowercase())
        .unwrap_or_default()
}

fn join_url(base: &str, path: &str) -> String {
    Url::parse(base)
        .ok()
        .and_then(|url| url.join(path).ok())
        .map(|url| url.to_string())
        .unwrap_or_else(|| format!("{}{}", base.trim_end_matches('/'), path))
}

fn status_text(status: u16) -> String {
    if status == 0 {
        String::new()
    } else {
        status.to_string()
    }
}

fn analyze_ftp_surface(row: &mut Row, domain: &str, config: &AssessmentConfig) {
    let hosts = ftp_hosts(domain, row);
    row.insert("ftp_hosts_found".into(), hosts.join("; "));
    let mut accessible = Vec::new();
    let mut webroots = Vec::new();
    for host in hosts.into_iter().take(4) {
        if let Some(paths) =
            anonymous_ftp_webroots(&host, config.timeout.min(Duration::from_secs(5)))
        {
            accessible.push(host.clone());
            for path in paths {
                webroots.push(format!("{host}:{path}"));
            }
        }
    }
    row.insert("anonymous_ftp_accessible".into(), accessible.join("; "));
    row.insert("ftp_webroot_paths_accessible".into(), webroots.join("; "));
}

fn ftp_hosts(domain: &str, row: &Row) -> Vec<String> {
    let mut hosts = vec![format!("ftp.{domain}")];
    for field in ["ct_subdomain_sample", "subdomain_sample"] {
        for host in text_value(row, field).split(';').map(str::trim) {
            let host = host.trim_start_matches("*.").trim().to_lowercase();
            if host == domain || host.starts_with("ftp.") || host.contains(".ftp.") {
                hosts.push(host);
            }
        }
    }
    crate::findings::dedupe_preserve_order(hosts)
}

fn anonymous_ftp_webroots(host: &str, timeout: Duration) -> Option<Vec<String>> {
    use std::net::ToSocketAddrs;
    let address = format!("{host}:21");
    let socket = address.to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&socket, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let banner = ftp_read(&mut stream);
    if !banner.starts_with("220") {
        return None;
    }
    ftp_write(&mut stream, "USER anonymous\r\n")?;
    let user = ftp_read(&mut stream);
    if !(user.starts_with("331") || user.starts_with("230")) {
        return None;
    }
    if user.starts_with("331") {
        ftp_write(&mut stream, "PASS review@example.invalid\r\n")?;
        let pass = ftp_read(&mut stream);
        if !pass.starts_with("230") {
            return None;
        }
    }
    let mut roots = Vec::new();
    for path in ["/public_html", "/www", "/htdocs", "/httpdocs"] {
        ftp_write(&mut stream, &format!("CWD {path}\r\n"))?;
        let response = ftp_read(&mut stream);
        if response.starts_with("250") {
            roots.push(path.to_string());
            let _ = ftp_write(&mut stream, "CDUP\r\n");
            let _ = ftp_read(&mut stream);
        }
    }
    let _ = ftp_write(&mut stream, "QUIT\r\n");
    if roots.is_empty() { None } else { Some(roots) }
}

fn ftp_read(stream: &mut TcpStream) -> String {
    let mut buffer = [0u8; 4096];
    stream
        .read(&mut buffer)
        .ok()
        .map(|size| String::from_utf8_lossy(&buffer[..size]).to_string())
        .unwrap_or_default()
}

fn ftp_write(stream: &mut TcpStream, command: &str) -> Option<()> {
    stream.write_all(command.as_bytes()).ok()
}

fn is_transient_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

fn first_capture(value: &str, patterns: &[&str]) -> String {
    patterns
        .iter()
        .find_map(|pattern| {
            Regex::new(pattern)
                .ok()?
                .captures(value)?
                .get(1)
                .map(|capture| capture.as_str().trim().to_string())
        })
        .unwrap_or_default()
}

fn text_value(row: &Row, field: &str) -> String {
    row.get(field).cloned().unwrap_or_default()
}

pub fn assess_url(url: &str, timeout: Duration) -> Result<Row> {
    let mut lead = Row::new();
    lead.insert("website".into(), url.into());
    let row = assess_lead(
        &lead,
        &AssessmentConfig {
            timeout,
            retries: 1,
        },
    );
    if row.get("error").is_some_and(|value| !value.is_empty())
        && row.get("reachable").map(String::as_str) != Some("true")
    {
        anyhow::bail!("{}", row.get("error").cloned().unwrap_or_default());
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn result(url: &str, body: &str) -> Fetch {
        result_with_status(url, 200, body)
    }

    fn result_with_status(url: &str, status: u16, body: &str) -> Fetch {
        Fetch {
            ok: true,
            status,
            final_url: url.into(),
            headers: HeaderMap::new(),
            body: body.into(),
            elapsed_ms: 1,
            error: String::new(),
        }
    }

    fn browser_test_requested() -> bool {
        std::env::var("DOMAIN_REVIEW_RUN_BROWSER_TESTS")
            .ok()
            .is_some_and(|value| {
                matches!(value.trim().to_lowercase().as_str(), "1" | "true" | "yes")
            })
    }

    #[test]
    fn confirms_git_head_signature() {
        assert!(confirmed_exposure(
            "/.git/HEAD",
            "https://example.com/.git/HEAD",
            &result("https://example.com/.git/HEAD", "ref: refs/heads/main"),
        ));
    }

    #[test]
    fn rejects_html_sensitive_path_false_positive() {
        assert!(!confirmed_exposure(
            "/.env",
            "https://example.com/.env",
            &result("https://example.com/.env", "<html>not found</html>"),
        ));
    }

    #[test]
    fn api_probe_discards_empty_shell_responses() {
        let homepage = "<html><body>Home</body></html>";
        let empty = r#"{"message":"Not Found"}"#;
        let empty_fingerprint = content_fingerprint(empty);

        assert!(!meaningful_api_response(
            "https://example.com/api/v1",
            200,
            "application/json",
            empty,
            &content_fingerprint(homepage),
            Some(&empty_fingerprint),
            "json_api",
        ));
        assert!(!meaningful_api_response(
            "https://example.com/api/v2",
            200,
            "application/json",
            r#"{"error":"route not found"}"#,
            &content_fingerprint(homepage),
            None,
            "json_api",
        ));
    }

    #[test]
    fn api_probe_keeps_structured_non_empty_responses() {
        assert!(meaningful_api_response(
            "https://example.com/api/members",
            200,
            "application/json",
            r#"{"members":[{"id":1,"name":"Example"}]}"#,
            &content_fingerprint("<html><body>Home</body></html>"),
            Some(&content_fingerprint(r#"{"message":"Not Found"}"#)),
            "json_api",
        ));
    }

    #[test]
    fn api_probe_discards_html_homepage_fallbacks_on_api_paths() {
        let homepage = "<!DOCTYPE html><html><head><title>Example Home</title></head><body>Status page</body></html>";
        assert!(!meaningful_api_response(
            "https://example.com/api/v2",
            200,
            "text/html",
            homepage,
            &content_fingerprint("<html><body>Different home</body></html>"),
            None,
            "health_endpoint",
        ));
        assert!(!meaningful_api_response(
            "https://example.com/api/v2",
            200,
            "",
            homepage,
            &content_fingerprint("<html><body>Different home</body></html>"),
            None,
            "health_endpoint",
        ));
        assert!(meaningful_api_response(
            "https://example.com/swagger/index.html",
            200,
            "text/html",
            "<!DOCTYPE html><html><body>Swagger UI OpenAPI</body></html>",
            &content_fingerprint("<html><body>Different home</body></html>"),
            None,
            "documentation",
        ));
    }

    #[test]
    fn sensitive_api_probe_rejects_homepage_and_empty_json() {
        assert!(!reportable_api_surface(
            "/api/v2",
            "https://example.com/api/v2",
            &result(
                "https://example.com/api/v2",
                "<!DOCTYPE html><html><head><title>Example Home</title></head><body>Welcome</body></html>",
            ),
        ));
        assert!(!reportable_api_surface(
            "/api/v2",
            "https://example.com/api/v2",
            &result("https://example.com/api/v2", "{}"),
        ));
        assert!(reportable_api_surface(
            "/api/v2",
            "https://example.com/api/v2",
            &result(
                "https://example.com/api/v2",
                r#"{"members":[{"id":1,"name":"Example"}]}"#,
            ),
        ));
        assert!(reportable_api_surface(
            "/api/v2",
            "https://example.com/api/v2",
            &result_with_status(
                "https://example.com/api/v2",
                401,
                r#"{"error":"unauthorized"}"#,
            ),
        ));
    }

    #[test]
    fn api_probe_discards_generic_structured_index_responses() {
        assert!(!meaningful_api_response(
            "https://example.com/index",
            200,
            "application/json",
            r#"{"status":"ok","message":"ready"}"#,
            &content_fingerprint("<html><body>Home</body></html>"),
            Some(&content_fingerprint(r#"{"message":"Not Found"}"#)),
            "json_api",
        ));
    }

    #[test]
    fn parses_dmarc_policy() {
        assert_eq!(
            tag_value("v=DMARC1; p=quarantine; pct=50", "p"),
            "quarantine"
        );
    }

    #[test]
    fn extracts_same_origin_scripts() {
        let urls = crate::deep_validation::same_origin_script_urls(
            r#"<script src="/app.js"></script><script src="https://cdn.example/x.js"></script>"#,
            "https://example.com/",
        );
        assert_eq!(urls[0], "https://example.com/app.js");
    }

    #[test]
    fn fills_contact_email_from_published_role_address() {
        let mut row = Row::new();
        row.insert("contact_email".into(), String::new());
        analyze_html(
            &mut row,
            r#"<a href="mailto:owner@example.com">Owner</a><a href="mailto:info@example.com">Info</a>"#,
            "https://example.com/",
        );
        assert_eq!(row["contact_email"], "info@example.com");
    }

    #[test]
    fn preserves_existing_contact_email_over_discovered_and_inferred_values() {
        let mut row = Row::from([("contact_email".into(), "admin@lead.example".into())]);
        analyze_html(
            &mut row,
            r#"<a href="mailto:info@example.com">Info</a>"#,
            "https://example.com/",
        );
        fill_missing_contact_email(&mut row, "example.com");
        assert_eq!(row["contact_email"], "admin@lead.example");
    }

    #[test]
    fn infers_short_role_email_list_when_no_public_contact_exists() {
        let mut row = Row::from([("contact_email".into(), String::new())]);
        fill_missing_contact_email(&mut row, "www.example.com");
        assert_eq!(
            row["contact_email"],
            "security@example.com; admin@example.com; info@example.com"
        );
    }

    #[test]
    fn records_stable_login_surface_without_calling_it_a_file_exposure() {
        assert!(reportable_admin_surface(
            "/login",
            "https://example.com/login",
            &result(
                "https://example.com/login",
                "<form><input type=\"password\">Sign in</form>"
            ),
        ));
        assert!(!confirmed_exposure(
            "/login",
            "https://example.com/login",
            &result(
                "https://example.com/login",
                "<form><input type=\"password\">Sign in</form>"
            ),
        ));
    }

    #[test]
    fn rejects_forbidden_gateway_admin_surfaces() {
        let forbidden = result_with_status(
            "https://example.com/admin/login",
            403,
            "<html><title>403 Forbidden</title><body>Gateway error: request blocked</body></html>",
        );
        assert!(gated_or_denied_response(forbidden.status, &forbidden.body));
        assert!(!reportable_admin_surface(
            "/admin/login",
            "https://example.com/admin/login",
            &forbidden,
        ));
    }

    #[test]
    fn rejects_not_found_admin_surfaces_returned_as_success() {
        let not_found = result_with_status(
            "https://example.com/admin/login",
            200,
            r#"
            <html><head><script>window.next = "/login";</script></head>
            <body>
              <main class="lost">
                <h1>404</h1>
                <p>Uh oh. It looks like you've somehow managed to arrive at a terminal with no rails leading here.</p>
                <a href="/dashboard/home">Take the train home</a>
                <a href="/login">Login</a>
              </main>
            </body></html>
            "#,
        );
        assert!(gated_or_denied_response(not_found.status, &not_found.body));
        assert!(!reportable_admin_surface(
            "/admin/login",
            "https://example.com/admin/login",
            &not_found,
        ));
        let not_found_api = result_with_status(
            "https://example.com/admin/api",
            200,
            r#"<html><body><h1>404</h1><p>Take the train home</p><a href="/login">Login</a></body></html>"#,
        );
        assert!(gated_or_denied_response(
            not_found_api.status,
            &not_found_api.body
        ));
        assert!(!reportable_api_surface(
            "/admin/api",
            "https://example.com/admin/api",
            &not_found_api,
        ));

        let http_not_found = result_with_status(
            "https://example.com/admin/login",
            404,
            "<html>Not found</html>",
        );
        assert!(gated_or_denied_response(
            http_not_found.status,
            &http_not_found.body
        ));
        assert!(!reportable_admin_surface(
            "/admin/login",
            "https://example.com/admin/login",
            &http_not_found,
        ));
    }

    #[test]
    fn rejects_forbidden_gateway_api_surfaces() {
        let forbidden = result_with_status(
            "https://example.com/admin/api",
            403,
            "<html><title>403 Forbidden</title><body>Access denied by gateway</body></html>",
        );
        assert!(gated_or_denied_response(forbidden.status, &forbidden.body));
        assert!(!reportable_api_surface(
            "/admin/api",
            "https://example.com/admin/api",
            &forbidden,
        ));
        assert!(!meaningful_api_response(
            "https://example.com/admin/api",
            forbidden.status,
            "text/html",
            &forbidden.body,
            &content_fingerprint("<html><body>Home</body></html>"),
            None,
            "unknown",
        ));
    }

    #[test]
    fn browser_fallback_preserves_status_headers_and_final_url() {
        let browser_test_requested = browser_test_requested();
        if !browser_test_requested {
            return;
        }
        if chromium_executable().is_none() {
            assert!(
                !browser_test_requested,
                "DOMAIN_REVIEW_RUN_BROWSER_TESTS was set, but no Chromium executable was available"
            );
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            let body = "<html><body>verify you are human</body></html>";
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nX-Domain-Review-Test: browser\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let url = format!("http://{address}/challenge");
        let Some(result) = browser_fetch(&url, Duration::from_secs(10), 50_000) else {
            assert!(
                !browser_test_requested,
                "DOMAIN_REVIEW_RUN_BROWSER_TESTS was set, but Chromium browser_fetch returned no result"
            );
            return;
        };
        assert!(!result.ok, "browser body: {}", result.body);
        assert_eq!(result.status, 403);
        assert_eq!(result.final_url, url);
        assert_eq!(
            result
                .headers
                .get("x-domain-review-test")
                .and_then(|value| value.to_str().ok()),
            Some("browser")
        );
        assert!(result.error.starts_with("human verification"));
    }

    #[test]
    fn extracts_same_origin_sitemap_urls() {
        let urls = sitemap_urls(
            "<urlset><url><loc>https://example.com/contact</loc></url><url><loc>https://other.example/page</loc></url></urlset>",
            "https://example.com/",
        );
        assert_eq!(urls, vec!["https://example.com/contact"]);
    }
}
