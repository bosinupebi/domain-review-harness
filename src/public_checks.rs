use crate::Row;
use chrono::Datelike;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

pub fn analyze_forms(body: &str, final_url: &str) -> Row {
    let form_re = Regex::new(r"(?is)<form\b[^>]*>(.*?)</form>").unwrap();
    let forms: Vec<_> = form_re.captures_iter(body).collect();
    if forms.is_empty() {
        return Row::from([
            ("forms_count".into(), "0".into()),
            ("forms_over_https".into(), "no_forms_seen".into()),
            ("password_fields_seen".into(), "false".into()),
            ("password_field_seen".into(), "false".into()),
            ("csrf_tokens_seen".into(), "false".into()),
            ("forms_without_https".into(), "0".into()),
        ]);
    }
    let action_re = Regex::new(r#"(?i)action=["']([^"']*)["']"#).unwrap();
    let password_re = Regex::new(r#"(?i)<input[^>]*type=["']password["']"#).unwrap();
    let csrf_re =
        Regex::new(r#"(?i)<input[^>]*name=["']([^"']*csrf[^"']*|[^"']*token[^"']*)["']"#).unwrap();
    let mut insecure = 0;
    let mut password = false;
    let mut csrf = false;
    for capture in &forms {
        let whole = capture.get(0).unwrap().as_str();
        let inner = capture.get(1).map(|value| value.as_str()).unwrap_or("");
        let action = action_re
            .captures(whole)
            .and_then(|value| value.get(1))
            .map(|value| value.as_str())
            .unwrap_or("");
        if action.starts_with("http://")
            || (action.is_empty()
                && Url::parse(final_url)
                    .ok()
                    .is_some_and(|url| url.scheme() == "http"))
        {
            insecure += 1;
        }
        password |= password_re.is_match(inner);
        csrf |= csrf_re.is_match(inner);
    }
    Row::from([
        ("forms_count".into(), forms.len().to_string()),
        (
            "forms_over_https".into(),
            if insecure > 0 {
                "insecure_form_action".into()
            } else {
                "likely_ok".into()
            },
        ),
        ("password_fields_seen".into(), password.to_string()),
        ("password_field_seen".into(), password.to_string()),
        ("csrf_tokens_seen".into(), csrf.to_string()),
        ("forms_without_https".into(), insecure.to_string()),
    ])
}

pub fn extract_wordpress_version(body: &str) -> String {
    for pattern in [
        r#"(?i)<meta[^>]*name=["']generator["'][^>]*content=["']WordPress (\d+\.\d+(?:\.\d+)?)"#,
        r#"(?i)wp-includes/js/wp-embed(?:-min)?\.js\?ver=(\d+\.\d+(?:\.\d+)?)"#,
    ] {
        if let Some(value) = Regex::new(pattern)
            .unwrap()
            .captures(body)
            .and_then(|capture| capture.get(1))
        {
            return value.as_str().into();
        }
    }
    String::new()
}

pub fn extract_hsts_max_age(header: &str) -> String {
    Regex::new(r"(?i)max-age=(\d+)")
        .unwrap()
        .captures(header)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str().to_string())
        .unwrap_or_default()
}

pub fn count_spf_dns_lookups(records: &[String]) -> usize {
    records
        .first()
        .map(|record| {
            Regex::new(r"(?i)\b(include|a|mx|ptr|exists):")
                .unwrap()
                .find_iter(record)
                .count()
        })
        .unwrap_or(0)
}

pub fn sees_privacy_policy(body: &str) -> bool {
    Regex::new(r#"(?i)privacy(?:\s|-|_)*policy|href=['"][^'"]*privacy"#)
        .unwrap()
        .is_match(body)
}
pub fn sees_contact_page(body: &str) -> bool {
    Regex::new(r#"(?i)contact\s*us|href=['"][^'"]*contact"#)
        .unwrap()
        .is_match(body)
}
pub fn sees_title(body: &str) -> bool {
    Regex::new(r"(?i)<title\b[^>]*>\s*[^<]+")
        .unwrap()
        .is_match(body)
}
pub fn sees_meta_description(body: &str) -> bool {
    Regex::new(r#"(?i)<meta\b[^>]*name=['"]description['"][^>]*content=['"][^'"]+"#)
        .unwrap()
        .is_match(body)
}
pub fn sees_h1(body: &str) -> bool {
    Regex::new(r"(?i)<h1\b").unwrap().is_match(body)
}
pub fn sees_viewport_meta(body: &str) -> bool {
    Regex::new(r#"(?i)<meta\b[^>]*name=['"]viewport['"]"#)
        .unwrap()
        .is_match(body)
}
pub fn sees_canonical(body: &str) -> bool {
    Regex::new(r#"(?i)<link\b[^>]*rel=['"][^'"]*canonical"#)
        .unwrap()
        .is_match(body)
}
pub fn sees_public_email(body: &str) -> bool {
    Regex::new(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}")
        .unwrap()
        .is_match(body)
}

pub fn public_role_emails(body: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let email_re = Regex::new(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}").unwrap();
    for value in email_re.find_iter(body) {
        let email = value
            .as_str()
            .trim_matches(['.', ',', ';', ':'])
            .to_lowercase();
        if is_public_role_email(&email) {
            seen.insert(email);
        }
    }
    seen.into_iter().collect()
}

pub fn inferred_role_emails(domain: &str) -> Vec<String> {
    let domain = domain
        .trim()
        .trim_start_matches("www.")
        .trim_matches('.')
        .to_lowercase();
    if domain.is_empty() || domain.contains('@') || !domain.contains('.') {
        return Vec::new();
    }
    ["security", "admin", "info"]
        .into_iter()
        .map(|role| format!("{role}@{domain}"))
        .collect()
}

fn is_public_role_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if domain.is_empty() || !domain.contains('.') {
        return false;
    }
    matches!(
        local,
        "security"
            | "admin"
            | "administrator"
            | "info"
            | "support"
            | "contact"
            | "hello"
            | "enquiry"
            | "enquiries"
            | "sales"
            | "office"
            | "customercare"
            | "customerservice"
    )
}

pub fn social_links_seen(body: &str) -> Vec<String> {
    [
        ("facebook", "facebook.com"),
        ("instagram", "instagram.com"),
        ("linkedin", "linkedin.com"),
        ("tiktok", "tiktok.com"),
        ("x", "twitter.com"),
        ("youtube", "youtube.com"),
    ]
    .into_iter()
    .filter(|(_, token)| body.contains(token))
    .map(|(name, _)| name.into())
    .collect()
}

pub fn cookie_flags(cookies: &[String]) -> (bool, Option<bool>, Option<bool>, Option<bool>) {
    if cookies.is_empty() {
        return (false, None, None, None);
    }
    let lower = cookies.join("\n").to_lowercase();
    (
        true,
        Some(lower.contains("secure")),
        Some(lower.contains("httponly")),
        Some(lower.contains("samesite")),
    )
}

pub fn generator_meta(body: &str) -> String {
    let whitespace = Regex::new(r"\s+").unwrap();
    for pattern in [
        r#"(?i)<meta\b[^>]*name=['"]generator['"][^>]*content=['"]([^'"]+)"#,
        r#"(?i)<meta\b[^>]*content=['"]([^'"]+)['"][^>]*name=['"]generator['"]"#,
    ] {
        if let Some(value) = Regex::new(pattern)
            .unwrap()
            .captures(body)
            .and_then(|capture| capture.get(1))
        {
            return whitespace
                .replace_all(value.as_str(), " ")
                .trim()
                .chars()
                .take(120)
                .collect();
        }
    }
    String::new()
}

pub fn technology_hints(headers: &BTreeMap<String, String>, body: &str) -> Vec<String> {
    let source = format!(
        "{} {} {} {}",
        headers.get("server").cloned().unwrap_or_default(),
        headers.get("x-powered-by").cloned().unwrap_or_default(),
        generator_meta(body),
        body.chars().take(50_000).collect::<String>()
    )
    .to_lowercase();
    [
        ("WordPress", &["wp-content", "wp-json", "wordpress"][..]),
        ("WooCommerce", &["woocommerce"][..]),
        ("Elementor", &["elementor"][..]),
        ("Drupal", &["drupal"][..]),
        ("Joomla", &["joomla"][..]),
        ("Laravel", &["laravel"][..]),
        ("ASP.NET", &["asp.net", "x-aspnet"][..]),
        ("PHP", &["php"][..]),
        ("Shopify", &["shopify"][..]),
        ("Wix", &["wixstatic", "wix.com"][..]),
        ("Squarespace", &["squarespace"][..]),
        ("Webflow", &["webflow"][..]),
        ("Cloudflare", &["cloudflare"][..]),
        ("Sucuri", &["sucuri"][..]),
        ("nginx", &["nginx"][..]),
        ("Apache", &["apache"][..]),
    ]
    .into_iter()
    .filter(|(_, tokens)| tokens.iter().any(|token| source.contains(token)))
    .map(|(name, _)| name.into())
    .take(12)
    .collect()
}

pub fn attr_value(attrs: &str, name: &str) -> String {
    Regex::new(&format!(
        r#"(?i)\b{}\s*=\s*['"]([^'"]+)['"]"#,
        regex::escape(name)
    ))
    .unwrap()
    .captures(attrs)
    .and_then(|capture| capture.get(1))
    .map(|value| {
        html_escape::decode_html_entities(value.as_str())
            .trim()
            .to_string()
    })
    .unwrap_or_default()
}

pub fn same_origin_script_urls(body: &str, final_url: &str) -> Vec<String> {
    let Ok(base) = Url::parse(final_url) else {
        return Vec::new();
    };
    let host = base.host_str();
    let mut urls = Vec::new();
    for capture in Regex::new(r"(?is)<script\b([^>]*)>")
        .unwrap()
        .captures_iter(body)
    {
        let source = attr_value(capture.get(1).unwrap().as_str(), "src");
        if source.is_empty() {
            continue;
        }
        if let Ok(url) = base.join(&source)
            && matches!(url.scheme(), "http" | "https")
            && url.host_str() == host
            && !urls.contains(&url.to_string())
        {
            urls.push(url.to_string());
        }
    }
    urls
}

pub fn external_script_hosts(scripts: &[(String, String)], final_url: &str) -> Vec<String> {
    let base = Url::parse(final_url).ok();
    let base_host = base.as_ref().and_then(Url::host_str);
    let mut hosts = Vec::new();
    for (_, source) in scripts {
        if source.is_empty() {
            continue;
        }
        let url = base.as_ref().and_then(|base| base.join(source).ok());
        if let Some(host) = url.as_ref().and_then(Url::host_str)
            && Some(host) != base_host
            && !hosts.contains(&host.to_string())
        {
            hosts.push(host.to_string());
        }
    }
    hosts.truncate(20);
    hosts
}

pub fn external_scripts_without_sri(scripts: &[(String, String)], final_url: &str) -> usize {
    let base = Url::parse(final_url).ok();
    let base_host = base.as_ref().and_then(Url::host_str);
    scripts
        .iter()
        .filter(|(attrs, source)| {
            !source.is_empty()
                && base
                    .as_ref()
                    .and_then(|base| base.join(source).ok())
                    .as_ref()
                    .and_then(Url::host_str)
                    .is_some_and(|host| Some(host) != base_host)
                && !Regex::new(r"(?i)\bintegrity\s*=").unwrap().is_match(attrs)
        })
        .count()
}

pub fn external_form_action_seen(forms: &[String], final_url: &str) -> bool {
    let base = Url::parse(final_url).ok();
    let base_host = base.as_ref().and_then(Url::host_str);
    forms.iter().any(|form| {
        let action = attr_value(form, "action");
        !action.is_empty()
            && base
                .as_ref()
                .and_then(|base| base.join(&action).ok())
                .as_ref()
                .and_then(Url::host_str)
                .is_some_and(|host| Some(host) != base_host)
    })
}

pub fn count_mixed_content_refs(body: &str) -> usize {
    Regex::new(r#"(?i)\b(?:src|href|action)\s*=\s*['"]http://"#)
        .unwrap()
        .find_iter(body)
        .count()
}

pub fn risk_terms_seen(value: &str, secret_only: bool) -> Vec<String> {
    let lower = value.to_lowercase();
    let mut patterns = vec![
        ("api_key", vec![r"api[_-]?key", r"apikey"]),
        ("secret", vec![r"\bsecret\b", r"client[_-]?secret"]),
        (
            "token",
            vec![
                r"\btoken\b",
                r"access[_-]?token",
                r"bearer\s+[a-z0-9._-]{12,}",
            ],
        ),
        ("password", vec![r"\bpassword\b", r"passwd", r"pwd"]),
        (
            "private_key",
            vec![
                r"private[_-]?key",
                r"begin\s+(rsa|ec|openssh)\s+private\s+key",
            ],
        ),
        ("staging", vec![r"\bstaging\b", r"\bdev\b", r"\bdebug\b"]),
        ("todo", vec![r"\btodo\b", r"\bfixme\b"]),
    ];
    if secret_only {
        patterns.retain(|(name, _)| !matches!(*name, "staging" | "todo"));
    }
    patterns
        .into_iter()
        .filter(|(_, values)| {
            values
                .iter()
                .any(|pattern| Regex::new(pattern).unwrap().is_match(&lower))
        })
        .map(|(name, _)| name.into())
        .collect()
}

pub fn secret_like_assignment_details(value: &str) -> Vec<String> {
    let patterns = [
        r#"(?i)([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,3})\s*(?:=|:)\s*'([^'\n\r]{1,160})'"#,
        r#"(?i)([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,3})\s*(?:=|:)\s*"([^"\n\r]{1,160})""#,
        r#"(?i)([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,3})\s*(?:=|:)\s*`([^`\n\r]{1,160})`"#,
        r#"(?i)([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,3})\s*(?:=|:)\s*([^\s'"`,;}\n][^,;}\n]{0,159})"#,
    ];
    let mut details = Vec::new();
    for pattern in patterns {
        for capture in Regex::new(pattern).unwrap().captures_iter(value) {
            let name = capture.get(1).unwrap().as_str().trim();
            if secret_like_name(name) {
                let cleaned = normalize_js_value(capture.get(2).unwrap().as_str());
                if !cleaned.is_empty() && secret_like_value(&cleaned) {
                    details.push(format!("{name}={cleaned}"));
                }
            }
        }
    }
    details
}

pub fn secret_like_name(name: &str) -> bool {
    let parts = identifier_parts(name);
    if parts.is_empty() {
        return false;
    }
    let flat: String = name
        .to_lowercase()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect();
    let non_secret_fragments = [
        "canceltoken",
        "domtoken",
        "domtokenlist",
        "metatokens",
        "requestpasswordreset",
        "resetpassword",
        "setpassword",
        "settoken",
        "tokenize",
        "tokenizer",
        "tokenlist",
        "tokenstofunction",
        "tokenstoregexp",
        "withcsrftoken",
        "withxsrftoken",
    ];
    if non_secret_fragments
        .iter()
        .any(|fragment| flat.contains(fragment))
    {
        return false;
    }

    let has = |term: &str| parts.iter().any(|part| part == term);
    if has("api") && has("key") || has("apikey") {
        return true;
    }
    if has("private") && has("key") || has("privatekey") {
        return true;
    }
    if has("secret") || flat.ends_with("secret") {
        return true;
    }
    if has("password") || has("passwd") || has("pwd") || flat.ends_with("password") {
        if ["reset", "request", "set", "forgot", "change"]
            .iter()
            .any(|term| has(term))
        {
            return false;
        }
        return true;
    }
    if has("token") || flat.ends_with("token") {
        if [
            "cancel", "meta", "with", "has", "list", "to", "function", "regexp", "lifetime",
            "expiry", "expires", "ttl",
        ]
        .iter()
        .any(|term| has(term))
        {
            return false;
        }
        return true;
    }
    false
}

fn identifier_parts(name: &str) -> Vec<String> {
    let acronym_spaced = Regex::new(r"([A-Z]+)([A-Z][a-z])")
        .unwrap()
        .replace_all(name, "$1 $2");
    let camel_spaced = Regex::new(r"([a-z0-9])([A-Z])")
        .unwrap()
        .replace_all(&acronym_spaced, "$1 $2");
    Regex::new(r"[A-Za-z0-9]+")
        .unwrap()
        .find_iter(&camel_spaced)
        .map(|part| part.as_str().to_lowercase())
        .collect()
}

fn secret_like_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    let trimmed = lower.trim();
    if matches!(trimmed, "true" | "false" | "null" | "undefined" | "nan") {
        return false;
    }
    if Regex::new(r"^-?\d+(?:\.\d+)?$").unwrap().is_match(value) {
        return false;
    }
    if Regex::new(r"^[A-Za-z_$][\w$]*$").unwrap().is_match(value) && value.len() <= 3 {
        return false;
    }
    !Regex::new(
        r"(?i)^(function\b|class\b|new\s+[A-Za-z_$][\w$]*\s*\(|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)",
    )
    .unwrap()
    .is_match(value)
}

pub fn normalize_js_value(value: &str) -> String {
    let cleaned = Regex::new(r"\s+")
        .unwrap()
        .replace_all(&html_escape::decode_html_entities(value), " ")
        .trim()
        .to_string();
    let unquoted = if cleaned.len() >= 2 {
        let first = cleaned.chars().next();
        let last = cleaned.chars().last();
        if matches!(first, Some('\'') | Some('"') | Some('`')) && first == last {
            cleaned
                .chars()
                .skip(1)
                .take(cleaned.chars().count().saturating_sub(2))
                .collect::<String>()
                .trim()
                .to_string()
        } else {
            cleaned
        }
    } else {
        cleaned
    };
    unquoted.chars().take(120).collect()
}

pub fn html_injection_sink_terms(value: &str) -> Vec<String> {
    let lower = value.to_lowercase();
    [
        ("innerHTML", vec![r"\binnerhtml\b"]),
        ("outerHTML", vec![r"\bouterhtml\b"]),
        ("insertAdjacentHTML", vec![r"\binsertadjacenthtml\b"]),
        ("document.write", vec![r"\bdocument\.write\s*\("]),
        (
            "dangerouslySetInnerHTML",
            vec![r"\bdangerouslysetinnerhtml\b"],
        ),
        ("v-html", vec![r"\bv-html\b"]),
        ("jQuery .html()", vec![r"\.html\s*\("]),
    ]
    .into_iter()
    .filter(|(_, patterns)| {
        patterns
            .iter()
            .any(|pattern| Regex::new(pattern).unwrap().is_match(&lower))
    })
    .map(|(name, _)| name.into())
    .collect()
}

pub fn admin_link_hints_seen(body: &str) -> bool {
    Regex::new(r#"(?i)href=['"][^'"]*(/wp-admin|/administrator|/admin\b|/login\b|/user/login)"#)
        .unwrap()
        .is_match(body)
}
pub fn api_endpoint_hints_seen(body: &str) -> bool {
    Regex::new(r#"(?i)['"](?:https?://[^'"]+)?/api/[^'"]+['"]|fetch\(['"][^'"]+['"]"#)
        .unwrap()
        .is_match(body)
}

pub fn outdated_copyright(body: &str, current_year: i32) -> Option<bool> {
    let years: Vec<i32> = Regex::new(r"(?i)(?:copyright|&copy;)[^0-9]{0,40}(20[0-9]{2})")
        .unwrap()
        .captures_iter(body)
        .filter_map(|capture| capture.get(1)?.as_str().parse().ok())
        .collect();
    years.iter().max().map(|year| *year < current_year)
}

pub fn current_year() -> i32 {
    chrono::Utc::now().year()
}
