use crate::findings::dedupe_preserve_order;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use url::{Url, form_urlencoded};

pub fn classify_api_response(content_type: &str, body: &str) -> String {
    let lower = body.to_lowercase();
    if lower.contains("graphql") || lower.contains("introspection") {
        "graphql"
    } else if lower.contains("swagger") || lower.contains("openapi") {
        "documentation"
    } else if content_type.contains("json") && serde_json::from_str::<Value>(body).is_ok() {
        "json_api"
    } else if content_type.contains("xml") {
        "xml_api"
    } else if lower.contains("prometheus") || lower.contains("metrics") {
        "metrics_endpoint"
    } else if ["health", "status", "\"ok\"", "\"up\""]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        "health_endpoint"
    } else {
        "unknown"
    }
    .into()
}

pub fn check_cors_open(headers: &BTreeMap<String, String>) -> bool {
    let origin = get_header(headers, "Access-Control-Allow-Origin");
    let credentials = get_header(headers, "Access-Control-Allow-Credentials").to_lowercase();
    origin.trim() == "*" || (!origin.trim().is_empty() && credentials == "true")
}

pub fn get_header(headers: &BTreeMap<String, String>, name: &str) -> String {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

pub fn indicates_data_leak(body: &str, content_type: &str) -> bool {
    let sensitive: BTreeSet<&str> = [
        "email",
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "ssn",
        "phone",
        "account",
        "accounts",
        "user",
        "users",
        "record",
        "records",
    ]
    .into_iter()
    .collect();
    let identity: BTreeSet<&str> = ["id", "uuid", "email", "username", "account_id", "user_id"]
        .into_iter()
        .collect();
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        return structured_data_has_sensitive_records(&value, &sensitive, &identity);
    }
    if (content_type.to_lowercase().contains("xml") || body.trim_start().starts_with("<?xml"))
        && let Ok(document) = roxmltree::Document::parse(body)
    {
        let root = document.root_element();
        let tags: BTreeSet<String> = root
            .descendants()
            .filter(|node| node.is_element())
            .map(|node| node.tag_name().name().to_lowercase())
            .collect();
        let child_count = root.children().filter(|node| node.is_element()).count();
        return tags.iter().any(|tag| sensitive.contains(tag.as_str()))
            || (child_count > 1 && tags.iter().any(|tag| identity.contains(tag.as_str())));
    }
    Regex::new(r"(?i)\b(?:password|access[_-]?token|api[_-]?key|secret)\b\s*[:=]")
        .unwrap()
        .is_match(body)
}

pub fn structured_data_has_sensitive_records(
    value: &Value,
    sensitive: &BTreeSet<&str>,
    identity: &BTreeSet<&str>,
) -> bool {
    match value {
        Value::Object(map) => {
            let keys: BTreeSet<String> = map.keys().map(|key| key.to_lowercase()).collect();
            keys.iter().any(|key| sensitive.contains(key.as_str()))
                || keys
                    .iter()
                    .filter(|key| identity.contains(key.as_str()))
                    .count()
                    >= 2
                || map
                    .values()
                    .any(|child| structured_data_has_sensitive_records(child, sensitive, identity))
        }
        Value::Array(values) => values
            .iter()
            .any(|child| structured_data_has_sensitive_records(child, sensitive, identity)),
        _ => false,
    }
}

pub fn extract_type_count(body: &str) -> usize {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| value["data"]["__schema"]["types"].as_array().map(Vec::len))
        .unwrap_or(0)
}

pub fn extract_cloud_assets(js: &str) -> BTreeMap<String, Vec<String>> {
    let url_patterns: &[(&str, &[&str])] = &[
        (
            "s3_buckets",
            &[
                r#"(?i)["'](https?://[^"']*\.s3[.-][\w-]+\.amazonaws\.com[^"']*)["']"#,
                r#"(?i)["'](https?://s3[.-][\w-]+\.amazonaws\.com/[^"']*)["']"#,
                r#"(?i)["'](https?://[^"']*s3\.amazonaws\.com/[^"']*)["']"#,
            ],
        ),
        (
            "gcs_buckets",
            &[
                r#"(?i)["'](https?://[^"']*\.storage\.googleapis\.com[^"']*)["']"#,
                r#"(?i)["'](https?://storage\.googleapis\.com/[^"']*)["']"#,
                r#"(?i)["'](https?://storage\.cloud\.google\.com/[^"']*)["']"#,
                r#"(?i)["'](https?://[^"']*\.appspot\.com[^"']*)["']"#,
            ],
        ),
        (
            "azure_blobs",
            &[
                r#"(?i)["'](https?://[^"']*\.blob\.core\.windows\.net[^"']*)["']"#,
                r#"(?i)["'](https?://[^"']*\.file\.core\.windows\.net[^"']*)["']"#,
            ],
        ),
        (
            "firebase",
            &[r#"(?i)["'](https?://[^"']*\.firebaseio\.com[^"']*)["']"#],
        ),
        (
            "cloudfront",
            &[r#"(?i)["'](https?://[^"']*\.cloudfront\.net[^"']*)["']"#],
        ),
        ("websockets", &[r#"(?i)["'](wss?://[^"']+)["']"#]),
        (
            "internal_urls",
            &[
                r#"(?i)["'](http://(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3})[^"']*)["']"#,
            ],
        ),
    ];
    let mut output = BTreeMap::new();
    for (category, patterns) in url_patterns {
        let mut values = Vec::new();
        for pattern in *patterns {
            values.extend(
                Regex::new(pattern)
                    .unwrap()
                    .captures_iter(js)
                    .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string())),
            );
        }
        output.insert((*category).into(), dedupe_preserve_order(values));
    }
    for (category, patterns) in [
        (
            "api_keys",
            vec![
                r#"(?i)["']?(?:api[_-]?key|apikey)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']"#,
                r#"(?i)["']?(?:secret[_-]?key|secret)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']"#,
            ],
        ),
        (
            "tokens",
            vec![
                r#"(?i)["']?(?:auth[_-]?token|access[_-]?token)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']"#,
                r#"(?i)["']?Authorization["']?\s*:\s*["']?(?:Bearer|Token)\s+([a-zA-Z0-9_\-]{20,})"#,
            ],
        ),
    ] {
        let mut values = Vec::new();
        for pattern in patterns {
            for capture in Regex::new(pattern).unwrap().captures_iter(js) {
                let credential = capture.get(1).unwrap().as_str();
                values.push(format!(
                    "{}...{}",
                    &credential[..8],
                    &credential[credential.len() - 4..]
                ));
            }
        }
        output.insert(category.into(), dedupe_preserve_order(values));
    }
    output
}

pub fn response_contains_protected_data(body: &str, content_type: &str) -> bool {
    indicates_data_leak(body, content_type)
}

pub fn same_origin_links(body: &str, final_url: &str) -> Vec<String> {
    extract_urls(
        body,
        final_url,
        r#"(?i)<a\b[^>]*href=["']([^"']+)["']"#,
        true,
        100,
    )
}

pub fn same_origin_script_urls(body: &str, final_url: &str) -> Vec<String> {
    extract_urls(
        body,
        final_url,
        r#"(?i)<script\b[^>]*src=["']([^"']+)["']"#,
        true,
        usize::MAX,
    )
}

pub fn extract_scripts(body: &str, final_url: &str) -> Vec<String> {
    extract_urls(
        body,
        final_url,
        r#"(?i)<script\b[^>]*src=["']([^"']+)["']"#,
        false,
        usize::MAX,
    )
}

fn extract_urls(
    body: &str,
    final_url: &str,
    pattern: &str,
    same_origin: bool,
    limit: usize,
) -> Vec<String> {
    let Ok(base) = Url::parse(final_url) else {
        return Vec::new();
    };
    let host = base.host_str();
    let mut values = Vec::new();
    for capture in Regex::new(pattern).unwrap().captures_iter(body) {
        if let Ok(url) =
            base.join(html_escape::decode_html_entities(capture.get(1).unwrap().as_str()).trim())
            && matches!(url.scheme(), "http" | "https")
            && (!same_origin || url.host_str() == host)
            && !values.contains(&url.to_string())
        {
            values.push(url.to_string());
            if values.len() >= limit {
                break;
            }
        }
    }
    values
}

pub fn has_integrity_attribute(script_url: &str, body: &str) -> bool {
    let filename = script_url.rsplit('/').next().unwrap_or("");
    Regex::new(&format!(
        r#"(?i)<script[^>]*src=["'][^"']*{}[^"']*["'][^>]*integrity=["']"#,
        regex::escape(filename)
    ))
    .unwrap()
    .is_match(body)
}

pub fn reflection_probe_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return value.into();
    };
    let mut query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    query.push((
        "domain_review_probe".into(),
        "domain_review_probe_20260614".into(),
    ));
    url.set_query(Some(
        &form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query)
            .finish(),
    ));
    url.to_string()
}

pub fn dom_xss_sinks_seen(value: &str) -> bool {
    [
        r"document\.write\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"eval\s*\(",
        r#"setTimeout\s*\(\s*['"]"#,
        r#"setInterval\s*\(\s*['"]"#,
        r"location\.href\s*=",
        r"location\.replace\s*\(",
    ]
    .iter()
    .any(|pattern| {
        Regex::new(&format!("(?i){pattern}"))
            .unwrap()
            .is_match(value)
    })
}

pub fn sql_error_text_seen(value: &str) -> bool {
    [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"PostgreSQL.*?ERROR",
        r"ORA-[0-9]{5}",
        r"Microsoft SQL Server.*?Error",
        r"ODBC SQL Server Driver",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"unclosed quotation mark",
        r"unexpected end of SQL command",
        r"quoted string not properly terminated",
    ]
    .iter()
    .any(|pattern| {
        Regex::new(&format!("(?i){pattern}"))
            .unwrap()
            .is_match(value)
    })
}

pub fn fingerprint_technology(body: &str, headers: &BTreeMap<String, String>) -> Vec<String> {
    let mut hints = Vec::new();
    let server = get_header(headers, "Server").to_lowercase();
    for (marker, label) in [
        ("apache", "Apache"),
        ("nginx", "Nginx"),
        ("microsoft-iis", "IIS"),
        ("cloudflare", "Cloudflare"),
    ] {
        if server.contains(marker) {
            hints.push(label.into());
        }
    }
    let powered = get_header(headers, "X-Powered-By").to_lowercase();
    if powered.contains("php") {
        hints.push("PHP".into());
    }
    if powered.contains("asp.net") {
        hints.push("ASP.NET".into());
    }
    let lower = body.to_lowercase();
    for (marker, label) in [
        ("wp-content", "WordPress"),
        ("drupal", "Drupal"),
        ("joomla", "Joomla"),
        ("react", "React"),
        ("vue.js", "Vue.js"),
        ("angular", "Angular"),
        ("next.js", "Next.js"),
        ("django", "Django"),
        ("laravel", "Laravel"),
        ("woocommerce", "WooCommerce"),
        ("shopify", "Shopify"),
        ("magento", "Magento"),
    ] {
        if lower.contains(marker) {
            hints.push(label.into());
        }
    }
    dedupe_preserve_order(hints)
}

pub fn extract_generator_meta(body: &str) -> String {
    for pattern in [
        r#"(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']"#,
        r#"(?i)<meta[^>]*content=["']([^"']+)["'][^>]*name=["']generator["']"#,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub has_password: bool,
    pub has_csrf: bool,
}

pub fn extract_forms(body: &str, base_url: &str) -> Vec<Form> {
    let Ok(base) = Url::parse(base_url) else {
        return Vec::new();
    };
    let form_re = Regex::new(r"(?is)<form[^>]*>(.*?)</form>").unwrap();
    let action_re = Regex::new(r#"(?i)action=["']([^"']*)["']"#).unwrap();
    let method_re = Regex::new(r#"(?i)method=["']([^"']*)["']"#).unwrap();
    let password_re = Regex::new(r#"(?i)<input[^>]*type=["']password["']"#).unwrap();
    let csrf_re =
        Regex::new(r#"(?i)<input[^>]*name=["']([^"']*csrf[^"']*|[^"']*token[^"']*)["']"#).unwrap();
    form_re
        .captures_iter(body)
        .map(|capture| {
            let whole = capture.get(0).unwrap().as_str();
            let inner = capture.get(1).unwrap().as_str();
            let action = action_re
                .captures(whole)
                .and_then(|capture| capture.get(1))
                .and_then(|value| base.join(value.as_str()).ok())
                .map(|url| url.to_string())
                .unwrap_or_else(|| base_url.into());
            let method = method_re
                .captures(whole)
                .and_then(|capture| capture.get(1))
                .map(|value| value.as_str().to_uppercase())
                .unwrap_or_else(|| "GET".into());
            Form {
                action,
                method,
                has_password: password_re.is_match(inner),
                has_csrf: csrf_re.is_match(inner),
            }
        })
        .collect()
}

pub fn extract_api_endpoints(js: &str) -> Vec<String> {
    let patterns = [
        (r#"["'](/api/v\d+[^"']*)["']"#, 1),
        (r#"["'](/graphql[^"']*)["']"#, 1),
        (r#"["'](/rest/[^"']*)["']"#, 1),
        (r#"["'](/wp-json/[^"']*)["']"#, 1),
        (r#"fetch\(["']([^"']+)["']"#, 1),
        (r#"axios\.(get|post|put|delete)\(["']([^"']+)["']"#, 2),
        (r#"url:\s*["']([^"']+)["']"#, 1),
    ];
    let mut endpoints = Vec::new();
    for (pattern, group) in patterns {
        for capture in Regex::new(pattern).unwrap().captures_iter(js) {
            if let Some(value) = capture.get(group) {
                let endpoint = value.as_str().to_string();
                if !endpoint.starts_with("http") && !endpoints.contains(&endpoint) {
                    endpoints.push(endpoint);
                    if endpoints.len() >= 20 {
                        return endpoints;
                    }
                }
            }
        }
    }
    endpoints
}

pub fn debug_terms_in_js(js: &str) -> Vec<String> {
    [
        r"console\.log\s*\(",
        r"debugger\s*;",
        r"DEBUG\s*[=:]",
        r"devMode\s*[=:]",
        r"__DEBUG__",
        r"webpack:///",
        r"sourceURL=webpack",
    ]
    .into_iter()
    .filter(|pattern| Regex::new(&format!("(?i){pattern}")).unwrap().is_match(js))
    .map(|pattern| pattern.replace(r"\.", ".").replace(r"\s*", " "))
    .collect()
}

pub fn source_map_references(value: &str) -> Vec<String> {
    Regex::new(r"sourceMappingURL=([^\s*]+)")
        .unwrap()
        .captures_iter(value)
        .filter_map(|capture| {
            capture
                .get(1)
                .map(|value| value.as_str().trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .collect()
}

pub fn extract_dmarc_policy(record: &str) -> String {
    if record.is_empty() {
        return String::new();
    }
    Regex::new(r"(?i)p=(\w+)")
        .unwrap()
        .captures(record)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str().into())
        .unwrap_or_else(|| "none".into())
}
