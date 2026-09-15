use url::Url;

pub fn normalize_website(value: &str) -> String {
    let raw = value.trim();
    if raw.is_empty() {
        return String::new();
    }
    let candidate = if raw.starts_with("//") {
        format!("https:{raw}")
    } else if has_scheme(raw) {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let Ok(parsed) = Url::parse(&candidate) else {
        return candidate;
    };
    let Some(host) = parsed.host_str() else {
        return candidate;
    };
    let port = parsed
        .port()
        .map(|value| format!(":{value}"))
        .unwrap_or_default();
    format!(
        "{}://{}{}{}",
        parsed.scheme().to_lowercase(),
        host.to_lowercase(),
        port,
        parsed.path()
    )
}

pub fn domain_from_url(value: &str) -> String {
    let normalized = normalize_website(value);
    Url::parse(&normalized)
        .ok()
        .and_then(|url| url.host_str().map(str::to_lowercase))
        .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
        .unwrap_or_default()
}

pub fn slug(value: &str) -> String {
    let mut output = String::new();
    let mut separator = false;
    for character in value.trim().to_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character);
            separator = false;
        } else if !separator && !output.is_empty() {
            output.push('-');
            separator = true;
        }
    }
    output.trim_matches('-').to_string()
}

pub fn company_from_domain(domain: &str) -> String {
    domain
        .split('.')
        .next()
        .unwrap_or("")
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(title_case)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "y"
    )
}

pub fn bool_text(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}

fn has_scheme(value: &str) -> bool {
    let Some(position) = value.find("://") else {
        return false;
    };
    let scheme = &value[..position];
    !scheme.is_empty()
        && scheme.chars().enumerate().all(|(index, character)| {
            if index == 0 {
                character.is_ascii_alphabetic()
            } else {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '.' | '-')
            }
        })
}
