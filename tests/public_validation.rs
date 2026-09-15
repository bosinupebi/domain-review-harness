use domain_review_harness::deep_validation::{
    check_cors_open, classify_api_response, debug_terms_in_js, dom_xss_sinks_seen,
    extract_api_endpoints, extract_cloud_assets, extract_forms, extract_scripts,
    extract_type_count, indicates_data_leak, reflection_probe_url, same_origin_links,
    same_origin_script_urls, source_map_references,
};
use domain_review_harness::public_checks::{
    analyze_forms, cookie_flags, generator_meta, risk_terms_seen, secret_like_assignment_details,
    sees_canonical, sees_h1, sees_meta_description, sees_title, sees_viewport_meta,
    social_links_seen,
};
use std::collections::BTreeMap;

#[test]
fn same_origin_extractors_and_reflection_probe_match_expected_behavior() {
    let html = r#"
        <a href="/contact">Contact</a>
        <a href="https://example.com/contact">Duplicate</a>
        <a href="https://other.example/contact">External</a>
        <script src="/static/app.js"></script>
        <script src="https://cdn.example/app.js"></script>
    "#;
    assert_eq!(
        same_origin_links(html, "https://example.com/"),
        vec!["https://example.com/contact"]
    );
    assert_eq!(
        same_origin_script_urls(html, "https://example.com/"),
        vec!["https://example.com/static/app.js"]
    );
    assert_eq!(
        extract_scripts(html, "https://example.com/"),
        vec![
            "https://example.com/static/app.js",
            "https://cdn.example/app.js"
        ]
    );
    assert_eq!(
        reflection_probe_url("https://example.com/search?q=lagos#results"),
        "https://example.com/search?q=lagos&domain_review_probe=domain_review_probe_20260614#results"
    );
}

#[test]
fn api_classification_leak_detection_and_cors_match_expected_behavior() {
    assert_eq!(
        classify_api_response("application/json", r#"{"data": [{"id": 1}]}"#),
        "json_api"
    );
    assert_eq!(
        classify_api_response("text/html", "Swagger UI"),
        "documentation"
    );
    assert!(indicates_data_leak(
        r#"{"email": "person@example.com"}"#,
        ""
    ));
    assert!(!indicates_data_leak(
        r#"{"data": {"status": "ok", "count": 1}}"#,
        ""
    ));
    assert!(!indicates_data_leak(
        r#"{"id": 1, "status": "healthy"}"#,
        ""
    ));
    assert!(indicates_data_leak(
        r#"<?xml version="1.0"?><users><user><email>a@example.com</email></user></users>"#,
        "application/xml"
    ));
    assert!(check_cors_open(&BTreeMap::from([
        (
            "access-control-allow-origin".into(),
            "https://example.com".into()
        ),
        ("access-control-allow-credentials".into(), "true".into()),
    ])));
}

#[test]
fn cloud_assets_are_deduplicated_and_credentials_redacted() {
    let assets = extract_cloud_assets(
        r#"
        const bucket = "https://demo.s3.us-east-1.amazonaws.com/public.json";
        const bucketAgain = "https://demo.s3.us-east-1.amazonaws.com/public.json";
        const socket = "wss://socket.example.com/events";
        const internal = "http://192.168.1.10/admin";
        const apiKey = "abcdefghijklmnopqrstuvwx";
        const accessToken = "zyxwvutsrqponmlkjihgfedc";
        const cdn = "https://d111111abcdef8.cloudfront.net/app.js";
        "#,
    );
    assert_eq!(
        assets["s3_buckets"],
        vec!["https://demo.s3.us-east-1.amazonaws.com/public.json"]
    );
    assert_eq!(
        assets["websockets"],
        vec!["wss://socket.example.com/events"]
    );
    assert_eq!(assets["internal_urls"], vec!["http://192.168.1.10/admin"]);
    assert_eq!(assets["api_keys"], vec!["abcdefgh...uvwx"]);
    assert_eq!(assets["tokens"], vec!["zyxwvuts...fedc"]);
    assert_eq!(
        assets["cloudfront"],
        vec!["https://d111111abcdef8.cloudfront.net/app.js"]
    );
}

#[test]
fn graphql_forms_and_javascript_helpers_match_expected_behavior() {
    assert_eq!(
        extract_type_count(r#"{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"}]}}}"#),
        2
    );
    assert_eq!(extract_type_count("not-json"), 0);
    let forms = extract_forms(
        r#"<form action="/submit" method="post"><input name="csrf_token"><input type="password"></form>"#,
        "https://example.com/",
    );
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].action, "https://example.com/submit");
    assert_eq!(forms[0].method, "POST");
    assert!(forms[0].has_password);
    assert!(forms[0].has_csrf);
    assert!(extract_api_endpoints("fetch('/api/v1/users')").contains(&"/api/v1/users".into()));
    assert!(debug_terms_in_js("console.log('debug')").contains(&r"console.log \(".into()));
    assert_eq!(
        source_map_references("//# sourceMappingURL=app.js.map"),
        vec!["app.js.map"]
    );
    assert!(dom_xss_sinks_seen("element.innerHTML = location.hash"));
}

#[test]
fn homepage_source_helpers_match_expected_behavior() {
    let html = r#"
    <html>
      <head>
        <title>Example</title>
        <meta name="description" content="Example description">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="canonical" href="https://example.com">
        <meta name="generator" content="WordPress 6.5">
      </head>
      <body>
        <!-- TODO remove staging api_key before launch -->
        <h1>Example</h1>
        <a href="https://www.linkedin.com/company/example">LinkedIn</a>
        <form action="http://forms.example.net/submit"><input type="password"></form>
      </body>
    </html>
    "#;
    assert!(sees_title(html));
    assert!(sees_meta_description(html));
    assert!(sees_viewport_meta(html));
    assert!(sees_canonical(html));
    assert!(sees_h1(html));
    assert!(social_links_seen(&html.to_lowercase()).contains(&"linkedin".into()));
    assert_eq!(generator_meta(html), "WordPress 6.5");
    assert!(risk_terms_seen(html, false).contains(&"api_key".into()));
    let forms = analyze_forms(html, "https://example.com/");
    assert_eq!(forms["forms_count"], "1");
    assert_eq!(forms["password_field_seen"], "true");
    assert_eq!(forms["forms_over_https"], "insecure_form_action");

    let (seen, secure, httponly, same_site) =
        cookie_flags(&["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax".into()]);
    assert!(seen);
    assert_eq!(secure, Some(true));
    assert_eq!(httponly, Some(true));
    assert_eq!(same_site, Some(true));
}

#[test]
fn secret_assignment_details_preserve_names_and_values() {
    let details = secret_like_assignment_details(
        r#"
        const config = {
          password: window.appPassword,
          apiKey: "sk_test_12345",
          clientSecret: mySecretValue,
          privateKey: `-----BEGIN PRIVATE KEY-----`,
        };
        "#,
    );
    assert_eq!(
        details,
        vec![
            "apiKey=sk_test_12345",
            "privateKey=-----BEGIN PRIVATE KEY-----",
            "password=window.appPassword",
            "clientSecret=mySecretValue",
        ]
    );
}

#[test]
fn secret_assignment_details_ignore_client_side_helper_names() {
    let details = secret_like_assignment_details(
        r#"
        DOMTokenList = 1;
        DOMTokenList.prototype.toggle = function(value) { return value };
        tokenize = function(value) { return value.replace(/x/g, "y") };
        tokenizer = makeTokenizer();
        detokenize = function(value) { return value };
        tokensToFunction = L;
        tokensToRegExp = M;
        cancelToken = source.token;
        metaTokens = true;
        withXSRFToken = spelling("withXSRFToken");
        PASSWORD_RESET = "settings:password-reset";
        requestPasswordReset = handler;
        resetPassword = q;
        token = n;
        password = "";
        password = r;
        "#,
    );
    assert!(details.is_empty());
}

#[test]
fn secret_assignment_details_keep_real_credential_names() {
    let details = secret_like_assignment_details(
        r#"
        accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        refresh_token = "rt_live_1234567890abcdef";
        localStorage.token = c.accessToken;
        account_token = "NPS-91affff7";
        private_key = "-----BEGIN RSA PRIVATE KEY-----";
        "#,
    );
    assert!(details.contains(&"accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9".into()));
    assert!(details.contains(&"refresh_token=rt_live_1234567890abcdef".into()));
    assert!(details.contains(&"localStorage.token=c.accessToken".into()));
    assert!(details.contains(&"account_token=NPS-91affff7".into()));
    assert!(details.contains(&"private_key=-----BEGIN RSA PRIVATE KEY-----".into()));
}
