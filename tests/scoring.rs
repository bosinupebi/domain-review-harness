use domain_review_harness::Row;
use domain_review_harness::scoring::compute_score;

#[test]
fn missing_dmarc_recommends_email_offer() {
    let row = Row::from([
        ("reachable".into(), "true".into()),
        ("https".into(), "true".into()),
        ("tls_valid".into(), "true".into()),
        ("hsts".into(), "true".into()),
        ("csp".into(), "true".into()),
        ("x_frame_options".into(), "true".into()),
        ("spf".into(), "true".into()),
        ("dmarc".into(), "false".into()),
    ]);
    let (score, _, notes, offer) = compute_score(&row);
    assert!(score < 100);
    assert!(notes.contains("DMARC"));
    assert_eq!(offer, "Email fraud protection setup");
}

#[test]
fn confirmed_source_exposure_has_large_penalty() {
    let row = Row::from([
        ("reachable".into(), "true".into()),
        ("https".into(), "true".into()),
        ("tls_valid".into(), "true".into()),
        ("hsts".into(), "true".into()),
        ("csp".into(), "true".into()),
        ("x_frame_options".into(), "true".into()),
        ("spf".into(), "true".into()),
        ("dmarc".into(), "true".into()),
        ("source_control_exposed".into(), "true".into()),
    ]);
    let (score, risk, _, offer) = compute_score(&row);
    assert!(score <= 65);
    assert!(matches!(risk.as_str(), "medium" | "high"));
    assert_eq!(offer, "Website source exposure review");
}
