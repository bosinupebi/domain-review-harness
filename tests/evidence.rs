use domain_review_harness::Row;
use domain_review_harness::evidence::{annotate, records};

#[test]
fn creates_confirmed_content_evidence() {
    let mut row = Row::from([
        ("domain".into(), "example.com".into()),
        ("company".into(), "Example".into()),
        ("source_control_exposed".into(), "true".into()),
        ("final_url".into(), "https://example.com/".into()),
    ]);
    let evidence = records(&row);
    assert_eq!(evidence[0].severity, "critical");
    assert_eq!(evidence[0].confidence, "confirmed");
    annotate(&mut row);
    assert_eq!(row["highest_finding_severity"], "critical");
    assert_eq!(row["manual_review_required"], "false");
}

#[test]
fn marks_source_pattern_for_review() {
    let mut row = Row::from([
        ("domain".into(), "example.com".into()),
        ("js_source_map_seen".into(), "true".into()),
    ]);
    annotate(&mut row);
    assert_eq!(row["manual_review_required"], "true");
    assert_eq!(row["manual_review_status"], "pending");
}
