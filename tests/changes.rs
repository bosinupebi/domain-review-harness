use domain_review_harness::Row;
use domain_review_harness::changes::compare;

#[test]
fn reports_security_regressions() {
    let previous = Row::from([
        ("domain".into(), "example.com".into()),
        ("hsts".into(), "true".into()),
    ]);
    let current = Row::from([
        ("domain".into(), "example.com".into()),
        ("hsts".into(), "false".into()),
    ]);
    let changes = compare(&[previous], &[current]);
    assert_eq!(changes[0].change_type, "changed");
    assert_eq!(changes[0].fields["hsts"]["before"], "true");
}

#[test]
fn reports_new_domain_with_checked_at() {
    let current = vec![Row::from([
        ("domain".into(), "new.example".into()),
        ("company".into(), "New Example".into()),
        ("checked_at".into(), "2026-06-21T12:00:00+00:00".into()),
    ])];
    let changes = compare(&[], &current);
    assert_eq!(changes[0].change_type, "new_assessment");
    assert_eq!(changes[0].checked_at, "2026-06-21T12:00:00+00:00");
    assert_eq!(changes[0].evidence_changed, None);
}
