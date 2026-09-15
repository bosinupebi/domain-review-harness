use domain_review_harness::normalize::{
    company_from_domain, domain_from_url, normalize_website, slug,
};

#[test]
fn normalizes_and_extracts_domains() {
    assert_eq!(normalize_website("example.com/"), "https://example.com/");
    assert_eq!(
        normalize_website("www.example.com/path?x=1"),
        "https://www.example.com/path"
    );
    assert_eq!(
        domain_from_url("https://www.example.com/path"),
        "example.com"
    );
    assert_eq!(company_from_domain("great-school.com.ng"), "Great School");
}

#[test]
fn creates_stable_slugs() {
    assert_eq!(slug("Example & Sons Ltd."), "example-sons-ltd");
}
