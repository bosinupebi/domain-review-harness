use std::{fs, process::Command};
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bankai"))
}
#[test]
fn review_requires_authorization_before_creating_output() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("run");
    let result = cli()
        .args(["review", "example.com", "--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--authorized"));
}
#[test]
fn diff_uses_saved_assessments_and_refuses_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let before = temp.path().join("before.csv");
    let after = temp.path().join("after.csv");
    let output = temp.path().join("changes.jsonl");
    fs::write(&before, "domain,hsts\nexample.com,false\n").unwrap();
    fs::write(&after, "domain,hsts\nexample.com,true\n").unwrap();
    let run = || {
        cli()
            .arg("diff")
            .arg("--previous")
            .arg(&before)
            .arg("--current")
            .arg(&after)
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap()
    };
    assert!(run().status.success());
    let saved = fs::read_to_string(&output).unwrap();
    assert!(saved.contains("hsts"));
    assert!(!run().status.success());
    assert_eq!(fs::read_to_string(&output).unwrap(), saved);
}

#[test]
fn domain_cannot_be_combined_with_an_advanced_subcommand() {
    let result = cli()
        .args(["--domain", "example.com", "serve"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("cannot be used with a subcommand"));
}
