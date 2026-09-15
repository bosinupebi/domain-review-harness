//! Read-only loopback dashboard for local reports.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};
use tiny_http::{Header, Method, Response, Server};

pub fn runs(root: &Path) -> Result<Value> {
    let root = root
        .canonicalize()
        .context("reports directory must exist")?;
    let mut runs = Vec::new();
    let mut errors = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        let read = || -> Result<Value> {
            let file = entry.path().join("assessment.json").canonicalize()?;
            ensure!(
                file.starts_with(&root),
                "report symlink escapes reports directory"
            );
            ensure!(
                fs::metadata(&file)?.len() <= 5_000_000,
                "assessment exceeds 5 MB"
            );
            let assessment: crate::Row = serde_json::from_slice(&fs::read(file)?)?;
            let evidence = crate::evidence::records(&assessment);
            Ok(json!({"id": id, "assessment": assessment, "evidence": evidence}))
        };
        match read() {
            Ok(run) => runs.push(run),
            Err(error) => errors.push(json!({"id": id, "error": error.to_string()})),
        }
    }
    runs.sort_by(|a, b| {
        b["assessment"]["checked_at"]
            .as_str()
            .cmp(&a["assessment"]["checked_at"].as_str())
    });
    Ok(json!({"runs": runs, "errors": errors}))
}
pub fn serve(root: &Path, port: u16) -> Result<()> {
    ensure!(
        root.is_dir(),
        "reports directory must exist; run a review first or create the directory"
    );
    let server = Server::http(("127.0.0.1", port)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let expected_host = format!("127.0.0.1:{port}");
    eprintln!("Dashboard: http://{expected_host} (Ctrl-C to stop)");
    for request in server.incoming_requests() {
        let valid_host = request
            .headers()
            .iter()
            .any(|h| h.field.equiv("Host") && h.value.as_str() == expected_host);
        let (status, content_type, body) = if !valid_host {
            (403, "text/plain", "Use the printed loopback URL".into())
        } else if request.method() != &Method::Get {
            (405, "text/plain", "Read-only dashboard".into())
        } else {
            match request.url() {
                "/" => (
                    200,
                    "text/html; charset=utf-8",
                    include_str!("../ui/index.html").to_string(),
                ),
                "/app.js" => (
                    200,
                    "text/javascript; charset=utf-8",
                    include_str!("../ui/app.js").to_string(),
                ),
                "/style.css" => (
                    200,
                    "text/css; charset=utf-8",
                    include_str!("../ui/style.css").to_string(),
                ),
                "/api/runs" => match runs(root) {
                    Ok(data) => (200, "application/json", data.to_string()),
                    Err(e) => (
                        500,
                        "application/json",
                        json!({"error":e.to_string()}).to_string(),
                    ),
                },
                _ => (404, "text/plain", "Not found".into()),
            }
        };
        let response = Response::from_string(body).with_status_code(status)
            .with_header(Header::from_bytes("Content-Type", content_type).unwrap())
            .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
            .with_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap())
            .with_header(Header::from_bytes("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'").unwrap());
        let _ = request.respond(response);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loads_valid_runs_and_reports_invalid_runs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("valid")).unwrap();
        fs::write(
            temp.path().join("valid/assessment.json"),
            r#"{"domain":"example.com","hsts":"true"}"#,
        )
        .unwrap();
        fs::create_dir(temp.path().join("broken")).unwrap();
        fs::write(temp.path().join("broken/assessment.json"), "invalid").unwrap();
        let result = runs(temp.path()).unwrap();
        assert_eq!(result["runs"].as_array().unwrap().len(), 1);
        assert_eq!(result["errors"].as_array().unwrap().len(), 1);
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "{}").unwrap();
        fs::create_dir(temp.path().join("run")).unwrap();
        std::os::unix::fs::symlink(outside.path(), temp.path().join("run/assessment.json"))
            .unwrap();
        assert_eq!(
            runs(temp.path()).unwrap()["runs"].as_array().unwrap().len(),
            0
        );
    }
}
