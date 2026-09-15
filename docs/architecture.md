# Architecture and extraction

This repository extracts the reusable Rust assessment engine from Kintsubyte's private lead-generation project at source revision `bb2ca6d5b6f99ce9fc1771d6948f424187fd927b`. It starts a new Git history and includes no campaign records, CRM state, generated outreach, original Git history, or private website assets.

## Components

- `src/main.rs`: standalone CLI, target validation, report writing, offline diff.
- `src/assessment.rs`: network checks, DNS/TLS, browser fallback, active discovery.
- `src/public_checks.rs` and `src/deep_validation.rs`: response parsing and detection helpers.
- `src/findings.rs`: severity classification and prioritization, extracted from the original brief-generation module; email generation removed.
- `src/evidence.rs`, `src/changes.rs`: evidence records and comparisons.
- `src/models.rs`, `src/validation_mapping.rs`: inherited assessment field contract.
- `src/scoring.rs`: heuristic score and suggested review areas.
- `src/io.rs`, `src/normalize.rs`: serialization and normalization.

The original campaign orchestration, collection integrations, CRM, email/proposal generation, Trivy workflow, and Python reference implementation are not included. The review engine retains legacy assessment field names so existing detection logic remains understandable. The standalone CLI runs one domain at a time.

## Extending a check

Add parsing logic with synthetic fixtures, connect it to the assessment pipeline, assign evidence/confidence conservatively, and document network effects in scope.md. A missing response should remain distinguishable from a confirmed negative. Keep detection and presentation separate. New active behavior needs explicit documentation and tests before it becomes a default.

## Dashboard

`src/dashboard.rs` serves embedded assets from `ui/` on loopback. The UI reads `/api/runs` and renders reports with text-safe DOM APIs. See [dashboard.md](dashboard.md) for storage and operational limits.
