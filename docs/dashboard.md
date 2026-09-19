# Local results dashboard

After building, start the dashboard from the repository root:

```bash
bankai serve --reports reports --port 8787
```

`bankai --domain your-company.example` starts this dashboard automatically. Open **http://127.0.0.1:8787** using the exact printed address while the review is running or after it completes. The dashboard refreshes saved runs every 10 seconds. The standalone `serve` command is useful for reopening an existing history. The reports directory must exist for `serve`; create it with `mkdir -p reports` for an empty workspace. Stop either command with Ctrl-C.

## Review workflow

1. Select a saved run in the sidebar; search by domain or folder name.
2. Check score, risk, finding count, and review status. “Recorded” means a reachable response was recorded; it does not mean the checks passed.
3. Filter findings by severity and expand one to see confidence, evidence URL, timestamp, method, and available response metadata.
4. Use All fields to inspect errors, unknown states, and complete assessment values.
5. Use Compare runs to select another run of the same domain. This view shows changed field values, including timestamps; it does not label every change as improvement or regression.
6. Export JSON for local analysis or click Refresh runs after a CLI review completes.

Evidence links open the target in a new tab and make a normal browser request. Review your scope before following them.

## Storage and operation

The server reads immediate child directories containing `assessment.json`, such as `reports/example-com-20260919T143000Z/assessment.json`. One-line Bankai reviews automatically create and retain these folders. While a review is in progress, its `run.json` status makes it visible as `Running` before results are written; a failed run is retained with its failed status. It recomputes displayed evidence from each completed assessment using the current engine. The original `evidence.jsonl` remains the historical export; the dashboard does not read manual edits to that file. Keep the harness version consistent when comparing results.

Malformed/missing assessments appear as warnings while valid runs remain usable. Files larger than 5 MB and report symlinks outside the reports root are rejected. Nested directories are not recursively discovered. All runs are loaded into memory, so use a focused reports directory for large archives.

The dashboard is read-only and does not launch scans or edit findings. It binds only to IPv4 loopback, validates the Host header, serves no arbitrary filesystem paths, and has no external assets or analytics. Report strings are rendered as text, not HTML. There is no authentication: keep this on a trusted local machine and do not expose it through a proxy/tunnel. Anyone able to access the local service can read its reports.

## UI development

The interface is framework-free HTML/CSS/JavaScript in `ui/` and embedded in the Rust binary at build time. Rebuild after changing assets. The server lives in `src/dashboard.rs`. There is no Node.js dependency for running the dashboard. Use semantic controls, keyboard focus indicators, responsive layouts, and text-safe DOM APIs for all report content.
