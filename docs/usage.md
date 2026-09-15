# CLI and configuration

## Commands

`domain-review review DOMAIN --authorized [--output DIRECTORY] [--timeout SECONDS] [--retries COUNT]`

- DOMAIN accepts a bare hostname or HTTP(S) root URL. Credentials, custom ports, paths, query strings, and fragments are rejected.
- `--authorized` is required before any review network work.
- `--output` defaults to `reports/latest` and must not already exist.
- `--timeout` defaults to 15 seconds, range 1–120, per operation.
- `--retries` defaults to 1, range 0–3.

`domain-review diff --previous FILE.csv --current FILE.csv --output FILE.jsonl`

Diff is offline. Both inputs must exist and the output must be new. It compares assessment fields and evidence; use CSV files produced by this harness.

`domain-review --help`, `domain-review review --help`, and `domain-review --version` are available without network access.

## Dashboard

`domain-review serve --reports reports --port 8787` starts the read-only local results UI. See [dashboard guide](dashboard.md).

## Environment

| Variable | Behavior |
| --- | --- |
| `DOMAIN_REVIEW_BROWSER_FALLBACK` | Set to `0`, `false`, or `no` to disable browser fallback. Otherwise enabled when a compatible browser is found. |
| `DOMAIN_REVIEW_CHROMIUM_PATH` | Explicit Chrome/Chromium executable; otherwise common paths are tried. |
| `DOMAIN_REVIEW_OPENSSL` | Alternate executable for OpenSSL HTTP fallback. Other TLS checks still invoke `openssl` from PATH. |
| `DOMAIN_REVIEW_RUN_BROWSER_TESTS` | Opt into browser-dependent tests; requires installed Chromium. |

No API keys are required. Dependencies are downloaded during the initial Cargo build; domain review itself needs network access.

## Exit behavior

Exit 0 means the command wrote its result successfully, not that the site is secure or every check completed. Network errors and incomplete checks can be represented inside an otherwise successful assessment. CLI validation and file errors return nonzero. The CLI has no severity-based CI failure threshold yet.

Ctrl-C interrupts the process. Interrupted runs may leave an empty or partial output directory; inspect it and choose a new directory for a rerun. There is no resume feature or overall deadline in this extracted CLI.
