# Reading results

Each review writes:

| File | Purpose |
| --- | --- |
| `report.md` | Short prioritized findings for a human reviewer. |
| `assessment.json` | Complete field/value assessment; values are strings. |
| `assessment.csv` | The same row as CSV for spreadsheets and offline comparisons. |
| `evidence.jsonl` | One evidence object per finding. |

Assessment field lists live in `src/models.rs`; runtime checks may add fields. Consumers should tolerate unknown fields. This pre-1.0 schema may change; pin a commit for stable automation.

## Review order

1. Read `error`, `validation_notes`, reachability fields, and browser fallback details. A blocked challenge or timeout is not evidence that the site is down.
2. Confirm the final URL and timestamp correspond to the intended system.
3. Review evidence URLs, detection method, confidence, and severity before making changes.
4. Reproduce suspected exposure within your authorized scope and determine whether the content is actually sensitive.
5. Remediate, rerun into a new directory, and compare assessments.

Evidence objects include `finding_id`, `domain`, `company`, `severity`, `confidence`, `finding`, `evidence_url`, `observed_at`, `http_status`, `response_sha256`, `detection_method`, and `manual_review_status`. Missing values do not establish that a check passed. Hash fields and evidence links reflect the inherited evidence mapping; not every finding has a separately captured response body.

## Interpretation limits

The score is a heuristic from 0 to 100, where higher is better. Risk labels are low at 80+, medium at 60–79, and high below 60. It mixes security and trust/maintenance observations; it is not CVSS or a compliance score. `recommended_offer` is a legacy field containing a suggested review area, not a paid-service requirement. Other legacy company/contact fields remain for schema compatibility.

API routes, login pages, missing headers, source maps, and JavaScript sink patterns are not by themselves exploitable vulnerabilities. A sensitive-path response needs a matching content signature; HTTP 200 alone is insufficient. False positives and missed findings remain possible. No findings does not establish security.

Diff emits JSON Lines for added, removed, or changed assessments and evidence metadata. Disappearing evidence may mean a fix, a timeout, or a changed response; confirm manually.

## Synthetic examples

`examples/before.csv` and `examples/after.csv` illustrate the offline comparison without contacting any domain:

```bash
cargo run --locked -- diff --previous examples/before.csv --current examples/after.csv --output reports/example-diff.jsonl
```
