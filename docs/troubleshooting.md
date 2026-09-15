# Troubleshooting

- **Cargo or linker missing:** install stable Rust and platform build tools. Use the committed Cargo.lock with `--locked`.
- **DNS/TLS fields incomplete:** confirm `dig` and `openssl` are executable on PATH. Inspect assessment errors. Missing tooling must not be interpreted as a secure configuration.
- **Verification page:** install Chromium or provide `DOMAIN_REVIEW_CHROMIUM_PATH`. A persistent challenge remains unknown; the tool does not solve CAPTCHAs.
- **Review takes a long time:** many sequential probes have their own timeout and retries. Reduce `--timeout`/`--retries`, or interrupt with Ctrl-C. There is no global deadline.
- **Output exists:** choose a new output directory. Preserve earlier evidence for comparison.
- **Unexpected finding:** reproduce within the approved scope and submit a sanitized synthetic fixture with the expected behavior. Do not post a live secret or customer report.
- **Corporate proxy/firewall:** confirm outbound DNS, HTTPS, and the documented optional services are permitted. A blocked request is not proof of a target vulnerability.
