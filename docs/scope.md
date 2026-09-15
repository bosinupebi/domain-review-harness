# Scope and network behavior

## Authorization

Run this tool only for domains and related infrastructure you own or have explicit permission to review. `--authorized` records your acknowledgement at invocation; it does not verify ownership or enforce a technical allowlist. Library callers are responsible for obtaining the same permission.

The inherited engine discovers related hosts and follows redirects. It is not restricted to an exact hostname. Do not run it where authorization covers only one URL or excludes the activities below. Shared hosting, CDN services, redirected hosts, and discovered subdomains can have separate owners.

## Requests performed

The engine retrieves the homepage, follows up to ten redirects, attempts HTTP/HTTPS transport variants, looks up DNS records through `dig`, and inspects TLS using OpenSSL. It reviews headers, cookies, forms, robots/sitemap, up to twelve same-origin JavaScript files, and up to eight representative pages.

It also probes configured source-control, environment, backup, admin, and API paths; sends GraphQL introspection; compares GET, HEAD, OPTIONS, and selected header variants; and may add a harmless reflection marker to a query URL. These requests can trigger monitoring alerts. A response body is bounded to 500,000 bytes, but there is no overall request budget or requests-per-second setting.

Certificate-transparency discovery queries the external `crt.sh` service, disclosing the target domain to that service. DNS queries use the machine's configured resolver. Related hosts can be contacted. FTP checks connect to port 21, attempt an anonymous login using a placeholder email, and try changing into common webroot directories. They do not upload or modify files.

Optional Chromium fallback renders recognizable verification pages. It can load third-party page resources and execute page JavaScript. It does not solve CAPTCHAs. Review browser behavior and your network policy before enabling it.

## Data handling

Reports are written locally. There is no report-upload or telemetry feature, but normal requests reveal your IP and user agent to contacted services. Evidence may contain URLs, contact addresses, infrastructure details, or sensitive excerpts. Some credential-like patterns are shortened; this is not a guarantee that every secret is redacted. Keep reports private and sanitize before sharing.

The tool is a local CLI, not a hosted multi-tenant scanner. It does not implement an SSRF boundary, an exact-host allowlist, or protection against malicious redirect destinations. Do not expose it as an unauthenticated web service.
