# Security policy

Only the latest main branch is currently maintained; there are no supported versioned releases yet.

To report a vulnerability in this harness, use GitHub's private vulnerability reporting feature if available under the Security tab. Otherwise contact the owner privately using the contact route on https://github.com/bosinupebi and request a secure channel before sending sensitive details. Do not open an issue containing exploit details, secrets, or customer reports.

Include the affected commit, impact, minimal reproduction using synthetic/local data, and a proposed mitigation if known. Maintainers will assess the report and coordinate a fix; response times are best effort and there is no bounty program.

A vulnerability discovered in a reviewed domain belongs to that domain's owner. Follow their disclosure policy; do not post it in this project's tracker.

Run the harness in a trusted local environment. It fetches untrusted content, invokes system utilities, and can render pages with Chromium. Read docs/scope.md for the network boundary and data handling limitations.
