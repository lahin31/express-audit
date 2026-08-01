# Security Policy

## Supported Versions

express-audit follows semantic versioning. Security fixes are applied to the
latest minor release on the `main` branch. Older minor versions do not receive
backported patches.

| Version | Supported |
|---|---|
| 0.1.x (latest) | ✅ Active |
| < 0.1.x | ❌ No longer supported |

Once the project reaches 1.0.0, this table will be updated to reflect a formal
long-term support window.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you believe you have found a security vulnerability in express-audit, report
it privately so it can be assessed and patched before public disclosure.

### How to report

Open a [GitHub Security Advisory](https://github.com/JSExplore/express-audit/security/advisories/new)
on the repository. This is the preferred channel — it keeps the report private
and gives us a shared workspace to coordinate the fix.

If you are unable to use GitHub Security Advisories, email the maintainer
directly:

**Muhammad Lahin** — use the email address listed on the
[GitHub profile](https://github.com/lahin31).

### What to include

A useful report contains:

- A description of the vulnerability and the potential impact
- The version of express-audit affected
- A minimal reproduction — a code snippet, Dockerfile, or test case that
  demonstrates the issue
- Any suggested fix or mitigation, if you have one

### What to expect

| Step | Timeframe |
|---|---|
| Acknowledgement of your report | Within 72 hours |
| Initial assessment and severity triage | Within 7 days |
| Patch or mitigation published | Within 30 days for critical/high severity |
| Public disclosure | After patch is released |

If a reported issue turns out not to be a vulnerability, we will let you know
promptly and explain the reasoning.

---

## Responsible Disclosure

We ask that you:

- Give us reasonable time to investigate and fix the issue before disclosing it
  publicly or to third parties
- Avoid accessing, modifying, or deleting data that does not belong to you
  during testing
- Act in good faith — we will do the same

We commit to:

- Acknowledging your report promptly
- Keeping you informed of our progress
- Crediting you in the release notes when the fix is published, unless you
  prefer to remain anonymous
- Not pursuing legal action against researchers who follow this policy

---

## Scope

This policy covers the **express-audit npm package** and its source code in
the [JSExplore/express-audit](https://github.com/JSExplore/express-audit) repository.

Out of scope:

- Vulnerabilities in third-party dependencies (report those upstream; we track
  them via `npm audit`)
- Issues in example applications under `examples/` that are intentionally
  vulnerable for demonstration purposes
- General bugs that have no security impact (open a regular issue instead)

---

## Vulnerability Disclosure History

No vulnerabilities have been reported or disclosed to date.

This section will be updated with CVE identifiers and release links as the
project matures.

---

## Contact

Maintainer: **Muhammad Lahin**
Repository: [github.com/JSExplore/express-audit](https://github.com/JSExplore/express-audit)
Security Advisories: [github.com/JSExplore/express-audit/security/advisories](https://github.com/JSExplore/express-audit/security/advisories)
