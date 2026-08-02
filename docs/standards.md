# Standards & Authoritative References

Every express-audit rule is grounded in at least one published standard, RFC, or authoritative
guidance document. This page lists the exact references for each rule so you know the findings
are not invented — they map directly to recognized security requirements.

Rules that carry a Google CASA reference are part of the CASA Readiness category. Static analysis
can only cover the subset of CASA requirements that are verifiable from source code. All other
CASA requirements — organizational controls, infrastructure review, and penetration testing —
require manual assessment.

---

## Authentication

### JWT001 — Hardcoded JWT Secret

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A07: Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| OWASP ASVS v4.0 | [V2.10: Service Authentication](https://owasp.org/www-project-application-security-verification-standard/) |
| RFC 8725 | [JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725) |
| CWE | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |
| OWASP | [Use of Hard-coded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password) |

### JWT002 — JWT Missing Expiration

| Standard | Reference |
|---|---|
| RFC 7519 | [JWT Claims — exp (§4.1.4)](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4) |
| RFC 8725 | [JWT Best Current Practices §3.9](https://www.rfc-editor.org/rfc/rfc8725#section-3.9) |
| OWASP ASVS v4.0 | [V3.5: Token-based Sessions](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) |
| CWE | [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) |

### AUTH001 — Weak bcrypt Cost Factor

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| OWASP ASVS v4.0 | [V2.4: Credential Storage](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| CWE | [CWE-916: Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html) |

### AUTH002 — Plaintext Password Comparison

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| OWASP ASVS v4.0 | [V2.4: Credential Storage](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| CWE | [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html) |
| CWE | [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html) |

---

## Authorization

### AUTHZ001 — Sensitive Route Missing Authentication

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| OWASP ASVS v4.0 | [V4.1: General Access Control](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
| CWE | [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) |

### AUTHZ002 — Admin Route Unprotected

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| OWASP ASVS v4.0 | [V4.2: Operation Level Access Control](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) |
| CWE | [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) |

---

## CORS

### CORS001 — CORS Wildcard Origin

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP ASVS v4.0 | [V14.4: HTTP Security Headers](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny) |
| W3C | [Cross-Origin Resource Sharing Specification](https://www.w3.org/TR/cors/) |
| MDN | [Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) |
| CWE | [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html) |
| Express | [CORS Middleware](https://expressjs.com/en/resources/middleware/cors.html) |

---

## Cookies & Sessions

### COOKIE001 — Insecure Cookie Configuration

| Standard | Reference |
|---|---|
| OWASP ASVS v4.0 | [V3.4: Cookie-based Session Management](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP Top 10 2021 | [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP | [Secure Cookie Attribute](https://owasp.org/www-community/controls/SecureCookieAttribute) |
| RFC 6265 | [HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265) |
| MDN | [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| CWE | [CWE-1004: Sensitive Cookie Without HttpOnly Flag](https://cwe.mitre.org/data/definitions/1004.html) |
| CWE | [CWE-614: Sensitive Cookie Without Secure Attribute](https://cwe.mitre.org/data/definitions/614.html) |
| Express | [res.cookie() Documentation](https://expressjs.com/en/api.html#res.cookie) |

### SESSION001 — Insecure Session Configuration

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A07: Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| OWASP ASVS v4.0 | [V3.2: Session Binding](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| CWE | [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html) |
| CWE | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |

---

## HTTP Security

### HTTP001 — Helmet Middleware Missing

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP ASVS v4.0 | [V14.4: HTTP Security Headers](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Secure Headers Project](https://owasp.org/www-project-secure-headers/) |
| Express | [Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html) |
| Helmet.js | [Documentation](https://helmetjs.github.io/) |

### CSP001 — Missing Content Security Policy

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A03: Injection (XSS)](https://owasp.org/Top10/A03_2021-Injection/) |
| OWASP ASVS v4.0 | [V14.4.6: Content Security Policy](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) |
| W3C | [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) |
| MDN | [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) |

### HEADER001 — X-Powered-By Header Enabled

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP ASVS v4.0 | [V14.3: Unintended Security Disclosure](https://owasp.org/www-project-application-security-verification-standard/) |
| CWE | [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html) |
| Express | [Security Best Practices – Disable X-Powered-By](https://expressjs.com/en/advanced/best-practice-security.html) |

---

## Secrets

### SECRET001–010 — Hardcoded Credentials & API Keys

Covers: AWS keys, Google API keys, Stripe keys, GitHub tokens, PEM private keys, database
connection strings, SendGrid API keys, and generic hardcoded passwords.

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| OWASP ASVS v4.0 | [V2.10: Service Authentication Secrets](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Use of Hard-coded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password) |
| CWE | [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) |
| CWE | [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html) |

---

## Input Validation

### PP001 — Prototype Pollution via Object Merge

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A03: Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| OWASP ASVS v4.0 | [V5.1: Input Validation](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Prototype Pollution](https://owasp.org/www-community/vulnerabilities/Prototype_Pollution) |
| CWE | [CWE-1321: Improperly Controlled Modification of Object Prototype](https://cwe.mitre.org/data/definitions/1321.html) |
| Snyk | [Prototype Pollution Guide](https://learn.snyk.io/lesson/prototype-pollution/) |

### INJECT001 — Code Injection via eval or new Function

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A03: Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| OWASP ASVS v4.0 | [V5.2: Sanitization and Sandboxing](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Code Injection](https://owasp.org/www-community/attacks/Code_Injection) |
| CWE | [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html) |
| CWE | [CWE-95: Improper Neutralization of Directives in eval()](https://cwe.mitre.org/data/definitions/95.html) |
| Node.js | [vm Module Documentation](https://nodejs.org/api/vm.html) |

---

## SQL Security

### SQL001 — SQL Injection Risk

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A03: Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| OWASP ASVS v4.0 | [V5.3: Output Encoding and Injection Prevention](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) |
| OWASP | [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) |
| CWE | [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) |

### SQL002 — Unsafe Prisma Raw Query

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A03: Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| CWE | [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) |
| Prisma | [SQL Injection Prevention](https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access#sql-injection-prevention) |

---

## Logging

### LOG001 — Sensitive Data in Logs

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| OWASP ASVS v4.0 | [V7.1: Log Content Requirements](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| CWE | [CWE-532: Information Exposure Through Log Files](https://cwe.mitre.org/data/definitions/532.html) |

### LOG002 — Logging Request Body

| Standard | Reference |
|---|---|
| OWASP ASVS v4.0 | [V7.1: Log Content Requirements](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| CWE | [CWE-532: Information Exposure Through Log Files](https://cwe.mitre.org/data/definitions/532.html) |

### LOG003 — Stack Trace Exposed to Client

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP ASVS v4.0 | [V7.4: Error Handling](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling) |
| CWE | [CWE-209: Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) |

### SEC001 — Sensitive Data in HTTP Response

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| OWASP ASVS v4.0 | [V8.3: Sensitive Private Data](https://owasp.org/www-project-application-security-verification-standard/) |
| CWE | [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html) |

---

## Error Handling

### ERR001 — Raw Error Object Returned to Client

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP ASVS v4.0 | [V7.4: Error Handling](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling) |
| CWE | [CWE-209: Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) |

### ERR002 — No Global Error-Handler Middleware

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP ASVS v4.0 | [V7.4: Error Handling](https://owasp.org/www-project-application-security-verification-standard/) |
| CWE | [CWE-390: Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html) |
| Express | [Error Handling Guide](https://expressjs.com/en/guide/error-handling.html) |

---

## Rate Limiting

### RATE001 — No Rate Limiting Detected

| Standard | Reference |
|---|---|
| OWASP API Security 2023 | [API4: Unrestricted Resource Consumption](https://owasp.org/www-project-api-security/) |
| OWASP ASVS v4.0 | [V13.2.6: Rate Limiting](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) |
| CWE | [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html) |
| Express | [Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html) |

---

## OAuth

### OAUTH001 — Missing PKCE in OAuth Flow

| Standard | Reference |
|---|---|
| RFC 7636 | [Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636) |
| RFC 6749 | [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749) |
| OAuth 2.0 Security BCP | [draft-ietf-oauth-security-topics](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) |
| OWASP ASVS v4.0 | [V3.5 / V8.3: Token-based Sessions](https://owasp.org/www-project-application-security-verification-standard/) |
| Google CASA | [CASA Requirements](https://appdefensealliance.dev/casa) |

### OAUTH002 — Missing OAuth State Validation

| Standard | Reference |
|---|---|
| RFC 6749 §10.12 | [CSRF — State Parameter](https://www.rfc-editor.org/rfc/rfc6749#section-10.12) |
| OAuth 2.0 Security BCP §4.7 | [CSRF](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.7) |
| OWASP ASVS v4.0 | [V13.2: RESTful Web Service](https://owasp.org/www-project-application-security-verification-standard/) |
| OWASP | [CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) |
| Google CASA | [CASA Requirements](https://appdefensealliance.dev/casa) |

### OAUTH003 — Overly Broad OAuth Scopes

| Standard | Reference |
|---|---|
| RFC 6749 §3.3 | [Access Token Scope](https://www.rfc-editor.org/rfc/rfc6749#section-3.3) |
| OAuth 2.0 Security BCP | [Scope](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) |
| OWASP Top 10 2021 | [A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) |
| OWASP | [OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html) |
| Google | [OAuth Scopes Best Practices](https://developers.google.com/identity/protocols/oauth2/scopes) |

---

## Google CASA Readiness

All CASA rules share these base references. Additional per-rule references are noted where applicable.

| Standard | Reference |
|---|---|
| Google CASA | [CASA Requirements](https://appdefensealliance.dev/casa) |
| OWASP ASVS v4.0 | [Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) |
| RFC 6749 | [The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749) |
| RFC 7636 | [Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636) |
| RFC 7009 | [OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009) |
| OpenID Connect Core 1.0 | [Specification](https://openid.net/specs/openid-connect-core-1_0.html) |

### CASA001 — Refresh Token Stored Insecurely
Additional: OWASP Top 10 2021 [A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

### CASA002 — Missing OAuth Token Revocation
Additional: [RFC 7009 – OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)

### CASA003 — OAuth Credentials in Logs
Additional: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) · [CWE-532](https://cwe.mitre.org/data/definitions/532.html)

### CASA004 — Missing Audit Logging for OAuth Events
Additional: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) · OWASP ASVS v4.0 V7.2

### CASA005 — Missing Nonce Validation
Additional: [OpenID Connect Core 1.0 – Nonce](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes) · [OAuth 2.0 Security BCP – Replay Prevention](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---

## Performance

### PERF001 — N+1 Query in Loop

| Standard | Reference |
|---|---|
| OWASP API Security 2023 | [API4: Unrestricted Resource Consumption](https://owasp.org/www-project-api-security/) |
| CWE | [CWE-1176: Inefficient CPU Computation](https://cwe.mitre.org/data/definitions/1176.html) |
| Prisma | [Query Optimization and N+1](https://www.prisma.io/docs/guides/performance-and-optimization/query-optimization-performance) |

---

## Production Readiness

### PROD001–PROD004 — Health Check, Graceful Shutdown, Trust Proxy, Compression

| Standard | Reference |
|---|---|
| OWASP ASVS v4.0 | [V14.5: HTTP Request Header Validation](https://owasp.org/www-project-application-security-verification-standard/) |
| Express | [Health Checks and Graceful Shutdown](https://expressjs.com/en/advanced/healthcheck-graceful-shutdown.html) |
| Express | [Behind Proxies](https://expressjs.com/en/guide/behind-proxies.html) |
| Kubernetes | [Liveness and Readiness Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/) |

---

## Docker

### DOCKER001–DOCKER005 — Container Security

| Standard | Reference |
|---|---|
| OWASP Top 10 2021 | [A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) |
| OWASP | [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) |
| CWE | [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html) |
| Docker | [Security Best Practices](https://docs.docker.com/develop/security-best-practices/) |
| Docker | [Dockerfile Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/) |
| Docker | [Docker Secrets](https://docs.docker.com/engine/swarm/secrets/) |

---

## Standards Index

A quick reference to the standards bodies and frameworks cited across all rules.

| Standard | Scope | URL |
|---|---|---|
| OWASP Top 10 2021 | Web application risk ranking | https://owasp.org/Top10/ |
| OWASP API Security Top 10 | API-specific risk ranking | https://owasp.org/www-project-api-security/ |
| OWASP ASVS v4.0 | Detailed security requirements | https://owasp.org/www-project-application-security-verification-standard/ |
| OWASP Cheat Sheet Series | Implementation guidance | https://cheatsheetseries.owasp.org/ |
| RFC 6265 | HTTP cookies | https://www.rfc-editor.org/rfc/rfc6265 |
| RFC 6749 | OAuth 2.0 framework | https://www.rfc-editor.org/rfc/rfc6749 |
| RFC 7009 | OAuth 2.0 token revocation | https://www.rfc-editor.org/rfc/rfc7009 |
| RFC 7519 | JSON Web Tokens | https://www.rfc-editor.org/rfc/rfc7519 |
| RFC 7636 | PKCE for OAuth | https://www.rfc-editor.org/rfc/rfc7636 |
| RFC 8725 | JWT best current practices | https://www.rfc-editor.org/rfc/rfc8725 |
| OAuth 2.0 Security BCP | Security guidance for OAuth 2.0 | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics |
| OpenID Connect Core 1.0 | Identity layer on OAuth 2.0 | https://openid.net/specs/openid-connect-core-1_0.html |
| W3C CORS | Cross-origin resource sharing | https://www.w3.org/TR/cors/ |
| W3C CSP Level 3 | Content Security Policy | https://www.w3.org/TR/CSP3/ |
| CWE | Common Weakness Enumeration | https://cwe.mitre.org/ |
| Google CASA | Cloud Application Security Assessment | https://appdefensealliance.dev/casa |
| Express.js | Framework documentation | https://expressjs.com/ |
