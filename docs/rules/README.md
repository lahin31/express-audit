# Rule Reference

Complete documentation for all express-audit rules.

## Authentication

| Rule | Severity | Title |
|------|----------|-------|
| [JWT001](./JWT001.md) | 🔴 Critical | Hardcoded JWT Secret |
| [JWT002](./JWT002.md) | ⚠️ High | JWT Missing Expiration |
| [AUTH001](./AUTH001.md) | ⚠️ High | Weak bcrypt Cost Factor |
| AUTH002 | 🔴 Critical | Plaintext Password Comparison |

## Authorization

| Rule | Severity | Title |
|------|----------|-------|
| [AUTHZ001](./AUTHZ001.md) | ⚠️ High | Sensitive Route Missing Authentication |
| AUTHZ002 | 🔴 Critical | Admin Route Unprotected |

## Input Validation

| Rule | Severity | Title |
|------|----------|-------|
| VAL001 | 📋 Medium | Unvalidated Request Body |
| VAL002 | 📋 Medium | Unvalidated Query Parameters |

## SQL Security

| Rule | Severity | Title |
|------|----------|-------|
| [SQL001](./SQL001.md) | 🔴 Critical | SQL Injection Risk |
| SQL002 | ⚠️ High | Unsafe Prisma Raw Query |

## HTTP Security

| Rule | Severity | Title |
|------|----------|-------|
| [HTTP001](./HTTP001.md) | ⚠️ High | Helmet Middleware Missing |
| [CSP001](./CSP001.md) | 📋 Medium | Missing Content Security Policy |
| HEADER001 | ℹ️ Low | X-Powered-By Header Enabled |

## Cookies & Sessions

| Rule | Severity | Title |
|------|----------|-------|
| [COOKIE001](./COOKIE001.md) | ⚠️ High | Insecure Cookie Configuration |
| [SESSION001](./SESSION001.md) | 🔴 Critical / ⚠️ High | Insecure Session Configuration |

## CORS

| Rule | Severity | Title |
|------|----------|-------|
| [CORS001](./CORS001.md) | ⚠️ High | CORS Wildcard Origin |

## Rate Limiting

| Rule | Severity | Title |
|------|----------|-------|
| [RATE001](./RATE001.md) | 📋 Medium | No Rate Limiting Detected |

## Secrets

| Rule | Severity | Title |
|------|----------|-------|
| [SECRET001–010](./SECRET001.md) | 🔴 Critical / ⚠️ High | Hardcoded Secrets (AWS, Google, Stripe, GitHub, PEM, DB…) |

## Logging

| Rule | Severity | Title |
|------|----------|-------|
| [LOG001](./LOG001.md) | ⚠️ High | Sensitive Data in Logs |
| LOG002 | 📋 Medium | Logging Request Body |
| LOG003 | 📋 Medium | Stack Trace Exposed to Client |

## Error Handling

| Rule | Severity | Title |
|------|----------|-------|
| [ERR001](./ERR001.md) | 📋 Medium | Raw Error Object Returned to Client |
| ERR002 | 📋 Medium | No Global Error-Handler Middleware |

## OAuth

| Rule | Severity | Title |
|------|----------|-------|
| [OAUTH001](./OAUTH001.md) | ⚠️ High | Missing PKCE in OAuth Flow |
| OAUTH002 | ⚠️ High | Missing OAuth State Validation |
| OAUTH003 | 📋 Medium | Overly Broad OAuth Scopes |

## Google CASA Readiness

> These checks indicate potential CASA readiness issues detectable via static analysis. Passing does not guarantee passing a full Google CASA assessment.

| Rule | Severity | Title |
|------|----------|-------|
| [CASA001](./CASA001.md) | 🔴 Critical | Refresh Token Stored Insecurely |
| CASA002 | ⚠️ High | Missing OAuth Token Revocation |
| CASA003 | 🔴 Critical | OAuth Credentials in Logs |
| CASA004 | 📋 Medium | Missing Audit Logging for OAuth Events |
| CASA005 | ⚠️ High | Missing Nonce Validation |

## Production Readiness

| Rule | Severity | Title |
|------|----------|-------|
| PROD001 | ℹ️ Low | Missing Health Check Endpoint |
| PROD002 | ℹ️ Low | Missing Graceful Shutdown |
| PROD003 | 📋 Medium | Missing Trust Proxy Configuration |
| PROD004 | ℹ️ Low | Compression Middleware Missing |

## Docker

| Rule | Severity | Title |
|------|----------|-------|
| [DOCKER001](./DOCKER001.md) | ⚠️ High | Container Running as Root |
| DOCKER002 | 📋 Medium | Using Latest Tag |
| DOCKER003 | ℹ️ Low | Missing HEALTHCHECK |
| DOCKER004 | 🔴 Critical | Secrets in Dockerfile |
| DOCKER005 | ℹ️ Low | COPY . . in Dockerfile |

---

## Severity Legend

| Icon | Level | Score Impact |
|------|-------|-------------|
| 🔴 | Critical | −25 points |
| ⚠️ | High | −10 points |
| 📋 | Medium | −5 points |
| ℹ️ | Low | −2 points |
| 💡 | Info | −0 points |
