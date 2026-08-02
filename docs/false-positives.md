# False Positives & False Negatives

## What these terms mean

**False positive** — the tool flags something as a problem, but your code is actually fine.

Example: express-audit reports `JWT001 – Hardcoded JWT Secret` on a line that looks like a
secret but is actually a placeholder in a test file.

**False negative** — your code has a real security problem, but the tool stays silent.

Example: a JWT secret is stored in a variable defined at the top of the file, then passed
into `jwt.sign()`. The tool sees a variable reference, not a string, so it does not fire.

---

## Why every security tool has both

express-audit reads your source code without running it. It cannot follow values across
variable assignments, trace data through function calls, or read environment variables.
It only sees the code as text and structure.

That creates a trade-off:

- If the tool flags everything that *might* be a problem → lots of false positives, noisy, gets ignored
- If the tool only flags things it is *certain* about → some real problems get missed

**express-audit is tuned toward fewer false positives.** When a rule cannot say with
confidence that a vulnerability exists, it stays silent. That means you can trust the
findings that do appear — but it also means the tool is not a complete security audit.

---

## Rule by rule

For each rule: what the tool might get wrong, with plain examples.

---

### JWT001 — Hardcoded JWT Secret

**Might report when code is fine (false positive)**

Almost never. The rule only fires when `jwt.sign()` is called with a string typed
directly in the source code:

```js
// ✅ Will fire — this is a real problem
jwt.sign(payload, 'my-secret-key');

// ✅ Will NOT fire — value comes from environment
jwt.sign(payload, process.env.JWT_SECRET);
```

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — secret is in a variable, not a string literal
const SECRET = 'my-secret-key';
jwt.sign(payload, SECRET);

// ❌ Will NOT fire — custom wrapper function, not jwt.sign directly
signToken(payload, 'my-secret-key');

// ❌ Will NOT fire — imported under a different name
import j from 'jsonwebtoken';
j.sign(payload, 'my-secret-key');
```

---

### JWT002 — JWT Missing Expiration

**Might report when code is fine (false positive)**

```js
// This will NOT fire — options come from a variable, rule stays silent
const opts = { expiresIn: '15m' };
jwt.sign(payload, secret, opts);
```

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — expiry is set inside the payload, not as an option
jwt.sign({ exp: Math.floor(Date.now() / 1000) + 900, userId }, secret);

// ❌ Will NOT fire — expiry is in a variable
const opts = {};   // forgot expiresIn
jwt.sign(payload, secret, opts);
```

---

### AUTH001 — Weak bcrypt Cost Factor

**Might report when code is fine (false positive)**

None known. The rule only fires when the number is literally written in the code:
```js
bcrypt.hash(password, 8);   // fires — 8 is below 12
bcrypt.hash(password, 12);  // does not fire
bcrypt.hash(password, ROUNDS);  // does not fire — ROUNDS is a variable
```

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — cost factor is in a constant defined elsewhere
const BCRYPT_ROUNDS = 4;
bcrypt.hash(password, BCRYPT_ROUNDS);
```

---

### AUTH002 — Plaintext Password Comparison

**Might report when code is fine (false positive)**

```js
// May fire incorrectly — this is a config check, not a login check
if (config.password === 'dev-default') {
  enableDebugMode();
}
```

The rule matches any equality check involving a `.password` property, regardless of
context. A configuration password check, a test assertion, or a non-authentication
comparison can trigger it.

**Fix:** rename the property, or add `// express-audit-disable AUTH002` on the line.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — password copied into a local variable first
const inputPwd = req.body.password;
if (user.storedPwd === inputPwd) { ... }
```

---

### AUTHZ001 — Sensitive Route Missing Authentication

**Might report when code is fine (false positive)**

```js
// May fire — middleware name 'enforcePolicy' has no auth keywords
router.delete('/users/:id', enforcePolicy, handler);
```

If the middleware name does not contain words like `auth`, `guard`, `verify`, `token`,
`permission`, or `session`, and its definition is not in the same file, the rule may not
recognize it as authentication middleware.

**Fix:** rename it (`authEnforcePolicy`) or define it in the same file so the rule can
inspect its body.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — auth applied at router level, not on the individual route
router.use(authenticate);
router.delete('/users/:id', handler);  // looks unprotected to the rule
```

---

### AUTHZ002 — Admin Route Unprotected

**Might report when code is fine (false positive)**

```js
// May fire — auth is on the router, not visible on the individual route
adminRouter.use(authenticate, requireAdmin);
adminRouter.get('/users', handler);  // rule checks this line in isolation
```

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — path not in the known admin pattern list
router.get('/superadmin/settings', handler);
```

The rule looks for `/admin`, `/superuser`, `/internal`, `/management`, `/backoffice`.
Other admin paths are not covered.

---

### CORS001 — CORS Wildcard Origin

**Might report when code is fine (false positive)**

```js
// Will fire at medium severity — rule cannot evaluate the function body
cors({
  origin: (origin, callback) => {
    if (allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error('Not allowed'));
  }
});
```

Any function used as the `origin` value is flagged as "dynamic origin validation" at
medium severity, even when the logic inside is correct.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — wildcard set via environment variable
cors({ origin: process.env.CORS_ORIGIN });  // even if CORS_ORIGIN='*' at runtime
```

---

### COOKIE001 — Insecure Cookie Configuration

**Might report when code is fine (false positive)**

```js
// May fire — non-sensitive cookie does not need httpOnly or secure
res.cookie('theme', 'dark');  // no security flags
```

The rule fires for all `res.cookie()` calls regardless of what the cookie stores. A
preference or analytics cookie may not need all security flags.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — secure flag is a variable that evaluates to false at runtime
res.cookie('token', value, { httpOnly: true, secure: isSecure });
```

---

### SESSION001 — Insecure Session Configuration

**Might report when code is fine (false positive)**

```js
// Will fire at medium — saveUninitialized is missing (defaults to true in express-session)
session({ secret: process.env.SESSION_SECRET });
```

The express-session default for `saveUninitialized` is `true`, which is the less secure
option. The rule flags the omission. This is technically correct but may feel noisy if you
know the default.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — secret comes from an imported config object
session({ secret: config.sessionSecret });
```

---

### HTTP001 — Helmet Missing

**Might report when code is fine (false positive)**

Extremely unlikely. The rule scans every file in the project for a helmet import before
reporting. If helmet is imported anywhere — even in a dedicated middleware file — no finding
is raised.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — helmet applied at framework level without a direct JS import
// e.g. NestJS applying helmet internally, invisible to the file scanner
```

---

### SECRET001–010 — Hardcoded Credentials

**Might report when code is fine (false positive)**

```js
// May fire — realistic-looking placeholder in a non-fixture source file
const exampleKey = "AKIAIOSFODNN7EXAMPLE";

// May fire — variable named 'password' holding a non-secret value
const defaultPassword = 'ChangeMe123';
```

To suppress: put these in a file with `fixture`, `mock`, or `spec` in the filename, or
prefix/suffix with `.env` — those files are always skipped.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — secret split across concatenation
const key = "AKIA" + "IOSFODNN7EXAMPLE";

// ❌ Will NOT fire — secret is in git history but removed from current files
// Use trufflehog or git-secrets for history scanning
```

---

### SQL001 — SQL Injection Risk

**Might report when code is fine (false positive)**

None known. The rule requires both a query call (`.query()`, `.execute()`, `.run()`) AND
`req.body`, `req.query`, `req.params`, or `req.headers` directly in the same expression.
Two hardcoded strings joined with `+` will not fire.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — user input stored in a variable first
const id = req.params.id;
db.query('SELECT * FROM users WHERE id = ' + id);

// ❌ Will NOT fire — destructured from req
const { id } = req.params;
db.query(`SELECT * FROM users WHERE id = ${id}`);
```

This is the most important false negative to know about. The workaround is code review or
a data-flow tool like Semgrep.

---

### LOG001 — Sensitive Data in Logs

**Might report when code is fine (false positive)**

```js
// May fire — token here is a non-sensitive tracking ID
console.log('Request tracking:', user.token);
```

The rule matches on property names like `password`, `token`, `secret`, `api_key` —
regardless of what the value actually contains.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — password is inside a spread object
console.log({ ...user });  // user.password is not inspected inside spread

// ❌ Will NOT fire — password is inside a template literal
console.log(`User password: ${user.password}`);
```

---

### SEC001 — Sensitive Data in HTTP Response

**Might report when code is fine (false positive)**

```js
// Will fire at medium — this is actually the correct OAuth pattern
res.json({ access_token: token, expires_in: 3600 });
```

A dedicated OAuth token endpoint must return `access_token` in the response body per the
RFC. The rule flags it at medium severity. This is a known acceptable finding for token
endpoints — suppress it there.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — sensitive field is nested, not at the top level
res.json({ data: { api_key: userKey } });

// ❌ Will NOT fire — response built from a variable
const body = { secret: s };
res.json(body);
```

---

### ERR001 — Raw Error Object Returned to Client

**Might report when code is fine (false positive)**

```js
// May fire — variable named 'error' is not actually an Error object
const error = { code: 404, message: 'Not found' };
res.json(error);
```

The rule matches identifiers named `err`, `error`, `e`, `ex`, or `exception` — regardless
of what they actually contain.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — error sent via chained status call
res.status(500).json(err);
```

---

### RATE001 — No Rate Limiting Detected

**Might report when code is fine (false positive)**

Almost never. The rule scans all project files for six known rate-limiting packages.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — rate limiting done at the nginx or API gateway layer
// ❌ Will NOT fire — custom in-house rate limiter not using a recognized package
```

---

### PERF001 — N+1 Query in Loop

**Might report when code is fine (false positive)**

```js
// Will fire — still N queries, just parallelized
const users = await Promise.all(
  ids.map(id => prisma.user.findUnique({ where: { id } }))
);
```

`Promise.all` with a `map` is treated as a loop body. The finding is not wrong — it is
still N queries — but if parallelism is acceptable in your context you can suppress it.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — no await, promise-chain style
items.forEach(item => {
  db.query('SELECT ...').then(result => { ... });
});

// ❌ Will NOT fire — custom repository method name not in the known list
await myRepo.fetch(item.id);  // 'fetch' is not a recognized DB method
```

---

### PP001 — Prototype Pollution via Object Merge

**Might report when code is fine (false positive)**

```js
// May fire — bare function named 'merge' that is unrelated to object merging
merge(outputStream, inputStream);  // stream merge, not object merge
```

The rule matches any bare function call named `merge`, `deepMerge`, `extend`, or
`defaults` with a user-input argument. A stream utility or custom function that happens
to share one of those names will trigger it.

**Fix:** rename the function or suppress the finding on that line.

**Might stay silent when code is vulnerable (false negative)**

```js
// ❌ Will NOT fire — user input assigned to a variable first
const data = req.body;
Object.assign(config, data);

// ❌ Will NOT fire — custom recursive merge function not in the known list
myDeepClone(target, req.body);

// ❌ Will NOT fire — spread into an object literal
const merged = { ...defaults, ...req.body };
```

Object spread (`{ ...req.body }`) is the most common false negative. It is functionally
equivalent to `Object.assign` for prototype pollution purposes but produces a different
AST node (`ObjectExpression` with `SpreadElement`) that this rule does not currently
cover. A separate rule or an expansion of PP001 would be needed to catch it.

---

## The bottom line

| What the tool is good at | What it misses |
|---|---|
| Literal hardcoded secrets and keys | Secrets assigned to variables first |
| Misconfigured options at the call site | Misconfigurations loaded from config files |
| Missing middleware on individual routes | Middleware applied at router or framework level |
| Known vulnerable patterns with direct user input | The same patterns after one variable assignment |

If a finding appears, it is almost certainly real. If no findings appear, that does not
mean the code is secure — it means no patterns the tool recognizes were found in the
current source files.

For deeper analysis, combine express-audit with code review, dependency scanning
(`npm audit`), and a data-flow tool like Semgrep or CodeQL for taint tracking across
variable assignments.
