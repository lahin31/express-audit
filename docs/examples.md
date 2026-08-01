# Real-World Examples

This page walks through five concrete vulnerabilities — from the code that triggers
them, through the finding express-audit reports, to the fix that makes it go away.
Every code snippet and every output block on this page comes from running the tool
against the actual `examples/` apps in this repository.

---

## How to follow along

```bash
# Install
npm install -g express-audit

# Run against the bundled vulnerable app
express-audit examples/vulnerable-app

# Run against the fixed app
express-audit examples/secure-app
```

---

## Example 1 — Hardcoded JWT Secret (JWT001)

### Vulnerable code

```js
// examples/vulnerable-app/app.js  line 34
function generateToken(userId) {
  return jwt.sign({ userId }, 'my-hardcoded-secret');
}
```

### Finding

```
🔴 Critical (1)
────────────────────────────────────────────────────────────
JWT001 | Hardcoded JWT Secret
Location: app.js:34
Impact:   Hardcoded secrets can be extracted from source code, allowing
          attackers to forge valid JWT tokens and impersonate any user.
Fix:      Use environment variables: jwt.sign(payload, process.env.JWT_SECRET)
```

### Fix

```js
// Move the secret to an environment variable.
// Never commit it to source control.
function generateToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: '15m',
  });
}
```

### After the fix

```
Express Audit v0.1.12
📊 Security Score: 100/100

Summary
------------------------------------------------------------
Total findings: 0
```

---

## Example 2 — SQL Injection (SQL001)

### Vulnerable code

```js
// examples/vulnerable-app/app.js  line 49
app.get('/users', async (req, res) => {
  const name = req.query.name;
  const users = await db.query(
    `SELECT * FROM users WHERE name = '${name}'`
  );
  res.json(users);
});
```

### Finding

```
🔴 Critical (1)
────────────────────────────────────────────────────────────
SQL001 | SQL Injection via Template Literal
Location: app.js:49
Impact:   Attackers can inject arbitrary SQL, leading to data theft,
          modification, or database destruction.
Fix:      Use parameterized queries:
          db.query("SELECT ... WHERE id = ?", [userInput])
```

### Fix

```js
app.get('/users', async (req, res) => {
  const name = req.query.name;
  const users = await db.query(
    'SELECT * FROM users WHERE name = ?',
    [name]   // user input goes in the parameter array, never in the string
  );
  res.json(users);
});
```

### After the fix

```
SQL Security              100% ████████████████████
Total findings: 0
```

---

## Example 3 — Sensitive Route Without Auth (AUTHZ001)

### Vulnerable code

```js
// examples/vulnerable-app/app.js  line 48
app.delete('/users/:id', async (req, res) => {
  await db.query(`DELETE FROM users WHERE id = ${req.params.id}`);
  res.json({ deleted: true });
});
```

### Finding

```
⚠️  High (1)
────────────────────────────────────────────────────────────
AUTHZ001 | Sensitive Route Missing Authentication
Location: app.js:48
Impact:   Unauthenticated users can modify or delete resources,
          leading to unauthorized data modification.
Fix:      Add auth middleware:
          router.delete("/users/:id", authenticate, handler)
```

### Fix

```js
// Protect the route with authentication middleware.
app.delete('/users/:id', authenticate, async (req, res) => {
  const id = parseInt(req.params.id);
  await db.query('DELETE FROM users WHERE id = ?', [id]);
  res.json({ deleted: true });
});
```

### After the fix

```
Authorization             100% ████████████████████
Total findings: 0
```

---

## Example 4 — CORS Wildcard Origin (CORS001)

### Vulnerable code

```js
// examples/vulnerable-app/app.js  line 18
app.use(cors());  // no options = allow all origins
```

### Finding

```
⚠️  High (1)
────────────────────────────────────────────────────────────
CORS001 | CORS Allows All Origins
Location: app.js:18
Impact:   Any website can make cross-origin requests to your API.
Fix:      Specify allowed origins:
          cors({ origin: ["https://yourdomain.com"] })
```

### Fix

```js
app.use(cors({
  origin: ['https://yourdomain.com'],
  credentials: true,
}));
```

### After the fix

```
CORS                      100% ████████████████████
Total findings: 0
```

---

## Example 5 — Hardcoded Session Secret (SESSION001)

### Vulnerable code

```js
// examples/vulnerable-app/app.js  line 21
app.use(session({
  secret: 'my-super-secret-key-123',
  saveUninitialized: true,
  resave: true,
}));
```

### Finding

```
🔴 Critical (1)
────────────────────────────────────────────────────────────
SESSION001 | Hardcoded Session Secret
Location: app.js:21
Impact:   Hardcoded secrets can be extracted from source,
          allowing session forgery.
Fix:      Use: secret: process.env.SESSION_SECRET
```

### Fix

```js
app.use(session({
  secret: process.env.SESSION_SECRET,
  saveUninitialized: false,
  resave: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  },
}));
```

### After the fix

```
Sessions                  100% ████████████████████
Total findings: 0
```

---

## Full scan: vulnerable app vs secure app

Running express-audit against both bundled example applications shows the
contrast clearly.

### Vulnerable app

```
express-audit examples/vulnerable-app

📊 Security Score: 79/100

🔴 Critical  (7)   JWT001, AUTH002, AUTHZ002, SESSION001, SQL001, DOCKER004 ×2
⚠️  High     (8)   JWT002, AUTH001, AUTHZ001, HTTP001, COOKIE001, CORS001, SECRET008, DOCKER001
📋 Medium    (5)   CSP001, SESSION001, RATE001, PROD003, DOCKER002
ℹ️  Low      (7)   HEADER001, SESSION001, PROD001, PROD002, PROD004, DOCKER003, DOCKER005

Total files scanned: 2
Total findings:     27
```

### Secure app

```
express-audit examples/secure-app

📊 Security Score: 100/100

Authentication            100% ████████████████████
Authorization             100% ████████████████████
CORS                      100% ████████████████████
Sessions                  100% ████████████████████
SQL Security              100% ████████████████████
HTTP Security             100% ████████████████████
... (all 17 categories)   100%

Total files scanned: 2
Total findings:      0
```

The two apps are in `examples/vulnerable-app/` and `examples/secure-app/` if
you want to read the full source side by side.
