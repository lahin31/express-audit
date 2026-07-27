/**
 * Example vulnerable Express app - used for testing express-audit
 * DO NOT use this in production - it contains intentional vulnerabilities
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');

const app = express();

// COOKIE001: Missing security flags
app.use(express.json());

// CORS001: Wildcard origin
app.use(cors());

// SESSION001: Hardcoded session secret
app.use(session({
  secret: 'my-super-secret-key-123',
  saveUninitialized: true,
  resave: true,
}));

// AUTH001: Weak bcrypt cost factor
async function hashPassword(password) {
  return bcrypt.hash(password, 4); // Too low!
}

// JWT001: Hardcoded JWT secret
function generateToken(userId) {
  return jwt.sign({ userId }, 'my-hardcoded-secret', {
    // JWT002: Missing expiration!
  });
}

// SQL001: SQL injection vulnerability
app.get('/users', async (req, res) => {
  const name = req.query.name;
  // Dangerous!
  const users = await db.query(`SELECT * FROM users WHERE name = '${name}'`);
  res.json(users);
});

// AUTHZ001: DELETE route without auth middleware
app.delete('/users/:id', async (req, res) => {
  await db.query(`DELETE FROM users WHERE id = ${req.params.id}`);
  res.json({ deleted: true });
});

// AUTHZ002: Admin route without protection  
app.get('/admin/users', async (req, res) => {
  const users = await db.query('SELECT * FROM users');
  res.json(users);
});

// LOG001: Logging sensitive data
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt:', email, password); // Dangerous!

  const user = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
  
  // AUTH002: Plaintext password comparison
  if (user && user.password === password) {
    const token = generateToken(user.id);
    res.cookie('token', token); // COOKIE001: Missing httpOnly, secure, sameSite
    res.json({ token });
  }
});

// LOG003: Stack trace exposed to client
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack, // Dangerous!
  });
});

app.listen(3000);
