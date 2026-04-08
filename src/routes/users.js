const express = require('express');
const router = express.Router();
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

// Rate limiter for routes that perform database access
const dbRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Stricter rate limiter for authentication endpoints
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 login attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' }
});

const db = new Database(':memory:');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL
  )
`);

db.exec(`
  INSERT INTO users (username, email, password) VALUES 
  ('admin', 'admin@example.com', 'admin123'),
  ('john', 'john@example.com', 'password123'),
  ('jane', 'jane@example.com', 'secret456')
`);

// TODO: Fix this security issue - SQL Injection vulnerability #1
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
router.get('/search', (req, res) => {
  const username = req.query.username;
  
  // VULNERABLE: Direct string concatenation in SQL query
  const query = "SELECT id, username, email FROM users WHERE username = '" + username + "'";
  
  try {
    const users = db.prepare(query).all();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// TODO: Fix this security issue - SQL Injection vulnerability #2
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
router.get('/find', (req, res) => {
  const email = req.query.email;
  
  // VULNERABLE: Template literal with unsanitized input
  const query = `SELECT id, username, email FROM users WHERE email = '${email}'`;
  
  try {
    const users = db.prepare(query).all();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// TODO: Fix this security issue - SQL Injection vulnerability #3
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
router.post('/login', authRateLimiter, (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: String concatenation for authentication query
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  
  try {
    const user = db.prepare(query).get();
    if (user) {
      res.json({ success: true, message: 'Login successful', userId: user.id });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Safe endpoint for comparison (not vulnerable)
router.get('/safe-search', dbRateLimiter, (req, res) => {
  const username = req.query.username;
  
  // SAFE: Using parameterized query
  const query = "SELECT id, username, email FROM users WHERE username = ?";
  
  try {
    const users = db.prepare(query).all(username);
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
