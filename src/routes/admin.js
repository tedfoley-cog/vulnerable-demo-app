const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const rateLimit = require('express-rate-limit');

// Rate limiter for routes that execute system commands
const commandRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // limit each IP to 30 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// Simple authentication middleware using environment variable
const authenticate = (req, res, next) => {
  const authHeader = req.headers['x-admin-auth'];
  const adminAuth = process.env.ADMIN_AUTH || 'admin';
  
  if (authHeader === adminAuth) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// TODO: Fix this security issue - Command Injection vulnerability #1
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
router.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // VULNERABLE: Direct command execution with user input
  exec('ping -c 4 ' + host, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// TODO: Fix this security issue - Command Injection vulnerability #2
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
router.post('/backup', authenticate, (req, res) => {
  const filename = req.body.filename;
  
  // VULNERABLE: Template literal with user input in shell command
  exec(`tar -czf /tmp/${filename}.tar.gz /var/log`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: `Backup created: ${filename}.tar.gz` });
    }
  });
});

// TODO: Fix this security issue - Command Injection vulnerability #3
// CWE-78: Improper Neutralization of Special Elements used in an OS Command
router.get('/lookup', commandRateLimiter, (req, res) => {
  const domain = req.query.domain;
  
  // VULNERABLE: User input directly in command string
  const command = 'nslookup ' + domain;
  
  exec(command, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ result: stdout });
    }
  });
});

// Endpoint that returns configuration
router.get('/config', authenticate, (req, res) => {
  res.json({
    token: process.env.SERVICE_TOKEN || 'demo',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Safe endpoint for comparison (not vulnerable)
router.get('/safe-ping', commandRateLimiter, (req, res) => {
  const host = req.query.host;
  
  // SAFE: Validate input before using in command
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
  
  if (!ipRegex.test(host) && !hostnameRegex.test(host)) {
    return res.status(400).json({ error: 'Invalid host format' });
  }
  
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
