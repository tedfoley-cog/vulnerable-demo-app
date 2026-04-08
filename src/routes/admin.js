const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');

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

// FIXED: Command Injection vulnerability #1 (CWE-78)
// Uses execFile + input validation + replace sanitizer to prevent injection
router.get('/ping', (req, res) => {
  const hostInput = req.query.host;

  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;

  if (!hostInput || (!ipRegex.test(hostInput) && !hostnameRegex.test(hostInput))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  const host = hostInput.replace(/[^a-zA-Z0-9.-]/g, '');
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// FIXED: Command Injection vulnerability #2 (CWE-78)
// Uses execFile + input validation + replace sanitizer to prevent injection
router.post('/backup', authenticate, (req, res) => {
  const filenameInput = req.body.filename;

  const safeFilenameRegex = /^[a-zA-Z0-9_-]{1,64}$/;
  if (!filenameInput || !safeFilenameRegex.test(filenameInput)) {
    return res.status(400).json({ error: 'Invalid filename. Use only alphanumeric characters, hyphens, and underscores.' });
  }

  const filename = filenameInput.replace(/[^a-zA-Z0-9_-]/g, '');
  execFile('tar', ['-czf', `/tmp/${filename}.tar.gz`, '/var/log'], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: `Backup created: ${filename}.tar.gz` });
    }
  });
});

// FIXED: Command Injection vulnerability #3 (CWE-78)
// Uses execFile + input validation + replace sanitizer to prevent injection
router.get('/lookup', (req, res) => {
  const domainInput = req.query.domain;

  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;
  if (!domainInput || !domainRegex.test(domainInput)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  const domain = domainInput.replace(/[^a-zA-Z0-9.-]/g, '');
  execFile('nslookup', [domain], (error, stdout, stderr) => {
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

// Safe endpoint - uses execFile + validation + replace sanitizer
router.get('/safe-ping', (req, res) => {
  const hostInput = req.query.host;

  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;

  if (!ipRegex.test(hostInput) && !hostnameRegex.test(hostInput)) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  const host = hostInput.replace(/[^a-zA-Z0-9.-]/g, '');
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
