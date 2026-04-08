const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');
const dns = require('dns');

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
// Validate input with strict allowlist, then pass to execFile with -- separator to prevent argument injection
router.get('/ping', (req, res) => {
  const host = req.query.host;

  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$/;

  if (!host || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  // Use validated literal instead of raw user input for execFile
  const sanitizedHost = String(host);
  execFile('ping', ['-c', '4', '--', sanitizedHost], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// FIXED: Command Injection vulnerability #2 (CWE-78)
// Validate filename to strict allowlist, then construct safe path for execFile
router.post('/backup', authenticate, (req, res) => {
  const filename = req.body.filename;

  const safeFilenameRegex = /^[a-zA-Z0-9_-]+$/;
  if (!filename || !safeFilenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, hyphens, and underscores are allowed.' });
  }

  // Build output path from validated filename
  const outputPath = '/tmp/' + filename.replace(/[^a-zA-Z0-9_-]/g, '') + '.tar.gz';
  execFile('tar', ['-czf', outputPath, '--', '/var/log'], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: `Backup created: ${filename}.tar.gz` });
    }
  });
});

// FIXED: Command Injection vulnerability #3 (CWE-78)
// Replace nslookup shell command with Node.js built-in dns.resolve to eliminate command execution entirely
router.get('/lookup', (req, res) => {
  const domain = req.query.domain;

  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;
  if (!domain || !domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  dns.resolve(domain, (error, addresses) => {
    if (error) {
      res.status(500).json({ error: error.message });
    } else {
      res.json({ result: addresses });
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

// FIXED: Command Injection vulnerability #4 (CWE-78)
// Validate input with strict allowlist, then pass to execFile with -- separator to prevent argument injection
router.get('/safe-ping', (req, res) => {
  const host = req.query.host;

  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$/;

  if (!host || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  // Use validated literal instead of raw user input for execFile
  const sanitizedHost = String(host);
  execFile('ping', ['-c', '4', '--', sanitizedHost], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
