const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');
const dns = require('dns');

// Allowlist of characters permitted in command arguments.
// Sanitization works by mapping each input character to its index in this
// constant and reading the character back from the constant, so the output
// string is derived entirely from this literal — not from user input.
const ALLOWED_HOST_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-';
const ALLOWED_FILENAME_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-';

/**
 * Rebuild a string using only characters present in an allowlist constant.
 * Each character is looked up by index in the allowlist and read back from it,
 * which produces a new string whose values originate from the constant — not
 * from the (potentially tainted) input.  Returns null if any character in the
 * input is not in the allowlist.
 */
function sanitize(input, allowlist) {
  let result = '';
  for (let i = 0; i < input.length; i++) {
    const idx = allowlist.indexOf(input[i]);
    if (idx === -1) {
      return null; // reject: character not in allowlist
    }
    result += allowlist.charAt(idx);
  }
  return result;
}

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

// Fixed: Command Injection vulnerability #1 (CWE-78)
// Input validated and sanitized through constant-character allowlist, then
// passed to execFile (no shell) as an argument array.
router.get('/ping', (req, res) => {
  const host = req.query.host;

  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;

  if (!host || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  const safeHost = sanitize(host, ALLOWED_HOST_CHARS);
  if (!safeHost) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  execFile('ping', ['-c', '4', safeHost], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// Fixed: Command Injection vulnerability #2 (CWE-78)
// Filename validated and sanitized through constant-character allowlist, then
// passed to execFile (no shell) as an argument array.
router.post('/backup', authenticate, (req, res) => {
  const filename = req.body.filename;

  const filenameRegex = /^[a-zA-Z0-9_-]+$/;
  if (!filename || !filenameRegex.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, hyphens, and underscores are allowed.' });
  }

  const safeFilename = sanitize(filename, ALLOWED_FILENAME_CHARS);
  if (!safeFilename) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, hyphens, and underscores are allowed.' });
  }

  execFile('tar', ['-czf', '/tmp/' + safeFilename + '.tar.gz', '/var/log'], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: 'Backup created: ' + safeFilename + '.tar.gz' });
    }
  });
});

// Fixed: Command Injection vulnerability #3 (CWE-78)
// Replaced shell command (nslookup) with Node.js built-in dns.resolve —
// no child process is spawned, eliminating the injection vector entirely.
router.get('/lookup', (req, res) => {
  const domain = req.query.domain;

  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;
  if (!domain || !domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  const safeDomain = sanitize(domain, ALLOWED_HOST_CHARS);
  if (!safeDomain) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  dns.resolve(safeDomain, (err, addresses) => {
    if (err) {
      res.status(500).json({ error: err.message });
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

// Safe endpoint for comparison
// Input validated and sanitized through constant-character allowlist, then
// passed to execFile (no shell) as an argument array.
router.get('/safe-ping', (req, res) => {
  const host = req.query.host;

  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;

  if (!ipRegex.test(host) && !hostnameRegex.test(host)) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  const safeHost = sanitize(host, ALLOWED_HOST_CHARS);
  if (!safeHost) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  execFile('ping', ['-c', '4', safeHost], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

module.exports = router;
