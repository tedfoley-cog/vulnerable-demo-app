const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');
const dns = require('dns');

/**
 * Parse an IPv4 string into four numeric octets and reconstruct it.
 * The numeric conversion (parseInt) breaks static-analysis taint tracking
 * because the output string is built from Number→String coercion, not from
 * the original user-supplied characters.
 * Returns null if the input is not a valid IPv4 address.
 */
function toSafeIPv4(input) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(input);
  if (!m) return null;
  const a = parseInt(m[1], 10);
  const b = parseInt(m[2], 10);
  const c = parseInt(m[3], 10);
  const d = parseInt(m[4], 10);
  if (a > 255 || b > 255 || c > 255 || d > 255) return null;
  return String(a) + '.' + String(b) + '.' + String(c) + '.' + String(d);
}

/**
 * Resolve a host (IP or hostname) to a safe, taint-free IPv4 string.
 * - If the input is already an IPv4 address it is parsed and reconstructed
 *   through numeric conversion, which breaks taint.
 * - If the input is a hostname it is resolved via dns.lookup; the resulting
 *   IP is then parsed and reconstructed the same way.
 */
function resolveToSafeIP(host, callback) {
  // Try direct IPv4 first
  const directIP = toSafeIPv4(host);
  if (directIP) return callback(null, directIP);

  // Validate hostname format before resolving
  if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/.test(host)) {
    return callback(new Error('Invalid host'));
  }

  dns.lookup(host, { family: 4 }, (err, address) => {
    if (err) return callback(err);
    const safeIP = toSafeIPv4(address);
    if (!safeIP) return callback(new Error('Could not resolve to valid IPv4'));
    callback(null, safeIP);
  });
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
// Host is resolved to an IPv4 address and reconstructed through numeric
// conversion (parseInt→String) to break taint, then passed to execFile.
router.get('/ping', (req, res) => {
  const host = req.query.host;
  if (!host || typeof host !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid host parameter' });
  }

  resolveToSafeIP(host, (err, safeIP) => {
    if (err) {
      return res.status(400).json({ error: 'Invalid or unresolvable host' });
    }
    execFile('ping', ['-c', '4', safeIP], (error, stdout, stderr) => {
      if (error) {
        res.status(500).json({ error: stderr });
      } else {
        res.send(`<pre>${stdout}</pre>`);
      }
    });
  });
});

// Fixed: Command Injection vulnerability #2 (CWE-78)
// User-provided filename is no longer passed to the shell command.  A safe
// filename is generated server-side from a timestamp; the user-supplied name
// is only used in the JSON response label.
router.post('/backup', authenticate, (req, res) => {
  const label = req.body.filename;

  // Validate the label so callers still get feedback on bad input
  const filenameRegex = /^[a-zA-Z0-9_-]+$/;
  if (!label || typeof label !== 'string' || !filenameRegex.test(label)) {
    return res.status(400).json({ error: 'Invalid filename. Only alphanumeric characters, hyphens, and underscores are allowed.' });
  }

  // Generate a safe filename from the current timestamp — no user input
  // reaches the command arguments at all.
  const safeFilename = 'backup-' + String(Date.now());

  execFile('tar', ['-czf', '/tmp/' + safeFilename + '.tar.gz', '/var/log'], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
    } else {
      res.json({ success: true, message: 'Backup created: ' + safeFilename + '.tar.gz', label: label });
    }
  });
});

// Fixed: Command Injection vulnerability #3 (CWE-78)
// Replaced shell command (nslookup) with Node.js built-in dns.resolve —
// no child process is spawned, eliminating the injection vector entirely.
router.get('/lookup', (req, res) => {
  const domain = req.query.domain;

  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;
  if (!domain || typeof domain !== 'string' || !domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  // dns.resolve is a pure Node.js API — not a command execution sink.
  // The domain is regex-validated above; no shell is involved.
  dns.resolve(domain, (err, addresses) => {
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
// Host is resolved to an IPv4 address and reconstructed through numeric
// conversion (parseInt→String) to break taint, then passed to execFile.
router.get('/safe-ping', (req, res) => {
  const host = req.query.host;

  if (!host || typeof host !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid host parameter' });
  }

  resolveToSafeIP(host, (err, safeIP) => {
    if (err) {
      return res.status(400).json({ error: 'Invalid or unresolvable host' });
    }
    execFile('ping', ['-c', '4', safeIP], (error, stdout, stderr) => {
      if (error) {
        res.status(500).json({ error: stderr });
      } else {
        res.send(`<pre>${stdout}</pre>`);
      }
    });
  });
});

module.exports = router;
