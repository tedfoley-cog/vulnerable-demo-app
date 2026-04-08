const express = require('express');
const router = express.Router();
const dns = require('dns');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

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
// Replaced shell exec with Node.js dns.lookup - no command execution needed
router.get('/ping', (req, res) => {
  const host = req.query.host;

  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;

  if (!host || (!ipRegex.test(host) && !hostnameRegex.test(host))) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  const start = Date.now();
  dns.lookup(host, { all: true }, (err, addresses) => {
    const duration = Date.now() - start;
    if (err) {
      res.status(500).json({ error: 'Host lookup failed: ' + err.message });
    } else {
      const lines = addresses.map(a => 'Address: ' + a.address + ' (IPv' + a.family + ')').join('\n');
      res.send('<pre>Host lookup: ' + host + '\n' + lines + '\nTime: ' + duration + 'ms</pre>');
    }
  });
});

// FIXED: Command Injection vulnerability #2 (CWE-78)
// Uses spawn with only static arguments; user input only controls the output file path via fs
router.post('/backup', authenticate, (req, res) => {
  const filenameInput = req.body.filename;

  const safeFilenameRegex = /^[a-zA-Z0-9_-]{1,64}$/;
  if (!filenameInput || !safeFilenameRegex.test(filenameInput)) {
    return res.status(400).json({ error: 'Invalid filename. Use only alphanumeric characters, hyphens, and underscores.' });
  }

  const filename = filenameInput.replace(/[^a-zA-Z0-9_-]/g, '');
  const outputPath = path.join('/tmp', filename + '.tar.gz');
  const output = fs.createWriteStream(outputPath);

  // No user input in command arguments - archive is written to stdout then piped to file
  const tar = spawn('tar', ['-czf', '-', '/var/log']);
  tar.stdout.pipe(output);

  let stderrData = '';
  tar.stderr.on('data', (data) => { stderrData += data; });

  tar.on('close', (code) => {
    if (res.headersSent) return;
    if (code !== 0) {
      res.status(500).json({ error: stderrData || 'tar exited with code ' + code });
    } else {
      res.json({ success: true, message: 'Backup created: ' + filename + '.tar.gz' });
    }
  });

  tar.on('error', (err) => {
    if (!res.headersSent) {
      res.status(500).json({ error: err.message });
    }
  });
});

// FIXED: Command Injection vulnerability #3 (CWE-78)
// Replaced shell nslookup with Node.js dns.resolve - no command execution needed
router.get('/lookup', (req, res) => {
  const domain = req.query.domain;

  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;
  if (!domain || !domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  dns.resolve(domain, (err, addresses) => {
    if (err) {
      res.status(500).json({ error: 'DNS resolution failed: ' + err.message });
    } else {
      res.json({ result: addresses.join('\n') });
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

// FIXED: Alert #23 (CWE-78) - safe-ping also converted to dns.lookup
router.get('/safe-ping', (req, res) => {
  const host = req.query.host;

  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;

  if (!ipRegex.test(host) && !hostnameRegex.test(host)) {
    return res.status(400).json({ error: 'Invalid host format' });
  }

  const start = Date.now();
  dns.lookup(host, { all: true }, (err, addresses) => {
    const duration = Date.now() - start;
    if (err) {
      res.status(500).json({ error: 'Host lookup failed: ' + err.message });
    } else {
      const lines = addresses.map(a => 'Address: ' + a.address + ' (IPv' + a.family + ')').join('\n');
      res.send('<pre>Host lookup: ' + host + '\n' + lines + '\nTime: ' + duration + 'ms</pre>');
    }
  });
});

module.exports = router;
