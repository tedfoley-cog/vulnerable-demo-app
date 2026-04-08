const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const UPLOADS_DIR = path.join(__dirname, '../../uploads');

// TODO: Fix this security issue - Path Traversal vulnerability #1
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
router.get('/read', (req, res) => {
  const filename = req.query.filename;
  
  // VULNERABLE: Direct path concatenation without sanitization
  const filePath = path.join(UPLOADS_DIR, filename);
  
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

// TODO: Fix this security issue - Path Traversal vulnerability #2
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
router.get('/download', (req, res) => {
  const filepath = req.query.path;
  
  // VULNERABLE: Using user input directly as file path
  try {
    const content = fs.readFileSync(filepath, 'utf8');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filepath)}"`);
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

// TODO: Fix this security issue - Path Traversal vulnerability #3
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
router.post('/write', (req, res) => {
  const { filename, content } = req.body;
  
  // VULNERABLE: Writing to user-controlled path
  const filePath = UPLOADS_DIR + '/' + filename;
  
  try {
    fs.writeFileSync(filePath, content);
    res.json({ success: true, message: 'File written successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Safe endpoint for comparison (not vulnerable)
router.get('/safe-read', (req, res) => {
  const filename = req.query.filename;
  
  // Ensure filename is a string to prevent type confusion (CWE-843)
  if (typeof filename !== 'string') {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // SAFE: Validate filename doesn't contain path traversal
  if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  const filePath = path.join(UPLOADS_DIR, filename);
  
  // Additional check: ensure resolved path is within uploads directory
  if (!filePath.startsWith(UPLOADS_DIR)) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

module.exports = router;
