/**
 * Simple HTTP Request Logger with SQLite Persistence and Enhanced Fingerprinting
 *
 * A minimal Express.js app that logs every incoming HTTP request to an SQLite database
 * stored in the OS temp directory and exposes the logs as JSON at '/logs'
 * and as an HTML page with embedded detailed fingerprinting at '/'.
 * It also provides a '/fingerprint' endpoint to receive client fingerprint data.
 * Works on Fly.dev, Render.com, or any environment with a writable OS temp directory.
 *
 * Setup:
 *   1. npm init -y
 *   2. npm install express sqlite3
 *   3. node index.js
 */

const express = require('express');
const path = require('path');
const os = require('os');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const port = process.env.PORT || 3000;

// Parse JSON bodies for fingerprint POSTs
app.use(express.json());

// Setup SQLite DB in OS temp directory
const dbPath = path.join(os.tmpdir(), 'logs.db');
const db = new sqlite3.Database(dbPath, err => {
  if (err) console.error('Failed to connect to DB:', err.message);
  else console.log(`Connected to SQLite DB at ${dbPath}`);
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      method TEXT,
      url TEXT,
      headers TEXT,
      body TEXT,
      timestamp TEXT
    )
  `, err => { if (err) console.error('Failed to create table:', err.message); });
});

// Logger middleware: insert each request into SQLite
app.use((req, res, next) => {
  const { method, originalUrl: url, headers, body } = req;
  const timestamp = new Date().toISOString();
  const headersStr = JSON.stringify(headers);
  const bodyStr = body && Object.keys(body).length ? JSON.stringify(body) : '';

  db.run(
    `INSERT INTO logs(method, url, headers, body, timestamp) VALUES (?, ?, ?, ?, ?)`,
    [method, url, headersStr, bodyStr, timestamp],
    err => { if (err) console.error('DB insert error:', err.message); }
  );
  next();
});

// Serve robots.txt
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *\nDisallow: /logs`);
});

// JSON logs at '/logs'
app.get('/logs', (req, res) => {
  db.all(`SELECT method, url, headers, body, timestamp FROM logs ORDER BY id`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const result = rows.map(r => ({
      method: r.method,
      url: r.url,
      headers: JSON.parse(r.headers || '{}'),
      body: r.body ? JSON.parse(r.body) : {},
      timestamp: r.timestamp
    }));
    res.json(result);
  });
});

// HTML view at '/' with detailed fingerprinting script
app.get('/', (req, res) => {
  db.all(`SELECT method, url, headers, body, timestamp FROM logs ORDER BY id`, [], (err, rows) => {
    if (err) return res.status(500).send('Error reading logs');

    const entriesHtml = rows.map(r => `
      <div style="margin-bottom:1em;padding:.5em;border:1px solid #ccc;">
        <h2>[${r.timestamp}] ${r.method} ${r.url}</h2>
        <h3>Headers:</h3>
        <pre style="white-space:pre-wrap;overflow-x:auto;">${JSON.stringify(JSON.parse(r.headers || '{}'), null, 2)}</pre>
        ${r.body ? `<h3>Body:</h3><pre style="white-space:pre-wrap;overflow-x:auto;">${JSON.stringify(JSON.parse(r.body), null, 2)}</pre>` : ''}
      </div>
    `).join('');

    const script = `
<script>
(function(){
  function getCanvasFingerprint(){
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '16px Arial';
    ctx.fillStyle = '#f60'; ctx.fillRect(125,1,62,20);
    ctx.fillStyle = '#069'; ctx.fillText('FPJS', 2, 15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('FPJS', 4, 17);
    return canvas.toDataURL();
  }
  const fingerprint = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: navigator.languages,
    screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    webdriver: navigator.webdriver || false,
    hasLanguages: Array.isArray(navigator.languages),
    pluginsCount: navigator.plugins.length,
    headlessUA: /HeadlessChrome/.test(navigator.userAgent),
    canvas: getCanvasFingerprint()
  };
  fetch('/fingerprint', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(fingerprint)
  });
})();
</script>
    `;

    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Request Logs</title></head><body>
<h1>Request Logs (HTML + Detailed Fingerprint)</h1>
${entriesHtml}
${script}
</body></html>`);
  });
});

// Receive fingerprint data
app.post('/fingerprint', (req, res) => {
  console.log('Fingerprint data:', req.body);
  res.sendStatus(200);
});

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));