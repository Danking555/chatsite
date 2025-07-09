/**
 * Simple HTTP Request Logger with SQLite Persistence
 *
 * A minimal Express.js app that logs every incoming HTTP request to both an in-memory
 * SQLite database stored in the OS temp directory and exposes the logs as HTML and JSON.
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

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Setup SQLite DB in OS temp directory
const dbPath = path.join(os.tmpdir(), 'logs.db');
const db = new sqlite3.Database(dbPath, (err) => {
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
  `, (err) => {
    if (err) console.error('Failed to create table:', err.message);
  });
});

// Logger middleware: insert each request into SQLite
app.use((req, res, next) => {
  const { method, originalUrl: url, headers, body } = req;
  const timestamp = new Date().toISOString();
  const headersStr = JSON.stringify(headers);
  const bodyStr = (body && Object.keys(body).length) ? JSON.stringify(body) : '';

  db.run(
    `INSERT INTO logs(method, url, headers, body, timestamp) VALUES (?, ?, ?, ?, ?)`,
    [method, url, headersStr, bodyStr, timestamp],
    (err) => {
      if (err) console.error('DB insert error:', err.message);
      else console.log(`Logged to DB: ${method} ${url} at ${timestamp}`);
    }
  );

  next();
});

// Serve robots.txt
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(
    `User-agent: *
Disallow: /logs`
  );
});

// Serve logs as HTML
app.get('/', (req, res) => {
  db.all(`SELECT * FROM logs ORDER BY id`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    const parsed = rows.map(r => ({
      method: r.method,
      url: r.url,
      headers: JSON.parse(r.headers || '{}'),
      body: r.body ? JSON.parse(r.body) : {},
      timestamp: r.timestamp
    }));

    res.json(parsed);
  });
});

// Expose logs as JSON
app.get('/logs', (req, res) => {
  db.all(`SELECT * FROM logs ORDER BY id`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    const parsed = rows.map(r => ({
      method: r.method,
      url: r.url,
      headers: JSON.parse(r.headers || '{}'),
      body: r.body ? JSON.parse(r.body) : {},
      timestamp: r.timestamp
    }));

    res.json(parsed);
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
