/**
 * Simple HTTP Request Logger
 *
 * A minimal Express.js app that logs every incoming HTTP request and exposes
 * the logs both as an HTML page and as JSON. It also serves a custom robots.txt.
 *
 * Setup:
 *   1. npm init -y
 *   2. npm install express
 *   3. node index.js
 */

const express = require('express');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// In-memory store for logs
const logs = [];

// Logger middleware
app.use((req, res, next) => {
  const { method, originalUrl: url, headers, body } = req;
  const timestamp = new Date().toISOString();
  const entry = { method, url, headers, body, timestamp };
  logs.push(entry);
  console.log(`Logged: ${method} ${url} at ${timestamp}`);
  next();
});

// Serve robots.txt
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  // Example: disallow /logs from crawlers
  res.send(
    `User-agent: *
Disallow: /logs`
  );
});

// Serve logs as HTML with full headers view
app.get('/', (req, res) => {
  let html = '<h1>HTTP Request Logs</h1>';
  for (const log of logs) {
    html += `<div style="margin-bottom: 1em; padding: .5em; border: 1px solid #ccc;">`;
    html += `<h2>[${log.timestamp}] ${log.method} ${log.url}</h2>`;
    html += `<h3>Headers:</h3>`;
    html += `<pre>${JSON.stringify(log.headers, null, 2)}</pre>`;
    html += `</div>`;
  }
  res.send(html);
});

// Expose logs as JSON
app.get('/logs', (req, res) => {
  res.json(logs);
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
