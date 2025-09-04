/**
 * Simplified HTTP Request Logger with Bot Detection
 * 
 * Minimal Express.js app that serves only "/" with bot detection on login form.
 * Logs HTTP requests to SQLite and includes WebSocket fingerprinting.
 * 
 * Setup:
 *   npm init -y
 *   npm install express sqlite3 ws
 *   node index.js
 */

const express = require('express');
const http = require('http');
const path = require('path');
const os = require('os');
const sqlite3 = require('sqlite3').verbose();
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 3000;

// JSON parsing
app.use(express.json());

// Initialize SQLite database
const dbPath = path.join(os.tmpdir(), 'logs.db');
const db = new sqlite3.Database(dbPath, err => {
  if (err) console.error('DB connection error:', err.message);
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
  `);
});

// Middleware: log every HTTP request
app.use((req, res, next) => {
  const { method, originalUrl: url, headers, body } = req;
  const timestamp = new Date().toISOString();
  const headersStr = JSON.stringify(headers);
  const bodyStr = body && Object.keys(body).length ? JSON.stringify(body) : '';
  db.run(
    `INSERT INTO logs(method,url,headers,body,timestamp) VALUES(?,?,?,?,?)`,
    [method, url, headersStr, bodyStr, timestamp]
  );
  next();
});

// Main route with bot detection
app.get('/', (req, res) => {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Home</title>
</head>
<body>
  <h1>HTTP Request Logger</h1>
  
  <!-- Login Form with Bot Detection -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #ccc; border-radius: 8px; max-width: 400px;">
    <h3>Login Form</h3>
    <form id="loginForm">
      <div style="margin-bottom: 15px;">
        <label for="username" style="display: block; margin-bottom: 5px; font-weight: bold;">Username:</label>
        <input type="text" id="username" name="username" placeholder="Enter username" 
               style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
      </div>
      <div style="margin-bottom: 15px;">
        <label for="password" style="display: block; margin-bottom: 5px; font-weight: bold;">Password:</label>
        <input type="password" id="password" name="password" placeholder="Enter password" 
               style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
      </div>
      <button type="submit" id="loginBtn" 
              style="background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">
        Login
      </button>
      <div id="loginStatus" style="margin-top: 10px; font-weight: bold;"></div>
    </form>
  </div>

  <script>
  // Bot Detection Script
  (function() {
    const username = document.getElementById("username");
    const password = document.getElementById("password");
    const loginBtn = document.getElementById("loginBtn");
    const form = document.getElementById("loginForm");
    
    let userTyped = false;
    let userClicked = false;
    const keyEvents = []; // Store key press events
    const clickEvents = []; // Store mouse click events
    
    // Function to detect synthetic events
    function isSyntheticEvent(event) {
      const synthetic = {
        isTrusted: event.isTrusted === false, // false means synthetic
        detail: event.detail === 0, // 0 often indicates synthetic
        timeStamp: event.timeStamp === 0, // 0 often indicates synthetic
        bubbles: event.bubbles === false, // some synthetic events don't bubble
        cancelable: event.cancelable === false, // some synthetic events aren't cancelable
        eventPhase: event.eventPhase === 0, // 0 = none phase
        hasPointerCoords: event.clientX === 0 && event.clientY === 0, // synthetic mouse events often at 0,0
        hasKeyData: event.key === undefined || event.code === undefined // synthetic key events may lack data
      };
      
      return {
        isSynthetic: !event.isTrusted || event.detail === 0 || event.timeStamp === 0,
        syntheticFlags: synthetic,
        confidence: Object.values(synthetic).filter(Boolean).length,
        trustLevel: event.isTrusted ? 'trusted' : 'untrusted'
      };
    }
    
    // Track key presses with timestamp and synthetic detection
    function trackKey(event) {
      userTyped = true;
      const syntheticInfo = isSyntheticEvent(event);
      
      // Create comprehensive event data
      const eventData = {
        key: event.key,
        code: event.code,
        keyCode: event.keyCode,
        which: event.which,
        timestamp: Date.now(),
        isTrusted: event.isTrusted,
        synthetic: syntheticInfo,
        target: event.target.id || event.target.tagName,
        // Additional key-specific properties
        altKey: event.altKey,
        ctrlKey: event.ctrlKey,
        shiftKey: event.shiftKey,
        metaKey: event.metaKey,
        repeat: event.repeat,
        location: event.location,
        // Full event object for debugging
        fullEvent: {
          type: event.type,
          bubbles: event.bubbles,
          cancelable: event.cancelable,
          defaultPrevented: event.defaultPrevented,
          eventPhase: event.eventPhase,
          timeStamp: event.timeStamp,
          detail: event.detail,
          view: event.view ? 'window' : 'null',
          currentTarget: event.currentTarget ? event.currentTarget.tagName : 'null',
          target: event.target ? event.target.tagName : 'null',
          srcElement: event.srcElement ? event.srcElement.tagName : 'null',
          returnValue: event.returnValue,
          cancelBubble: event.cancelBubble,
          composed: event.composed,
          isTrusted: event.isTrusted
        }
      };
      
      keyEvents.push(eventData);
      
      // Log comprehensive event information
      console.log("=== KEYBOARD EVENT DETAILS ===");
      console.log("Key:", event.key, "Code:", event.code, "at", new Date().toISOString());
      console.log("Synthetic:", syntheticInfo.isSynthetic, "Trust:", syntheticInfo.trustLevel);
      console.log("Full Event Object:", event);
      console.log("Event Data:", eventData);
      console.log("================================");
    }
    
    username.addEventListener("keydown", trackKey);
    password.addEventListener("keydown", trackKey);
    
    // Track mouse clicks with synthetic detection
    document.addEventListener("click", (e) => {
      userClicked = true;
      const syntheticInfo = isSyntheticEvent(e);
      
      // Create comprehensive event data
      const eventData = {
        x: e.clientX,
        y: e.clientY,
        target: e.target.id || e.target.tagName,
        timestamp: Date.now(),
        button: e.button,
        buttons: e.buttons,
        isTrusted: e.isTrusted,
        synthetic: syntheticInfo,
        detail: e.detail,
        eventPhase: e.eventPhase,
        // Additional mouse-specific properties
        screenX: e.screenX,
        screenY: e.screenY,
        pageX: e.pageX,
        pageY: e.pageY,
        offsetX: e.offsetX,
        offsetY: e.offsetY,
        movementX: e.movementX,
        movementY: e.movementY,
        altKey: e.altKey,
        ctrlKey: e.ctrlKey,
        shiftKey: e.shiftKey,
        metaKey: e.metaKey,
        // Full event object for debugging
        fullEvent: {
          type: e.type,
          bubbles: e.bubbles,
          cancelable: e.cancelable,
          defaultPrevented: e.defaultPrevented,
          eventPhase: e.eventPhase,
          timeStamp: e.timeStamp,
          detail: e.detail,
          view: e.view ? 'window' : 'null',
          currentTarget: e.currentTarget ? e.currentTarget.tagName : 'null',
          target: e.target ? e.target.tagName : 'null',
          srcElement: e.srcElement ? e.srcElement.tagName : 'null',
          returnValue: e.returnValue,
          cancelBubble: e.cancelBubble,
          composed: e.composed,
          isTrusted: e.isTrusted,
          relatedTarget: e.relatedTarget ? e.relatedTarget.tagName : 'null'
        }
      };
      
      clickEvents.push(eventData);
      
      // Log comprehensive event information
      console.log("=== MOUSE CLICK EVENT DETAILS ===");
      console.log("Click at:", e.clientX, e.clientY, "on", e.target.id || e.target.tagName);
      console.log("Synthetic:", syntheticInfo.isSynthetic, "Trust:", syntheticInfo.trustLevel);
      console.log("Full Event Object:", e);
      console.log("Event Data:", eventData);
      console.log("==================================");
    });
    
    // On form submit, check behavior
    form.addEventListener("submit", (e) => {
      e.preventDefault(); // Always prevent default for demo
      
      if (!userTyped || !userClicked) {
        alert("⚠️ Possible bot detected: no real typing or clicking.");
        console.warn("Bot-like behavior detected.");
        document.getElementById("loginStatus").innerHTML = 
          '<span style="color: red;">Bot detected - Login blocked</span>';
      } else {
        console.log("User likely human ✅");
        console.log("Key events:", keyEvents);
        console.log("Click events:", clickEvents);
        document.getElementById("loginStatus").innerHTML = 
          '<span style="color: green;">Human verified - Login successful</span>';
        
        // Send detection data via WebSocket
        sendDetectionData({
          humanVerified: true,
          keyEvents: keyEvents,
          clickEvents: clickEvents
        });
      }
    });
    
    // Fingerprinting functions
    function getCanvasFingerprint() {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '16px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('FPJS', 2, 15);
      ctx.fillStyle = 'rgba(102,204,0,0.7)';
      ctx.fillText('FPJS', 4, 17);
      return canvas.toDataURL();
    }
    
    // Send fingerprint and detection data
    function sendDetectionData(detectionData) {
      const fp = {
        origin: location.pathname,
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        languages: navigator.languages,
        screen: {
          width: screen.width,
          height: screen.height,
          colorDepth: screen.colorDepth
        },
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        webdriver: navigator.webdriver || false,
        pluginsCount: navigator.plugins.length,
        canvas: getCanvasFingerprint(),
        botDetection: detectionData,
        timestamp: new Date().toISOString()
      };
      
      // Send via WebSocket
      const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'fingerprint', data: fp }));
        ws.close();
      };
    }
    
    // Send initial fingerprint on page load
    window.addEventListener('load', () => {
      setTimeout(() => {
        sendDetectionData({
          humanVerified: false,
          keyEvents: [],
          clickEvents: [],
          pageLoad: true
        });
      }, 1000);
    });
  })();
  </script>
</body>
</html>`;
  
  res.send(html);
});

// WebSocket server for fingerprint messages
const wss = new WebSocket.Server({ server });
wss.on('connection', ws => {
  ws.on('message', message => {
    try {
      const msg = JSON.parse(message);
      if (msg.type === 'fingerprint') {
        const { origin, ...data } = msg.data;
        const ts = new Date().toISOString();
        db.run(
          `INSERT INTO logs(method,url,headers,body,timestamp) VALUES(?,?,?,?,?)`,
          ['WS', origin, '{}', JSON.stringify(data), ts]
        );
        console.log('Fingerprint received:', {
          origin,
          botDetection: data.botDetection,
          timestamp: ts
        });
      }
    } catch (e) {
      console.error('WS parse error:', e);
    }
  });
});

// Start server
server.listen(port, () => console.log(`Server running on http://localhost:${port}`));