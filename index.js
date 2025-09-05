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
const port = process.env.PORT || 3001;

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
  <style>
    body {
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
    }
    h1 {
      color: #ffffff;
      text-align: center;
      margin-bottom: 30px;
    }
  </style>
</head>
<body>
  <h1>HTTP Request Logger</h1>
  
  <!-- Browser Objects Properties Section -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #4a90e2; border-radius: 8px; max-width: 800px; background-color: #2d2d2d;">
    <h3 style="color: #4a90e2; margin-top: 0;">🌐 Browser & Environment Objects</h3>
    
    <div id="browserObjects" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-top: 15px;">
      <!-- Browser objects will be populated by JavaScript -->
    </div>
  </div>
  
  <!-- Side Panel for Stored Data -->
  <div id="sidePanel" style="position: fixed; top: 0; right: -400px; width: 400px; height: 100vh; background-color: #2d2d2d; border-left: 2px solid #555; transition: right 0.3s ease; z-index: 1000; overflow-y: auto;">
    <div style="padding: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="color: #e0e0e0; margin: 0;">📊 Stored Sessions</h3>
        <button id="closePanel" style="background: none; border: none; color: #e0e0e0; font-size: 20px; cursor: pointer;">×</button>
      </div>
      <div id="sessionsList" style="color: #b0b0b0;">
        <!-- Sessions will be populated here -->
      </div>
    </div>
  </div>
  
  <!-- Toggle Button for Side Panel -->
  <button id="togglePanel" style="position: fixed; top: 20px; right: 20px; background-color: #007bff; color: white; border: none; border-radius: 50%; width: 50px; height: 50px; cursor: pointer; z-index: 1001; font-size: 18px;">📊</button>

  <script>
  // Function to get all properties of an object (global scope)
  function getAllProperties(obj) {
    const properties = new Set();
    
    // Get own properties
    Object.getOwnPropertyNames(obj).forEach(prop => properties.add(prop));
    
    // Get prototype properties
    let proto = Object.getPrototypeOf(obj);
    while (proto && proto !== Object.prototype) {
      Object.getOwnPropertyNames(proto).forEach(prop => {
        if (prop !== 'constructor') {
          properties.add(prop);
        }
      });
      proto = Object.getPrototypeOf(proto);
    }
    
    // Get enumerable properties
    for (let prop in obj) {
      properties.add(prop);
    }
    
    // Get symbol properties
    Object.getOwnPropertySymbols(obj).forEach(sym => properties.add(sym.toString()));
    
    return Array.from(properties).sort();
  }
  
  // Browser Objects Properties Display
  (function() {
    const browserObjectsContainer = document.getElementById('browserObjects');
    
    // Define browser objects and their descriptions
    const browserObjects = {
      window: {
        description: "the global object representing the browser window/tab; contains all other APIs",
        object: window
      },
      document: {
        description: "entry point to the DOM; lets you read and manipulate HTML & CSS",
        object: document
      },
      navigator: {
        description: "information about the browser, user agent, platform, permissions, etc.",
        object: navigator
      },
      location: {
        description: "represents the current URL; allows reading or changing it (redirects, reloads)",
        object: location
      },
      history: {
        description: "allows navigation through the session history (back(), forward(), pushState())",
        object: history
      },
      screen: {
        description: "provides details about the user's screen (size, color depth, etc.)",
        object: screen
      }
    };
    
    // Function to get property type and value info
    function getPropertyInfo(obj, propName) {
      try {
        const descriptor = Object.getOwnPropertyDescriptor(obj, propName);
        const value = obj[propName];
        const type = typeof value;
        
        let info = {
          type: type,
          enumerable: descriptor ? descriptor.enumerable : false,
          configurable: descriptor ? descriptor.configurable : false,
          writable: descriptor ? descriptor.writable : false,
          hasGetter: descriptor && descriptor.get !== undefined,
          hasSetter: descriptor && descriptor.set !== undefined
        };
        
        // Add value preview for non-function types
        if (type !== 'function' && type !== 'object') {
          info.value = String(value).substring(0, 50);
        } else if (type === 'function') {
          info.value = 'function';
        } else if (type === 'object' && value !== null) {
          info.value = value.constructor ? value.constructor.name : 'object';
        }
        
        return info;
      } catch (e) {
        return {
          type: 'restricted',
          value: 'restricted access',
          error: e.message
        };
      }
    }
    
    // Create HTML for each browser object
    Object.entries(browserObjects).forEach(([objectName, objectInfo]) => {
      const objectDiv = document.createElement('div');
      objectDiv.style.cssText = 
        'background: #3d3d3d; ' +
        'border: 1px solid #555; ' +
        'border-radius: 6px; ' +
        'padding: 15px; ' +
        'box-shadow: 0 2px 4px rgba(0,0,0,0.3);';
      
      // Get all properties dynamically
      const allProperties = getAllProperties(objectInfo.object);
      
      // Create property cards
      const propertiesHtml = allProperties.map(prop => {
        const propInfo = getPropertyInfo(objectInfo.object, prop);
        const typeColor = {
          'function': '#007bff',
          'string': '#28a745',
          'number': '#fd7e14',
          'boolean': '#6f42c1',
          'object': '#20c997',
          'undefined': '#6c757d',
          'restricted': '#dc3545'
        }[propInfo.type] || '#6c757d';
        
        return '<div style="background: #4d4d4d; border: 1px solid #666; padding: 8px; border-radius: 4px; margin: 2px; display: inline-block; min-width: 200px; vertical-align: top;">' +
          '<div style="font-family: monospace; font-size: 12px; font-weight: bold; color: #e0e0e0; margin-bottom: 4px;">' + prop + '</div>' +
          '<div style="font-size: 11px; color: ' + typeColor + '; margin-bottom: 2px;">' + propInfo.type + '</div>' +
          (propInfo.value ? '<div style="font-size: 10px; color: #b0b0b0; font-style: italic;">' + propInfo.value + '</div>' : '') +
          '<div style="font-size: 10px; color: #b0b0b0; margin-top: 2px;">' +
            (propInfo.enumerable ? 'E' : '') +
            (propInfo.configurable ? 'C' : '') +
            (propInfo.writable ? 'W' : '') +
            (propInfo.hasGetter ? 'G' : '') +
            (propInfo.hasSetter ? 'S' : '') +
          '</div>' +
        '</div>';
      }).join('');
      
      objectDiv.innerHTML = 
        '<h4 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 16px;">' +
          '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 14px; color: #e0e0e0;">' + objectName + '</span>' +
          ' <span style="font-size: 12px; color: #b0b0b0;">(' + allProperties.length + ' properties)</span>' +
        '</h4>' +
        '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
          objectInfo.description +
        '</p>' +
        '<div style="margin-top: 10px;">' +
          '<strong style="color: #e0e0e0; font-size: 13px;">All Properties & Methods:</strong>' +
          '<div style="margin-top: 5px; max-height: 300px; overflow-y: auto; border: 1px solid #666; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
            propertiesHtml +
          '</div>' +
          '<div style="margin-top: 5px; font-size: 11px; color: #b0b0b0;">' +
            'Legend: E=Enumerable, C=Configurable, W=Writable, G=Getter, S=Setter' +
          '</div>' +
        '</div>';
      
      browserObjectsContainer.appendChild(objectDiv);
    });
  })();
  
  // Side Panel and Data Storage
  (function() {
    const sidePanel = document.getElementById('sidePanel');
    const togglePanel = document.getElementById('togglePanel');
    const closePanel = document.getElementById('closePanel');
    const sessionsList = document.getElementById('sessionsList');
    
    // Side panel toggle functionality
    togglePanel.addEventListener('click', () => {
      sidePanel.style.right = sidePanel.style.right === '0px' ? '-400px' : '0px';
    });
    
    closePanel.addEventListener('click', () => {
      sidePanel.style.right = '-400px';
    });
    
    // Storage key for sessions
    const STORAGE_KEY = 'browserObjectsSessions';
    
    // Get stored sessions
    function getStoredSessions() {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? JSON.parse(stored) : [];
    }
    
    // Save sessions to localStorage
    function saveSessions(sessions) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
    }
    
    // Store current session data
    function storeCurrentSession() {
      const sessions = getStoredSessions();
      const currentData = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        date: new Date().toLocaleDateString(),
        time: new Date().toLocaleTimeString(),
        browserObjects: {}
      };
      
      // Collect all browser object data
      const browserObjects = ['window', 'document', 'navigator', 'location', 'history', 'screen'];
      browserObjects.forEach(objName => {
        const obj = window[objName];
        if (obj) {
          currentData.browserObjects[objName] = {
            properties: getAllProperties(obj),
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            screen: {
              width: screen.width,
              height: screen.height,
              colorDepth: screen.colorDepth
            }
          };
        }
      });
      
      sessions.unshift(currentData); // Add to beginning
      
      // Keep only last 50 sessions
      if (sessions.length > 50) {
        sessions.splice(50);
      }
      
      saveSessions(sessions);
      updateSessionsList();
    }
    
    // Update the sessions list display
    function updateSessionsList() {
      const sessions = getStoredSessions();
      sessionsList.innerHTML = sessions.map(session => {
        const totalProperties = Object.values(session.browserObjects).reduce((sum, obj) => sum + (obj.properties ? obj.properties.length : 0), 0);
        const objectCounts = Object.keys(session.browserObjects).map(obj => obj + ': ' + (session.browserObjects[obj].properties ? session.browserObjects[obj].properties.length : 0)).join(', ');
        
        return '<div style="background: #3d3d3d; border: 1px solid #555; border-radius: 6px; padding: 15px; margin-bottom: 10px; cursor: pointer;" onclick="loadSession(' + session.id + ')">' +
          '<div style="color: #e0e0e0; font-weight: bold; margin-bottom: 5px;">' + session.date + ' ' + session.time + '</div>' +
          '<div style="font-size: 12px; color: #b0b0b0; margin-bottom: 5px;">' + totalProperties + ' total properties</div>' +
          '<div style="font-size: 11px; color: #888;">' + objectCounts + '</div>' +
        '</div>';
      }).join('');
    }
    
    // Load a specific session
    window.loadSession = function(sessionId) {
      const sessions = getStoredSessions();
      const session = sessions.find(s => s.id === sessionId);
      if (session) {
        // Clear current display
        const browserObjectsContainer = document.getElementById('browserObjects');
        browserObjectsContainer.innerHTML = '';
        
        // Recreate the display with stored data
        Object.entries(session.browserObjects).forEach(([objectName, objectData]) => {
          const objectDiv = document.createElement('div');
          objectDiv.style.cssText = 
            'background: #3d3d3d; ' +
            'border: 1px solid #555; ' +
            'border-radius: 6px; ' +
            'padding: 15px; ' +
            'box-shadow: 0 2px 4px rgba(0,0,0,0.3);';
          
          const propertiesHtml = objectData.properties.map(prop => {
            return '<div style="background: #4d4d4d; border: 1px solid #666; padding: 8px; border-radius: 4px; margin: 2px; display: inline-block; min-width: 200px; vertical-align: top;">' +
              '<div style="font-family: monospace; font-size: 12px; font-weight: bold; color: #e0e0e0; margin-bottom: 4px;">' + prop + '</div>' +
              '<div style="font-size: 11px; color: #007bff; margin-bottom: 2px;">stored</div>' +
            '</div>';
          }).join('');
          
          objectDiv.innerHTML = 
            '<h4 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 16px;">' +
              '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 14px; color: #e0e0e0;">' + objectName + '</span>' +
              ' <span style="font-size: 12px; color: #b0b0b0;">(' + objectData.properties.length + ' properties)</span>' +
              ' <span style="font-size: 10px; color: #007bff;">[LOADED FROM STORAGE]</span>' +
            '</h4>' +
            '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
              'Stored session from ' + session.date + ' ' + session.time +
            '</p>' +
            '<div style="margin-top: 10px;">' +
              '<strong style="color: #e0e0e0; font-size: 13px;">Stored Properties:</strong>' +
              '<div style="margin-top: 5px; max-height: 300px; overflow-y: auto; border: 1px solid #666; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
                propertiesHtml +
              '</div>' +
            '</div>';
          
          browserObjectsContainer.appendChild(objectDiv);
        });
        
        // Close the side panel
        sidePanel.style.right = '-400px';
      }
    };
    
    // Store current session on page load
    window.addEventListener('load', () => {
      setTimeout(() => {
        storeCurrentSession();
      }, 2000); // Wait for browser objects to be populated
    });
    
    // Update sessions list on load
    updateSessionsList();
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