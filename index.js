/**
 * Simple HTTP Request Logger with SQLite Persistence and WebSocket-based Fingerprinting
 *
 * A minimal Express.js app that logs every incoming HTTP request to an SQLite database
 * stored in the OS temp directory. It exposes logs as JSON at '/logs' and serves an
 * HTML page with embedded detailed fingerprinting via WebSocket at '/' and HTML logs
 * view at '/logs' when requested by browsers. Fingerprint scripts run on both pages
 * and include the origin path. Requires 'express', 'sqlite3', and 'ws'.
 *
 * Setup:
 *   1. npm init -y
 *   2. npm install express sqlite3 ws
 *   3. node index.js
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

// JSON parsing for any future needs
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

// Middleware: log every HTTP request (method, url, headers, body, timestamp)
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

// robots.txt
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *\nDisallow: /logs`);
});

// Content negotiation on '/logs'
app.get('/logs', (req, res) => {
  db.all(`SELECT method,url,headers,body,timestamp FROM logs ORDER BY id DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    // JSON API
    if (!req.accepts('html')) {
      const result = rows.map(r => ({
        method: r.method,
        url: r.url,
        headers: JSON.parse(r.headers || '{}'),
        body: r.body ? JSON.parse(r.body) : {},
        timestamp: r.timestamp
      }));
      return res.json(result);
    }

    // HTML view with fingerprinting script
    const entriesHtml = rows.map(r => `
      <div style="margin-bottom:1em;padding:.5em;border:1px solid #ccc;">
        <h2>[${r.timestamp}] ${r.method} ${r.url}</h2>
        <h3>Headers:</h3>
        <pre style="white-space:pre-wrap;overflow-x:auto;">${JSON.stringify(JSON.parse(r.headers||'{}'),null,2)}</pre>
        ${r.body ? `<h3>Body:</h3><pre style="white-space:pre-wrap;overflow-x:auto;">${JSON.stringify(JSON.parse(r.body),null,2)}</pre>` : ''}
      </div>
    `).join('');

    const script = `
<script>
(function(){
  function getCanvasFingerprint(){
    const canvas=document.createElement('canvas');
    const ctx=canvas.getContext('2d');
    ctx.textBaseline='top';ctx.font='16px Arial';
    ctx.fillStyle='#f60';ctx.fillRect(125,1,62,20);
    ctx.fillStyle='#069';ctx.fillText('FPJS',2,15);
    ctx.fillStyle='rgba(102,204,0,0.7)';ctx.fillText('FPJS',4,17);
    return canvas.toDataURL();
  }
  
  function parseCookies(cookieString) {
    if (!cookieString) return {};
    const cookies = {};
    cookieString.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies[name] = decodeURIComponent(value);
      }
    });
    return cookies;
  }
  
  // SharedWorker fingerprinting with Blob-based approach
  let sharedWorkerFingerprint = {};
  try {
    // Check for SharedWorker support with proper constructor validation
    const Wkr = window.frameElement ? window.frameElement.SharedWorker : SharedWorker;
    if (!Wkr || Wkr.prototype.constructor.name !== "SharedWorker") {
      sharedWorkerFingerprint = { 
        supported: false, 
        error: 'SharedWorker not available or invalid constructor' 
      };
    } else {
      // Create fingerprinting JavaScript for the worker
      const fingerprintingJS = \`
        self.onconnect = function(e) {
          const port = e.ports[0];
          port.start();
          
          // Comprehensive fingerprinting from within the worker context
          function collectFingerprint() {
            try {
              const fp = {
                // Worker context information
                workerContext: {
                  type: 'SharedWorker',
                  constructor: self.constructor.name,
                  prototype: self.constructor.prototype ? Object.getOwnPropertyNames(self.constructor.prototype).length : 0,
                  maxWorkers: navigator.hardwareConcurrency || 'unknown',
                  userAgent: navigator.userAgent,
                  platform: navigator.platform,
                  languages: navigator.languages,
                  language: navigator.language,
                  cookieEnabled: navigator.cookieEnabled,
                  onLine: navigator.onLine,
                  doNotTrack: navigator.doNotTrack,
                  maxTouchPoints: navigator.maxTouchPoints || 'unknown',
                  msMaxTouchPoints: navigator.msMaxTouchPoints || 'unknown'
                },
                
                // Enhanced User-Agent and Platform data
                userAgentData: navigator.userAgentData ? {
                  brands: navigator.userAgentData.brands,
                  mobile: navigator.userAgentData.mobile,
                  platform: navigator.userAgentData.platform,
                  architecture: navigator.userAgentData.architecture,
                  bitness: navigator.userAgentData.bitness,
                  model: navigator.userAgentData.model,
                  platformVersion: navigator.userAgentData.platformVersion,
                  fullVersionList: navigator.userAgentData.fullVersionList,
                  wow64: navigator.userAgentData.wow64
                } : 'unsupported',
                
                // Additional platform and system information
                platformDetails: {
                  platform: navigator.platform,
                  vendor: navigator.vendor,
                  product: navigator.product,
                  productSub: navigator.productSub,
                  appName: navigator.appName,
                  appVersion: navigator.appVersion,
                  appCodeName: navigator.appCodeName
                },
                
                // Enhanced language and locale information
                localeInfo: {
                  languages: navigator.languages,
                  language: navigator.language,
                  hasLanguages: Array.isArray(navigator.languages),
                  languageCount: navigator.languages ? navigator.languages.length : 0,
                  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                  timezoneOffset: new Date().getTimezoneOffset(),
                  dateFormat: new Intl.DateTimeFormat().formatToParts(new Date()).map(p => p.type),
                  numberFormat: new Intl.NumberFormat().resolvedOptions(),
                  collator: new Intl.Collator().resolvedOptions()
                },
                
                // Hardware and performance information
                hardwareInfo: {
                  hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                  deviceMemory: navigator.deviceMemory || 'unknown',
                  connection: navigator.connection ? {
                    effectiveType: navigator.connection.effectiveType,
                    downlink: navigator.connection.downlink,
                    rtt: navigator.connection.rtt
                  } : 'unsupported'
                },
                
                // Worker-specific capabilities (only worker-available APIs)
                workerCapabilities: {
                  sharedWorker: true, // We're already in a SharedWorker
                  worker: typeof Worker !== 'undefined',
                  serviceWorker: 'serviceWorker' in navigator,
                  worklet: false, // CSS not available in workers
                  offscreenCanvas: typeof OffscreenCanvas !== 'undefined'
                },
                
                // Media capabilities (only worker-available APIs)
                mediaCapabilities: {
                  mediaSession: 'mediaSession' in navigator,
                  mediaDevices: 'mediaDevices' in navigator,
                  permissions: 'permissions' in navigator,
                  credentials: 'credentials' in navigator,
                  storage: 'storage' in navigator,
                  presentation: 'presentation' in navigator,
                  wakeLock: 'wakeLock' in navigator,
                  usb: 'usb' in navigator,
                  bluetooth: 'bluetooth' in navigator,
                  hid: 'hid' in navigator,
                  serial: 'serial' in navigator
                },
                
                // Performance information
                performanceInfo: {
                  memory: performance.memory ? {
                    usedJSHeapSize: performance.memory.usedJSHeapSize,
                    totalJSHeapSize: performance.memory.totalJSHeapSize,
                    jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                  } : 'unsupported',
                  timing: performance.timing ? {
                    navigationStart: performance.timing.navigationStart,
                    loadEventEnd: performance.timing.loadEventEnd,
                    domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
                  } : 'unsupported',
                  navigation: performance.navigation ? {
                    type: performance.navigation.type,
                    redirectCount: performance.navigation.redirectCount
                  } : 'unsupported'
                },
                
                // Canvas fingerprinting (simplified for worker)
                canvas: 'offscreen_supported'
              };
              
              return fp;
            } catch (e) {
              return { error: 'Worker fingerprinting failed: ' + e.message };
            }
          }
          
          // Collect and send fingerprint immediately
          try {
            const fp = collectFingerprint();
            port.postMessage({ type: 'fingerprint', data: fp });
          } catch (error) {
            port.postMessage({ type: 'error', error: error.message });
          }
        };
      \`;
      
      // Create Blob-based SharedWorker
      const worker = new Wkr(
        URL.createObjectURL(
          new Blob([fingerprintingJS], { type: "application/javascript" })
        )
      );
      
      sharedWorkerFingerprint = {
        supported: true,
        constructor: Wkr.name,
        prototype: Wkr.prototype ? Object.getOwnPropertyNames(Wkr.prototype).length : 0,
        maxWorkers: navigator.hardwareConcurrency || 'unknown'
      };
      
      // Handle messages from the worker
      worker.port.onmessage = function(e) {
        if (e.data.type === 'fingerprint') {
          sharedWorkerFingerprint.working = true;
          sharedWorkerFingerprint.workerData = e.data.data;
          console.log('SharedWorker fingerprint collected:', e.data.data);
        } else if (e.data.type === 'error') {
          sharedWorkerFingerprint.error = e.data.error;
          console.error('SharedWorker error:', e.data.error);
        }
      };
      
      // Handle worker errors
      worker.port.onerror = function(e) {
        sharedWorkerFingerprint.error = 'Port error: ' + e.message;
        console.error('SharedWorker port error:', e);
      };
      
      worker.port.start();
      
      // Set a timeout to mark as failed if no response
      setTimeout(() => {
        if (!sharedWorkerFingerprint.working && !sharedWorkerFingerprint.error) {
          sharedWorkerFingerprint.error = 'Timeout: No response from worker';
          console.warn('SharedWorker timeout - no response received');
        }
      }, 5000);
      
      // Clean up the blob URL when done
      setTimeout(() => {
        URL.revokeObjectURL(worker.port.url);
      }, 10000);
    }
  } catch (e) {
    sharedWorkerFingerprint = { supported: false, error: e.message };
  }
  
  const fp = {
    origin: location.pathname,
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: navigator.languages,
    screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    webdriver: navigator.webdriver||false,
    hasLanguages: Array.isArray(navigator.languages),
    pluginsCount: navigator.plugins.length,
    headlessUA: /HeadlessChrome/.test(navigator.userAgent),
    canvas: getCanvasFingerprint(),
    cookies: parseCookies(document.cookie),
    rawCookies: document.cookie,
    sharedWorker: sharedWorkerFingerprint,
    // Additional SharedWorker-related properties
    workerSupport: {
      sharedWorker: typeof SharedWorker !== 'undefined',
      worker: typeof Worker !== 'undefined',
      serviceWorker: 'serviceWorker' in navigator,
      worklet: 'worklet' in CSS
    },
    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
    deviceMemory: navigator.deviceMemory || 'unknown',
    connection: navigator.connection ? {
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt
    } : 'unsupported',
    // Enhanced User-Agent and Platform data
    userAgentData: navigator.userAgentData ? {
      brands: navigator.userAgentData.brands,
      mobile: navigator.userAgentData.mobile,
      platform: navigator.userAgentData.platform,
      architecture: navigator.userAgentData.architecture,
      bitness: navigator.userAgentData.bitness,
      model: navigator.userAgentData.model,
      platformVersion: navigator.userAgentData.platformVersion,
      fullVersionList: navigator.userAgentData.fullVersionList,
      wow64: navigator.userAgentData.wow64
    } : 'unsupported',
    // Additional platform and system information
    platformDetails: {
      platform: navigator.platform,
      vendor: navigator.vendor,
      product: navigator.product,
      productSub: navigator.productSub,
      appName: navigator.appName,
      appVersion: navigator.appVersion,
      appCodeName: navigator.appCodeName,
      cookieEnabled: navigator.cookieEnabled,
      onLine: navigator.onLine,
      doNotTrack: navigator.doNotTrack,
      maxTouchPoints: navigator.maxTouchPoints || 'unknown',
      msMaxTouchPoints: navigator.msMaxTouchPoints || 'unknown'
    },
    // Enhanced language and locale information
    localeInfo: {
      languages: navigator.languages,
      language: navigator.language,
      hasLanguages: Array.isArray(navigator.languages),
      languageCount: navigator.languages ? navigator.languages.length : 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      dateFormat: new Intl.DateTimeFormat().formatToParts(new Date()).map(p => p.type),
      numberFormat: new Intl.NumberFormat().resolvedOptions(),
      collator: new Intl.Collator().resolvedOptions()
    },
    // Screen and display information
    displayInfo: {
      screen: { 
        width: screen.width, 
        height: screen.height, 
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        orientation: screen.orientation ? {
          type: screen.orientation.type,
          angle: screen.orientation.angle
        } : 'unsupported'
      },
      window: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        devicePixelRatio: window.devicePixelRatio,
        colorGamut: window.matchMedia('(color-gamut: srgb)').matches ? 'srgb' : 
                    window.matchMedia('(color-gamut: p3)').matches ? 'p3' : 
                    window.matchMedia('(color-gamut: rec2020)').matches ? 'rec2020' : 'unknown'
      }
    },
    // Media capabilities and codecs
    mediaCapabilities: {
      mediaSession: 'mediaSession' in navigator,
      mediaDevices: 'mediaDevices' in navigator,
      permissions: 'permissions' in navigator,
      credentials: 'credentials' in navigator,
      storage: 'storage' in navigator,
      presentation: 'presentation' in navigator,
      wakeLock: 'wakeLock' in navigator,
      usb: 'usb' in navigator,
      bluetooth: 'bluetooth' in navigator,
      hid: 'hid' in navigator,
      serial: 'serial' in navigator
    },
    // Performance and memory information
    performanceInfo: {
      memory: performance.memory ? {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
      } : 'unsupported',
      timing: performance.timing ? {
        navigationStart: performance.timing.navigationStart,
        loadEventEnd: performance.timing.loadEventEnd,
        domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
      } : 'unsupported',
      navigation: performance.navigation ? {
        type: performance.navigation.type,
        redirectCount: performance.navigation.redirectCount
      } : 'unsupported'
    },
    // WebGL and graphics information
    graphicsInfo: {
      webgl: (() => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return 'unsupported';
          
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          return {
            vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
            renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown',
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
          };
        } catch (e) {
          return 'error: ' + e.message;
        }
      })(),
      webgl2: (() => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl2');
          if (!gl) return 'unsupported';
          
          return {
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
          };
        } catch (e) {
          return 'error: ' + e.message;
        }
      })()
    }
  };
  
  // Wait a bit for SharedWorker to respond before sending fingerprint
  setTimeout(() => {
    const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host);
    ws.onopen=()=>ws.send(JSON.stringify({type:'fingerprint',data:fp}));
  }, 1000);
})();
</script>
    `;

    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Logs</title></head><body>
<h1>Logs (HTML + WS Fingerprint)</h1>
${entriesHtml}
${script}
</body></html>`);
  });
});

// HTML view at '/' with fingerprinting script
app.get('/', (req, res) => {
  db.all(`SELECT method,url,headers,body,timestamp FROM logs ORDER BY id DESC`, (err, rows) => {
    if (err) return res.status(500).send('Error reading logs');

    const entriesHtml = rows.map(r => `
      <div class="log-entry">
        <h2>[${r.timestamp}] ${r.method} ${r.url}</h2>
        <h3>Headers:</h3>
        <pre>${JSON.stringify(JSON.parse(r.headers||'{}'),null,2)}</pre>
        ${r.body ? `<h3>Body:</h3><pre>${JSON.stringify(JSON.parse(r.body),null,2)}</pre>` : ''}
      </div>
    `).join('');

    const script = `
<script>
(function(){
  function getCanvasFingerprint(){
    const canvas=document.createElement('canvas');
    const ctx=canvas.getContext('2d');
    ctx.textBaseline='top';ctx.font='16px Arial';
    ctx.fillStyle='#f60';ctx.fillRect(125,1,62,20);
    ctx.fillStyle='#069';ctx.fillText('FPJS',2,15);
    ctx.fillStyle='rgba(102,204,0,0.7)';ctx.fillText('FPJS',4,17);
    return canvas.toDataURL();
  }
  
  function parseCookies(cookieString) {
    if (!cookieString) return {};
    const cookies = {};
    cookieString.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies[name] = decodeURIComponent(value);
      }
    });
    return cookies;
  }
  
  // SharedWorker fingerprinting with Blob-based approach
  let sharedWorkerFingerprint = {};
  try {
    // Check for SharedWorker support with proper constructor validation
    const Wkr = window.frameElement ? window.frameElement.SharedWorker : SharedWorker;
    if (!Wkr || Wkr.prototype.constructor.name !== "SharedWorker") {
      sharedWorkerFingerprint = { 
        supported: false, 
        error: 'SharedWorker not available or invalid constructor' 
      };
    } else {
      // Create fingerprinting JavaScript for the worker
      const fingerprintingJS = \`
        self.onconnect = function(e) {
          const port = e.ports[0];
          port.start();
          
          // Comprehensive fingerprinting from within the worker context
          function collectFingerprint() {
            try {
              const fp = {
                // Worker context information
                workerContext: {
                  type: 'SharedWorker',
                  constructor: self.constructor.name,
                  prototype: self.constructor.prototype ? Object.getOwnPropertyNames(self.constructor.prototype).length : 0,
                  maxWorkers: navigator.hardwareConcurrency || 'unknown',
                  userAgent: navigator.userAgent,
                  platform: navigator.platform,
                  languages: navigator.languages,
                  language: navigator.language,
                  cookieEnabled: navigator.cookieEnabled,
                  onLine: navigator.onLine,
                  doNotTrack: navigator.doNotTrack,
                  maxTouchPoints: navigator.maxTouchPoints || 'unknown',
                  msMaxTouchPoints: navigator.msMaxTouchPoints || 'unknown'
                },
                
                // Enhanced User-Agent and Platform data
                userAgentData: navigator.userAgentData ? {
                  brands: navigator.userAgentData.brands,
                  mobile: navigator.userAgentData.mobile,
                  platform: navigator.userAgentData.platform,
                  architecture: navigator.userAgentData.architecture,
                  bitness: navigator.userAgentData.bitness,
                  model: navigator.userAgentData.model,
                  platformVersion: navigator.userAgentData.platformVersion,
                  fullVersionList: navigator.userAgentData.fullVersionList,
                  wow64: navigator.userAgentData.wow64
                } : 'unsupported',
                
                // Additional platform and system information
                platformDetails: {
                  platform: navigator.platform,
                  vendor: navigator.vendor,
                  product: navigator.product,
                  productSub: navigator.productSub,
                  appName: navigator.appName,
                  appVersion: navigator.appVersion,
                  appCodeName: navigator.appCodeName
                },
                
                // Enhanced language and locale information
                localeInfo: {
                  languages: navigator.languages,
                  language: navigator.language,
                  hasLanguages: Array.isArray(navigator.languages),
                  languageCount: navigator.languages ? navigator.languages.length : 0,
                  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                  timezoneOffset: new Date().getTimezoneOffset(),
                  dateFormat: new Intl.DateTimeFormat().formatToParts(new Date()).map(p => p.type),
                  numberFormat: new Intl.NumberFormat().resolvedOptions(),
                  collator: new Intl.Collator().resolvedOptions()
                },
                
                // Hardware and performance information
                hardwareInfo: {
                  hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                  deviceMemory: navigator.deviceMemory || 'unknown',
                  connection: navigator.connection ? {
                    effectiveType: navigator.connection.effectiveType,
                    downlink: navigator.connection.downlink,
                    rtt: navigator.connection.rtt
                  } : 'unsupported'
                },
                
                // Worker-specific capabilities (only worker-available APIs)
                workerCapabilities: {
                  sharedWorker: true, // We're already in a SharedWorker
                  worker: typeof Worker !== 'undefined',
                  serviceWorker: 'serviceWorker' in navigator,
                  worklet: false, // CSS not available in workers
                  offscreenCanvas: typeof OffscreenCanvas !== 'undefined'
                },
                
                // Media capabilities (only worker-available APIs)
                mediaCapabilities: {
                  mediaSession: 'mediaSession' in navigator,
                  mediaDevices: 'mediaDevices' in navigator,
                  permissions: 'permissions' in navigator,
                  credentials: 'credentials' in navigator,
                  storage: 'storage' in navigator,
                  presentation: 'presentation' in navigator,
                  wakeLock: 'wakeLock' in navigator,
                  usb: 'usb' in navigator,
                  bluetooth: 'bluetooth' in navigator,
                  hid: 'hid' in navigator,
                  serial: 'serial' in navigator
                },
                
                // Performance information
                performanceInfo: {
                  memory: performance.memory ? {
                    usedJSHeapSize: performance.memory.usedJSHeapSize,
                    totalJSHeapSize: performance.memory.totalJSHeapSize,
                    jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                  } : 'unsupported',
                  timing: performance.timing ? {
                    navigationStart: performance.timing.navigationStart,
                    loadEventEnd: performance.timing.loadEventEnd,
                    domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
                  } : 'unsupported',
                  navigation: performance.navigation ? {
                    type: performance.navigation.type,
                    redirectCount: performance.navigation.redirectCount
                  } : 'unsupported'
                },
                
                // Canvas fingerprinting (simplified for worker)
                canvas: 'offscreen_supported'
              };
              
              return fp;
            } catch (e) {
              return { error: 'Worker fingerprinting failed: ' + e.message };
            }
          }
          
          // Collect and send fingerprint immediately
          try {
            const fp = collectFingerprint();
            port.postMessage({ type: 'fingerprint', data: fp });
          } catch (error) {
            port.postMessage({ type: 'error', error: error.message });
          }
        };
      \`;
      
      // Create Blob-based SharedWorker
      const worker = new Wkr(
        URL.createObjectURL(
          new Blob([fingerprintingJS], { type: "application/javascript" })
        )
      );
      
      sharedWorkerFingerprint = {
        supported: true,
        constructor: Wkr.name,
        prototype: Wkr.prototype ? Object.getOwnPropertyNames(Wkr.prototype).length : 0,
        maxWorkers: navigator.hardwareConcurrency || 'unknown'
      };
      
      // Handle messages from the worker
      worker.port.onmessage = function(e) {
        if (e.data.type === 'fingerprint') {
          sharedWorkerFingerprint.working = true;
          sharedWorkerFingerprint.workerData = e.data.data;
          console.log('SharedWorker fingerprint collected:', e.data.data);
        } else if (e.data.type === 'error') {
          sharedWorkerFingerprint.error = e.data.error;
          console.error('SharedWorker error:', e.data.error);
        }
      };
      
      // Handle worker errors
      worker.port.onerror = function(e) {
        sharedWorkerFingerprint.error = 'Port error: ' + e.message;
        console.error('SharedWorker port error:', e);
      };
      
      worker.port.start();
      
      // Set a timeout to mark as failed if no response
      setTimeout(() => {
        if (!sharedWorkerFingerprint.working && !sharedWorkerFingerprint.error) {
          sharedWorkerFingerprint.error = 'Timeout: No response from worker';
          console.warn('SharedWorker timeout - no response received');
        }
      }, 5000);
      
      // Clean up the blob URL when done
      setTimeout(() => {
        URL.revokeObjectURL(worker.port.url);
      }, 10000);
    }
  } catch (e) {
    sharedWorkerFingerprint = { supported: false, error: e.message };
  }
  
  const fp = {
    origin: location.pathname,
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: navigator.languages,
    screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    webdriver: navigator.webdriver||false,
    hasLanguages: Array.isArray(navigator.languages),
    pluginsCount: navigator.plugins.length,
    headlessUA: /HeadlessChrome/.test(navigator.userAgent),
    canvas: getCanvasFingerprint(),
    cookies: parseCookies(document.cookie),
    rawCookies: document.cookie,
    sharedWorker: sharedWorkerFingerprint,
    // Additional SharedWorker-related properties
    workerSupport: {
      sharedWorker: typeof SharedWorker !== 'undefined',
      worker: typeof Worker !== 'undefined',
      serviceWorker: 'serviceWorker' in navigator,
      worklet: 'worklet' in CSS
    },
    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
    deviceMemory: navigator.deviceMemory || 'unknown',
    connection: navigator.connection ? {
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt
    } : 'unsupported',
    // Enhanced User-Agent and Platform data
    userAgentData: navigator.userAgentData ? {
      brands: navigator.userAgentData.brands,
      mobile: navigator.userAgentData.mobile,
      platform: navigator.userAgentData.platform,
      architecture: navigator.userAgentData.architecture,
      bitness: navigator.userAgentData.bitness,
      model: navigator.userAgentData.model,
      platformVersion: navigator.userAgentData.platformVersion,
      fullVersionList: navigator.userAgentData.fullVersionList,
      wow64: navigator.userAgentData.wow64
    } : 'unsupported',
    // Additional platform and system information
    platformDetails: {
      platform: navigator.platform,
      vendor: navigator.vendor,
      product: navigator.product,
      productSub: navigator.productSub,
      appName: navigator.appName,
      appVersion: navigator.appVersion,
      appCodeName: navigator.appCodeName,
      cookieEnabled: navigator.cookieEnabled,
      onLine: navigator.onLine,
      doNotTrack: navigator.doNotTrack,
      maxTouchPoints: navigator.maxTouchPoints || 'unknown',
      msMaxTouchPoints: navigator.msMaxTouchPoints || 'unknown'
    },
    // Enhanced language and locale information
    localeInfo: {
      languages: navigator.languages,
      language: navigator.language,
      hasLanguages: Array.isArray(navigator.languages),
      languageCount: navigator.languages ? navigator.languages.length : 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      dateFormat: new Intl.DateTimeFormat().formatToParts(new Date()).map(p => p.type),
      numberFormat: new Intl.NumberFormat().resolvedOptions(),
      collator: new Intl.Collator().resolvedOptions()
    },
    // Screen and display information
    displayInfo: {
      screen: { 
        width: screen.width, 
        height: screen.height, 
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        orientation: screen.orientation ? {
          type: screen.orientation.type,
          angle: screen.orientation.angle
        } : 'unsupported'
      },
      window: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        devicePixelRatio: window.devicePixelRatio,
        colorGamut: window.matchMedia('(color-gamut: srgb)').matches ? 'srgb' : 
                    window.matchMedia('(color-gamut: p3)').matches ? 'p3' : 
                    window.matchMedia('(color-gamut: rec2020)').matches ? 'rec2020' : 'unknown'
      }
    },
    // Media capabilities and codecs
    mediaCapabilities: {
      mediaSession: 'mediaSession' in navigator,
      mediaDevices: 'mediaDevices' in navigator,
      permissions: 'permissions' in navigator,
      credentials: 'credentials' in navigator,
      storage: 'storage' in navigator,
      presentation: 'presentation' in navigator,
      wakeLock: 'wakeLock' in navigator,
      usb: 'usb' in navigator,
      bluetooth: 'bluetooth' in navigator,
      hid: 'hid' in navigator,
      serial: 'serial' in navigator
    },
    // Performance and memory information
    performanceInfo: {
      memory: performance.memory ? {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
      } : 'unsupported',
      timing: performance.timing ? {
        navigationStart: performance.timing.navigationStart,
        loadEventEnd: performance.timing.loadEventEnd,
        domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
      } : 'unsupported',
      navigation: performance.navigation ? {
        type: performance.navigation.type,
        redirectCount: performance.navigation.redirectCount
      } : 'unsupported'
    },
    // WebGL and graphics information
    graphicsInfo: {
      webgl: (() => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return 'unsupported';
          
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          return {
            vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
            renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown',
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
          };
        } catch (e) {
          return 'error: ' + e.message;
        }
      })(),
      webgl2: (() => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl2');
          if (!gl) return 'unsupported';
          
          return {
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
          };
        } catch (e) {
          return 'error: ' + e.message;
        }
      })()
    }
  };
  
  // Wait a bit for SharedWorker to respond before sending fingerprint
  setTimeout(() => {
    const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host);
    ws.onopen=()=>ws.send(JSON.stringify({type:'fingerprint',data:fp}));
  }, 1000);
})();
</script>
    `;

    res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>HTTP Request Logger</title>
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
    .log-entry {
      background-color: #2d2d2d;
      border: 1px solid #555;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.3);
    }
    .log-entry h2 {
      color: #4a90e2;
      margin-top: 0;
      margin-bottom: 15px;
      font-size: 18px;
    }
    .log-entry h3 {
      color: #e0e0e0;
      margin-bottom: 10px;
      font-size: 14px;
    }
    pre {
      background-color: #3d3d3d;
      border: 1px solid #666;
      border-radius: 4px;
      padding: 15px;
      color: #b0b0b0;
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
    }
    .nav-link {
      display: inline-block;
      background-color: #007bff;
      color: white;
      padding: 10px 20px;
      text-decoration: none;
      border-radius: 6px;
      margin: 10px 5px;
      transition: background-color 0.3s;
    }
    .nav-link:hover {
      background-color: #0056b3;
    }
  </style>
</head>
<body>
  <h1>🌐 HTTP Request Logger</h1>
  
  <div style="text-align: center; margin-bottom: 30px;">
    <a href="/objects" class="nav-link">🔍 Browser Objects Explorer</a>
    <a href="/logs" class="nav-link">📋 View Logs API</a>
  </div>
  
  <div class="log-entries">
    ${entriesHtml}
  </div>
  
  ${script}
</body>
</html>`);
  });
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
      }
    } catch (e) {
      console.error('WS parse error:', e);
    }
  });
});

// Browser Objects route
app.get('/objects', (req, res) => {
  const html = `<!DOCTYPE html>
<html>
  <head>
  <meta charset="utf-8">
  <title>Browser Objects Explorer</title>
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
  <h1>🌐 Browser Objects Explorer</h1>
  
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
  
  <!-- Save Session Button -->
  <button id="saveSession" style="position: fixed; top: 80px; right: 20px; background-color: #28a745; color: white; border: none; border-radius: 50%; width: 50px; height: 50px; cursor: pointer; z-index: 1001; font-size: 18px;" title="Save Current Session">💾</button>

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
  
  // Browser Objects Properties Display with Dynamic Observation
  (function() {
    const browserObjectsContainer = document.getElementById('browserObjects');
    let observedObjects = new Map();
    let propertyChangeCallbacks = new Map();
    
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
    
    // Create a proxy to observe property changes
    function createObservingProxy(originalObj, objectName) {
      const knownProperties = new Set(getAllProperties(originalObj));
      
      return new Proxy(originalObj, {
        set(target, property, value) {
          const isNewProperty = !knownProperties.has(property);
          const result = Reflect.set(target, property, value);
          
          if (isNewProperty) {
            knownProperties.add(property);
            console.log('New property detected on ' + objectName + ': ' + String(property));
            
            // Notify all callbacks about the new property
            const callbacks = propertyChangeCallbacks.get(objectName);
            if (callbacks) {
              callbacks.forEach(callback => callback(property, value, 'added'));
            }
          }
          
          return result;
        },
        
        defineProperty(target, property, descriptor) {
          const isNewProperty = !knownProperties.has(property);
          const result = Reflect.defineProperty(target, property, descriptor);
          
          if (isNewProperty) {
            knownProperties.add(property);
            console.log('New property defined on ' + objectName + ': ' + String(property));
            
            // Notify all callbacks about the new property
            const callbacks = propertyChangeCallbacks.get(objectName);
            if (callbacks) {
              callbacks.forEach(callback => callback(property, descriptor, 'defined'));
            }
          }
          
          return result;
        },
        
        deleteProperty(target, property) {
          const hadProperty = knownProperties.has(property);
          const result = Reflect.deleteProperty(target, property);
          
          if (hadProperty) {
            knownProperties.delete(property);
            console.log('Property deleted from ' + objectName + ': ' + String(property));
            
            // Notify all callbacks about the deleted property
            const callbacks = propertyChangeCallbacks.get(objectName);
            if (callbacks) {
              callbacks.forEach(callback => callback(property, undefined, 'deleted'));
            }
          }
          
          return result;
        }
      });
    }
    
    // Function to register a callback for property changes
    function onPropertyChange(objectName, callback) {
      if (!propertyChangeCallbacks.has(objectName)) {
        propertyChangeCallbacks.set(objectName, []);
      }
      propertyChangeCallbacks.get(objectName).push(callback);
    }
    
    // Function to update the display for a specific object
    function updateObjectDisplay(objectName, objectInfo) {
      const existingDiv = document.querySelector('[data-object-name="' + objectName + '"]');
      if (!existingDiv) return;
      
      const allProperties = getAllProperties(objectInfo.object);
      const propertiesContainer = existingDiv.querySelector('.properties-container');
      const propertyCount = existingDiv.querySelector('.property-count');
      
      // Update property count
      if (propertyCount) {
        propertyCount.textContent = '(' + allProperties.length + ' properties)';
      }
      
      // Create new properties HTML
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
      
      // Update the properties container
      if (propertiesContainer) {
        propertiesContainer.innerHTML = propertiesHtml;
      }
    }
    
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
    
    // Create HTML for each browser object with observation
    Object.entries(browserObjects).forEach(([objectName, objectInfo]) => {
      const objectDiv = document.createElement('div');
      objectDiv.setAttribute('data-object-name', objectName);
      objectDiv.style.cssText = 
        'background: #3d3d3d; ' +
        'border: 1px solid #555; ' +
        'border-radius: 6px; ' +
        'padding: 15px; ' +
        'box-shadow: 0 2px 4px rgba(0,0,0,0.3);';
      
      // Create observing proxy for this object
      const observedObj = createObservingProxy(objectInfo.object, objectName);
      observedObjects.set(objectName, observedObj);
      
      // Register callback for property changes
      onPropertyChange(objectName, (property, value, action) => {
        console.log('Property ' + action + ': ' + property + ' on ' + objectName, value);
        updateObjectDisplay(objectName, { ...objectInfo, object: observedObj });
        
        // Add visual indicator for new properties
        if (action === 'added' || action === 'defined') {
          const propertyElement = objectDiv.querySelector('[data-property="' + property + '"]');
          if (propertyElement) {
            propertyElement.style.animation = 'highlight 2s ease-in-out';
            propertyElement.style.border = '2px solid #28a745';
            setTimeout(() => {
              propertyElement.style.animation = '';
              propertyElement.style.border = '1px solid #666';
            }, 2000);
          }
        }
      });
      
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
        
        return '<div data-property="' + prop + '" style="background: #4d4d4d; border: 1px solid #666; padding: 8px; border-radius: 4px; margin: 2px; display: inline-block; min-width: 200px; vertical-align: top;">' +
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
          ' <span class="property-count" style="font-size: 12px; color: #b0b0b0;">(' + allProperties.length + ' properties)</span>' +
          ' <span style="font-size: 10px; color: #28a745;">[LIVE OBSERVING]</span>' +
        '</h4>' +
        '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
          objectInfo.description +
        '</p>' +
        '<div style="margin-top: 10px;">' +
          '<strong style="color: #e0e0e0; font-size: 13px;">All Properties & Methods (Live Updates):</strong>' +
          '<div class="properties-container" style="margin-top: 5px; max-height: 300px; overflow-y: auto; border: 1px solid #666; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
            propertiesHtml +
          '</div>' +
          '<div style="margin-top: 5px; font-size: 11px; color: #b0b0b0;">' +
            'Legend: E=Enumerable, C=Configurable, W=Writable, G=Getter, S=Setter | 🆕 New properties will be highlighted' +
          '</div>' +
        '</div>';
      
      browserObjectsContainer.appendChild(objectDiv);
    });
    
    // Add CSS animation for highlighting new properties
    const style = document.createElement('style');
    style.textContent = 
      '@keyframes highlight {' +
        '0% { background-color: #4d4d4d; }' +
        '50% { background-color: #28a745; }' +
        '100% { background-color: #4d4d4d; }' +
      '}';
    document.head.appendChild(style);
    
    // Expose observed objects map globally for storage system
    window.observedObjects = observedObjects;
    
    // Expose global functions for testing property observation
    window.addTestProperty = function(objectName, propertyName, value) {
      const obj = observedObjects.get(objectName);
      if (obj) {
        obj[propertyName] = value;
        console.log('Added test property ' + propertyName + ' to ' + objectName);
      } else {
        console.error('Object ' + objectName + ' not found');
      }
    };
    
    window.removeTestProperty = function(objectName, propertyName) {
      const obj = observedObjects.get(objectName);
      if (obj) {
        delete obj[propertyName];
        console.log('Removed test property ' + propertyName + ' from ' + objectName);
      } else {
        console.error('Object ' + objectName + ' not found');
      }
    };
    
    // Expose function to manually trigger storage
    window.saveCurrentSession = function() {
      storeCurrentSession();
      console.log('Current session saved to storage');
    };
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
    
    // Save session button functionality
    const saveSessionBtn = document.getElementById('saveSession');
    saveSessionBtn.addEventListener('click', () => {
      storeCurrentSession();
      // Visual feedback
      saveSessionBtn.style.backgroundColor = '#20c997';
      saveSessionBtn.textContent = '✓';
      setTimeout(() => {
        saveSessionBtn.style.backgroundColor = '#28a745';
        saveSessionBtn.textContent = '💾';
      }, 1000);
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
      
      // Collect all browser object data from observed objects
      const browserObjects = ['window', 'document', 'navigator', 'location', 'history', 'screen'];
      browserObjects.forEach(objName => {
        // Get the observed object from the global observedObjects map
        const observedObj = window.observedObjects ? window.observedObjects.get(objName) : window[objName];
        const obj = observedObj || window[objName];
        
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

// Start server
server.listen(port, () => console.log(`Server running on http://localhost:${port}`));