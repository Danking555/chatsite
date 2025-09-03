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
  
  // SharedWorker fingerprinting with comprehensive data collection
  let sharedWorkerFingerprint = {};
  try {
    if (typeof SharedWorker !== 'undefined') {
      // Create a SharedWorker that performs comprehensive fingerprinting
      const workerScript = \`
        self.onconnect = function(e) {
          const port = e.ports[0];
          port.start();
          
          // Comprehensive fingerprinting from within the worker context
          function getCanvasFingerprint() {
            try {
              const canvas = new OffscreenCanvas(100, 100);
              const ctx = canvas.getContext('2d');
              if (!ctx) return 'unsupported';
              
              ctx.textBaseline = 'top';
              ctx.font = '16px Arial';
              ctx.fillStyle = '#f60';
              ctx.fillRect(125, 1, 62, 20);
              ctx.fillStyle = '#069';
              ctx.fillText('FPJS', 2, 15);
              ctx.fillStyle = 'rgba(102,204,0,0.7)';
              ctx.fillText('FPJS', 4, 17);
              
              // Convert to blob for fingerprinting
              return canvas.convertToBlob().then(() => 'canvas_supported');
            } catch (e) {
              return 'error: ' + e.message;
            }
          }
          
          async function collectFingerprint() {
            const fp = {
              // Worker context information
              workerContext: {
                type: 'SharedWorker',
                constructor: SharedWorker.name,
                prototype: SharedWorker.prototype ? Object.getOwnPropertyNames(SharedWorker.prototype).length : 0,
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
              
              // Worker-specific capabilities
              workerCapabilities: {
                sharedWorker: typeof SharedWorker !== 'undefined',
                worker: typeof Worker !== 'undefined',
                serviceWorker: 'serviceWorker' in navigator,
                worklet: 'worklet' in CSS,
                offscreenCanvas: typeof OffscreenCanvas !== 'undefined',
                webgl: (() => {
                  try {
                    const canvas = new OffscreenCanvas(100, 100);
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
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
                })(),
                webgl2: (() => {
                  try {
                    const canvas = new OffscreenCanvas(100, 100);
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
              },
              
              // Media capabilities
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
              
              // Canvas fingerprinting
              canvas: await getCanvasFingerprint()
            };
            
            return fp;
          }
          
          // Collect and send fingerprint
          collectFingerprint().then(fp => {
            port.postMessage({ type: 'fingerprint', data: fp });
          }).catch(error => {
            port.postMessage({ type: 'error', error: error.message });
          });
        };
      \`;
      
      const sw = new SharedWorker('data:text/javascript,' + encodeURIComponent(workerScript));
      sharedWorkerFingerprint = {
        supported: true,
        constructor: SharedWorker.name,
        prototype: SharedWorker.prototype ? Object.getOwnPropertyNames(SharedWorker.prototype).length : 0,
        maxWorkers: navigator.hardwareConcurrency || 'unknown'
      };
      
      // Handle messages from the worker
      sw.port.onmessage = function(e) {
        if (e.data.type === 'fingerprint') {
          sharedWorkerFingerprint.working = true;
          sharedWorkerFingerprint.workerData = e.data.data;
        } else if (e.data.type === 'error') {
          sharedWorkerFingerprint.error = e.data.error;
        }
      };
      sw.port.start();
    } else {
      sharedWorkerFingerprint = { supported: false };
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
  const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host);
  ws.onopen=()=>ws.send(JSON.stringify({type:'fingerprint',data:fp}));
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
  
  // SharedWorker fingerprinting with comprehensive data collection
  let sharedWorkerFingerprint = {};
  try {
    if (typeof SharedWorker !== 'undefined') {
      // Create a SharedWorker that performs comprehensive fingerprinting
      const workerScript = \`
        self.onconnect = function(e) {
          const port = e.ports[0];
          port.start();
          
          // Comprehensive fingerprinting from within the worker context
          function getCanvasFingerprint() {
            try {
              const canvas = new OffscreenCanvas(100, 100);
              const ctx = canvas.getContext('2d');
              if (!ctx) return 'unsupported';
              
              ctx.textBaseline = 'top';
              ctx.font = '16px Arial';
              ctx.fillStyle = '#f60';
              ctx.fillRect(125, 1, 62, 20);
              ctx.fillStyle = '#069';
              ctx.fillText('FPJS', 2, 15);
              ctx.fillStyle = 'rgba(102,204,0,0.7)';
              ctx.fillText('FPJS', 4, 17);
              
              // Convert to blob for fingerprinting
              return canvas.convertToBlob().then(() => 'canvas_supported');
            } catch (e) {
              return 'error: ' + e.message;
            }
          }
          
          async function collectFingerprint() {
            const fp = {
              // Worker context information
              workerContext: {
                type: 'SharedWorker',
                constructor: SharedWorker.name,
                prototype: SharedWorker.prototype ? Object.getOwnPropertyNames(SharedWorker.prototype).length : 0,
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
              
              // Worker-specific capabilities
              workerCapabilities: {
                sharedWorker: typeof SharedWorker !== 'undefined',
                worker: typeof Worker !== 'undefined',
                serviceWorker: 'serviceWorker' in navigator,
                worklet: 'worklet' in CSS,
                offscreenCanvas: typeof OffscreenCanvas !== 'undefined',
                webgl: (() => {
                  try {
                    const canvas = new OffscreenCanvas(100, 100);
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
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
                })(),
                webgl2: (() => {
                  try {
                    const canvas = new OffscreenCanvas(100, 100);
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
              },
              
              // Media capabilities
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
              
              // Canvas fingerprinting
              canvas: await getCanvasFingerprint()
            };
            
            return fp;
          }
          
          // Collect and send fingerprint
          collectFingerprint().then(fp => {
            port.postMessage({ type: 'fingerprint', data: fp });
          }).catch(error => {
            port.postMessage({ type: 'error', error: error.message });
          });
        };
      \`;
      
      const sw = new SharedWorker('data:text/javascript,' + encodeURIComponent(workerScript));
      sharedWorkerFingerprint = {
        supported: true,
        constructor: SharedWorker.name,
        prototype: SharedWorker.prototype ? Object.getOwnPropertyNames(SharedWorker.prototype).length : 0,
        maxWorkers: navigator.hardwareConcurrency || 'unknown'
      };
      
      // Handle messages from the worker
      sw.port.onmessage = function(e) {
        if (e.data.type === 'fingerprint') {
          sharedWorkerFingerprint.working = true;
          sharedWorkerFingerprint.workerData = e.data.data;
        } else if (e.data.type === 'error') {
          sharedWorkerFingerprint.error = e.data.error;
        }
      };
      sw.port.start();
    } else {
      sharedWorkerFingerprint = { supported: false };
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
  const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host);
  ws.onopen=()=>ws.send(JSON.stringify({type:'fingerprint',data:fp}));
})();
</script>
    `;

    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Home</title></head><body>
<h1>Home (HTML + WS Fingerprint)</h1>
${entriesHtml}
${script}
</body></html>`);
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

// Start server
server.listen(port, () => console.log(`Server running on http://localhost:${port}`));