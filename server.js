/**
 * NetSentry — IoT Network Monitor & Traffic Inspector
 * Main server: Express HTTP + WebSocket + DNS Proxy
 */

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const path = require('path');

const { scanNetwork, getNetworkInfo } = require('./lib/scanner');
const { startCapture, startDNSMonitor, stopCaptureForIP, stopAllCaptures, getActiveCaptures } = require('./lib/capture');
const { TrafficAnalyzer } = require('./lib/analyzer');
const { DNSProxy } = require('./lib/dns-proxy');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;

// State
let cachedScanResult = null;
let isScanning = false;
const analyzer = new TrafficAnalyzer();
const dnsLog = [];
const MAX_DNS_LOG = 5000;
let dnsMonitorId = null;
let dnsProxy = null;

// Per-device DNS tracking (from the DNS proxy)
const deviceDNS = new Map(); // ip -> { queries: [], topDomains: Map, lastSeen }

// Track connected WebSocket clients
const wsClients = new Set();

// ============================
// Serve static frontend
// ============================
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ============================
// REST API Endpoints
// ============================

app.get('/api/network-info', (req, res) => {
  try {
    const info = getNetworkInfo();
    res.json({ success: true, data: info });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/scan', async (req, res) => {
  if (isScanning) {
    return res.json({ success: false, error: 'Scan already in progress' });
  }

  isScanning = true;
  broadcast({ type: 'scan_started' });

  try {
    const result = await scanNetwork();

    // Merge with existing traffic stats & DNS data
    for (const device of result.devices) {
      const stats = analyzer.getStats(device.ip);
      if (stats) {
        device.riskScore = stats.riskScore;
        device.trafficStats = {
          packets: stats.totalPackets,
          bytes: stats.totalBytes,
          connections: stats.uniqueDestinations
        };
      }
      // Merge DNS query count
      const dns = deviceDNS.get(device.ip);
      if (dns) {
        device.dnsQueryCount = dns.queries.length;
        device.topDomains = getTopDomains(device.ip, 3);
      }
    }

    cachedScanResult = result;
    isScanning = false;

    broadcast({ type: 'scan_complete', data: result });
    res.json({ success: true, data: result });
  } catch (err) {
    isScanning = false;
    broadcast({ type: 'scan_error', error: err.message });
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/devices', (req, res) => {
  if (!cachedScanResult) {
    return res.json({ success: true, data: { devices: [], networkInfo: null, scanMethod: 'none' } });
  }
  res.json({ success: true, data: cachedScanResult });
});

app.post('/api/capture/start/:ip', (req, res) => {
  const { ip } = req.params;
  try {
    const networkInfo = getNetworkInfo();
    const captureId = startCapture(ip, networkInfo.iface, (packet) => {
      const analysis = analyzer.analyzePacket(packet);
      broadcast({
        type: 'packet',
        data: packet,
        riskScore: analysis.riskScore,
        alerts: analysis.alerts
      });
    });
    res.json({ success: true, captureId, ip, iface: networkInfo.iface });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/capture/stop/:ip', (req, res) => {
  const { ip } = req.params;
  stopCaptureForIP(ip);
  res.json({ success: true, message: `Capture stopped for ${ip}` });
});

app.post('/api/capture/stop-all', (req, res) => {
  stopAllCaptures();
  res.json({ success: true, message: 'All captures stopped' });
});

app.get('/api/captures', (req, res) => {
  res.json({ success: true, data: getActiveCaptures() });
});

app.get('/api/dns-log', (req, res) => {
  const { device, limit } = req.query;
  let filtered = dnsLog;
  if (device) {
    filtered = dnsLog.filter(d => d.deviceIP === device);
  }
  const max = parseInt(limit) || 200;
  res.json({ success: true, data: filtered.slice(-max) });
});

/**
 * GET /api/device-dns/:ip
 * Get full DNS activity profile for a device (from DNS proxy)
 */
app.get('/api/device-dns/:ip', (req, res) => {
  const { ip } = req.params;
  const dns = deviceDNS.get(ip);
  if (!dns) {
    return res.json({ success: true, data: { queries: [], topDomains: [], totalQueries: 0 } });
  }
  res.json({
    success: true,
    data: {
      queries: dns.queries.slice(-300),
      topDomains: getTopDomains(ip, 20),
      totalQueries: dns.queries.length
    }
  });
});

app.get('/api/alerts', (req, res) => {
  const { device } = req.query;
  const alerts = analyzer.getAlerts(device);
  res.json({ success: true, data: alerts });
});

app.get('/api/device-stats/:ip', (req, res) => {
  const stats = analyzer.getStats(req.params.ip);
  if (!stats) {
    return res.json({ success: true, data: null });
  }
  res.json({ success: true, data: stats });
});

/**
 * GET /api/dns-proxy/stats
 * Get DNS proxy statistics
 */
app.get('/api/dns-proxy/stats', (req, res) => {
  if (!dnsProxy) {
    return res.json({ success: true, data: { running: false } });
  }
  res.json({ success: true, data: dnsProxy.getStats() });
});

/**
 * GET /api/lookup/:ip
 * Reverse DNS lookup + IP metadata
 */
app.get('/api/lookup/:ip', async (req, res) => {
  const { ip } = req.params;
  const dns = require('dns').promises;
  const result = {
    ip,
    hostnames: [],
    isPrivate: /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/.test(ip),
    deviceInfo: null,
    dnsActivity: null,
    trafficStats: null
  };

  // Reverse DNS
  try {
    result.hostnames = await dns.reverse(ip);
  } catch (e) {
    result.hostnames = [];
  }

  // Check if it's a known device on the network
  if (cachedScanResult && cachedScanResult.devices) {
    const device = cachedScanResult.devices.find(d => d.ip === ip);
    if (device) {
      result.deviceInfo = {
        hostname: device.hostname,
        mac: device.mac,
        vendor: device.vendor,
        type: device.type
      };
    }
  }

  // DNS activity for this IP
  const dnsData = deviceDNS.get(ip);
  if (dnsData) {
    result.dnsActivity = {
      totalQueries: dnsData.queries.length,
      recentQueries: dnsData.queries.slice(-10),
      topDomains: getTopDomains(ip, 5)
    };
  }

  // Check DNS log for domains resolving TO this IP
  const resolvedDomains = [];
  for (const entry of dnsLog) {
    if (entry.answer && entry.answer.includes(ip)) {
      if (!resolvedDomains.includes(entry.domain)) {
        resolvedDomains.push(entry.domain);
      }
    }
  }
  result.resolvedDomains = resolvedDomains.slice(0, 10);

  // Traffic stats
  const stats = analyzer.getStats(ip);
  if (stats) {
    result.trafficStats = stats;
  }

  res.json({ success: true, data: result });
});

/**
 * POST /api/request-builder
 * Send an arbitrary HTTP request and return the response
 */
app.post('/api/request-builder', async (req, res) => {
  const { url, method, headers, body } = req.body;
  if (!url) return res.status(400).json({ success: false, error: 'URL is required' });

  try {
    const parsedUrl = new URL(url);
    const isHTTPS = parsedUrl.protocol === 'https:';
    const lib = isHTTPS ? require('https') : require('http');

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHTTPS ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: (method || 'GET').toUpperCase(),
      headers: headers || {},
      rejectUnauthorized: false, // Allow self-signed certs
      timeout: 10000
    };

    const startTime = Date.now();

    const proxyReq = lib.request(options, (proxyRes) => {
      let responseBody = '';
      proxyRes.on('data', chunk => responseBody += chunk.toString());
      proxyRes.on('end', () => {
        const elapsed = Date.now() - startTime;
        // Convert headers to plain object
        const resHeaders = {};
        for (const [k, v] of Object.entries(proxyRes.headers)) {
          resHeaders[k] = v;
        }
        res.json({
          success: true,
          data: {
            status: proxyRes.statusCode,
            statusMessage: proxyRes.statusMessage,
            headers: resHeaders,
            body: responseBody.substring(0, 50000), // Cap at 50KB
            elapsed,
            size: Buffer.byteLength(responseBody)
          }
        });
      });
    });

    proxyReq.on('error', (err) => {
      res.json({ success: false, error: err.message });
    });

    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      res.json({ success: false, error: 'Request timed out (10s)' });
    });

    if (body) proxyReq.write(body);
    proxyReq.end();
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/analyze-connections/:ip
 * Resolve all domains a device contacts and identify providers
 */
app.get('/api/analyze-connections/:ip', async (req, res) => {
  const dns = require('dns').promises;
  const ip = req.params.ip;
  const deviceDns = deviceDNS.get(ip);
  if (!deviceDns) return res.json({ success: true, data: { connections: [] } });

  // Get unique domains
  const domainMap = {};
  for (const q of deviceDns.queries) {
    if (!domainMap[q.domain]) domainMap[q.domain] = { count: 0, lastSeen: q.timestamp };
    domainMap[q.domain].count++;
    domainMap[q.domain].lastSeen = q.timestamp;
  }

  const domains = Object.keys(domainMap);
  const connections = [];

  // Resolve each domain to IP
  for (const domain of domains.slice(0, 30)) { // Cap at 30
    try {
      const addresses = await dns.resolve4(domain).catch(() => []);
      const resolvedIP = addresses[0] || null;
      connections.push({
        domain,
        resolvedIP,
        queryCount: domainMap[domain].count,
        lastSeen: domainMap[domain].lastSeen
      });
    } catch (e) {
      connections.push({ domain, resolvedIP: null, queryCount: domainMap[domain].count, lastSeen: domainMap[domain].lastSeen });
    }
  }

  // Batch lookup IPs via ip-api.com (free, 45/min, batch up to 100)
  const ipsToLookup = connections.filter(c => c.resolvedIP && !/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/.test(c.resolvedIP)).map(c => c.resolvedIP);
  const uniqueIPs = [...new Set(ipsToLookup)];

  let ipInfo = {};
  if (uniqueIPs.length > 0) {
    try {
      const http = require('http');
      const body = JSON.stringify(uniqueIPs.map(ip => ({ query: ip, fields: 'query,country,isp,org,as,reverse' })));
      const result = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: 'ip-api.com', port: 80, path: '/batch',
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          timeout: 5000
        }, (res) => {
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve([]); } });
        });
        req.on('error', () => resolve([]));
        req.on('timeout', () => { req.destroy(); resolve([]); });
        req.write(body);
        req.end();
      });
      for (const r of result) {
        if (r.query) ipInfo[r.query] = { country: r.country, isp: r.isp, org: r.org, as: r.as, reverse: r.reverse };
      }
    } catch (e) { /* ip-api failed, continue without */ }
  }

  // Known safe providers
  const safeProviders = ['google','amazon','aws','microsoft','azure','apple','cloudflare','akamai','fastly','meta','facebook','cloudfront','gcore'];

  // Enrich connections
  for (const conn of connections) {
    if (conn.resolvedIP && ipInfo[conn.resolvedIP]) {
      const info = ipInfo[conn.resolvedIP];
      conn.provider = info.org || info.isp || 'Unknown';
      conn.country = info.country || '';
      conn.as = info.as || '';
      conn.reverse = info.reverse || '';
      // Risk assessment
      const providerLower = (conn.provider + ' ' + (conn.as || '')).toLowerCase();
      if (safeProviders.some(s => providerLower.includes(s))) {
        conn.risk = 'safe';
      } else if (conn.domain.includes('.') && !conn.domain.match(/\.(tk|ml|ga|cf|gq|duckdns|ddns|no-ip|dyndns)/i)) {
        conn.risk = 'caution';
      } else {
        conn.risk = 'suspicious';
      }
    } else if (conn.resolvedIP) {
      conn.provider = 'Private/Local';
      conn.risk = 'safe';
    } else {
      conn.provider = 'Unresolvable';
      conn.risk = 'caution';
    }
  }

  // Sort: suspicious first, then caution, then safe
  const riskOrder = { suspicious: 0, caution: 1, safe: 2 };
  connections.sort((a, b) => (riskOrder[a.risk] || 1) - (riskOrder[b.risk] || 1));

  res.json({ success: true, data: { connections, deviceIP: ip } });
});

// ============================
// Helper: Get top domains for a device
// ============================
function getTopDomains(ip, limit = 10) {
  const dns = deviceDNS.get(ip);
  if (!dns) return [];
  return [...dns.topDomains.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([domain, count]) => ({ domain, count }));
}

// ============================
// WebSocket
// ============================
wss.on('connection', (ws) => {
  wsClients.add(ws);
  console.log(`[WS] Client connected (total: ${wsClients.size})`);

  ws.send(JSON.stringify({
    type: 'welcome',
    data: {
      devices: cachedScanResult,
      dnsLog: dnsLog.slice(-100),
      alerts: analyzer.getAlerts().slice(0, 50),
      captures: getActiveCaptures(),
      dnsProxyRunning: dnsProxy ? dnsProxy.running : false
    }
  }));

  ws.on('close', () => {
    wsClients.delete(ws);
  });

  ws.on('error', () => {
    wsClients.delete(ws);
  });
});

function broadcast(message) {
  const data = JSON.stringify(message);
  for (const client of wsClients) {
    if (client.readyState === 1) {
      client.send(data);
    }
  }
}

// ============================
// DNS Proxy Setup
// ============================
async function startDNSProxy() {
  // Get the LAN IP to bind to (avoids conflict with macOS mDNSResponder on 127.0.0.1:53)
  let bindIP = '0.0.0.0';
  try {
    const info = getNetworkInfo();
    bindIP = info.ip; // Bind to LAN IP only
  } catch (e) {}

  try {
    dnsProxy = new DNSProxy({
      upstream: '8.8.8.8',
      port: 53,
      bindAddress: bindIP,

      onQuery: (query) => {
        // Store in per-device tracking
        if (!deviceDNS.has(query.deviceIP)) {
          deviceDNS.set(query.deviceIP, {
            queries: [],
            topDomains: new Map(),
            lastSeen: Date.now()
          });
        }
        const ddata = deviceDNS.get(query.deviceIP);
        ddata.queries.push({
          domain: query.domain,
          queryType: query.queryType,
          timestamp: query.timestamp
        });
        // Cap stored queries per device
        if (ddata.queries.length > 1000) {
          ddata.queries = ddata.queries.slice(-1000);
        }
        ddata.topDomains.set(query.domain, (ddata.topDomains.get(query.domain) || 0) + 1);
        ddata.lastSeen = Date.now();

        // Add to global DNS log
        const entry = {
          deviceIP: query.deviceIP,
          domain: query.domain,
          queryType: query.queryType,
          isQuery: true,
          answer: '',
          timestamp: query.timestamp,
          source: 'proxy'
        };
        dnsLog.push(entry);
        if (dnsLog.length > MAX_DNS_LOG) {
          dnsLog.splice(0, dnsLog.length - MAX_DNS_LOG);
        }

        // Analyze
        const analysis = analyzer.analyzeDNS(entry);

        // Broadcast
        broadcast({ type: 'dns', data: entry, alerts: analysis.alerts });
      },

      onResponse: (response) => {
        // Add answer info to the most recent query entry for this device+domain
        const answersStr = response.answers
          .filter(a => a.type === 'A' || a.type === 'AAAA' || a.type === 'CNAME')
          .map(a => a.data)
          .join(', ');

        if (answersStr) {
          // Find and update the log entry
          for (let i = dnsLog.length - 1; i >= Math.max(0, dnsLog.length - 50); i--) {
            if (dnsLog[i].deviceIP === response.deviceIP && dnsLog[i].domain === response.domain && !dnsLog[i].answer) {
              dnsLog[i].answer = answersStr;
              break;
            }
          }
        }
      }
    });

    await dnsProxy.start();
    console.log(`[DNS Proxy] ✅ Running on ${bindIP}:53 — devices can now use this machine as DNS server`);
  } catch (err) {
    console.error(`[DNS Proxy] ⚠️  Failed to start: ${err.message}`);
    console.error('[DNS Proxy] Falling back to passive tcpdump DNS monitoring.');
    dnsProxy = null;
    startPassiveDNSMonitor();
  }
}

// Fallback: passive DNS monitoring via tcpdump
function startPassiveDNSMonitor() {
  try {
    const networkInfo = getNetworkInfo();
    dnsMonitorId = startDNSMonitor(networkInfo.iface, (dns) => {
      dnsLog.push(dns);
      if (dnsLog.length > MAX_DNS_LOG) {
        dnsLog.splice(0, dnsLog.length - MAX_DNS_LOG);
      }
      const analysis = analyzer.analyzeDNS(dns);
      broadcast({ type: 'dns', data: dns, alerts: analysis.alerts });
    });
    console.log(`[DNS Monitor] Passive monitoring started on ${networkInfo.iface}`);
  } catch (err) {
    console.error('[DNS Monitor] Failed to start:', err.message);
  }
}

// ============================
// Startup
// ============================
server.listen(PORT, () => {
  console.log('');
  console.log('  ╔═══════════════════════════════════════════════════╗');
  console.log('  ║                                                   ║');
  console.log('  ║   🛡️  NetSentry — IoT Network Monitor              ║');
  console.log('  ║                                                   ║');
  console.log(`  ║   Dashboard:   http://localhost:${PORT}              ║`);
  console.log(`  ║   DNS Proxy:   ${'{LAN_IP}'}:53                        ║`);
  console.log('  ║                                                   ║');
  console.log('  ╚═══════════════════════════════════════════════════╝');
  console.log('');

  try {
    const info = getNetworkInfo();
    console.log(`  Interface:   ${info.iface}`);
    console.log(`  Local IP:    ${info.ip}`);
    console.log(`  Subnet:      ${info.cidr}`);
    console.log(`  Gateway:     ${info.gateway}`);
    console.log('');
    console.log('  📋 To enable DNS monitoring for ALL devices:');
    console.log(`     Set your router's DNS to ${info.ip}`);
    console.log('');
  } catch (e) {
    console.log('  ⚠️  Could not detect network info:', e.message);
  }

  // Start DNS proxy
  startDNSProxy();
});

// Graceful shutdown
function shutdown() {
  console.log('\n  Shutting down...');
  stopAllCaptures();
  if (dnsProxy) dnsProxy.stop();
  server.close();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
