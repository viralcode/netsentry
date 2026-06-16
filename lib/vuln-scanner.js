/**
 * NetSentry — Vulnerability Scanner Engine
 * Port scanning, service detection, banner grabbing, CVE signatures,
 * default credential checking, UPnP discovery, TLS analysis
 *
 * Uses vuln-database.js for 200+ vulnerability signatures across 13 categories
 */

const { spawn, execSync } = require('child_process');
const net = require('net');
const dgram = require('dgram');
const dns = require('dns').promises;
const vulnDB = require('./vuln-database');

// Flatten all signatures from the database
const ALL_SIGNATURES = vulnDB.getAllSignatures();
const { MALWARE_DOMAINS, DEFAULT_CREDS, PORT_RISK } = vulnDB;

console.log(`[VulnScanner] Loaded ${ALL_SIGNATURES.length} vulnerability signatures across ${Object.keys(vulnDB.SIGNATURES).length} categories`);

// ============================
// Scanner State
// ============================
const scanResults = new Map(); // ip -> results
const scanProgress = new Map(); // ip -> { phase, percent, status }

/**
 * Run a full vulnerability scan on a target IP
 */
async function runScan(ip, iface, onProgress) {
  const startTime = Date.now();
  const results = {
    ip,
    scanTime: new Date().toISOString(),
    duration: 0,
    securityScore: 100,
    os: null,
    openPorts: [],
    services: [],
    vulnerabilities: [],
    tlsCerts: [],
    upnp: null,
    banners: [],
    defaultCreds: [],
    portRiskBreakdown: { critical: 0, high: 0, medium: 0, iot: 0, safe: 0 },
    signatureStats: { total: ALL_SIGNATURES.length, matched: 0, categories: {} },
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  };

  const updateProgress = (phase, percent) => {
    scanProgress.set(ip, { phase, percent, status: 'scanning' });
    if (onProgress) onProgress({ phase, percent });
  };

  try {
    // Phase 1: Port Scan + Service Detection + OS Fingerprint (0-35%)
    updateProgress('Port Scanning & Service Detection', 5);
    const nmapResults = await runNmapScan(ip);
    results.openPorts = nmapResults.ports;
    results.services = nmapResults.services;
    results.os = nmapResults.os;
    updateProgress(`Found ${nmapResults.ports.length} open ports`, 35);

    // Phase 2: Port Risk Classification (35-40%)
    updateProgress('Classifying Port Risk', 36);
    for (const p of nmapResults.ports) {
      const portNum = p.port;
      if (PORT_RISK.critical.has(portNum)) { results.portRiskBreakdown.critical++; p.risk = 'critical'; }
      else if (PORT_RISK.high.has(portNum)) { results.portRiskBreakdown.high++; p.risk = 'high'; }
      else if (PORT_RISK.medium.has(portNum)) { results.portRiskBreakdown.medium++; p.risk = 'medium'; }
      else if (PORT_RISK.iot.has(portNum)) { results.portRiskBreakdown.iot++; p.risk = 'iot'; }
      else { results.portRiskBreakdown.safe++; p.risk = 'safe'; }
    }
    updateProgress('Port Classification Complete', 40);

    // Phase 3: Banner Grabbing (40-52%)
    updateProgress('Banner Grabbing', 42);
    results.banners = await grabBanners(ip, nmapResults.ports);
    updateProgress(`Grabbed ${results.banners.length} banners`, 52);

    // Phase 4: Vulnerability Signature Matching (52-68%)
    updateProgress(`Matching ${ALL_SIGNATURES.length} vulnerability signatures`, 54);
    const sigVulns = matchSignatures(nmapResults.services, nmapResults.ports, results.banners);
    results.vulnerabilities.push(...sigVulns);
    results.signatureStats.matched = sigVulns.length;

    // Count categories
    for (const [cat, sigs] of Object.entries(vulnDB.SIGNATURES)) {
      const catMatches = sigVulns.filter(v => sigs.some(s => s.id === v.id));
      results.signatureStats.categories[cat] = { total: sigs.length, matched: catMatches.length };
    }
    updateProgress(`${sigVulns.length} vulnerabilities matched`, 68);

    // Phase 5: TLS Certificate Analysis (68-76%)
    updateProgress('Analyzing TLS Certificates', 70);
    const tlsPorts = nmapResults.ports.filter(p =>
      [443, 8443, 993, 995, 8883, 636, 5001, 9443].includes(p.port) ||
      p.service?.includes('ssl') || p.service?.includes('https') || p.service?.includes('tls')
    );
    for (const p of tlsPorts) {
      const cert = await analyzeTLS(ip, p.port);
      if (cert) {
        results.tlsCerts.push(cert);
        // Add TLS vulns
        if (cert.expired) {
          results.vulnerabilities.push({
            id: 'TLS-EXPIRED', severity: 'high', name: 'Expired TLS Certificate',
            description: `Certificate on port ${p.port} expired ${Math.abs(cert.daysUntilExpiry)} days ago.`,
            remediation: 'Renew TLS certificate immediately.', port: p.port
          });
        }
        if (cert.selfSigned) {
          results.vulnerabilities.push({
            id: 'TLS-SELFSIGNED', severity: 'medium', name: 'Self-Signed TLS Certificate',
            description: `Certificate on port ${p.port} is self-signed. Susceptible to MITM.`,
            remediation: 'Use a certificate from a trusted CA.', port: p.port
          });
        }
      }
    }
    updateProgress('TLS Analysis Complete', 76);

    // Phase 6: UPnP/SSDP Discovery (76-82%)
    updateProgress('UPnP Discovery', 78);
    results.upnp = await checkUPnP(ip);
    if (results.upnp && results.upnp.found) {
      results.vulnerabilities.push({
        id: 'UPNP-ENABLED', severity: 'high', name: 'UPnP Enabled',
        description: `UPnP is enabled on this device (${results.upnp.server || 'unknown server'}). Attackers can exploit UPnP to open firewall ports remotely.`,
        remediation: 'Disable UPnP in device settings.',
        port: 1900
      });
    }
    updateProgress('UPnP Discovery Complete', 82);

    // Phase 7: Default Credential Check (82-93%)
    updateProgress('Checking Default Credentials', 84);
    const httpPorts = nmapResults.ports.filter(p => [80, 8080, 8888, 443, 8443, 8000, 8081, 9000].includes(p.port));
    const totalCreds = httpPorts.length;
    for (let i = 0; i < httpPorts.length; i++) {
      const p = httpPorts[i];
      updateProgress(`Checking credentials on port ${p.port} (${i+1}/${totalCreds})`, 84 + Math.floor(9 * i / Math.max(totalCreds, 1)));
      const credResult = await checkHTTPDefaultCreds(ip, p.port);
      if (credResult) {
        results.defaultCreds.push(credResult);
        results.vulnerabilities.push({
          id: 'DEFAULT-CREDS', severity: 'critical',
          name: `Default Credentials on Port ${p.port}`,
          description: `Admin interface on port ${p.port} accepts default credentials (${credResult.username}:${credResult.password}). This is the #1 way IoT devices get compromised.`,
          remediation: 'Change the default admin password immediately.',
          port: p.port
        });
      }
    }
    updateProgress('Credential Check Complete', 93);

    // Phase 8: Calculate Security Score (93-100%)
    updateProgress('Calculating Security Score', 95);

    // Deduplicate vulnerabilities by ID
    const seen = new Set();
    results.vulnerabilities = results.vulnerabilities.filter(v => {
      const key = `${v.id}-${v.port || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    for (const v of results.vulnerabilities) {
      results.summary[v.severity] = (results.summary[v.severity] || 0) + 1;
    }
    // Deduct points based on severity
    results.securityScore = Math.max(0, 100
      - (results.summary.critical * 20)
      - (results.summary.high * 12)
      - (results.summary.medium * 5)
      - (results.summary.low * 2)
      - (results.summary.info * 1)
    );

    results.duration = Date.now() - startTime;
    updateProgress('Scan Complete', 100);
    scanProgress.set(ip, { phase: 'Complete', percent: 100, status: 'complete' });
    console.log(`[VulnScan] ${ip}: Score ${results.securityScore}/100, ${results.vulnerabilities.length} vulns, ${results.openPorts.length} ports in ${(results.duration/1000).toFixed(1)}s`);

  } catch (err) {
    console.error(`[VulnScan] Error scanning ${ip}:`, err.message);
    scanProgress.set(ip, { phase: 'Error: ' + err.message, percent: 0, status: 'error' });
  }

  scanResults.set(ip, results);
  return results;
}

/**
 * Run nmap scan with service detection and OS fingerprinting
 * Extended port list covers IoT, SCADA, databases, containers, management
 */
function runNmapScan(ip) {
  return new Promise((resolve) => {
    // Comprehensive port list: IoT, cameras, SCADA, databases, management, containers, VPN
    const extPorts = [
      21,22,23,25,53,69,80,110,111,135,139,143,161,162,389,443,445,
      500,502,514,515,554,631,636,873,993,995,
      1080,1099,1194,1433,1434,1723,1883,1900,
      2049,2222,2323,2375,2376,2379,2380,
      3000,3128,3260,3306,3389,3460,3480,
      4443,4444,4500,4567,4840,4843,5000,5001,5353,5432,5555,5601,
      5683,5684,5900,5901,5984,
      6379,6443,6667,6668,6669,
      7000,7443,7547,8000,8001,8008,8060,8080,8081,8083,8086,8088,
      8118,8181,8291,8333,8443,8554,8728,8787,8883,8888,8899,
      9000,9001,9010,9042,9050,9090,9100,9160,9191,9200,9300,9443,9527,9999,
      10250,10255,10443,10554,
      11211,12345,20000,27017,27018,27374,
      30000,31337,32100,32761,34567,36866,37777,39500,41794,
      44818,47808,49152,50000,51820,55443,65535
    ].join(',');

    const args = [
      '-sV', '-sC', '-O',          // Service versions, scripts, OS detection
      '-p', extPorts,               // Comprehensive port list
      '--open',                     // Only show open ports
      '-T4',                        // Aggressive timing
      '--max-retries', '1',
      '--host-timeout', '180s',
      '-oX', '-',                   // XML output to stdout
      ip
    ];

    const proc = spawn('nmap', args, { timeout: 200000 });
    let output = '';
    let stderr = '';

    proc.stdout.on('data', d => output += d.toString());
    proc.stderr.on('data', d => stderr += d.toString());

    proc.on('close', () => {
      const result = { ports: [], services: [], os: null };

      // Parse XML output — extract ports
      const portMatches = output.matchAll(/<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)".*?\/>.*?<service name="([^"]*)"(?:.*?product="([^"]*)")?(?:.*?version="([^"]*)")?(?:.*?extrainfo="([^"]*)")?/gs);
      for (const m of portMatches) {
        const port = {
          protocol: m[1],
          port: parseInt(m[2]),
          state: m[3],
          service: m[4] || '',
          product: m[5] || '',
          version: m[6] || '',
          extra: m[7] || ''
        };
        result.ports.push(port);
        result.services.push({
          port: port.port,
          name: port.service,
          product: port.product,
          version: port.version,
          banner: `${port.product} ${port.version} ${port.extra}`.trim()
        });
      }

      // Extract OS
      const osMatch = output.match(/<osmatch name="([^"]*)".*?accuracy="(\d+)"/);
      if (osMatch) {
        result.os = { name: osMatch[1], accuracy: parseInt(osMatch[2]) };
      }

      resolve(result);
    });

    proc.on('error', () => resolve({ ports: [], services: [], os: null }));

    // Timeout
    setTimeout(() => { try { proc.kill(); } catch(e) {} }, 200000);
  });
}

/**
 * Banner grabbing — connect to each open port and read response
 */
async function grabBanners(ip, ports) {
  const banners = [];
  const tcpPorts = ports.filter(p => p.protocol === 'tcp').slice(0, 30);

  const grabOne = (p) => new Promise((resolve) => {
    const sock = new net.Socket();
    let data = '';
    sock.setTimeout(3000);
    sock.connect(p.port, ip, () => {
      if ([80, 443, 8080, 8443, 8888, 8000, 8081, 9000].includes(p.port)) {
        sock.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\n\r\n`);
      }
    });
    sock.on('data', d => { data += d.toString(); if (data.length > 1024) sock.destroy(); });
    sock.on('timeout', () => { sock.destroy(); resolve(data || null); });
    sock.on('end', () => resolve(data || null));
    sock.on('error', () => resolve(null));
    setTimeout(() => { sock.destroy(); resolve(data || null); }, 4000);
  });

  // Grab banners in parallel batches of 10
  for (let i = 0; i < tcpPorts.length; i += 10) {
    const batch = tcpPorts.slice(i, i + 10);
    const results = await Promise.all(batch.map(async (p) => {
      const banner = await grabOne(p);
      return banner ? { port: p.port, banner: banner.substring(0, 500) } : null;
    }));
    banners.push(...results.filter(Boolean));
  }
  return banners;
}

/**
 * Match collected service/banner data against ALL vulnerability signatures
 */
function matchSignatures(services, ports, banners) {
  const vulns = [];
  const openPortNumbers = new Set(ports.map(p => p.port));
  const allBannerText = [...services.map(s => s.banner), ...banners.map(b => b.banner)].join(' ').toLowerCase();

  for (const sig of ALL_SIGNATURES) {
    // Check if any signature ports are open
    const hasPort = sig.ports.some(p => openPortNumbers.has(p));
    if (!hasPort) continue;

    // Check banner/service match
    if (sig.match === null || sig.match.test(allBannerText)) {
      const matchedPort = sig.ports.find(p => openPortNumbers.has(p));
      vulns.push({
        id: sig.id,
        severity: sig.severity,
        name: sig.name,
        description: sig.description,
        remediation: sig.remediation,
        port: matchedPort
      });
    }
  }
  return vulns;
}

/**
 * Analyze TLS certificate on a given port
 */
function analyzeTLS(ip, port) {
  return new Promise((resolve) => {
    try {
      const result = execSync(
        `echo | openssl s_client -connect ${ip}:${port} -servername ${ip} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -serial 2>/dev/null`,
        { timeout: 8000, encoding: 'utf-8' }
      );
      if (!result || result.trim().length === 0) return resolve(null);

      const cert = { port, raw: result.trim() };
      const subjectMatch = result.match(/subject=(.+)/);
      const issuerMatch = result.match(/issuer=(.+)/);
      const notBeforeMatch = result.match(/notBefore=(.+)/);
      const notAfterMatch = result.match(/notAfter=(.+)/);

      if (subjectMatch) cert.subject = subjectMatch[1].trim();
      if (issuerMatch) cert.issuer = issuerMatch[1].trim();
      if (notBeforeMatch) cert.notBefore = notBeforeMatch[1].trim();
      if (notAfterMatch) {
        cert.notAfter = notAfterMatch[1].trim();
        const expiry = new Date(cert.notAfter);
        cert.expired = expiry < new Date();
        cert.daysUntilExpiry = Math.floor((expiry - new Date()) / 86400000);
      }

      cert.selfSigned = cert.subject === cert.issuer;
      resolve(cert);
    } catch (e) {
      resolve(null);
    }
  });
}

/**
 * Check for UPnP via SSDP M-SEARCH
 */
function checkUPnP(ip) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    const msg = Buffer.from(
      'M-SEARCH * HTTP/1.1\r\n' +
      `HOST: ${ip}:1900\r\n` +
      'MAN: "ssdp:discover"\r\n' +
      'MX: 2\r\n' +
      'ST: upnp:rootdevice\r\n\r\n'
    );

    let response = null;

    sock.on('message', (msg, rinfo) => {
      if (rinfo.address === ip) {
        const text = msg.toString();
        const serverMatch = text.match(/SERVER:\s*(.+)/i);
        const locationMatch = text.match(/LOCATION:\s*(.+)/i);
        response = {
          found: true,
          server: serverMatch ? serverMatch[1].trim() : '',
          location: locationMatch ? locationMatch[1].trim() : ''
        };
      }
    });

    sock.on('error', () => { sock.close(); resolve({ found: false }); });

    try {
      sock.send(msg, 0, msg.length, 1900, ip);
    } catch (e) {
      resolve({ found: false });
      return;
    }

    setTimeout(() => {
      sock.close();
      resolve(response || { found: false });
    }, 3000);
  });
}

/**
 * Check HTTP admin panels for default credentials
 */
function checkHTTPDefaultCreds(ip, port) {
  return new Promise((resolve) => {
    const http = port === 443 || port === 8443 ? require('https') : require('http');
    const creds = DEFAULT_CREDS.http || [];

    let index = 0;
    const tryNext = () => {
      if (index >= creds.length) return resolve(null);
      const [username, password] = creds[index++];
      const auth = Buffer.from(`${username}:${password}`).toString('base64');

      const req = http.request({
        hostname: ip, port, path: '/', method: 'GET',
        headers: { 'Authorization': `Basic ${auth}` },
        rejectUnauthorized: false, timeout: 4000
      }, (res) => {
        if (res.statusCode === 200 || res.statusCode === 302) {
          resolve({ port, username, password, status: res.statusCode });
        } else if (res.statusCode === 401 || res.statusCode === 403) {
          tryNext();
        } else {
          tryNext();
        }
        res.resume();
      });

      req.on('error', () => tryNext());
      req.on('timeout', () => { req.destroy(); tryNext(); });
      req.end();
    };

    tryNext();
  });
}

// ============================
// IDS — Intrusion Detection
// ============================
const idsAlerts = [];
const connectionTracker = new Map();

function analyzeForIntrusion(packet) {
  const alerts = [];
  const now = Date.now();

  if (!connectionTracker.has(packet.srcIP)) {
    connectionTracker.set(packet.srcIP, { ports: new Set(), timestamps: [], firstSeen: now });
  }
  const tracker = connectionTracker.get(packet.srcIP);
  tracker.ports.add(packet.dstPort);
  tracker.timestamps.push(now);

  // Clean old timestamps (keep last 60s)
  tracker.timestamps = tracker.timestamps.filter(t => now - t < 60000);

  // Port Scan Detection: >15 unique ports in 60s
  if (tracker.ports.size > 15 && now - tracker.firstSeen < 60000) {
    const alert = {
      id: 'IDS-PORTSCAN', severity: 'high', timestamp: new Date().toISOString(),
      name: 'Port Scan Detected',
      description: `${packet.srcIP} probed ${tracker.ports.size} ports in ${Math.floor((now - tracker.firstSeen) / 1000)}s`,
      sourceIP: packet.srcIP, detail: `Ports: ${[...tracker.ports].slice(0, 20).join(', ')}`
    };
    if (!idsAlerts.find(a => a.id === 'IDS-PORTSCAN' && a.sourceIP === packet.srcIP && now - new Date(a.timestamp).getTime() < 300000)) {
      idsAlerts.push(alert);
      alerts.push(alert);
    }
  }

  // SYN Flood Detection: >100 SYN packets in 60s
  if (packet.flags && packet.flags.includes('S') && !packet.flags.includes('.')) {
    if (tracker.timestamps.length > 100) {
      const alert = {
        id: 'IDS-SYNFLOOD', severity: 'critical', timestamp: new Date().toISOString(),
        name: 'SYN Flood Detected',
        description: `${packet.srcIP} sent ${tracker.timestamps.length} SYN packets in 60s`,
        sourceIP: packet.srcIP
      };
      if (!idsAlerts.find(a => a.id === 'IDS-SYNFLOOD' && a.sourceIP === packet.srcIP && now - new Date(a.timestamp).getTime() < 300000)) {
        idsAlerts.push(alert);
        alerts.push(alert);
      }
    }
  }

  // Suspicious port access (from PORT_RISK)
  const dstPort = parseInt(packet.dstPort);
  if (PORT_RISK.critical.has(dstPort)) {
    const alert = {
      id: 'IDS-SUSPICIOUS-PORT', severity: 'high', timestamp: new Date().toISOString(),
      name: 'Critical Port Access',
      description: `Traffic to high-risk port ${packet.dstPort} from ${packet.srcIP}`,
      sourceIP: packet.srcIP, port: packet.dstPort
    };
    if (!idsAlerts.find(a => a.id === 'IDS-SUSPICIOUS-PORT' && a.port === packet.dstPort && a.sourceIP === packet.srcIP && now - new Date(a.timestamp).getTime() < 300000)) {
      idsAlerts.push(alert);
      alerts.push(alert);
    }
  }

  return alerts;
}

/**
 * Check DNS query against known malware domains
 */
function checkDNSThreat(domain) {
  const lower = domain.toLowerCase();
  for (const pattern of MALWARE_DOMAINS) {
    if (lower.includes(pattern)) {
      return {
        id: 'IDS-MALWARE-DNS', severity: 'critical',
        name: 'Suspicious DNS Query',
        description: `Query for ${domain} matches known malware/suspicious pattern: ${pattern}`,
        domain
      };
    }
  }
  return null;
}

module.exports = {
  runScan,
  scanResults,
  scanProgress,
  analyzeForIntrusion,
  checkDNSThreat,
  idsAlerts,
  ALL_SIGNATURES
};
