/**
 * NetSentry — Vulnerability Scanner Engine
 * Port scanning, service detection, banner grabbing, CVE signatures,
 * default credential checking, UPnP discovery, TLS analysis
 */

const { spawn, execSync } = require('child_process');
const net = require('net');
const dgram = require('dgram');
const dns = require('dns').promises;

// ============================
// Vulnerability Signature Database
// ============================
const VULN_SIGNATURES = [
  // Critical: Remote Code Execution
  { id: 'CVE-2021-36260', severity: 'critical', name: 'Hikvision Command Injection', match: /hikvision/i, ports: [80, 443, 8080], description: 'Hikvision IP cameras vulnerable to unauthenticated command injection via crafted HTTP requests.', remediation: 'Update firmware to latest version from Hikvision website.' },
  { id: 'CVE-2021-44228', severity: 'critical', name: 'Log4Shell (Log4j RCE)', match: /java|tomcat|spring|elastic/i, ports: [8080, 8443, 9200, 9300], description: 'Apache Log4j2 remote code execution via JNDI injection.', remediation: 'Update Log4j to 2.17.1+, or set log4j2.formatMsgNoLookups=true.' },
  { id: 'CVE-2022-30525', severity: 'critical', name: 'Zyxel Firewall RCE', match: /zyxel|zywall/i, ports: [80, 443], description: 'Zyxel firewall OS command injection via administrative HTTP interface.', remediation: 'Update Zyxel firmware to patched version.' },
  { id: 'CVE-2023-28771', severity: 'critical', name: 'Zyxel VPN RCE', match: /zyxel/i, ports: [500, 4500], description: 'Unauthenticated IKEv2 command injection in Zyxel VPN devices.', remediation: 'Update firmware immediately.' },
  { id: 'CVE-2023-46747', severity: 'critical', name: 'F5 BIG-IP Auth Bypass', match: /big-?ip|f5/i, ports: [443, 8443], description: 'F5 BIG-IP unauthenticated RCE via request smuggling.', remediation: 'Apply F5 security hotfix.' },

  // Critical: IoT Botnets
  { id: 'MIRAI-TELNET', severity: 'critical', name: 'Mirai Botnet Vector (Telnet)', match: null, ports: [23, 2323], description: 'Telnet port open — primary infection vector for Mirai and variant botnets. Attackers brute-force default credentials.', remediation: 'Disable Telnet. Use SSH instead. Change all default passwords.' },
  { id: 'MIRAI-SSH', severity: 'high', name: 'Mirai Botnet Vector (SSH)', match: /dropbear/i, ports: [22], description: 'Dropbear SSH detected — common in IoT devices targeted by Mirai variants.', remediation: 'Change default SSH credentials. Disable root login.' },

  // High: Exposed Services
  { id: 'MQTT-NOAUTH', severity: 'high', name: 'MQTT Broker Without Auth', match: /mosquitto|emqx|mqtt/i, ports: [1883], description: 'MQTT broker accessible without authentication. Attackers can subscribe to all topics and inject messages.', remediation: 'Enable MQTT authentication and TLS (port 8883).' },
  { id: 'RTSP-EXPOSED', severity: 'high', name: 'RTSP Camera Stream Exposed', match: /rtsp|live555|streaming/i, ports: [554, 8554], description: 'RTSP streaming port open — camera feed may be accessible without authentication.', remediation: 'Require authentication for RTSP. Disable if not needed.' },
  { id: 'FTP-OPEN', severity: 'high', name: 'FTP Service Exposed', match: /ftp|vsftpd|proftpd/i, ports: [21], description: 'FTP service detected. FTP transmits credentials in plaintext.', remediation: 'Use SFTP/SCP instead of FTP. Disable FTP service.' },
  { id: 'SMB-EXPOSED', severity: 'high', name: 'SMB/NetBIOS Exposed', match: /samba|microsoft-ds|netbios/i, ports: [139, 445], description: 'SMB ports open — vulnerable to EternalBlue, WannaCry, and lateral movement attacks.', remediation: 'Disable SMB if not needed. Block ports 139/445 at firewall.' },
  { id: 'RDP-EXPOSED', severity: 'high', name: 'RDP Exposed', match: /ms-wbt-server|rdp/i, ports: [3389], description: 'Remote Desktop Protocol exposed. Vulnerable to BlueKeep and brute force attacks.', remediation: 'Use VPN for remote access. Enable NLA. Disable if not needed.' },
  { id: 'UPNP-ENABLED', severity: 'high', name: 'UPnP Enabled', match: null, ports: [1900, 5000, 5431], description: 'UPnP allows devices to automatically open firewall ports. Attackers can exploit this for remote access.', remediation: 'Disable UPnP on router and device settings.' },

  // High: Camera/DVR
  { id: 'CVE-2021-33044', severity: 'high', name: 'Dahua Camera Auth Bypass', match: /dahua|dh-/i, ports: [80, 443, 37777], description: 'Dahua cameras vulnerable to authentication bypass allowing unauthorized access.', remediation: 'Update Dahua firmware to latest version.' },
  { id: 'CVE-2020-25078', severity: 'high', name: 'D-Link Camera Info Leak', match: /d-?link|dcs-/i, ports: [80, 443], description: 'D-Link cameras leak admin credentials via /config/getuser endpoint.', remediation: 'Update D-Link camera firmware.' },
  { id: 'CVE-2019-3929', severity: 'high', name: 'Barracuda/Crestron RCE', match: /crestron|barracuda/i, ports: [80, 443, 41794], description: 'Multiple vendors vulnerable to unauthenticated RCE via CGI endpoint.', remediation: 'Update device firmware.' },

  // Medium: Weak Configurations
  { id: 'HTTP-NOSSL', severity: 'medium', name: 'Unencrypted Admin Panel', match: /http/i, ports: [80, 8080, 8888], description: 'HTTP admin interface without TLS encryption. Credentials transmitted in plaintext.', remediation: 'Enable HTTPS/TLS on the admin interface.' },
  { id: 'DNS-OPEN', severity: 'medium', name: 'Open DNS Resolver', match: /dns|domain/i, ports: [53], description: 'Open DNS resolver can be exploited for DNS amplification DDoS attacks.', remediation: 'Restrict DNS to local network only.' },
  { id: 'SNMP-DEFAULT', severity: 'medium', name: 'SNMP Default Community', match: /snmp/i, ports: [161], description: 'SNMP service may use default community strings (public/private).', remediation: 'Change SNMP community strings. Use SNMPv3 with auth.' },
  { id: 'MDNS-EXPOSED', severity: 'low', name: 'mDNS Service Exposed', match: /mdns|bonjour/i, ports: [5353], description: 'mDNS leaks device information to all network devices.', remediation: 'Disable if not needed for local discovery.' },
  { id: 'VNC-EXPOSED', severity: 'high', name: 'VNC Remote Access Exposed', match: /vnc|rfb/i, ports: [5900, 5901], description: 'VNC remote access exposed. Often runs without encryption.', remediation: 'Use SSH tunneling for VNC. Disable if not needed.' },

  // Medium: IoT Specific
  { id: 'COAP-EXPOSED', severity: 'medium', name: 'CoAP Protocol Exposed', match: /coap/i, ports: [5683, 5684], description: 'CoAP (Constrained Application Protocol) exposed. Can leak IoT sensor data.', remediation: 'Enable DTLS for CoAP. Restrict to local network.' },
  { id: 'SSDP-EXPOSED', severity: 'medium', name: 'SSDP Discovery Exposed', match: /ssdp/i, ports: [1900], description: 'SSDP used for device discovery. Can be exploited for DDoS amplification.', remediation: 'Disable SSDP/UPnP if not needed.' },
  { id: 'ISCSI-EXPOSED', severity: 'high', name: 'iSCSI Storage Exposed', match: /iscsi/i, ports: [3260], description: 'iSCSI storage protocol exposed. Allows unauthorized disk access.', remediation: 'Restrict iSCSI to VLAN. Enable CHAP authentication.' },

  // Info
  { id: 'PRINTER-EXPOSED', severity: 'low', name: 'Network Printer Exposed', match: /jetdirect|printer|cups|ipp/i, ports: [9100, 631], description: 'Network printer accessible. Can be exploited for data exfiltration or as pivot point.', remediation: 'Restrict printer access to authorized IPs.' },
  { id: 'NTP-OPEN', severity: 'low', name: 'NTP Service Open', match: /ntp/i, ports: [123], description: 'NTP service can be used for NTP amplification attacks.', remediation: 'Restrict NTP to trusted clients.' },
];

// Known IoT default credentials to check
const DEFAULT_CREDS = [
  { service: 'http', creds: [['admin','admin'],['admin','password'],['admin','1234'],['admin',''],['root','root'],['root',''],['user','user']] },
  { service: 'telnet', creds: [['admin','admin'],['root','root'],['root',''],['admin',''],['user','user'],['support','support']] },
  { service: 'ftp', creds: [['admin','admin'],['anonymous',''],['ftp','ftp'],['root','root']] },
];

// Known malware C2 domains
const MALWARE_DOMAINS = [
  'scan.shadowserver.org', 'cnc.', 'botnet.', '.onion.', 'cryptonight',
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
  'duckdns.org', 'no-ip.com', 'dyndns.org', 'hopto.org', 'zapto.org',
  'serveftp.com', 'ddns.net', 'myftp.org'
];

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
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  };

  const updateProgress = (phase, percent) => {
    scanProgress.set(ip, { phase, percent, status: 'scanning' });
    if (onProgress) onProgress({ phase, percent });
  };

  try {
    // Phase 1: Port Scan + Service Detection + OS Fingerprint (0-40%)
    updateProgress('Port Scanning & Service Detection', 5);
    const nmapResults = await runNmapScan(ip);
    results.openPorts = nmapResults.ports;
    results.services = nmapResults.services;
    results.os = nmapResults.os;
    updateProgress('Port Scanning Complete', 40);

    // Phase 2: Banner Grabbing (40-55%)
    updateProgress('Banner Grabbing', 42);
    results.banners = await grabBanners(ip, nmapResults.ports);
    updateProgress('Banner Grabbing Complete', 55);

    // Phase 3: Vulnerability Signature Matching (55-65%)
    updateProgress('Matching Vulnerability Signatures', 57);
    const sigVulns = matchSignatures(nmapResults.services, nmapResults.ports, results.banners);
    results.vulnerabilities.push(...sigVulns);
    updateProgress('Signature Matching Complete', 65);

    // Phase 4: TLS Certificate Analysis (65-75%)
    updateProgress('Analyzing TLS Certificates', 67);
    const tlsPorts = nmapResults.ports.filter(p => [443, 8443, 993, 995, 8883].includes(p.port) || p.service?.includes('ssl') || p.service?.includes('https'));
    for (const p of tlsPorts) {
      const cert = await analyzeTLS(ip, p.port);
      if (cert) results.tlsCerts.push(cert);
    }
    updateProgress('TLS Analysis Complete', 75);

    // Phase 5: UPnP/SSDP Discovery (75-82%)
    updateProgress('UPnP Discovery', 77);
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

    // Phase 6: Default Credential Check (82-95%)
    updateProgress('Checking Default Credentials', 84);
    const httpPorts = nmapResults.ports.filter(p => [80, 8080, 8888, 443, 8443].includes(p.port));
    for (const p of httpPorts) {
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
    updateProgress('Credential Check Complete', 95);

    // Phase 7: Calculate Security Score (95-100%)
    updateProgress('Calculating Security Score', 97);
    for (const v of results.vulnerabilities) {
      results.summary[v.severity] = (results.summary[v.severity] || 0) + 1;
    }
    // Deduct points based on severity
    results.securityScore = Math.max(0, 100
      - (results.summary.critical * 25)
      - (results.summary.high * 15)
      - (results.summary.medium * 8)
      - (results.summary.low * 3)
      - (results.summary.info * 1)
    );

    results.duration = Date.now() - startTime;
    updateProgress('Scan Complete', 100);
    scanProgress.set(ip, { phase: 'Complete', percent: 100, status: 'complete' });

  } catch (err) {
    console.error(`[VulnScan] Error scanning ${ip}:`, err.message);
    scanProgress.set(ip, { phase: 'Error: ' + err.message, percent: 0, status: 'error' });
  }

  scanResults.set(ip, results);
  return results;
}

/**
 * Run nmap scan with service detection and OS fingerprinting
 */
function runNmapScan(ip) {
  return new Promise((resolve) => {
    // Scan top 1000 ports + IoT-specific ports, service detection, OS detection
    const iotPorts = '23,80,443,554,1883,1900,5000,5353,5683,8080,8443,8883,9100,37777,49152';
    const args = [
      '-sV', '-sC', '-O',          // Service versions, scripts, OS detection
      '--top-ports', '200',         // Top 200 ports
      '-p', iotPorts,               // Plus IoT-specific ports
      '--open',                     // Only show open ports
      '-T4',                        // Aggressive timing
      '--max-retries', '1',
      '-oX', '-',                   // XML output to stdout
      ip
    ];

    const proc = spawn('nmap', args, { timeout: 120000 });
    let output = '';
    let stderr = '';

    proc.stdout.on('data', d => output += d.toString());
    proc.stderr.on('data', d => stderr += d.toString());

    proc.on('close', () => {
      const result = { ports: [], services: [], os: null };

      // Parse XML output
      // Extract ports
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
    setTimeout(() => { try { proc.kill(); } catch(e) {} }, 120000);
  });
}

/**
 * Banner grabbing — connect to each open port and read response
 */
async function grabBanners(ip, ports) {
  const banners = [];
  const tcpPorts = ports.filter(p => p.protocol === 'tcp').slice(0, 20);

  for (const p of tcpPorts) {
    try {
      const banner = await new Promise((resolve, reject) => {
        const sock = new net.Socket();
        let data = '';
        sock.setTimeout(3000);
        sock.connect(p.port, ip, () => {
          // Send probe for HTTP
          if ([80, 443, 8080, 8443, 8888].includes(p.port)) {
            sock.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\n\r\n`);
          } else {
            // Just wait for banner
          }
        });
        sock.on('data', d => { data += d.toString(); if (data.length > 1024) sock.destroy(); });
        sock.on('timeout', () => { sock.destroy(); resolve(data || null); });
        sock.on('end', () => resolve(data || null));
        sock.on('error', () => resolve(null));
        setTimeout(() => { sock.destroy(); resolve(data || null); }, 4000);
      });
      if (banner) banners.push({ port: p.port, banner: banner.substring(0, 500) });
    } catch (e) { /* skip */ }
  }
  return banners;
}

/**
 * Match collected service/banner data against vulnerability signatures
 */
function matchSignatures(services, ports, banners) {
  const vulns = [];
  const openPortNumbers = ports.map(p => p.port);
  const allBannerText = [...services.map(s => s.banner), ...banners.map(b => b.banner)].join(' ');

  for (const sig of VULN_SIGNATURES) {
    // Check if any signature ports are open
    const hasPort = sig.ports.some(p => openPortNumbers.includes(p));
    if (!hasPort) continue;

    // Check banner/service match
    if (sig.match === null || sig.match.test(allBannerText)) {
      const matchedPort = sig.ports.find(p => openPortNumbers.includes(p));
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

      // Self-signed check
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

    let found = false;
    let response = null;

    sock.on('message', (msg, rinfo) => {
      if (rinfo.address === ip) {
        found = true;
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
    const creds = DEFAULT_CREDS.find(c => c.service === 'http')?.creds || [];

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
const connectionTracker = new Map(); // sourceIP -> { ports: Set, timestamps: [] }

function analyzeForIntrusion(packet) {
  const alerts = [];
  const now = Date.now();

  // Track connections per source IP
  if (!connectionTracker.has(packet.srcIP)) {
    connectionTracker.set(packet.srcIP, { ports: new Set(), timestamps: [], firstSeen: now });
  }
  const tracker = connectionTracker.get(packet.srcIP);
  tracker.ports.add(packet.dstPort);
  tracker.timestamps.push(now);

  // Clean old timestamps (keep last 60s)
  tracker.timestamps = tracker.timestamps.filter(t => now - t < 60000);

  // Port Scan Detection: >15 unique ports in 60s from same IP
  if (tracker.ports.size > 15 && now - tracker.firstSeen < 60000) {
    const alert = {
      id: 'IDS-PORTSCAN', severity: 'high', timestamp: new Date().toISOString(),
      name: 'Port Scan Detected',
      description: `${packet.srcIP} probed ${tracker.ports.size} ports in ${Math.floor((now - tracker.firstSeen) / 1000)}s`,
      sourceIP: packet.srcIP, detail: `Ports: ${[...tracker.ports].slice(0, 20).join(', ')}`
    };
    // Only alert once per source per 5 minutes
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

  // Suspicious port access
  const suspiciousPorts = [23, 1080, 3128, 4444, 5555, 6667, 6668, 6669, 31337];
  if (suspiciousPorts.includes(parseInt(packet.dstPort))) {
    const alert = {
      id: 'IDS-SUSPICIOUS-PORT', severity: 'medium', timestamp: new Date().toISOString(),
      name: 'Suspicious Port Access',
      description: `Traffic to suspicious port ${packet.dstPort} from ${packet.srcIP}`,
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
  VULN_SIGNATURES
};
