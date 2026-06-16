/**
 * Traffic Capture Module
 * Captures and parses network traffic using tcpdump.
 */

const { spawn } = require('child_process');

// Active capture processes
let activeCaptures = new Map();

/**
 * Start capturing traffic for a specific device IP
 * @param {string} ip - Target device IP
 * @param {string} iface - Network interface (e.g., 'en0')
 * @param {function} onPacket - Callback for each parsed packet
 * @returns {string} Capture ID
 */
function startCapture(ip, iface, onPacket) {
  const captureId = `capture-${ip}-${Date.now()}`;
  
  // Stop any existing capture for this IP
  stopCaptureForIP(ip);
  
  // tcpdump args:
  //   -i <iface>  : interface
  //   -l          : line-buffered output
  //   -nn         : don't resolve hostnames or ports
  //   -tttt       : full timestamp
  //   -A          : print payload in ASCII
  //   -s 512      : capture first 512 bytes of each packet
  //   host <ip>   : filter to this host
  const args = [
    '-i', iface,
    '-l', '-nn', '-tttt',
    '-A', '-s', '512',
    'host', ip
  ];
  
  const proc = spawn('tcpdump', args, {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  
  let buffer = '';
  let pendingPacket = null;
  let payloadLines = [];
  
  proc.stdout.on('data', (data) => {
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop(); // Keep incomplete line in buffer
    
    for (const line of lines) {
      // Check if this is a new packet header (starts with timestamp)
      const isHeader = /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(line);
      
      if (isHeader) {
        // Emit previous packet with accumulated payload
        if (pendingPacket) {
          pendingPacket.payload = payloadLines.join('\n');
          onPacket(pendingPacket);
        }
        // Parse new packet header
        pendingPacket = parseTcpdumpLine(line, ip);
        payloadLines = [];
      } else if (pendingPacket && line.trim().length > 0) {
        // This is a payload/continuation line
        payloadLines.push(line);
      }
    }
  });
  
  proc.stderr.on('data', (data) => {
    const msg = data.toString();
    // tcpdump writes "listening on..." to stderr, ignore it
    if (!msg.includes('listening on') && !msg.includes('packets captured')) {
      console.log(`[Capture:${ip}] stderr: ${msg.trim()}`);
    }
  });
  
  proc.on('error', (err) => {
    console.error(`[Capture:${ip}] Error: ${err.message}`);
  });
  
  proc.on('close', (code) => {
    activeCaptures.delete(captureId);
    console.log(`[Capture:${ip}] Process exited with code ${code}`);
  });
  
  activeCaptures.set(captureId, { proc, ip, iface, startTime: Date.now() });
  console.log(`[Capture] Started capture for ${ip} on ${iface} (ID: ${captureId})`);
  
  return captureId;
}

/**
 * Start monitoring all DNS queries on the network
 * @param {string} iface - Network interface
 * @param {function} onDNS - Callback for each DNS query/response
 * @returns {string} Capture ID
 */
function startDNSMonitor(iface, onDNS) {
  const captureId = `dns-monitor-${Date.now()}`;
  
  // Capture DNS traffic (port 53)
  const args = [
    '-i', iface,
    '-l', '-nn', '-tttt',
    'port', '53'
  ];
  
  const proc = spawn('tcpdump', args, {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  
  let buffer = '';
  
  proc.stdout.on('data', (data) => {
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop();
    
    for (const line of lines) {
      const dns = parseDNSLine(line);
      if (dns) {
        onDNS(dns);
      }
    }
  });
  
  proc.stderr.on('data', () => {}); // Suppress stderr
  
  proc.on('error', (err) => {
    console.error(`[DNS Monitor] Error: ${err.message}`);
  });
  
  proc.on('close', (code) => {
    activeCaptures.delete(captureId);
    console.log(`[DNS Monitor] Process exited with code ${code}`);
  });
  
  activeCaptures.set(captureId, { proc, ip: 'dns', iface, startTime: Date.now() });
  console.log(`[DNS Monitor] Started on ${iface}`);
  
  return captureId;
}

/**
 * Parse a tcpdump output line into a structured packet object
 * @param {string} line - Raw tcpdump output line
 * @param {string} targetIP - The monitored device's IP
 * @returns {object|null} Parsed packet or null
 */
function parseTcpdumpLine(line, targetIP) {
  if (!line || line.trim().length === 0) return null;
  
  // Example tcpdump output:
  // 2024-01-15 10:30:45.123456 IP 192.168.1.100.443 > 192.168.1.1.52341: Flags [P.], seq 1:100, ...length 99
  // 2024-01-15 10:30:45.123456 IP 192.168.1.100.80 > 192.168.1.1.52341: Flags [S], ...
  
  try {
    // Extract timestamp
    const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)/);
    if (!tsMatch) return null;
    
    const timestamp = tsMatch[1];
    
    // Determine protocol
    let protocol = 'OTHER';
    if (line.includes(' IP ') || line.includes(' IP6 ')) {
      protocol = line.includes(' IP6 ') ? 'IPv6' : 'IP';
    }
    if (line.includes(' ARP')) {
      protocol = 'ARP';
    }
    if (line.includes(' ICMP')) {
      protocol = 'ICMP';
    }
    
    // Extract source and destination (IP.port format)
    const addrMatch = line.match(/(?:IP|IP6)\s+(\S+)\s+>\s+(\S+?):/);
    if (!addrMatch && protocol !== 'ARP') return null;
    
    let srcIP = '', srcPort = '', dstIP = '', dstPort = '';
    
    if (addrMatch) {
      const src = addrMatch[1];
      const dst = addrMatch[2];
      
      // Parse IP.port format (last dot-separated component is port)
      const srcParts = src.split('.');
      const dstParts = dst.split('.');
      
      if (srcParts.length >= 5) {
        srcPort = srcParts.pop();
        srcIP = srcParts.join('.');
      } else {
        srcIP = src;
      }
      
      if (dstParts.length >= 5) {
        dstPort = dstParts.pop();
        dstIP = dstParts.join('.');
      } else {
        dstIP = dst;
      }
    }
    
    // Determine higher-level protocol from port numbers
    if (srcPort === '53' || dstPort === '53') protocol = 'DNS';
    else if (srcPort === '443' || dstPort === '443') protocol = 'HTTPS';
    else if (srcPort === '80' || dstPort === '80') protocol = 'HTTP';
    else if (srcPort === '22' || dstPort === '22') protocol = 'SSH';
    else if (srcPort === '21' || dstPort === '21') protocol = 'FTP';
    else if (srcPort === '23' || dstPort === '23') protocol = 'TELNET';
    else if (srcPort === '25' || dstPort === '25') protocol = 'SMTP';
    else if (srcPort === '1080' || dstPort === '1080') protocol = 'SOCKS';
    else if (srcPort === '3128' || dstPort === '3128' || srcPort === '8080' || dstPort === '8080') protocol = 'PROXY';
    else if (srcPort === '8883' || dstPort === '8883' || srcPort === '1883' || dstPort === '1883') protocol = 'MQTT';
    else if (srcPort === '5683' || dstPort === '5683') protocol = 'CoAP';
    else if (protocol === 'IP') protocol = 'TCP/UDP';
    
    // Extract TCP flags
    let flags = '';
    const flagsMatch = line.match(/Flags \[([^\]]+)\]/);
    if (flagsMatch) flags = flagsMatch[1];
    
    // Extract packet length
    let length = 0;
    const lenMatch = line.match(/length\s+(\d+)/);
    if (lenMatch) length = parseInt(lenMatch[1]);
    
    // Determine direction relative to target device
    const direction = (srcIP === targetIP) ? 'outbound' : 'inbound';
    
    return {
      timestamp,
      srcIP,
      srcPort,
      dstIP,
      dstPort,
      protocol,
      flags,
      length,
      direction,
      raw: line.substring(0, 200) // Truncated raw line
    };
  } catch (e) {
    return null;
  }
}

/**
 * Parse DNS query/response from tcpdump output
 * @param {string} line - Raw tcpdump line
 * @returns {object|null} Parsed DNS entry or null
 */
function parseDNSLine(line) {
  if (!line || line.trim().length === 0) return null;
  
  try {
    const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)/);
    if (!tsMatch) return null;
    
    const timestamp = tsMatch[1];
    
    // Extract source IP
    const addrMatch = line.match(/IP\s+(\S+)\s+>\s+(\S+?):/);
    if (!addrMatch) return null;
    
    const src = addrMatch[1];
    const dst = addrMatch[2];
    
    // Parse IP from IP.port format
    const srcParts = src.split('.');
    const srcPort = srcParts.pop();
    const srcIP = srcParts.join('.');
    
    const dstParts = dst.split('.');
    const dstPort = dstParts.pop();
    const dstIP = dstParts.join('.');
    
    // Extract DNS query domain
    // Look for patterns like: A? example.com. or AAAA? example.com.
    const queryMatch = line.match(/(\w+\?)\s+([\w\.\-]+)\./);
    const responseMatch = line.match(/(\d+\/\d+\/\d+)/); // answer/authority/additional counts
    
    const isQuery = srcPort !== '53'; // If source port is not 53, it's a query
    
    let domain = '';
    let queryType = '';
    
    if (queryMatch) {
      queryType = queryMatch[1].replace('?', '');
      domain = queryMatch[2];
    }
    
    // Also try to capture answer records
    // Pattern: example.com. A 93.184.216.34
    const answerMatch = line.match(/([\w\.\-]+)\.\s+(?:A|AAAA|CNAME)\s+([\w\.\:]+)/);
    let answer = '';
    if (answerMatch) {
      domain = domain || answerMatch[1];
      answer = answerMatch[2];
    }
    
    if (!domain) return null;
    
    return {
      timestamp,
      deviceIP: isQuery ? srcIP : dstIP,
      domain,
      queryType: queryType || 'A',
      isQuery,
      answer,
      raw: line.substring(0, 200)
    };
  } catch (e) {
    return null;
  }
}

/**
 * Stop capture for a specific IP
 * @param {string} ip - Device IP to stop capturing
 */
function stopCaptureForIP(ip) {
  for (const [id, capture] of activeCaptures) {
    if (capture.ip === ip) {
      capture.proc.kill('SIGTERM');
      activeCaptures.delete(id);
      console.log(`[Capture] Stopped capture for ${ip}`);
    }
  }
}

/**
 * Stop all captures
 */
function stopAllCaptures() {
  for (const [id, capture] of activeCaptures) {
    capture.proc.kill('SIGTERM');
  }
  activeCaptures.clear();
  console.log('[Capture] All captures stopped');
}

/**
 * Get list of active captures
 * @returns {Array} Active capture info
 */
function getActiveCaptures() {
  const captures = [];
  for (const [id, capture] of activeCaptures) {
    captures.push({
      id,
      ip: capture.ip,
      iface: capture.iface,
      uptime: Date.now() - capture.startTime
    });
  }
  return captures;
}

module.exports = {
  startCapture,
  startDNSMonitor,
  stopCaptureForIP,
  stopAllCaptures,
  getActiveCaptures
};
