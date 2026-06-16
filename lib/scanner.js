/**
 * Network Scanner Module
 * Discovers devices on the local network using nmap and ARP table.
 */

const { execSync, exec } = require('child_process');
const os = require('os');
const { lookupVendor, identifyDeviceType } = require('./oui-database');

/**
 * Get local network information (IP, subnet, gateway, interface)
 * @returns {{ ip: string, subnet: string, cidr: string, gateway: string, iface: string, mac: string }}
 */
function getNetworkInfo() {
  const interfaces = os.networkInterfaces();
  
  // Find the active non-loopback IPv4 interface
  let activeIface = null;
  let ifaceName = '';
  
  // Prefer en0 on macOS
  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        if (!activeIface || name === 'en0') {
          activeIface = addr;
          ifaceName = name;
        }
      }
    }
  }
  
  if (!activeIface) {
    throw new Error('No active network interface found');
  }
  
  // Calculate CIDR from netmask
  const maskParts = activeIface.netmask.split('.').map(Number);
  const cidrBits = maskParts.reduce((acc, octet) => {
    return acc + octet.toString(2).split('1').length - 1;
  }, 0);
  
  // Calculate subnet base
  const ipParts = activeIface.address.split('.').map(Number);
  const subnetParts = ipParts.map((part, i) => part & maskParts[i]);
  const subnet = subnetParts.join('.');
  const cidr = `${subnet}/${cidrBits}`;
  
  // Get default gateway
  let gateway = '';
  try {
    const routeOutput = execSync('netstat -nr -f inet 2>/dev/null | grep default | head -1', { encoding: 'utf8' });
    const parts = routeOutput.trim().split(/\s+/);
    gateway = parts[1] || '';
  } catch (e) {
    // Try route command
    try {
      const routeOutput = execSync('route -n get default 2>/dev/null | grep gateway', { encoding: 'utf8' });
      gateway = routeOutput.trim().split(':').pop().trim();
    } catch (e2) {
      gateway = subnetParts.slice(0, 3).join('.') + '.1';
    }
  }
  
  return {
    ip: activeIface.address,
    subnet: subnet,
    cidr: cidr,
    netmask: activeIface.netmask,
    gateway: gateway,
    iface: ifaceName,
    mac: activeIface.mac || ''
  };
}

/**
 * Scan network using nmap (preferred method)
 * @param {string} cidr - Network CIDR (e.g., '192.168.1.0/24')
 * @returns {Promise<Array>} Array of discovered devices
 */
function scanWithNmap(cidr) {
  return new Promise((resolve, reject) => {
    // Use -sn for ping scan (no port scan), -oX for XML output
    const cmd = `nmap -sn -oX - ${cidr} 2>/dev/null`;
    
    exec(cmd, { maxBuffer: 1024 * 1024 * 10, timeout: 30000 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`nmap scan failed: ${err.message}`));
        return;
      }
      
      const devices = parseNmapXML(stdout);
      resolve(devices);
    });
  });
}

/**
 * Parse nmap XML output into device objects
 * @param {string} xml - nmap XML output
 * @returns {Array} Parsed device list
 */
function parseNmapXML(xml) {
  const devices = [];
  
  // Match each host block
  const hostRegex = /<host\b[^>]*>([\s\S]*?)<\/host>/g;
  let hostMatch;
  
  while ((hostMatch = hostRegex.exec(xml)) !== null) {
    const hostBlock = hostMatch[1];
    
    // Check if host is up
    if (!hostBlock.includes('state="up"')) continue;
    
    const device = {
      ip: '',
      mac: '',
      vendor: '',
      hostname: '',
      latency: '',
      status: 'up',
      type: 'Unknown',
      icon: '❓',
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      riskScore: 0,
      trafficStats: { packets: 0, bytes: 0, connections: 0 }
    };
    
    // Extract IP address
    const ipMatch = hostBlock.match(/<address addr="([^"]+)" addrtype="ipv4"/);
    if (ipMatch) device.ip = ipMatch[1];
    
    // Extract MAC address
    const macMatch = hostBlock.match(/<address addr="([^"]+)" addrtype="mac"(?:\s+vendor="([^"]*)")?/);
    if (macMatch) {
      device.mac = macMatch[1];
      device.vendor = macMatch[2] || lookupVendor(macMatch[1]);
    }
    
    // Extract hostname
    const hostnameMatch = hostBlock.match(/<hostname name="([^"]+)"/);
    if (hostnameMatch) device.hostname = hostnameMatch[1];
    
    // Extract latency
    const latencyMatch = hostBlock.match(/srtt="(\d+)"/);
    if (latencyMatch) device.latency = `${(parseInt(latencyMatch[1]) / 1000).toFixed(1)}ms`;
    
    // If no vendor from nmap, try OUI lookup
    if (!device.vendor || device.vendor === '') {
      device.vendor = lookupVendor(device.mac);
    }
    
    // Identify device type
    const typeInfo = identifyDeviceType(device.vendor, device.hostname);
    device.type = typeInfo.type;
    device.icon = typeInfo.icon;
    
    if (device.ip) {
      devices.push(device);
    }
  }
  
  return devices;
}

/**
 * Fallback: scan using ARP table
 * @returns {Promise<Array>} Array of discovered devices
 */
function scanWithArp() {
  return new Promise((resolve, reject) => {
    exec('arp -a', { encoding: 'utf8', timeout: 10000 }, (err, stdout) => {
      if (err) {
        reject(new Error(`ARP scan failed: ${err.message}`));
        return;
      }
      
      const devices = [];
      const lines = stdout.split('\n');
      
      for (const line of lines) {
        // Parse ARP output: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        const match = line.match(/\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)\s+on\s+(\w+)/i);
        if (!match) continue;
        
        const [, ip, mac, iface] = match;
        
        // Skip incomplete entries
        if (mac === '(incomplete)' || mac === 'ff:ff:ff:ff:ff:ff') continue;
        
        const vendor = lookupVendor(mac);
        const typeInfo = identifyDeviceType(vendor, '');
        
        devices.push({
          ip,
          mac: mac.toUpperCase(),
          vendor,
          hostname: '',
          latency: '',
          status: 'up',
          type: typeInfo.type,
          icon: typeInfo.icon,
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          riskScore: 0,
          trafficStats: { packets: 0, bytes: 0, connections: 0 }
        });
      }
      
      resolve(devices);
    });
  });
}

/**
 * Main scan function — tries nmap first, falls back to ARP
 * @returns {Promise<{ devices: Array, networkInfo: object, scanMethod: string }>}
 */
async function scanNetwork() {
  const networkInfo = getNetworkInfo();
  let devices = [];
  let scanMethod = 'nmap';
  
  try {
    // Check if nmap is available
    execSync('which nmap', { encoding: 'utf8' });
    devices = await scanWithNmap(networkInfo.cidr);
  } catch (e) {
    console.log('[Scanner] nmap not available, falling back to ARP scan');
    scanMethod = 'arp';
    devices = await scanWithArp();
  }
  
  // Ensure local machine is in the list
  const localDevice = devices.find(d => d.ip === networkInfo.ip);
  if (!localDevice) {
    const typeInfo = identifyDeviceType(lookupVendor(networkInfo.mac), os.hostname());
    devices.push({
      ip: networkInfo.ip,
      mac: networkInfo.mac.toUpperCase(),
      vendor: lookupVendor(networkInfo.mac),
      hostname: os.hostname(),
      latency: '0ms',
      status: 'up',
      type: typeInfo.type,
      icon: typeInfo.icon,
      isLocal: true,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      riskScore: 0,
      trafficStats: { packets: 0, bytes: 0, connections: 0 }
    });
  } else {
    localDevice.isLocal = true;
    if (!localDevice.hostname) localDevice.hostname = os.hostname();
  }
  
  // Mark gateway
  const gatewayDevice = devices.find(d => d.ip === networkInfo.gateway);
  if (gatewayDevice) {
    gatewayDevice.isGateway = true;
    if (gatewayDevice.type === 'Unknown') {
      gatewayDevice.type = 'Router';
      gatewayDevice.icon = '📡';
    }
  }
  
  // Sort: gateway first, local second, then by IP
  devices.sort((a, b) => {
    if (a.isGateway) return -1;
    if (b.isGateway) return 1;
    if (a.isLocal) return -1;
    if (b.isLocal) return 1;
    const aParts = a.ip.split('.').map(Number);
    const bParts = b.ip.split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      if (aParts[i] !== bParts[i]) return aParts[i] - bParts[i];
    }
    return 0;
  });
  
  return { devices, networkInfo, scanMethod, timestamp: new Date().toISOString() };
}

module.exports = { scanNetwork, getNetworkInfo };
