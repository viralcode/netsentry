/**
 * Anomaly Detection & Risk Scoring Module
 * Analyzes network traffic patterns to detect suspicious IoT behavior.
 */

// Suspicious ports commonly associated with proxies, VPNs, and botnets
const SUSPICIOUS_PORTS = {
  '1080': { name: 'SOCKS Proxy', severity: 'high' },
  '3128': { name: 'HTTP Proxy (Squid)', severity: 'high' },
  '8080': { name: 'HTTP Proxy/Alt', severity: 'medium' },
  '8443': { name: 'HTTPS Alt', severity: 'low' },
  '9050': { name: 'Tor SOCKS', severity: 'critical' },
  '9051': { name: 'Tor Control', severity: 'critical' },
  '1194': { name: 'OpenVPN', severity: 'medium' },
  '1723': { name: 'PPTP VPN', severity: 'medium' },
  '500':  { name: 'IKE/IPSec VPN', severity: 'medium' },
  '4500': { name: 'IPSec NAT-T', severity: 'medium' },
  '51820': { name: 'WireGuard', severity: 'medium' },
  '6667': { name: 'IRC (Botnet C2)', severity: 'high' },
  '6668': { name: 'IRC (Botnet C2)', severity: 'high' },
  '6669': { name: 'IRC (Botnet C2)', severity: 'high' },
  '4444': { name: 'Metasploit/Backdoor', severity: 'critical' },
  '5555': { name: 'ADB (Android Debug)', severity: 'high' },
  '23':   { name: 'Telnet', severity: 'high' },
  '2323': { name: 'Alt Telnet (Mirai)', severity: 'critical' },
  '37215': { name: 'Huawei Router Exploit', severity: 'critical' },
  '52869': { name: 'UPnP Exploit', severity: 'high' },
  '81':   { name: 'Alt HTTP (IoT cams)', severity: 'medium' },
  '8888': { name: 'Alt HTTP/Proxy', severity: 'medium' },
  '8000': { name: 'Alt HTTP/IoT', severity: 'low' },
  '554':  { name: 'RTSP (Camera stream)', severity: 'medium' },
};

// Suspicious DNS domains (dynamic DNS, known C2 infrastructure)
const SUSPICIOUS_DNS_PATTERNS = [
  { pattern: /\.dyndns\./i, name: 'DynDNS', severity: 'medium' },
  { pattern: /\.no-ip\./i, name: 'No-IP Dynamic DNS', severity: 'medium' },
  { pattern: /\.ddns\./i, name: 'Dynamic DNS', severity: 'medium' },
  { pattern: /\.freedns\./i, name: 'FreeDNS', severity: 'medium' },
  { pattern: /\.duckdns\./i, name: 'DuckDNS', severity: 'medium' },
  { pattern: /\.ngrok\./i, name: 'Ngrok Tunnel', severity: 'high' },
  { pattern: /\.serveo\./i, name: 'Serveo Tunnel', severity: 'high' },
  { pattern: /\.portmap\./i, name: 'Portmap', severity: 'high' },
  { pattern: /\.onion\./i, name: 'Tor Hidden Service', severity: 'critical' },
  { pattern: /\.bit$/i, name: 'Namecoin (.bit)', severity: 'high' },
  { pattern: /\.(tk|ml|ga|cf|gq)$/i, name: 'Free TLD (Abuse Risk)', severity: 'medium' },
  { pattern: /^[a-z0-9]{20,}\./i, name: 'DGA-like Domain', severity: 'high' },
];

class TrafficAnalyzer {
  constructor() {
    // Per-device tracking
    this.deviceStats = new Map();
    this.alerts = [];
    this.maxAlerts = 500;
  }
  
  /**
   * Get or create device stats tracker
   * @param {string} ip - Device IP
   * @returns {object} Device stats
   */
  getDeviceStats(ip) {
    if (!this.deviceStats.has(ip)) {
      this.deviceStats.set(ip, {
        ip,
        uniqueDestinations: new Set(),
        uniquePorts: new Set(),
        suspiciousPorts: new Set(),
        totalPackets: 0,
        totalBytes: 0,
        outboundPackets: 0,
        inboundPackets: 0,
        outboundBytes: 0,
        inboundBytes: 0,
        dnsQueries: [],
        suspiciousDNS: [],
        connectionBursts: [],
        protocols: {},
        lastMinuteConnections: [],
        riskScore: 0,
        riskFactors: []
      });
    }
    return this.deviceStats.get(ip);
  }
  
  /**
   * Analyze a packet and update device stats
   * @param {object} packet - Parsed packet from capture module
   * @returns {{ alerts: Array, riskScore: number }}
   */
  analyzePacket(packet) {
    if (!packet || !packet.srcIP) return { alerts: [], riskScore: 0 };
    
    const deviceIP = packet.direction === 'outbound' ? packet.srcIP : packet.dstIP;
    const stats = this.getDeviceStats(deviceIP);
    const newAlerts = [];
    
    // Update basic counters
    stats.totalPackets++;
    stats.totalBytes += packet.length || 0;
    
    if (packet.direction === 'outbound') {
      stats.outboundPackets++;
      stats.outboundBytes += packet.length || 0;
      stats.uniqueDestinations.add(packet.dstIP);
      
      if (packet.dstPort) {
        stats.uniquePorts.add(packet.dstPort);
      }
    } else {
      stats.inboundPackets++;
      stats.inboundBytes += packet.length || 0;
    }
    
    // Track protocols
    if (packet.protocol) {
      stats.protocols[packet.protocol] = (stats.protocols[packet.protocol] || 0) + 1;
    }
    
    // Track connection rate (sliding window of 60 seconds)
    const now = Date.now();
    stats.lastMinuteConnections.push(now);
    stats.lastMinuteConnections = stats.lastMinuteConnections.filter(t => now - t < 60000);
    
    // === ANOMALY CHECKS ===
    
    // 1. Suspicious port detection
    const portToCheck = packet.direction === 'outbound' ? packet.dstPort : packet.srcPort;
    if (portToCheck && SUSPICIOUS_PORTS[portToCheck]) {
      const portInfo = SUSPICIOUS_PORTS[portToCheck];
      if (!stats.suspiciousPorts.has(portToCheck)) {
        stats.suspiciousPorts.add(portToCheck);
        const alert = {
          id: `port-${deviceIP}-${portToCheck}-${now}`,
          type: 'suspicious_port',
          severity: portInfo.severity,
          deviceIP,
          message: `Traffic on ${portInfo.name} port ${portToCheck}`,
          details: `${packet.direction === 'outbound' ? 'Outbound to' : 'Inbound from'} ${packet.direction === 'outbound' ? packet.dstIP : packet.srcIP}:${portToCheck}`,
          timestamp: new Date().toISOString()
        };
        newAlerts.push(alert);
        this.addAlert(alert);
      }
    }
    
    // 2. High connection rate (potential scanning or proxy behavior)
    if (stats.lastMinuteConnections.length > 50 && packet.direction === 'outbound') {
      const rateAlert = {
        id: `rate-${deviceIP}-${now}`,
        type: 'high_connection_rate',
        severity: 'high',
        deviceIP,
        message: `High connection rate: ${stats.lastMinuteConnections.length} connections/min`,
        details: `Device is making ${stats.lastMinuteConnections.length} connections per minute to ${stats.uniqueDestinations.size} unique destinations`,
        timestamp: new Date().toISOString()
      };
      // Only alert every 30 seconds for rate issues
      const recentRateAlert = this.alerts.find(a => 
        a.type === 'high_connection_rate' && 
        a.deviceIP === deviceIP && 
        now - new Date(a.timestamp).getTime() < 30000
      );
      if (!recentRateAlert) {
        newAlerts.push(rateAlert);
        this.addAlert(rateAlert);
      }
    }
    
    // 3. High unique destination count (potential proxy/botnet behavior)
    if (stats.uniqueDestinations.size > 30) {
      const destAlert = {
        id: `dest-${deviceIP}-${now}`,
        type: 'many_destinations',
        severity: 'medium',
        deviceIP,
        message: `Connecting to ${stats.uniqueDestinations.size} unique IPs`,
        details: 'High number of unique destinations may indicate proxy relay or botnet activity',
        timestamp: new Date().toISOString()
      };
      const recentDestAlert = this.alerts.find(a => 
        a.type === 'many_destinations' && 
        a.deviceIP === deviceIP && 
        now - new Date(a.timestamp).getTime() < 60000
      );
      if (!recentDestAlert) {
        newAlerts.push(destAlert);
        this.addAlert(destAlert);
      }
    }
    
    // Recalculate risk score
    stats.riskScore = this.calculateRiskScore(stats);
    
    return { alerts: newAlerts, riskScore: stats.riskScore };
  }
  
  /**
   * Analyze a DNS query
   * @param {object} dns - Parsed DNS entry
   * @returns {{ alerts: Array }}
   */
  analyzeDNS(dns) {
    if (!dns || !dns.deviceIP) return { alerts: [] };
    
    const stats = this.getDeviceStats(dns.deviceIP);
    const newAlerts = [];
    
    if (dns.isQuery) {
      stats.dnsQueries.push({
        domain: dns.domain,
        queryType: dns.queryType,
        timestamp: dns.timestamp
      });
      
      // Keep only last 500 DNS queries per device
      if (stats.dnsQueries.length > 500) {
        stats.dnsQueries = stats.dnsQueries.slice(-500);
      }
      
      // Check against suspicious patterns
      for (const pattern of SUSPICIOUS_DNS_PATTERNS) {
        if (pattern.pattern.test(dns.domain)) {
          const alert = {
            id: `dns-${dns.deviceIP}-${dns.domain}-${Date.now()}`,
            type: 'suspicious_dns',
            severity: pattern.severity,
            deviceIP: dns.deviceIP,
            message: `Suspicious DNS: ${dns.domain}`,
            details: `${pattern.name} detected — domain: ${dns.domain}`,
            timestamp: new Date().toISOString()
          };
          
          // Avoid duplicate alerts for same domain
          const existing = this.alerts.find(a => 
            a.type === 'suspicious_dns' && 
            a.deviceIP === dns.deviceIP && 
            a.message === alert.message
          );
          if (!existing) {
            newAlerts.push(alert);
            this.addAlert(alert);
            stats.suspiciousDNS.push(dns.domain);
          }
        }
      }
      
      // Check for excessive DNS queries (potential DNS tunneling or DGA)
      const recentDNS = stats.dnsQueries.filter(q => {
        const qTime = new Date(q.timestamp.replace(/\.\d+$/, '')).getTime();
        return Date.now() - qTime < 60000;
      });
      
      if (recentDNS.length > 100) {
        const alert = {
          id: `dns-flood-${dns.deviceIP}-${Date.now()}`,
          type: 'dns_flood',
          severity: 'high',
          deviceIP: dns.deviceIP,
          message: `Excessive DNS queries: ${recentDNS.length}/min`,
          details: 'May indicate DNS tunneling, DGA malware, or data exfiltration',
          timestamp: new Date().toISOString()
        };
        const recentFloodAlert = this.alerts.find(a =>
          a.type === 'dns_flood' &&
          a.deviceIP === dns.deviceIP &&
          Date.now() - new Date(a.timestamp).getTime() < 60000
        );
        if (!recentFloodAlert) {
          newAlerts.push(alert);
          this.addAlert(alert);
        }
      }
    }
    
    stats.riskScore = this.calculateRiskScore(stats);
    
    return { alerts: newAlerts };
  }
  
  /**
   * Calculate risk score (0-100) for a device
   * @param {object} stats - Device stats
   * @returns {number} Risk score 0-100
   */
  calculateRiskScore(stats) {
    let score = 0;
    const factors = [];
    
    // Suspicious ports (up to 40 points)
    if (stats.suspiciousPorts.size > 0) {
      let portScore = 0;
      for (const port of stats.suspiciousPorts) {
        const info = SUSPICIOUS_PORTS[port];
        if (info) {
          switch (info.severity) {
            case 'critical': portScore += 20; break;
            case 'high': portScore += 12; break;
            case 'medium': portScore += 6; break;
            case 'low': portScore += 2; break;
          }
        }
      }
      portScore = Math.min(portScore, 40);
      score += portScore;
      if (portScore > 0) factors.push(`Suspicious ports: ${[...stats.suspiciousPorts].join(', ')}`);
    }
    
    // High connection rate (up to 20 points)
    const connRate = stats.lastMinuteConnections.length;
    if (connRate > 100) {
      score += 20;
      factors.push(`Very high connection rate: ${connRate}/min`);
    } else if (connRate > 50) {
      score += 10;
      factors.push(`High connection rate: ${connRate}/min`);
    }
    
    // Many unique destinations (up to 15 points)
    const destCount = stats.uniqueDestinations.size;
    if (destCount > 50) {
      score += 15;
      factors.push(`${destCount} unique destinations`);
    } else if (destCount > 30) {
      score += 8;
      factors.push(`${destCount} unique destinations`);
    }
    
    // Suspicious DNS (up to 15 points)
    if (stats.suspiciousDNS.length > 5) {
      score += 15;
      factors.push(`${stats.suspiciousDNS.length} suspicious DNS queries`);
    } else if (stats.suspiciousDNS.length > 0) {
      score += stats.suspiciousDNS.length * 3;
      factors.push(`${stats.suspiciousDNS.length} suspicious DNS queries`);
    }
    
    // Outbound/Inbound ratio (up to 10 points) — proxies have high outbound
    if (stats.outboundPackets > 100 && stats.inboundPackets > 0) {
      const ratio = stats.outboundPackets / stats.inboundPackets;
      if (ratio > 10) {
        score += 10;
        factors.push(`Very high outbound ratio: ${ratio.toFixed(1)}:1`);
      } else if (ratio > 5) {
        score += 5;
        factors.push(`High outbound ratio: ${ratio.toFixed(1)}:1`);
      }
    }
    
    stats.riskFactors = factors;
    return Math.min(score, 100);
  }
  
  /**
   * Add alert, maintaining max size
   * @param {object} alert
   */
  addAlert(alert) {
    this.alerts.unshift(alert);
    if (this.alerts.length > this.maxAlerts) {
      this.alerts = this.alerts.slice(0, this.maxAlerts);
    }
  }
  
  /**
   * Get all alerts, optionally filtered by device IP
   * @param {string} [deviceIP] - Optional filter
   * @returns {Array}
   */
  getAlerts(deviceIP) {
    if (deviceIP) {
      return this.alerts.filter(a => a.deviceIP === deviceIP);
    }
    return this.alerts;
  }
  
  /**
   * Get stats for a device
   * @param {string} ip
   * @returns {object}
   */
  getStats(ip) {
    const stats = this.deviceStats.get(ip);
    if (!stats) return null;
    
    return {
      ip: stats.ip,
      totalPackets: stats.totalPackets,
      totalBytes: stats.totalBytes,
      outboundPackets: stats.outboundPackets,
      inboundPackets: stats.inboundPackets,
      outboundBytes: stats.outboundBytes,
      inboundBytes: stats.inboundBytes,
      uniqueDestinations: stats.uniqueDestinations.size,
      uniquePorts: stats.uniquePorts.size,
      suspiciousPorts: [...stats.suspiciousPorts],
      connectionRate: stats.lastMinuteConnections.length,
      protocols: stats.protocols,
      dnsQueryCount: stats.dnsQueries.length,
      suspiciousDNS: stats.suspiciousDNS,
      riskScore: stats.riskScore,
      riskFactors: stats.riskFactors,
      recentDNS: stats.dnsQueries.slice(-20)
    };
  }
  
  /**
   * Get summary for all tracked devices
   * @returns {Array}
   */
  getAllDeviceStats() {
    const results = [];
    for (const [ip] of this.deviceStats) {
      results.push(this.getStats(ip));
    }
    return results;
  }
}

module.exports = { TrafficAnalyzer, SUSPICIOUS_PORTS, SUSPICIOUS_DNS_PATTERNS };
