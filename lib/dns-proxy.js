/**
 * DNS Proxy Module
 * Runs a local DNS server that intercepts, logs, and forwards all DNS queries.
 * This gives NetSentry full visibility into every domain every device contacts.
 */

const dgram = require('dgram');

// DNS record type mapping
const DNS_TYPES = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
  16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 43: 'DS',
  46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 50: 'NSEC3',
  52: 'TLSA', 65: 'HTTPS', 99: 'SPF', 255: 'ANY', 257: 'CAA'
};

class DNSProxy {
  constructor(options = {}) {
    this.upstreamDNS = options.upstream || '8.8.8.8';
    this.upstreamPort = options.upstreamPort || 53;
    this.listenPort = options.port || 53;
    this.bindAddress = options.bindAddress || '0.0.0.0';
    this.onQuery = options.onQuery || (() => {});
    this.onResponse = options.onResponse || (() => {});
    this.server = null;
    this.stats = {
      totalQueries: 0,
      totalResponses: 0,
      errors: 0,
      startTime: null,
      queriesPerDevice: {}
    };
    this.running = false;
  }

  /**
   * Start the DNS proxy server
   */
  start() {
    return new Promise((resolve, reject) => {
      this.server = dgram.createSocket('udp4');

      this.server.on('message', (msg, rinfo) => {
        this.handleQuery(msg, rinfo);
      });

      this.server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          console.error(`[DNS Proxy] Port ${this.listenPort} is already in use on ${this.bindAddress}.`);
          reject(err);
        } else if (err.code === 'EACCES') {
          console.error(`[DNS Proxy] Permission denied on port ${this.listenPort}. Run with sudo.`);
          reject(err);
        } else {
          console.error(`[DNS Proxy] Error: ${err.message}`);
          reject(err);
        }
      });

      this.server.on('listening', () => {
        const addr = this.server.address();
        this.running = true;
        this.stats.startTime = Date.now();
        console.log(`[DNS Proxy] Listening on ${addr.address}:${addr.port}`);
        console.log(`[DNS Proxy] Forwarding to upstream ${this.upstreamDNS}:${this.upstreamPort}`);
        resolve();
      });

      this.server.bind(this.listenPort, this.bindAddress);
    });
  }

  /**
   * Handle incoming DNS query
   */
  handleQuery(msg, rinfo) {
    this.stats.totalQueries++;

    // Track per-device queries
    if (!this.stats.queriesPerDevice[rinfo.address]) {
      this.stats.queriesPerDevice[rinfo.address] = 0;
    }
    this.stats.queriesPerDevice[rinfo.address]++;

    // Parse the query
    const query = this.parseDNSPacket(msg);
    if (!query) return;

    // Notify listeners
    this.onQuery({
      deviceIP: rinfo.address,
      devicePort: rinfo.port,
      domain: query.domain,
      queryType: query.typeName,
      queryTypeNum: query.type,
      timestamp: new Date().toISOString(),
      id: query.id
    });

    // Forward to upstream DNS
    const upstream = dgram.createSocket('udp4');

    upstream.send(msg, 0, msg.length, this.upstreamPort, this.upstreamDNS, (err) => {
      if (err) {
        console.error(`[DNS Proxy] Forward error: ${err.message}`);
        this.stats.errors++;
        try { upstream.close(); } catch (e) {}
      }
    });

    upstream.on('message', (response) => {
      this.stats.totalResponses++;

      // Parse response for answers
      const parsed = this.parseDNSResponse(response);

      // Notify listeners with response data
      this.onResponse({
        deviceIP: rinfo.address,
        domain: query.domain,
        queryType: query.typeName,
        answers: parsed.answers,
        responseCode: parsed.rcode,
        timestamp: new Date().toISOString()
      });

      // Send response back to the requesting device
      this.server.send(response, 0, response.length, rinfo.port, rinfo.address, (err) => {
        if (err) {
          console.error(`[DNS Proxy] Response relay error: ${err.message}`);
          this.stats.errors++;
        }
      });

      try { upstream.close(); } catch (e) {}
    });

    upstream.on('error', (err) => {
      console.error(`[DNS Proxy] Upstream error: ${err.message}`);
      this.stats.errors++;
      try { upstream.close(); } catch (e) {}
    });

    // Timeout: if upstream doesn't respond in 5s, clean up
    const timeout = setTimeout(() => {
      try { upstream.close(); } catch (e) {}
    }, 5000);

    upstream.on('close', () => clearTimeout(timeout));
  }

  /**
   * Parse DNS query packet to extract domain and type
   */
  parseDNSPacket(buffer) {
    try {
      if (buffer.length < 12) return null;

      const id = buffer.readUInt16BE(0);
      const flags = buffer.readUInt16BE(2);
      const qdcount = buffer.readUInt16BE(4);

      if (qdcount === 0) return null;

      // Parse question section (starts at offset 12)
      let offset = 12;
      let domain = '';

      while (offset < buffer.length) {
        const labelLen = buffer[offset];
        if (labelLen === 0) {
          offset++;
          break;
        }
        // Check for pointer (compression)
        if ((labelLen & 0xc0) === 0xc0) {
          offset += 2;
          break;
        }
        if (domain.length > 0) domain += '.';
        offset++;
        if (offset + labelLen > buffer.length) return null;
        domain += buffer.slice(offset, offset + labelLen).toString('ascii');
        offset += labelLen;
      }

      if (offset + 2 > buffer.length) return null;

      const qtype = buffer.readUInt16BE(offset);
      const typeName = DNS_TYPES[qtype] || `TYPE${qtype}`;

      return { id, domain, type: qtype, typeName, flags };
    } catch (e) {
      return null;
    }
  }

  /**
   * Parse DNS response to extract answer records
   */
  parseDNSResponse(buffer) {
    try {
      if (buffer.length < 12) return { answers: [], rcode: -1 };

      const flags = buffer.readUInt16BE(2);
      const rcode = flags & 0x0f;
      const qdcount = buffer.readUInt16BE(4);
      const ancount = buffer.readUInt16BE(6);

      // Skip header + question section
      let offset = 12;

      // Skip questions
      for (let i = 0; i < qdcount && offset < buffer.length; i++) {
        while (offset < buffer.length) {
          const len = buffer[offset];
          if (len === 0) { offset++; break; }
          if ((len & 0xc0) === 0xc0) { offset += 2; break; }
          offset += len + 1;
        }
        offset += 4; // skip QTYPE + QCLASS
      }

      // Parse answer records
      const answers = [];
      for (let i = 0; i < ancount && offset < buffer.length; i++) {
        const answer = this.parseResourceRecord(buffer, offset);
        if (!answer) break;
        answers.push(answer);
        offset = answer._nextOffset;
      }

      return { answers, rcode };
    } catch (e) {
      return { answers: [], rcode: -1 };
    }
  }

  /**
   * Parse a single DNS resource record
   */
  parseResourceRecord(buffer, offset) {
    try {
      // Parse name (may be compressed)
      const nameResult = this.readName(buffer, offset);
      if (!nameResult) return null;
      offset = nameResult.offset;

      if (offset + 10 > buffer.length) return null;

      const type = buffer.readUInt16BE(offset);
      const cls = buffer.readUInt16BE(offset + 2);
      const ttl = buffer.readUInt32BE(offset + 4);
      const rdlength = buffer.readUInt16BE(offset + 8);
      offset += 10;

      if (offset + rdlength > buffer.length) return null;

      let data = '';
      const typeName = DNS_TYPES[type] || `TYPE${type}`;

      // Parse RDATA based on type
      if (type === 1 && rdlength === 4) {
        // A record - IPv4
        data = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
      } else if (type === 28 && rdlength === 16) {
        // AAAA record - IPv6
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
          parts.push(buffer.readUInt16BE(offset + i).toString(16));
        }
        data = parts.join(':');
      } else if (type === 5 || type === 2 || type === 12) {
        // CNAME, NS, PTR
        const nameRes = this.readName(buffer, offset);
        data = nameRes ? nameRes.name : '';
      } else {
        data = `[${rdlength} bytes]`;
      }

      return {
        name: nameResult.name,
        type: typeName,
        ttl,
        data,
        _nextOffset: offset + rdlength
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * Read a DNS name from buffer, handling compression pointers
   */
  readName(buffer, offset, depth = 0) {
    if (depth > 10 || offset >= buffer.length) return null;

    let name = '';
    let jumped = false;
    let nextOffset = offset;

    while (offset < buffer.length) {
      const len = buffer[offset];

      if (len === 0) {
        if (!jumped) nextOffset = offset + 1;
        break;
      }

      if ((len & 0xc0) === 0xc0) {
        // Pointer
        if (offset + 1 >= buffer.length) return null;
        const ptr = buffer.readUInt16BE(offset) & 0x3fff;
        if (!jumped) nextOffset = offset + 2;
        offset = ptr;
        jumped = true;
        continue;
      }

      offset++;
      if (offset + len > buffer.length) return null;
      if (name.length > 0) name += '.';
      name += buffer.slice(offset, offset + len).toString('ascii');
      offset += len;
    }

    return { name, offset: jumped ? nextOffset : offset + 1 };
  }

  /**
   * Get proxy statistics
   */
  getStats() {
    return {
      ...this.stats,
      uptime: this.stats.startTime ? Date.now() - this.stats.startTime : 0,
      running: this.running
    };
  }

  /**
   * Stop the DNS proxy
   */
  stop() {
    this.running = false;
    if (this.server) {
      this.server.close();
      console.log('[DNS Proxy] Stopped');
    }
  }
}

module.exports = { DNSProxy };
