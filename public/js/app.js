/**
 * NetSentry v2 — Frontend Application
 * SVG icon system, DNS proxy integration, per-device inspection, charts
 */

// ============================
// SVG Icon System
// ============================
const ICONS = {
  shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  router: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6.01 18H6M10.01 18H10"/><path d="M15 14V6a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v8"/><path d="M12 6v2"/></svg>`,
  computer: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>`,
  phone: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/></svg>`,
  tv: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2"/><polyline points="17 2 12 7 7 2"/></svg>`,
  speaker: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><circle cx="12" cy="14" r="4"/><path d="M12 6h.01"/></svg>`,
  camera: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3l-2.5-3z"/><circle cx="12" cy="13" r="3"/></svg>`,
  smarthome: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
  iot: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg>`,
  printer: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>`,
  gamepad: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 12h4M8 10v4"/><line x1="15" y1="13" x2="15.01" y2="13"/><line x1="18" y1="11" x2="18.01" y2="11"/><path d="M17.32 5H6.68a4 4 0 0 0-3.978 3.59c-.006.052-.01.101-.017.152C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.545-.604-6.584-.685-7.258-.007-.05-.011-.1-.017-.151A4 4 0 0 0 17.32 5z"/></svg>`,
  vacuum: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1"/></svg>`,
  security: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
  garage: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 20h20"/><path d="M4 20V8l8-5 8 5v12"/><path d="M6 12h12M6 16h12"/></svg>`,
  unknown: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>`,
  // Stat icons
  packets: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  data: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  globe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10"/></svg>`,
  dns: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10"/></svg>`,
  risk: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01"/></svg>`,
  alert: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01"/></svg>`,
  inspect: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><circle cx="11" cy="11" r="3"/></svg>`,
};

// Device type → icon mapping
function getDeviceIcon(device) {
  const type = (device.type || '').toLowerCase();
  const vendor = (device.vendor || '').toLowerCase();
  const hostname = (device.hostname || '').toLowerCase();
  const combined = `${type} ${vendor} ${hostname}`;

  if (device.isGateway) return ICONS.router;
  if (combined.includes('router') || combined.includes('arcadyan') || combined.includes('telus')) return ICONS.router;
  if (combined.includes('phone') || combined.includes('iphone') || combined.includes('android') || combined.includes('samsung') || combined.includes('pixel')) return ICONS.phone;
  if (combined.includes('smart tv') || combined.includes('television') || combined.includes('lg electron') || combined.includes('roku') || combined.includes('fire tv') || combined.includes('chromecast')) return ICONS.tv;
  if (combined.includes('speaker') || combined.includes('sonos') || combined.includes('echo') || combined.includes('homepod') || combined.includes('google home')) return ICONS.speaker;
  if (combined.includes('camera') || combined.includes('ring') || combined.includes('wyze') || combined.includes('nest cam') || combined.includes('arlo')) return ICONS.camera;
  if (combined.includes('smart home') || combined.includes('chamberlain') || combined.includes('hue') || combined.includes('wemo') || combined.includes('smart plug') || combined.includes('tp-link')) return ICONS.smarthome;
  if (combined.includes('security') || combined.includes('alarm') || combined.includes('qolsys')) return ICONS.security;
  if (combined.includes('garage')) return ICONS.garage;
  if (combined.includes('irobot') || combined.includes('roomba') || combined.includes('vacuum') || combined.includes('roborock')) return ICONS.vacuum;
  if (combined.includes('printer') || combined.includes('epson') || combined.includes('hp inc') || combined.includes('canon') || combined.includes('brother')) return ICONS.printer;
  if (combined.includes('xbox') || combined.includes('playstation') || combined.includes('nintendo') || combined.includes('game')) return ICONS.gamepad;
  if (combined.includes('iot') || combined.includes('espressif') || combined.includes('esp32') || combined.includes('shenzhen') || combined.includes('tuya')) return ICONS.iot;
  if (combined.includes('computer') || combined.includes('apple') || combined.includes('intel') || combined.includes('dell') || combined.includes('lenovo') || combined.includes('hp ') || combined.includes('mac')) return ICONS.computer;
  return ICONS.unknown;
}

// ============================
// State
// ============================
let ws = null;
let devices = [];
let selectedDevice = null;
let capturedPackets = [];
let dnsEntries = [];
let alerts = [];
let isCapturing = false;
let packetCount = 0;
let trafficHistory = [];
let protocolCounts = {};
let reconnectAttempt = 0;
let dnsProxyRunning = false;
const MAX_PACKETS_DISPLAY = 500;
const MAX_DNS_DISPLAY = 2000;

// ============================
// WebSocket Connection
// ============================
function connectWebSocket() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${location.host}`);

  ws.onopen = () => {
    reconnectAttempt = 0;
    updateWSStatus(true);
  };

  ws.onmessage = (event) => {
    try { handleWSMessage(JSON.parse(event.data)); }
    catch (e) { console.error('[WS] Parse error:', e); }
  };

  ws.onclose = () => {
    updateWSStatus(false);
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempt), 10000);
    reconnectAttempt++;
    setTimeout(connectWebSocket, delay);
  };

  ws.onerror = () => {};
}

function updateWSStatus(connected) {
  const dot = document.getElementById('ws-dot');
  const text = document.getElementById('ws-text');
  dot.classList.toggle('disconnected', !connected);
  text.textContent = connected ? 'Connected' : 'Reconnecting...';
}

function handleWSMessage(msg) {
  switch (msg.type) {
    case 'welcome':
      if (msg.data.devices) renderDevices(msg.data.devices);
      if (msg.data.dnsLog) msg.data.dnsLog.forEach(d => addDNSEntry(d));
      if (msg.data.alerts) msg.data.alerts.forEach(a => addAlert(a));
      dnsProxyRunning = msg.data.dnsProxyRunning;
      updateDNSProxyStatus();
      break;
    case 'scan_started': setScanningState(true); break;
    case 'scan_complete':
      setScanningState(false);
      renderDevices(msg.data);
      showToast('Scan complete', `Found ${msg.data.devices.length} devices`);
      break;
    case 'scan_error':
      setScanningState(false);
      showToast('Scan failed', msg.error, 'error');
      break;
    case 'packet':
      handlePacket(msg.data, msg.riskScore, msg.alerts);
      break;
    case 'dns':
      addDNSEntry(msg.data);
      if (msg.alerts && msg.alerts.length > 0) msg.alerts.forEach(a => addAlert(a));
      break;
    case 'vuln-scan-progress':
      updateVulnScanProgress(msg);
      break;
    case 'vuln-scan-complete':
      if (selectedDevice && msg.ip === selectedDevice.ip) loadVulnResults(msg.ip);
      showToast('Scan Complete', `Security scan finished for ${msg.ip}`);
      break;
  }
}

// ============================
// DNS Proxy Status
// ============================
function updateDNSProxyStatus() {
  const el = document.getElementById('dns-proxy-status');
  const badge = document.getElementById('dns-proxy-badge');
  if (dnsProxyRunning) {
    el.classList.remove('inactive');
    el.innerHTML = `<span class="dns-proxy-dot"></span> DNS Proxy`;
    if (badge) { badge.style.display = ''; badge.innerHTML = `<span class="dns-proxy-dot"></span> DNS Proxy Active`; }
  } else {
    el.classList.add('inactive');
    el.innerHTML = `<span class="dns-proxy-dot"></span> DNS Passive`;
    if (badge) { badge.style.display = 'none'; }
  }
}

// ============================
// Network Info
// ============================
async function loadNetworkInfo() {
  try {
    const res = await fetch('/api/network-info');
    const json = await res.json();
    if (json.success) {
      const d = json.data;
      document.getElementById('net-iface').textContent = d.iface;
      document.getElementById('net-ip').textContent = d.ip;
      document.getElementById('net-cidr').textContent = d.cidr;
      document.getElementById('net-gateway').textContent = d.gateway;
    }
  } catch (e) { console.error('Failed to load network info:', e); }
}

// ============================
// Scanning
// ============================
async function triggerScan() {
  if (document.getElementById('btn-scan').classList.contains('scanning')) return;
  setScanningState(true);
  try {
    const res = await fetch('/api/scan');
    const json = await res.json();
    if (json.success) renderDevices(json.data);
    else showToast('Scan failed', json.error, 'error');
  } catch (e) { showToast('Scan failed', e.message, 'error'); }
  setScanningState(false);
}

function setScanningState(scanning) {
  const btn = document.getElementById('btn-scan');
  const text = document.getElementById('scan-btn-text');
  btn.classList.toggle('scanning', scanning);
  text.textContent = scanning ? 'Scanning...' : 'Scan Network';
  if (scanning && devices.length === 0) {
    const grid = document.getElementById('device-grid');
    const emptyState = document.getElementById('empty-devices');
    if (emptyState) emptyState.style.display = 'none';
    let skeletons = '';
    for (let i = 0; i < 6; i++) {
      skeletons += `<div class="scan-skeleton"><div class="scan-skeleton-line"></div><div class="scan-skeleton-line"></div><div class="scan-skeleton-line"></div></div>`;
    }
    grid.innerHTML = skeletons;
  }
}

// ============================
// Device Rendering
// ============================
function renderDevices(scanData) {
  if (!scanData || !scanData.devices) return;
  devices = scanData.devices;
  const grid = document.getElementById('device-grid');
  document.getElementById('device-count').textContent = devices.length;

  if (devices.length === 0) {
    grid.innerHTML = `<div class="empty-state" id="empty-devices">
      <svg class="empty-state-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"/></svg>
      <div class="empty-state-title">No devices discovered yet</div>
      <div class="empty-state-description">Click "Scan Network" to discover all devices.</div>
    </div>`;
    return;
  }

  let html = '';
  for (const device of devices) {
    const riskClass = device.riskScore >= 50 ? 'risk-high' : device.riskScore >= 25 ? 'risk-medium' : '';
    const selectedClass = selectedDevice && selectedDevice.ip === device.ip ? 'selected' : '';
    const riskLevel = device.riskScore >= 50 ? 'high' : device.riskScore >= 25 ? 'medium' : 'low';
    const icon = getDeviceIcon(device);
    const dnsCount = device.dnsQueryCount || 0;

    html += `
    <div class="device-card ${riskClass} ${selectedClass}"
         id="device-${device.ip.replace(/\./g, '-')}"
         onclick="selectDevice('${device.ip}')">
      <div class="device-card-header">
        <div class="device-icon-wrap">${icon}</div>
        <div class="device-badges">
          <span class="badge badge-online">● Online</span>
          ${device.isLocal ? '<span class="badge badge-local">This Device</span>' : ''}
          ${device.isGateway ? '<span class="badge badge-gateway">Gateway</span>' : ''}
          ${device.riskScore > 20 ? `<span class="badge badge-risk">Risk: ${device.riskScore}</span>` : ''}
          ${dnsCount > 0 ? `<span class="badge badge-dns">${dnsCount} DNS</span>` : ''}
        </div>
      </div>
      <div class="device-name">${esc(device.hostname || device.vendor || device.ip)}</div>
      <div class="device-type">${esc(device.type)}</div>
      <div class="device-details">
        <div class="device-detail"><span class="label">IP Address</span><span class="value">${device.ip}</span></div>
        <div class="device-detail"><span class="label">MAC Address</span><span class="value">${device.mac || '—'}</span></div>
        <div class="device-detail"><span class="label">Vendor</span><span class="value">${esc(device.vendor || 'Unknown')}</span></div>
        <div class="device-detail"><span class="label">Latency</span><span class="value">${device.latency || '—'}</span></div>
      </div>
      ${device.riskScore > 0 ? `
      <div class="risk-gauge">
        <div class="risk-gauge-header">
          <span class="risk-gauge-label">Risk Score</span>
          <span class="risk-gauge-value ${riskLevel}">${device.riskScore}/100</span>
        </div>
        <div class="risk-bar"><div class="risk-bar-fill ${riskLevel}" style="width:${device.riskScore}%"></div></div>
      </div>` : ''}
      ${device.topDomains && device.topDomains.length > 0 ? `
      <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border-subtle);">
        <div style="font-size:0.55rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--text-tertiary);font-weight:600;margin-bottom:4px;">Top Domains</div>
        ${device.topDomains.map(d => `<div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(d.domain)} <span style="color:var(--text-tertiary)">(${d.count})</span></div>`).join('')}
      </div>` : ''}
      <div class="device-card-actions">
        <button class="btn btn-inspect" onclick="event.stopPropagation(); selectDevice('${device.ip}')">
          ${ICONS.inspect}
          <span>Inspect Traffic</span>
        </button>
      </div>
    </div>`;
  }
  grid.innerHTML = html;
}

// ============================
// Device Selection & Inspector
// ============================
function selectDevice(ip) {
  const device = devices.find(d => d.ip === ip);
  if (!device) return;
  selectedDevice = device;

  document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
  const cardEl = document.getElementById(`device-${ip.replace(/\./g, '-')}`);
  if (cardEl) cardEl.classList.add('selected');

  const inspector = document.getElementById('inspector');
  inspector.classList.add('active');

  // Set icon
  document.getElementById('inspector-icon-wrap').innerHTML = getDeviceIcon(device);
  document.getElementById('inspector-name').textContent = device.hostname || device.vendor || 'Unknown Device';
  document.getElementById('inspector-ip').textContent = device.ip;
  document.getElementById('inspector-mac').textContent = device.mac || '';
  document.getElementById('inspector-vendor').textContent = device.vendor || '';

  // Set stat icons
  document.getElementById('stat-icon-packets').innerHTML = ICONS.packets;
  document.getElementById('stat-icon-bytes').innerHTML = ICONS.data;
  document.getElementById('stat-icon-dest').innerHTML = ICONS.globe;
  document.getElementById('stat-icon-dns').innerHTML = ICONS.dns;
  document.getElementById('stat-icon-risk').innerHTML = ICONS.risk;

  // Reset
  capturedPackets = [];
  packetCount = 0;
  trafficHistory = [];
  protocolCounts = {};
  document.getElementById('packet-tbody').innerHTML = '';
  updateInspectorStats();
  clearCharts();

  // Load device DNS and stats
  loadDeviceStats(ip);
  loadDeviceDNS(ip);

  // Default to DNS Activity tab
  switchInspectorTab('dns-activity');

  inspector.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function closeInspector() {
  document.getElementById('inspector').classList.remove('active');
  if (selectedDevice && isCapturing) stopCapture();
  selectedDevice = null;
  document.querySelectorAll('.device-card').forEach(c => c.classList.remove('selected'));
}

async function loadDeviceStats(ip) {
  try {
    const res = await fetch(`/api/device-stats/${ip}`);
    const json = await res.json();
    if (json.success && json.data) {
      const s = json.data;
      setText('stat-packets', s.totalPackets);
      setText('stat-bytes', formatBytes(s.totalBytes));
      setText('stat-destinations', s.uniqueDestinations);
      const riskEl = document.getElementById('stat-risk');
      riskEl.textContent = s.riskScore;
      riskEl.className = 'stat-value' + (s.riskScore >= 50 ? ' danger' : s.riskScore >= 25 ? ' warning' : '');
      if (s.protocols && Object.keys(s.protocols).length > 0) {
        protocolCounts = s.protocols;
        drawProtocolChart();
      }
    }
  } catch (e) { console.error('Failed to load stats:', e); }
}

async function loadDeviceDNS(ip) {
  try {
    const res = await fetch(`/api/device-dns/${ip}`);
    const json = await res.json();
    if (json.success && json.data) {
      setText('stat-dns-queries', json.data.totalQueries);
      // Render DNS activity table
      renderDeviceDNSTable(json.data.queries);
      // Render top domains
      renderTopDomains(json.data.topDomains);
    }
  } catch (e) { console.error('Failed to load DNS:', e); }
}

function renderDeviceDNSTable(queries) {
  const tbody = document.getElementById('device-dns-tbody');
  tbody.innerHTML = '';
  if (!queries || queries.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text-tertiary);">No DNS queries recorded for this device</td></tr>`;
    return;
  }
  // Render in reverse order (newest first)
  for (let i = queries.length - 1; i >= 0; i--) {
    const q = queries[i];
    const row = document.createElement('tr');
    const isSuspicious = checkSuspiciousDomain(q.domain);
    if (isSuspicious) row.classList.add('suspicious');
    const time = formatTime(q.timestamp);
    row.innerHTML = `<td>${time}</td><td class="domain">${esc(q.domain)}${isSuspicious ? ' ⚠️' : ''}</td><td>${q.queryType || 'A'}</td><td>${q.answer || '—'}</td>`;
    tbody.appendChild(row);
  }
}

function renderTopDomains(topDomains) {
  const container = document.getElementById('top-domains-list');
  if (!topDomains || topDomains.length === 0) {
    container.innerHTML = `<div class="empty-state-mini">No DNS data yet for this device.</div>`;
    return;
  }
  const maxCount = topDomains[0].count;
  let html = '';
  topDomains.forEach((d, i) => {
    const pct = (d.count / maxCount * 100).toFixed(0);
    const isSuspicious = checkSuspiciousDomain(d.domain);
    html += `
    <div class="top-domain-item${isSuspicious ? ' suspicious' : ''}">
      <div class="top-domain-rank">#${i + 1}</div>
      <div class="top-domain-info">
        <div class="top-domain-name">${esc(d.domain)}${isSuspicious ? ' ⚠️' : ''}</div>
        <div class="top-domain-bar-wrap"><div class="top-domain-bar" style="width:${pct}%"></div></div>
      </div>
      <div class="top-domain-count">${d.count}</div>
    </div>`;
  });
  container.innerHTML = html;
}

// ============================
// Inspector Sub-Tabs
// ============================
function switchInspectorTab(tabName) {
  document.querySelectorAll('.inspector-tab').forEach(t => t.classList.toggle('active', t.dataset.itab === tabName));
  document.querySelectorAll('.inspector-sub').forEach(p => p.classList.toggle('active', p.id === `isub-${tabName}`));
  if (tabName === 'charts') {
    setTimeout(() => { drawProtocolChart(); drawTrafficChart(); }, 50);
  }
  if (tabName === 'connections' && selectedDevice) {
    loadConnections(selectedDevice.ip);
  }
  if (tabName === 'security' && selectedDevice) {
    // Load existing results if available
    fetch(`/api/vuln-scan/${selectedDevice.ip}/results`)
      .then(r => r.json())
      .then(j => { if (j.success) renderVulnResults(document.getElementById('security-content'), j.data); })
      .catch(() => {});
  }
}

async function loadConnections(ip) {
  const container = document.getElementById('connections-content');
  container.innerHTML = '<div class="conn-loading"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Analyzing connections & identifying providers...</div>';
  try {
    const res = await fetch(`/api/analyze-connections/${ip}`);
    const json = await res.json();
    if (json.success) renderConnections(container, json.data.connections);
    else container.innerHTML = '<div class="empty-state-mini">Failed to analyze connections</div>';
  } catch (e) {
    container.innerHTML = `<div class="empty-state-mini">Error: ${esc(e.message)}</div>`;
  }
}

function renderConnections(container, connections) {
  if (!connections || connections.length === 0) {
    container.innerHTML = '<div class="empty-state-mini">No DNS queries recorded yet. Wait for the device to make requests.</div>';
    return;
  }

  const riskIcons = { safe: '✅', caution: '⚠️', suspicious: '🚨' };
  const riskLabels = { safe: 'Known Provider', caution: 'Unknown Provider', suspicious: 'Suspicious' };

  // Summary
  const safe = connections.filter(c => c.risk === 'safe').length;
  const caution = connections.filter(c => c.risk === 'caution').length;
  const suspicious = connections.filter(c => c.risk === 'suspicious').length;

  let html = `
    <div class="conn-summary">
      <div class="conn-summary-item safe"><span class="conn-count">${safe}</span><span class="conn-label">✅ Known</span></div>
      <div class="conn-summary-item caution"><span class="conn-count">${caution}</span><span class="conn-label">⚠️ Unknown</span></div>
      <div class="conn-summary-item suspicious"><span class="conn-count">${suspicious}</span><span class="conn-label">🚨 Suspicious</span></div>
      <div class="conn-summary-item total"><span class="conn-count">${connections.length}</span><span class="conn-label">Total</span></div>
    </div>
    <div class="conn-grid">`;

  for (const c of connections) {
    html += `
      <div class="conn-card ${c.risk}">
        <div class="conn-card-header">
          <span class="conn-risk-icon">${riskIcons[c.risk] || '❓'}</span>
          <span class="conn-domain">${esc(c.domain)}</span>
          <span class="conn-badge ${c.risk}">${riskLabels[c.risk]}</span>
        </div>
        <div class="conn-details">
          <div class="conn-kv">
            <span class="conn-key">IP</span>
            <span class="conn-val">${c.resolvedIP || 'Unresolvable'}</span>
          </div>
          <div class="conn-kv">
            <span class="conn-key">Provider</span>
            <span class="conn-val">${esc(c.provider || '—')}</span>
          </div>
          ${c.country ? `<div class="conn-kv"><span class="conn-key">Country</span><span class="conn-val">${esc(c.country)}</span></div>` : ''}
          ${c.as ? `<div class="conn-kv"><span class="conn-key">AS</span><span class="conn-val" style="font-size:0.65rem">${esc(c.as)}</span></div>` : ''}
          <div class="conn-kv">
            <span class="conn-key">Queries</span>
            <span class="conn-val">${c.queryCount}×</span>
          </div>
        </div>
        ${c.resolvedIP && !/^(10\.|172\.|192\.168\.|127\.)/.test(c.resolvedIP) ? `
        <div class="conn-card-actions">
          <a href="https://ipinfo.io/${c.resolvedIP}" target="_blank" rel="noopener" class="conn-link">IP Info</a>
          <a href="https://www.abuseipdb.com/check/${c.resolvedIP}" target="_blank" rel="noopener" class="conn-link">Abuse DB</a>
          <a href="https://www.shodan.io/host/${c.resolvedIP}" target="_blank" rel="noopener" class="conn-link">Shodan</a>
        </div>` : ''}
      </div>`;
  }
  html += '</div>';
  container.innerHTML = html;
}

// ============================
// Traffic Capture
// ============================
async function startCapture() {
  if (!selectedDevice) return;
  try {
    const res = await fetch(`/api/capture/start/${selectedDevice.ip}`, { method: 'POST' });
    const json = await res.json();
    if (json.success) {
      isCapturing = true;
      packetCount = 0;
      capturedPackets = [];
      document.getElementById('packet-tbody').innerHTML = '';
      document.getElementById('btn-start-capture').style.display = 'none';
      document.getElementById('btn-stop-capture').style.display = '';
      const bar = document.getElementById('capture-bar');
      bar.classList.add('active');
      document.getElementById('capture-ip').textContent = selectedDevice.ip;
      document.getElementById('capture-packet-count').textContent = '0 packets';
      // Switch to live traffic tab
      switchInspectorTab('live-traffic');
      showToast('Capture started', `Monitoring traffic for ${selectedDevice.ip}`);
    } else {
      showToast('Capture failed', json.error, 'error');
    }
  } catch (e) { showToast('Capture failed', e.message, 'error'); }
}

async function stopCapture() {
  if (!selectedDevice) return;
  try { await fetch(`/api/capture/stop/${selectedDevice.ip}`, { method: 'POST' }); } catch (e) {}
  isCapturing = false;
  document.getElementById('btn-start-capture').style.display = '';
  document.getElementById('btn-stop-capture').style.display = 'none';
  document.getElementById('capture-bar').classList.remove('active');
  showToast('Capture stopped', `Captured ${packetCount} packets`);
}

function handlePacket(packet, riskScore, newAlerts) {
  if (!selectedDevice || (packet.srcIP !== selectedDevice.ip && packet.dstIP !== selectedDevice.ip)) return;

  packetCount++;
  capturedPackets.push(packet);
  if (capturedPackets.length > MAX_PACKETS_DISPLAY) capturedPackets.shift();

  document.getElementById('capture-packet-count').textContent = `${packetCount} packets`;
  addPacketRow(packet);

  if (packet.protocol) protocolCounts[packet.protocol] = (protocolCounts[packet.protocol] || 0) + 1;

  const now = Math.floor(Date.now() / 1000);
  let lastEntry = trafficHistory[trafficHistory.length - 1];
  if (!lastEntry || lastEntry.time !== now) {
    lastEntry = { time: now, inbound: 0, outbound: 0 };
    trafficHistory.push(lastEntry);
    if (trafficHistory.length > 60) trafficHistory.shift();
  }
  lastEntry[packet.direction === 'inbound' ? 'inbound' : 'outbound'] += packet.length || 0;

  setText('stat-packets', packetCount);

  if (typeof riskScore === 'number') {
    const riskEl = document.getElementById('stat-risk');
    riskEl.textContent = riskScore;
    riskEl.className = 'stat-value' + (riskScore >= 50 ? ' danger' : riskScore >= 25 ? ' warning' : '');
  }

  if (newAlerts) newAlerts.forEach(a => addAlert(a));
  if (packetCount % 10 === 0) { drawProtocolChart(); drawTrafficChart(); refreshInspectorStats(); }
}

function addPacketRow(packet) {
  const tbody = document.getElementById('packet-tbody');
  const row = document.createElement('tr');
  row.classList.add('clickable');
  row._packetData = packet;

  const isSuspicious = ['SOCKS', 'PROXY', 'TELNET', 'FTP'].includes(packet.protocol);
  const pClass = packet.protocol === 'HTTP' ? 'http' : packet.protocol === 'HTTPS' ? 'https' : packet.protocol === 'DNS' ? 'dns' : isSuspicious ? 'suspicious' : '';
  const timeStr = formatTime(packet.timestamp);
  row.innerHTML = `
    <td>${timeStr}</td>
    <td><span class="direction ${packet.direction}">${packet.direction === 'inbound' ? '↓ IN' : '↑ OUT'}</span></td>
    <td>${packet.srcIP}${packet.srcPort ? ':' + packet.srcPort : ''}</td>
    <td>${packet.dstIP}${packet.dstPort ? ':' + packet.dstPort : ''}</td>
    <td><span class="protocol-badge ${pClass}">${packet.protocol}</span></td>
    <td>${packet.length || 0}</td>
    <td>${packet.flags || '—'}</td>`;

  row.addEventListener('click', () => openPacketDrawer(packet, row));
  tbody.insertBefore(row, tbody.firstChild);
  while (tbody.children.length > MAX_PACKETS_DISPLAY) tbody.removeChild(tbody.lastChild);
}

async function refreshInspectorStats() {
  if (!selectedDevice) return;
  try {
    const res = await fetch(`/api/device-stats/${selectedDevice.ip}`);
    const json = await res.json();
    if (json.success && json.data) {
      setText('stat-bytes', formatBytes(json.data.totalBytes));
      setText('stat-destinations', json.data.uniqueDestinations);
    }
  } catch (e) {}
}

function updateInspectorStats() {
  setText('stat-packets', '0');
  setText('stat-bytes', '0 B');
  setText('stat-destinations', '0');
  setText('stat-dns-queries', '0');
  const riskEl = document.getElementById('stat-risk');
  riskEl.textContent = '0';
  riskEl.className = 'stat-value';
}

// ============================
// DNS Log (Global)
// ============================
function addDNSEntry(dns) {
  if (!dns || !dns.domain) return;
  dnsEntries.unshift(dns);
  if (dnsEntries.length > MAX_DNS_DISPLAY) dnsEntries.pop();

  document.getElementById('dns-count-badge').textContent = dnsEntries.length;
  document.getElementById('dns-total-count').textContent = `${dnsEntries.length} queries`;

  const tbody = document.getElementById('dns-tbody');
  const emptyDNS = document.getElementById('empty-dns');
  if (emptyDNS) emptyDNS.style.display = 'none';

  const row = document.createElement('tr');
  const isSuspicious = checkSuspiciousDomain(dns.domain);
  if (isSuspicious) row.classList.add('suspicious');
  const timeStr = formatTime(dns.timestamp);
  const sourceClass = dns.source === 'proxy' ? 'proxy' : 'passive';
  row.innerHTML = `
    <td>${timeStr}</td>
    <td class="device-ip">${dns.deviceIP || '—'}</td>
    <td class="domain">${esc(dns.domain)}${isSuspicious ? ' ⚠️' : ''}</td>
    <td>${dns.queryType || 'A'}</td>
    <td>${dns.answer || '—'}</td>
    <td><span class="dns-source-badge ${sourceClass}">${dns.source || 'passive'}</span></td>`;
  tbody.insertBefore(row, tbody.firstChild);
  while (tbody.children.length > MAX_DNS_DISPLAY) tbody.removeChild(tbody.lastChild);
}

function checkSuspiciousDomain(domain) {
  if (!domain) return false;
  const patterns = [
    /\.dyndns\./i, /\.no-ip\./i, /\.ddns\./i, /\.freedns\./i,
    /\.duckdns\./i, /\.ngrok\./i, /\.onion\./i,
    /\.(tk|ml|ga|cf|gq)$/i, /^[a-z0-9]{20,}\./i
  ];
  return patterns.some(p => p.test(domain));
}

function filterDNS() {
  const filter = document.getElementById('dns-filter').value.toLowerCase();
  const rows = document.getElementById('dns-tbody').querySelectorAll('tr');
  let shown = 0;
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    const visible = !filter || text.includes(filter);
    row.style.display = visible ? '' : 'none';
    if (visible) shown++;
  });
  document.getElementById('dns-total-count').textContent = `${shown} of ${dnsEntries.length} queries`;
}

function filterDeviceDNS() {
  const filter = document.getElementById('device-dns-filter').value.toLowerCase();
  document.getElementById('device-dns-tbody').querySelectorAll('tr').forEach(row => {
    row.style.display = (!filter || row.textContent.toLowerCase().includes(filter)) ? '' : 'none';
  });
}

// ============================
// Alerts
// ============================
function addAlert(alert) {
  if (!alert || !alert.message) return;
  if (alerts.find(a => a.id === alert.id)) return;
  alerts.unshift(alert);
  if (alerts.length > 200) alerts.pop();
  document.getElementById('alert-count').textContent = alerts.length;

  const container = document.getElementById('alerts-container');
  const emptyAlerts = document.getElementById('empty-alerts');
  if (emptyAlerts) emptyAlerts.style.display = 'none';

  const card = document.createElement('div');
  card.className = `alert-card severity-${alert.severity || 'medium'}`;
  card.innerHTML = `
    <div class="alert-severity-icon">${ICONS.alert}</div>
    <div class="alert-content">
      <div class="alert-message">${esc(alert.message)}</div>
      <div class="alert-details">${esc(alert.details || '')}</div>
      <div class="alert-meta">
        <span class="device-ip">${alert.deviceIP || ''}</span>
        <span>${new Date(alert.timestamp).toLocaleTimeString()}</span>
        <span class="badge badge-${alert.severity === 'critical' || alert.severity === 'high' ? 'risk' : 'online'}">${(alert.severity || 'unknown').toUpperCase()}</span>
      </div>
    </div>`;
  container.insertBefore(card, container.firstChild);
  while (container.children.length > 101) container.removeChild(container.lastChild);

  if (alert.severity === 'critical' || alert.severity === 'high') {
    showToast('⚠️ Alert', alert.message, 'warning');
  }
}

// ============================
// Tab Navigation
// ============================
function switchTab(tabName) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabName));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${tabName}`));
}

// ============================
// Charts
// ============================
function drawProtocolChart() {
  const canvas = document.getElementById('chart-protocols');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr; canvas.height = 200 * dpr;
  ctx.scale(dpr, dpr);
  const width = rect.width, height = 200;
  ctx.clearRect(0, 0, width, height);

  const entries = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (entries.length === 0) {
    ctx.fillStyle = '#64748b'; ctx.font = '13px Inter, sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('No data yet', width / 2, height / 2);
    return;
  }

  const total = entries.reduce((s, [, v]) => s + v, 0);
  const cx = width * 0.35, cy = height / 2;
  const outerR = Math.min(width * 0.3, height * 0.4), innerR = outerR * 0.6;
  const colors = ['#00e5ff', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#3b82f6', '#ec4899', '#6366f1'];
  let startAngle = -Math.PI / 2;

  entries.forEach(([, count], i) => {
    const slice = (count / total) * Math.PI * 2;
    ctx.beginPath(); ctx.arc(cx, cy, outerR, startAngle, startAngle + slice);
    ctx.arc(cx, cy, innerR, startAngle + slice, startAngle, true); ctx.closePath();
    ctx.fillStyle = colors[i % colors.length]; ctx.fill();
    startAngle += slice;
  });

  ctx.fillStyle = '#f1f5f9'; ctx.font = 'bold 18px JetBrains Mono, monospace'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.fillText(total.toLocaleString(), cx, cy - 8);
  ctx.fillStyle = '#64748b'; ctx.font = '10px Inter, sans-serif'; ctx.fillText('PACKETS', cx, cy + 10);

  const lx = width * 0.68, ly0 = 20, ls = 22;
  entries.forEach(([protocol, count], i) => {
    const y = ly0 + i * ls;
    ctx.beginPath(); ctx.arc(lx, y + 5, 4, 0, Math.PI * 2); ctx.fillStyle = colors[i % colors.length]; ctx.fill();
    ctx.fillStyle = '#f1f5f9'; ctx.font = '12px Inter, sans-serif'; ctx.textAlign = 'left'; ctx.fillText(protocol, lx + 12, y + 9);
    ctx.fillStyle = '#64748b'; ctx.font = '11px JetBrains Mono, monospace';
    ctx.fillText(`${((count / total) * 100).toFixed(1)}%`, lx + 80, y + 9);
  });
}

function drawTrafficChart() {
  const canvas = document.getElementById('chart-traffic');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr; canvas.height = 200 * dpr;
  ctx.scale(dpr, dpr);
  const width = rect.width, height = 200;
  const pad = { top: 20, right: 20, bottom: 30, left: 50 };
  ctx.clearRect(0, 0, width, height);

  if (trafficHistory.length < 2) {
    ctx.fillStyle = '#64748b'; ctx.font = '13px Inter, sans-serif'; ctx.textAlign = 'center';
    ctx.fillText('Collecting data...', width / 2, height / 2);
    return;
  }

  const plotW = width - pad.left - pad.right, plotH = height - pad.top - pad.bottom;
  let maxVal = 1;
  for (const e of trafficHistory) maxVal = Math.max(maxVal, e.inbound, e.outbound);
  maxVal *= 1.1;

  ctx.strokeStyle = 'rgba(148,163,184,0.06)'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (plotH * i) / 4;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(width - pad.right, y); ctx.stroke();
    ctx.fillStyle = '#64748b'; ctx.font = '10px JetBrains Mono, monospace'; ctx.textAlign = 'right';
    ctx.fillText(formatBytes(maxVal - (maxVal * i) / 4), pad.left - 8, y + 3);
  }

  const drawLine = (data, color, key) => {
    ctx.beginPath(); ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = 'round';
    data.forEach((entry, i) => {
      const x = pad.left + (i / (data.length - 1)) * plotW;
      const y = pad.top + plotH - (entry[key] / maxVal) * plotH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.lineTo(pad.left + plotW, pad.top + plotH); ctx.lineTo(pad.left, pad.top + plotH); ctx.closePath();
    ctx.fillStyle = color.replace(')', ', 0.08)').replace('rgb(', 'rgba('); ctx.fill();
  };

  drawLine(trafficHistory, 'rgb(0, 229, 255)', 'inbound');
  drawLine(trafficHistory, 'rgb(139, 92, 246)', 'outbound');

  const ly = height - 8;
  ctx.font = '11px Inter, sans-serif';
  ctx.fillStyle = '#00e5ff'; ctx.beginPath(); ctx.arc(pad.left + 8, ly - 3, 4, 0, Math.PI * 2); ctx.fill();
  ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'left'; ctx.fillText('Inbound', pad.left + 18, ly);
  ctx.fillStyle = '#8b5cf6'; ctx.beginPath(); ctx.arc(pad.left + 90, ly - 3, 4, 0, Math.PI * 2); ctx.fill();
  ctx.fillStyle = '#94a3b8'; ctx.fillText('Outbound', pad.left + 100, ly);
}

function clearCharts() {
  ['chart-protocols', 'chart-traffic'].forEach(id => {
    const c = document.getElementById(id);
    if (c) c.getContext('2d').clearRect(0, 0, c.width, c.height);
  });
}

// ============================
// Toast
// ============================
function showToast(title, message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast';
  const icons = { info: 'ℹ️', error: '❌', warning: '⚠️', success: '✅' };
  toast.innerHTML = `<span>${icons[type] || icons.info}</span><div><strong>${esc(title)}</strong>${message ? `<div style="font-size:0.75rem;color:var(--text-secondary);margin-top:2px;">${esc(message)}</div>` : ''}</div>`;
  container.appendChild(toast);
  setTimeout(() => { toast.classList.add('leaving'); setTimeout(() => toast.remove(), 300); }, 4000);
}

// ============================
// Utilities
// ============================
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}

function formatTime(timestamp) {
  if (!timestamp) return '—';
  const parts = timestamp.split('T');
  if (parts.length > 1) return parts[1].substring(0, 12);
  const sp = timestamp.split(' ');
  return sp.length > 1 ? sp[1].substring(0, 12) : timestamp;
}

function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

// ============================
// Packet Detail Drawer
// ============================
let activePacketRow = null;
let ipLookupCache = {};

function openPacketDrawer(packet, rowEl) {
  if (activePacketRow) activePacketRow.classList.remove('active-row');
  activePacketRow = rowEl;
  rowEl.classList.add('active-row');

  const drawer = document.getElementById('packet-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  const body = document.getElementById('packet-drawer-body');

  const remoteIP = (selectedDevice && packet.srcIP === selectedDevice.ip) ? packet.dstIP : packet.srcIP;
  const isPrivate = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/.test(remoteIP);
  const portService = getServiceName(packet.dstPort || packet.srcPort);
  const pClass = getProtocolClass(packet);

  body.innerHTML = `
    <div class="drawer-section">
      <div class="drawer-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 16 16 12 12 8"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
        Connection Flow
      </div>
      <div class="connection-flow">
        <div class="flow-node source">
          <div class="flow-node-label">Source</div>
          <div class="flow-node-ip">${packet.srcIP}</div>
          <div class="flow-node-port">${packet.srcPort ? 'Port ' + packet.srcPort : '—'}</div>
        </div>
        <div class="flow-arrow">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
          <div class="flow-arrow-label"><span class="protocol-badge ${pClass}">${packet.protocol}</span></div>
        </div>
        <div class="flow-node dest">
          <div class="flow-node-label">Destination</div>
          <div class="flow-node-ip">${packet.dstIP}</div>
          <div class="flow-node-port">${packet.dstPort ? 'Port ' + packet.dstPort : '—'}</div>
        </div>
      </div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Packet Info
      </div>
      <div class="drawer-kv">
        <div class="drawer-kv-label">Timestamp</div>
        <div class="drawer-kv-value">${packet.timestamp || '—'}</div>
        <div class="drawer-kv-label">Direction</div>
        <div class="drawer-kv-value ${packet.direction === 'inbound' ? 'green' : 'cyan'}">${packet.direction === 'inbound' ? '↓ Inbound' : '↑ Outbound'}</div>
        <div class="drawer-kv-label">Protocol</div>
        <div class="drawer-kv-value">${packet.protocol} ${portService ? '(' + portService + ')' : ''}</div>
        <div class="drawer-kv-label">Size</div>
        <div class="drawer-kv-value">${packet.length || 0} bytes (${formatBytes(packet.length || 0)})</div>
        <div class="drawer-kv-label">TCP Flags</div>
        <div class="drawer-kv-value muted">${formatFlags(packet.flags)}</div>
        <div class="drawer-kv-label">Source</div>
        <div class="drawer-kv-value cyan">${packet.srcIP}${packet.srcPort ? ':' + packet.srcPort : ''}</div>
        <div class="drawer-kv-label">Destination</div>
        <div class="drawer-kv-value cyan">${packet.dstIP}${packet.dstPort ? ':' + packet.dstPort : ''}</div>
      </div>
    </div>
    <div class="drawer-section" id="drawer-lookup-section">
      <div class="drawer-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
        Remote IP — ${remoteIP}
        <span class="ip-type-badge ${isPrivate ? 'private' : 'public'}">${isPrivate ? '🏠 Private' : '🌐 Public'}</span>
      </div>
      <div id="drawer-lookup-content">
        <div class="lookup-loading">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
          Looking up ${remoteIP}...
        </div>
      </div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/></svg>
        Related Packets (same connection)
      </div>
      <div class="related-packets" id="drawer-related-packets">
        ${renderRelatedPackets(packet)}
      </div>
    </div>
    ${packet.payload ? `
    <div class="drawer-section">
      <div class="drawer-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 18l2-2-2-2"/><path d="M8 18l-2-2 2-2"/><path d="M12 2v20"/></svg>
        Payload (ASCII)
      </div>
      <pre class="payload-dump">${esc(packet.payload)}</pre>
    </div>` : `
    <div class="drawer-section">
      <div class="drawer-section-title" style="color:var(--text-tertiary);">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 18l2-2-2-2"/><path d="M8 18l-2-2 2-2"/><path d="M12 2v20"/></svg>
        Payload
      </div>
      <div style="font-size:0.75rem;color:var(--text-tertiary);padding:4px 0;">
        ${packet.protocol === 'HTTPS' ? '🔒 Encrypted (TLS/SSL) — payload not readable' : 'No payload captured for this packet'}
      </div>
    </div>`}
    <div class="drawer-actions">
      <button class="btn btn-sm" onclick="copyPacketDetails()">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy Details
      </button>
      <button class="btn btn-sm btn-primary" onclick="openRequestBuilder('${packet.dstIP}', '${packet.dstPort}', '${packet.protocol}')">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
        Replay / Build Request
      </button>
      ${!isPrivate ? `
      <a class="btn btn-sm" href="https://ipinfo.io/${remoteIP}" target="_blank" rel="noopener">🌐 IP Info</a>
      <a class="btn btn-sm" href="https://www.abuseipdb.com/check/${remoteIP}" target="_blank" rel="noopener">🛡️ Abuse Check</a>
      <a class="btn btn-sm" href="https://www.shodan.io/host/${remoteIP}" target="_blank" rel="noopener">🔍 Shodan</a>
      ` : ''}
    </div>`;


  drawer.classList.add('open');
  backdrop.classList.add('open');
  lookupIP(remoteIP);
}

function closePacketDrawer() {
  document.getElementById('packet-drawer').classList.remove('open');
  document.getElementById('drawer-backdrop').classList.remove('open');
  if (activePacketRow) activePacketRow.classList.remove('active-row');
  activePacketRow = null;
}

document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closePacketDrawer(); });

function getProtocolClass(p) {
  if (p.protocol === 'HTTP') return 'http';
  if (p.protocol === 'HTTPS') return 'https';
  if (p.protocol === 'DNS') return 'dns';
  if (['SOCKS','PROXY','TELNET','FTP'].includes(p.protocol)) return 'suspicious';
  return '';
}

function getServiceName(port) {
  const s = { 20:'FTP Data',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',123:'NTP',143:'IMAP',443:'HTTPS',445:'SMB',587:'SMTP',993:'IMAPS',995:'POP3S',1080:'SOCKS',1194:'OpenVPN',3306:'MySQL',3389:'RDP',5060:'SIP',5353:'mDNS',5432:'PostgreSQL',5900:'VNC',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB',51820:'WireGuard' };
  return s[port] || null;
}

function formatFlags(flags) {
  if (!flags || flags === '—' || flags === '.') return 'No flags';
  const m = { S:'SYN (Start)',F:'FIN (End)',R:'RST (Reset)',P:'PSH (Push)','.':'ACK',U:'URG',E:'ECE',W:'CWR' };
  return flags.split('').map(f => m[f] || f).join(', ');
}

function renderRelatedPackets(cur) {
  const key = [cur.srcIP, cur.dstIP].sort().join('-');
  const related = capturedPackets.filter(p => [p.srcIP, p.dstIP].sort().join('-') === key).slice(-20);
  if (related.length <= 1) return '<div style="color:var(--text-tertiary);font-size:0.75rem;padding:8px 0;">No other packets in this connection yet.</div>';
  return related.map(p => {
    const isCur = p.timestamp === cur.timestamp && p.srcPort === cur.srcPort;
    return `<div class="related-packet-row${isCur ? ' current' : ''}">
      <span>${formatTime(p.timestamp)}</span>
      <span>${p.direction === 'inbound' ? '↓' : '↑'} ${p.srcIP}:${p.srcPort||'?'} → ${p.dstIP}:${p.dstPort||'?'}</span>
      <span>${p.protocol}</span>
      <span>${p.length||0}B</span>
    </div>`;
  }).join('');
}

async function lookupIP(ip) {
  const container = document.getElementById('drawer-lookup-content');
  if (!container) return;
  if (ipLookupCache[ip]) { renderLookupResult(container, ipLookupCache[ip]); return; }
  try {
    const res = await fetch(`/api/lookup/${ip}`);
    const json = await res.json();
    if (json.success) { ipLookupCache[ip] = json.data; renderLookupResult(container, json.data); }
    else container.innerHTML = '<div style="color:var(--text-tertiary);font-size:0.75rem;">Lookup failed</div>';
  } catch (e) { container.innerHTML = `<div style="color:var(--text-tertiary);font-size:0.75rem;">Error: ${esc(e.message)}</div>`; }
}

function renderLookupResult(container, data) {
  let h = '<div class="drawer-kv">';
  h += '<div class="drawer-kv-label">Hostname(s)</div><div class="drawer-kv-value">';
  h += data.hostnames && data.hostnames.length > 0 ? data.hostnames.map(x => `<span class="hostname-tag">${esc(x)}</span>`).join('') : '<span class="muted">No reverse DNS</span>';
  h += '</div>';
  h += `<div class="drawer-kv-label">IP Type</div><div class="drawer-kv-value"><span class="ip-type-badge ${data.isPrivate?'private':'public'}">${data.isPrivate?'Private (LAN)':'Public (Internet)'}</span></div>`;
  if (data.deviceInfo) {
    h += `<div class="drawer-kv-label">Device</div><div class="drawer-kv-value green">${esc(data.deviceInfo.hostname||data.deviceInfo.vendor||'Known')}</div>`;
    if (data.deviceInfo.mac) h += `<div class="drawer-kv-label">MAC</div><div class="drawer-kv-value muted">${esc(data.deviceInfo.mac)}</div>`;
    if (data.deviceInfo.vendor) h += `<div class="drawer-kv-label">Vendor</div><div class="drawer-kv-value muted">${esc(data.deviceInfo.vendor)}</div>`;
  }
  if (data.resolvedDomains && data.resolvedDomains.length > 0) {
    h += '<div class="drawer-kv-label">Known As</div><div class="drawer-kv-value">';
    h += data.resolvedDomains.map(d => `<span class="domain-tag">${esc(d)}</span>`).join('');
    h += '</div>';
  }
  if (data.dnsActivity) {
    h += `<div class="drawer-kv-label">DNS Queries</div><div class="drawer-kv-value">${data.dnsActivity.totalQueries} total</div>`;
    if (data.dnsActivity.topDomains && data.dnsActivity.topDomains.length > 0) {
      h += '<div class="drawer-kv-label">Top Domains</div><div class="drawer-kv-value">' + data.dnsActivity.topDomains.map(d => `<span class="domain-tag">${esc(d.domain)} (${d.count})</span>`).join('') + '</div>';
    }
  }
  if (data.trafficStats) {
    h += `<div class="drawer-kv-label">Total Traffic</div><div class="drawer-kv-value">${data.trafficStats.totalPackets} pkts / ${formatBytes(data.trafficStats.totalBytes)}</div>`;
    h += `<div class="drawer-kv-label">Risk Score</div><div class="drawer-kv-value ${data.trafficStats.riskScore>=50?'red':data.trafficStats.riskScore>=25?'amber':'green'}">${data.trafficStats.riskScore}/100</div>`;
  }
  h += '</div>';
  container.innerHTML = h;
}

function copyPacketDetails() {
  if (!activePacketRow || !activePacketRow._packetData) return;
  const p = activePacketRow._packetData;
  const txt = `Timestamp: ${p.timestamp}\nDirection: ${p.direction}\nSource: ${p.srcIP}:${p.srcPort||'?'}\nDest: ${p.dstIP}:${p.dstPort||'?'}\nProtocol: ${p.protocol}\nSize: ${p.length||0} bytes\nFlags: ${p.flags||'none'}\nService: ${getServiceName(p.dstPort)||'unknown'}${p.payload ? '\n\nPayload:\n' + p.payload : ''}`;
  navigator.clipboard.writeText(txt).then(() => showToast('Copied', 'Packet details copied', 'success')).catch(() => showToast('Error', 'Copy failed', 'error'));
}

// ============================
// Request Builder
// ============================
function openRequestBuilder(dstIP, dstPort, protocol) {
  const isHTTPS = protocol === 'HTTPS' || dstPort === '443';
  const scheme = isHTTPS ? 'https' : 'http';
  const defaultPort = isHTTPS ? '443' : '80';
  const portSuffix = dstPort && dstPort !== defaultPort ? ':' + dstPort : '';
  const url = `${scheme}://${dstIP}${portSuffix}/`;

  const body = document.getElementById('packet-drawer-body');
  body.innerHTML = `
    <div class="drawer-section">
      <div class="drawer-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
        Request Builder
      </div>
      <div class="req-builder">
        <div class="req-builder-row">
          <label class="req-label">Method</label>
          <select id="rb-method" class="req-input req-select">
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
            <option value="HEAD">HEAD</option>
            <option value="OPTIONS">OPTIONS</option>
          </select>
        </div>
        <div class="req-builder-row">
          <label class="req-label">URL</label>
          <input type="text" id="rb-url" class="req-input" value="${esc(url)}" placeholder="https://example.com/path">
        </div>
        <div class="req-builder-row">
          <label class="req-label">Headers <span style="font-weight:400;color:var(--text-tertiary)">(JSON)</span></label>
          <textarea id="rb-headers" class="req-input req-textarea" rows="3" placeholder='{"Content-Type": "application/json"}'>{}</textarea>
        </div>
        <div class="req-builder-row">
          <label class="req-label">Body</label>
          <textarea id="rb-body" class="req-input req-textarea" rows="4" placeholder="Request body (for POST/PUT/PATCH)"></textarea>
        </div>
        <div class="req-builder-actions">
          <button class="btn btn-primary" onclick="sendRequest()" id="rb-send-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            Send Request
          </button>
          <button class="btn btn-sm" onclick="closePacketDrawer()">Cancel</button>
        </div>
      </div>
    </div>
    <div class="drawer-section" id="rb-response-section" style="display:none;">
      <div class="drawer-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Response
      </div>
      <div id="rb-response-content"></div>
    </div>`;
}

async function sendRequest() {
  const url = document.getElementById('rb-url').value.trim();
  const method = document.getElementById('rb-method').value;
  const headersStr = document.getElementById('rb-headers').value.trim();
  const body = document.getElementById('rb-body').value;
  const btn = document.getElementById('rb-send-btn');

  if (!url) { showToast('Error', 'URL is required', 'error'); return; }

  let headers = {};
  try {
    if (headersStr && headersStr !== '{}') headers = JSON.parse(headersStr);
  } catch (e) {
    showToast('Error', 'Invalid headers JSON', 'error'); return;
  }

  btn.disabled = true;
  btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Sending...';

  try {
    const res = await fetch('/api/request-builder', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, method, headers, body: body || undefined })
    });
    const json = await res.json();

    const section = document.getElementById('rb-response-section');
    const content = document.getElementById('rb-response-content');
    section.style.display = '';

    if (json.success) {
      const d = json.data;
      const statusClass = d.status < 300 ? 'green' : d.status < 400 ? 'amber' : 'red';
      let h = `<div class="drawer-kv">
        <div class="drawer-kv-label">Status</div>
        <div class="drawer-kv-value ${statusClass}">${d.status} ${d.statusMessage}</div>
        <div class="drawer-kv-label">Time</div>
        <div class="drawer-kv-value">${d.elapsed}ms</div>
        <div class="drawer-kv-label">Size</div>
        <div class="drawer-kv-value">${formatBytes(d.size)}</div>
      </div>`;

      // Response headers
      h += `<details style="margin-top:12px;">
        <summary style="cursor:pointer;font-size:0.68rem;color:var(--text-secondary);font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Response Headers (${Object.keys(d.headers).length})</summary>
        <div class="drawer-kv" style="margin-top:8px;">
          ${Object.entries(d.headers).map(([k,v]) => `<div class="drawer-kv-label">${esc(k)}</div><div class="drawer-kv-value muted">${esc(String(v))}</div>`).join('')}
        </div>
      </details>`;

      // Response body
      h += `<div style="margin-top:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
          <span style="font-size:0.68rem;color:var(--text-secondary);font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Response Body</span>
          <button class="btn btn-sm" onclick="navigator.clipboard.writeText(document.getElementById('rb-resp-body').textContent).then(()=>showToast('Copied','Response body copied','success'))">Copy</button>
        </div>
        <pre class="payload-dump" id="rb-resp-body">${esc(d.body)}</pre>
      </div>`;

      content.innerHTML = h;
    } else {
      content.innerHTML = `<div style="color:var(--accent-red);font-size:0.8rem;padding:8px 0;">❌ ${esc(json.error)}</div>`;
    }
  } catch (e) {
    document.getElementById('rb-response-content').innerHTML = `<div style="color:var(--accent-red);font-size:0.8rem;">❌ ${esc(e.message)}</div>`;
  }

  btn.disabled = false;
  btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg> Send Request';
}

// ============================
// Vulnerability Scanner UI
// ============================

async function startVulnScan() {
  if (!selectedDevice) return showToast('Error', 'Select a device first', 'error');
  const container = document.getElementById('security-content');
  container.innerHTML = `
    <div class="scan-progress">
      <div class="scan-progress-header">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2" class="scan-spinner"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>Scanning ${esc(selectedDevice.ip)}...</span>
      </div>
      <div class="scan-progress-bar"><div class="scan-progress-fill" id="vuln-progress-fill" style="width:0%"></div></div>
      <div class="scan-progress-phase" id="vuln-progress-phase">Initializing...</div>
    </div>`;
  try {
    await fetch(`/api/vuln-scan/${selectedDevice.ip}`, { method: 'POST' });
  } catch (e) {
    container.innerHTML = `<div class="empty-state-mini">❌ ${esc(e.message)}</div>`;
  }
}

function updateVulnScanProgress(msg) {
  if (!selectedDevice || msg.ip !== selectedDevice.ip) return;
  const fill = document.getElementById('vuln-progress-fill');
  const phase = document.getElementById('vuln-progress-phase');
  if (fill) fill.style.width = msg.percent + '%';
  if (phase) phase.textContent = msg.phase;
}

async function loadVulnResults(ip) {
  const container = document.getElementById('security-content');
  try {
    const res = await fetch(`/api/vuln-scan/${ip}/results`);
    const json = await res.json();
    if (json.success) renderVulnResults(container, json.data);
    else container.innerHTML = '<div class="empty-state-mini">No scan results yet.</div>';
  } catch (e) {
    container.innerHTML = `<div class="empty-state-mini">Error: ${esc(e.message)}</div>`;
  }
}

function renderVulnResults(container, data) {
  const scoreColor = data.securityScore >= 80 ? 'var(--accent-green)' : data.securityScore >= 50 ? 'var(--accent-amber)' : 'var(--accent-red)';
  const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' };

  let html = `
    <div class="vuln-header">
      <div class="security-score">
        <div class="score-circle" style="--score-color:${scoreColor};--score-pct:${data.securityScore}">
          <span class="score-number">${data.securityScore}</span>
          <span class="score-label">/ 100</span>
        </div>
        <div class="score-meta">
          <div class="score-title">Security Score</div>
          <div class="score-time">Scanned in ${(data.duration / 1000).toFixed(1)}s</div>
          ${data.os ? `<div class="score-os">🖥️ ${esc(data.os.name)} (${data.os.accuracy}% confidence)</div>` : ''}
        </div>
      </div>
      <div class="vuln-summary-badges">
        ${data.summary.critical ? `<span class="vuln-sbadge critical">${data.summary.critical} Critical</span>` : ''}
        ${data.summary.high ? `<span class="vuln-sbadge high">${data.summary.high} High</span>` : ''}
        ${data.summary.medium ? `<span class="vuln-sbadge medium">${data.summary.medium} Medium</span>` : ''}
        ${data.summary.low ? `<span class="vuln-sbadge low">${data.summary.low} Low</span>` : ''}
        ${Object.values(data.summary).every(v => v === 0) ? '<span class="vuln-sbadge safe">✅ No Vulnerabilities Found</span>' : ''}
      </div>
      <button class="btn btn-rescan" onclick="startVulnScan()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.3"/></svg>
        Re-scan
      </button>
    </div>`;

  // Open Ports Map
  html += `<div class="vuln-section"><div class="vuln-section-title">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>
    Open Ports (${data.openPorts.length})</div>
    <div class="port-grid">`;

  if (data.openPorts.length === 0) {
    html += '<div class="empty-state-mini">No open ports detected — device may be well-firewalled.</div>';
  } else {
    for (const p of data.openPorts) {
      const isDangerous = [23, 21, 1080, 3128, 4444, 5555, 6667, 31337].includes(p.port);
      html += `<div class="port-chip ${isDangerous ? 'dangerous' : 'normal'}">
        <span class="port-num">${p.port}</span>
        <span class="port-svc">${esc(p.service || '?')} ${esc(p.product || '')}</span>
      </div>`;
    }
  }
  html += '</div></div>';

  // Vulnerabilities
  html += `<div class="vuln-section"><div class="vuln-section-title">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    Vulnerabilities (${data.vulnerabilities.length})</div>`;

  if (data.vulnerabilities.length === 0) {
    html += '<div class="vuln-clean">✅ No known vulnerabilities detected. Device appears secure.</div>';
  } else {
    for (const v of data.vulnerabilities) {
      html += `<div class="vuln-card ${v.severity}">
        <div class="vuln-card-top">
          <span class="vuln-severity ${v.severity}">${v.severity.toUpperCase()}</span>
          <span class="vuln-name">${esc(v.name)}</span>
          ${v.id.startsWith('CVE') ? `<a href="https://nvd.nist.gov/vuln/detail/${v.id}" target="_blank" class="vuln-cve-link">${v.id}</a>` : `<span class="vuln-id">${esc(v.id)}</span>`}
        </div>
        <div class="vuln-desc">${esc(v.description)}</div>
        ${v.port ? `<div class="vuln-port">Port: ${v.port}</div>` : ''}
        <div class="vuln-fix">💡 ${esc(v.remediation)}</div>
      </div>`;
    }
  }
  html += '</div>';

  // TLS Certificates
  if (data.tlsCerts.length > 0) {
    html += `<div class="vuln-section"><div class="vuln-section-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      TLS Certificates</div>`;
    for (const c of data.tlsCerts) {
      const statusClass = c.expired ? 'critical' : c.selfSigned ? 'medium' : 'safe';
      const statusText = c.expired ? '⚠️ EXPIRED' : c.selfSigned ? '⚠️ Self-Signed' : '✅ Valid';
      html += `<div class="tls-card ${statusClass}">
        <div class="tls-status">${statusText}</div>
        <div class="tls-detail"><span>Port:</span> ${c.port}</div>
        ${c.subject ? `<div class="tls-detail"><span>Subject:</span> ${esc(c.subject)}</div>` : ''}
        ${c.issuer ? `<div class="tls-detail"><span>Issuer:</span> ${esc(c.issuer)}</div>` : ''}
        ${c.notAfter ? `<div class="tls-detail"><span>Expires:</span> ${esc(c.notAfter)} (${c.daysUntilExpiry}d)</div>` : ''}
      </div>`;
    }
    html += '</div>';
  }

  // Default Credentials
  if (data.defaultCreds.length > 0) {
    html += `<div class="vuln-section"><div class="vuln-section-title crit-title">🚨 DEFAULT CREDENTIALS FOUND</div>`;
    for (const c of data.defaultCreds) {
      html += `<div class="cred-card">
        <span>Port ${c.port}:</span> <code>${esc(c.username)}:${esc(c.password)}</code>
        <span class="cred-status">HTTP ${c.status}</span>
      </div>`;
    }
    html += '</div>';
  }

  container.innerHTML = html;
}

// ============================
// Init
// ============================
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('logo-icon').innerHTML = ICONS.shield;
  loadNetworkInfo();
  connectWebSocket();
  setTimeout(triggerScan, 500);
});
