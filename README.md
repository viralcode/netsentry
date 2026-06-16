# 🛡️ NetSentry — IoT Network Monitor & Traffic Inspector

**Real-time network surveillance tool for discovering IoT devices, monitoring their traffic, intercepting DNS queries, and inspecting packet-level data on your local network.**

Built in response to growing concerns about IoT devices being exploited as residential proxies and botnet nodes. NetSentry gives you full visibility into what every device on your network is doing.

---

## ✨ Features

### 🔍 Network Discovery
- **ARP-based device scanning** — discovers all devices on your local subnet
- **Vendor identification** via MAC address OUI lookup
- **Device type classification** — routers, phones, smart TVs, security cameras, robot vacuums, IoT sensors, and more
- **Smart iconography** — 15+ SVG icons mapped to device types and vendors

### 📡 Live Traffic Capture
- **Real-time packet capture** via `tcpdump` with ASCII payload extraction
- **Per-device traffic monitoring** — select any device to inspect its traffic
- **Protocol detection** — HTTP, HTTPS, DNS, SSH, FTP, MQTT, CoAP, SOCKS, and more
- **TCP flag decoding** — SYN, ACK, FIN, RST, PSH with human-readable labels
- **Traffic statistics** — packets, bytes transferred, unique destinations, risk scoring

### 🌐 DNS Proxy & Monitoring
- **Built-in DNS proxy** — intercepts all DNS queries when devices use your machine as DNS server
- **Passive DNS monitoring** — fallback `tcpdump`-based DNS capture
- **Per-device DNS profiles** — see which domains each device contacts
- **Top domains ranking** — identify the most contacted domains per device
- **Suspicious domain detection** — flags DynDNS, free TLDs, and suspicious patterns

### 🔬 Packet Inspector (Click any packet row)
- **Connection flow diagram** — visual Source → Protocol → Destination layout
- **Full packet metadata** — timestamp, direction, protocol, port service name, size, TCP flags
- **ASCII payload viewer** — see raw HTTP headers, DNS queries, and unencrypted data
- **Reverse DNS lookup** — automatic hostname resolution for remote IPs
- **IP intelligence** — links to IPinfo.io, AbuseIPDB, and Shodan for public IPs
- **Related packets** — group packets by connection (same src/dst pair)
- **Copy to clipboard** — full packet details including payload

### 🛠️ Request Builder (Built-in HTTP Client)
- **Replay captured requests** — pre-fills destination IP, port, and protocol
- **Full HTTP client** — edit URL, method (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS), headers, and body
- **Response inspector** — status code, timing, response headers, and full response body
- **Supports HTTPS** — with self-signed certificate tolerance

### ⚠️ Risk Analysis
- **Per-device risk scoring** (0-100) based on traffic patterns
- **Alert system** — detects proxy ports, botnet indicators, suspicious DNS, and anomalies
- **Severity levels** — low, medium, high, critical with visual indicators

### 📊 Visualization
- **Protocol distribution** — donut chart showing traffic breakdown
- **Traffic over time** — real-time line chart of inbound/outbound data
- **Risk gauges** — per-device risk bars with color-coded severity

---

## 🚀 Quick Start

### Prerequisites
- **macOS** or **Linux** (uses `tcpdump` and `arp`)
- **Node.js** 18+
- **sudo access** (required for packet capture and DNS proxy on port 53)

### Install & Run

```bash
# Clone the repo
git clone https://github.com/viralcode/netsentry.git
cd netsentry

# Install dependencies
npm install

# Run with sudo (required for tcpdump and port 53)
sudo node server.js
```

Open **http://localhost:3000** in your browser.

### What happens on startup:
1. Express server starts on port 3000
2. DNS proxy binds to your LAN IP on port 53
3. WebSocket server initializes for real-time updates
4. Dashboard is ready — click **Scan Network** to discover devices

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  Browser (UI)                    │
│  Device Grid → Inspector → Packet Drawer        │
│  DNS Log → Alerts → Charts                      │
└──────────────┬──────────────────────────────────┘
               │ WebSocket + REST API
┌──────────────┴──────────────────────────────────┐
│              Node.js Server                      │
│  ┌──────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ Scanner  │ │ Capture  │ │   DNS Proxy     │  │
│  │ (arp)    │ │(tcpdump) │ │ (UDP port 53)   │  │
│  └──────────┘ └──────────┘ └─────────────────┘  │
│  ┌──────────────────────────────────────────┐    │
│  │           Traffic Analyzer               │    │
│  │  Risk scoring, protocol detection,       │    │
│  │  anomaly detection, alert generation     │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
netsentry/
├── server.js              # Main server: Express + WebSocket + DNS Proxy
├── lib/
│   ├── scanner.js          # Network scanning (arp, ping sweep)
│   ├── capture.js          # Traffic capture via tcpdump (with payload)
│   ├── analyzer.js         # Traffic analysis & risk scoring
│   └── dns-proxy.js        # UDP DNS proxy server
├── public/
│   ├── index.html          # Single-page dashboard
│   ├── css/style.css       # Glassmorphic dark theme design system
│   └── js/app.js           # Frontend: WebSocket, charts, drawer, request builder
└── package.json
```

---

## 🔧 Configuration

### Enable Full DNS Visibility

To see DNS queries from **all devices** on your network (not just your Mac):

1. Set your **router's DNS server** to your Mac's IP (shown in the terminal output)
2. Or configure individual devices to use your Mac as DNS

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT`   | `3000`  | HTTP server port |

---

## 🛡️ Security Considerations

- **This tool requires root/sudo** for packet capture and DNS port 53
- **Only use on networks you own or have permission to monitor**
- The DNS proxy forwards all queries to upstream (8.8.8.8 by default)
- The request builder can send HTTP requests to any host — use responsibly
- No data is sent externally — everything stays local

---

## 🧰 Tech Stack

- **Backend**: Node.js, Express, WebSocket (`ws`)
- **Frontend**: Vanilla JS, CSS (no frameworks)
- **Network**: `tcpdump`, `arp`, raw UDP sockets (DNS proxy)
- **Design**: Glassmorphic dark theme, SVG icon system, Canvas charts

---

## 📋 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/network-info` | Get network interface info |
| GET | `/api/scan` | Trigger network scan |
| GET | `/api/devices` | Get cached scan results |
| POST | `/api/capture/start/:ip` | Start packet capture for device |
| POST | `/api/capture/stop/:ip` | Stop capture for device |
| GET | `/api/dns-log` | Get DNS query log |
| GET | `/api/device-dns/:ip` | Get DNS profile for a device |
| GET | `/api/lookup/:ip` | Reverse DNS + IP metadata |
| POST | `/api/request-builder` | Send arbitrary HTTP request |
| GET | `/api/alerts` | Get security alerts |
| GET | `/api/dns-proxy/stats` | DNS proxy statistics |

---

## 📄 License

MIT

---

**Built with ☕ and paranoia about IoT devices.**
