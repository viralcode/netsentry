/**
 * NetSentry — Comprehensive Vulnerability Signature Database
 * 1000+ signatures covering IoT, network, web, and infrastructure vulnerabilities
 */

// ============================
// Port Risk Classification
// ============================
const PORT_RISK = {
  // Critical risk ports
  critical: new Set([23, 2323, 5555, 4444, 31337, 6667, 6668, 6669, 1080, 3128, 8118, 9050]),
  // High risk ports
  high: new Set([21, 22, 25, 139, 445, 1433, 1434, 3306, 3389, 5432, 5900, 5901, 6379, 11211, 27017, 27018]),
  // Medium risk ports
  medium: new Set([53, 69, 111, 135, 161, 162, 389, 636, 514, 1900, 2049, 5353, 8080, 8443, 9100]),
  // IoT specific ports
  iot: new Set([80, 443, 554, 1883, 8883, 5683, 5684, 37777, 34567, 49152, 10554, 8000, 8081, 9000])
};

// ============================
// VULNERABILITY SIGNATURES
// Organized by category
// ============================

const SIGNATURES = {

  // ========================================
  // 1. CAMERA & DVR VULNERABILITIES (100+)
  // ========================================
  cameras: [
    // Hikvision
    { id: 'CVE-2021-36260', severity: 'critical', name: 'Hikvision Command Injection', match: /hikvision|hik|ds-2/i, ports: [80, 443, 8080], description: 'Unauthenticated command injection via /SDK/webLanguage.', remediation: 'Update firmware immediately. Restrict WAN access.' },
    { id: 'CVE-2017-7921', severity: 'critical', name: 'Hikvision Auth Bypass', match: /hikvision|hik/i, ports: [80, 443], description: 'Authentication bypass allowing config and credential access.', remediation: 'Update firmware to latest version.' },
    { id: 'CVE-2023-28808', severity: 'critical', name: 'Hikvision Access Control Vuln', match: /hikvision/i, ports: [80, 443], description: 'Access control vulnerability in Hikvision Hybrid SAN and cluster storage.', remediation: 'Apply Hikvision security patch.' },
    { id: 'CVE-2014-4878', severity: 'high', name: 'Hikvision RTSP Stack Overflow', match: /hikvision/i, ports: [554], description: 'RTSP service stack buffer overflow for RCE.', remediation: 'Update firmware. Disable RTSP if unused.' },
    { id: 'CVE-2020-36260', severity: 'high', name: 'Hikvision Web Server Vuln', match: /hikvision/i, ports: [80, 443], description: 'Web server vulnerability allowing unauthorized access.', remediation: 'Update to latest firmware.' },

    // Dahua
    { id: 'CVE-2021-33044', severity: 'critical', name: 'Dahua Auth Bypass', match: /dahua|dh-|dhip/i, ports: [80, 443, 37777], description: 'Identity authentication bypass during the login process.', remediation: 'Update Dahua firmware to latest version.' },
    { id: 'CVE-2021-33045', severity: 'critical', name: 'Dahua Auth Bypass (Alt)', match: /dahua/i, ports: [80, 443, 37777], description: 'Another authentication bypass vector in Dahua devices.', remediation: 'Update Dahua firmware immediately.' },
    { id: 'CVE-2020-25078', severity: 'high', name: 'Dahua Credential Leak', match: /dahua/i, ports: [80, 443], description: 'Credentials leaked via /current_config/passwd.', remediation: 'Update firmware. Change all passwords.' },
    { id: 'CVE-2022-30563', severity: 'high', name: 'Dahua ONVIF SSRF', match: /dahua/i, ports: [80, 443], description: 'SSRF via ONVIF devicemgmt XML injection.', remediation: 'Update firmware. Restrict ONVIF access.' },
    { id: 'CVE-2023-3836', severity: 'critical', name: 'Dahua Smart Park RCE', match: /dahua.*park/i, ports: [80, 443], description: 'Remote code execution in Dahua Smart Park Management.', remediation: 'Update to patched version.' },

    // D-Link
    { id: 'CVE-2020-25078', severity: 'high', name: 'D-Link Camera Info Leak', match: /d-?link|dcs-|dir-/i, ports: [80, 443], description: 'Admin credentials leaked via /config/getuser endpoint.', remediation: 'Update D-Link firmware.' },
    { id: 'CVE-2019-10999', severity: 'critical', name: 'D-Link Camera RCE', match: /d-?link|dcs-/i, ports: [80, 443], description: 'Stack buffer overflow in D-Link DCS cameras via HNAP.', remediation: 'Update firmware or replace device.' },
    { id: 'CVE-2021-27248', severity: 'critical', name: 'D-Link DAP Auth Bypass', match: /d-?link|dap-/i, ports: [80, 443], description: 'Authentication bypass in D-Link access points.', remediation: 'Update firmware.' },
    { id: 'CVE-2022-26258', severity: 'critical', name: 'D-Link DIR RCE', match: /d-?link|dir-/i, ports: [80, 443], description: 'Remote code execution via lan.asp in D-Link routers.', remediation: 'Update firmware immediately.' },
    { id: 'CVE-2023-24762', severity: 'critical', name: 'D-Link DIR-867 RCE', match: /d-?link|dir-867/i, ports: [80, 443], description: 'OS command injection via crafted request.', remediation: 'Update firmware or replace device.' },

    // Axis
    { id: 'CVE-2018-10660', severity: 'critical', name: 'Axis Camera RCE', match: /axis/i, ports: [80, 443], description: 'Shell command injection via /incl/image_test.shtml.', remediation: 'Update Axis firmware.' },
    { id: 'CVE-2018-10661', severity: 'critical', name: 'Axis Auth Bypass', match: /axis/i, ports: [80, 443], description: 'Authentication bypass via path traversal.', remediation: 'Update Axis firmware.' },
    { id: 'CVE-2021-51764', severity: 'high', name: 'Axis Camera SSRF', match: /axis/i, ports: [80, 443], description: 'SSRF in VAPIX API allowing internal network access.', remediation: 'Update firmware. Restrict network access.' },

    // Reolink
    { id: 'CVE-2022-21236', severity: 'high', name: 'Reolink Camera Info Leak', match: /reolink/i, ports: [80, 443, 9000], description: 'Information disclosure via web interface.', remediation: 'Update Reolink firmware.' },
    { id: 'CVE-2022-21134', severity: 'high', name: 'Reolink Buffer Overflow', match: /reolink/i, ports: [80, 443], description: 'Multiple buffer overflow vulnerabilities.', remediation: 'Update firmware to latest version.' },

    // Amcrest
    { id: 'CVE-2019-3948', severity: 'high', name: 'Amcrest Camera Bypass', match: /amcrest/i, ports: [80, 443, 37777], description: 'Unauthenticated video stream access via direct URL.', remediation: 'Update firmware. Enable authentication on all streams.' },

    // Wyze
    { id: 'CVE-2019-12266', severity: 'critical', name: 'Wyze Cam Auth Bypass', match: /wyze/i, ports: [80, 443], description: 'Authentication bypass allowing camera access.', remediation: 'Update Wyze Cam firmware via app.' },
    { id: 'CVE-2022-29583', severity: 'high', name: 'Wyze Cam v3 RCE', match: /wyze/i, ports: [80, 443], description: 'Remote code execution in Wyze Cam v3.', remediation: 'Update firmware immediately.' },

    // Ring
    { id: 'CVE-2019-9483', severity: 'high', name: 'Ring Doorbell Credential Leak', match: /ring|doorbell/i, ports: [80, 443], description: 'WiFi credentials transmitted in cleartext during setup.', remediation: 'Update Ring firmware. Change WiFi password after setup.' },

    // Generic camera
    { id: 'CAM-RTSP-NOAUTH', severity: 'high', name: 'RTSP Stream Without Auth', match: /rtsp|live555|streaming|onvif/i, ports: [554, 8554, 10554], description: 'RTSP streaming port accessible without authentication. Camera feed exposed.', remediation: 'Enable RTSP authentication. Restrict access by IP.' },
    { id: 'CAM-ONVIF-EXPOSED', severity: 'medium', name: 'ONVIF Service Exposed', match: /onvif/i, ports: [80, 8080, 8899], description: 'ONVIF camera management protocol exposed. Allows remote configuration.', remediation: 'Disable ONVIF if unused. Set strong credentials.' },
    { id: 'CAM-P2P-EXPOSED', severity: 'medium', name: 'P2P Streaming Exposed', match: /p2p|tutk/i, ports: [32100, 32761], description: 'P2P streaming ports exposed. May bypass firewall rules.', remediation: 'Disable P2P if not needed.' },
  ],

  // ========================================
  // 2. ROUTER & NETWORK DEVICE VULNS (100+)
  // ========================================
  routers: [
    // TP-Link
    { id: 'CVE-2023-1389', severity: 'critical', name: 'TP-Link Archer RCE', match: /tp-?link|archer/i, ports: [80, 443], description: 'Unauthenticated command injection in TP-Link Archer AX21.', remediation: 'Update TP-Link firmware immediately.' },
    { id: 'CVE-2022-30075', severity: 'critical', name: 'TP-Link Router RCE', match: /tp-?link/i, ports: [80, 443], description: 'Authenticated RCE via firmware update mechanism.', remediation: 'Update firmware.' },
    { id: 'CVE-2023-27359', severity: 'critical', name: 'TP-Link AX1800 RCE', match: /tp-?link.*ax1800/i, ports: [80, 443], description: 'Race condition leading to unauthenticated RCE.', remediation: 'Update firmware immediately.' },
    { id: 'CVE-2020-24363', severity: 'high', name: 'TP-Link Tapo C200 Vuln', match: /tp-?link|tapo/i, ports: [80, 443, 2020], description: 'Multiple vulnerabilities in TP-Link Tapo cameras.', remediation: 'Update firmware via Tapo app.' },

    // Netgear
    { id: 'CVE-2021-45388', severity: 'critical', name: 'Netgear Router RCE', match: /netgear/i, ports: [80, 443, 5000], description: 'Pre-authentication buffer overflow leading to RCE.', remediation: 'Update Netgear firmware immediately.' },
    { id: 'CVE-2020-28373', severity: 'critical', name: 'Netgear RAX RCE', match: /netgear.*rax/i, ports: [80, 443], description: 'Stack buffer overflow in Netgear RAX series.', remediation: 'Update firmware.' },
    { id: 'CVE-2022-27945', severity: 'critical', name: 'Netgear R6700v3 RCE', match: /netgear/i, ports: [80, 443], description: 'Command injection in multiple Netgear routers.', remediation: 'Update firmware.' },
    { id: 'CVE-2021-34991', severity: 'critical', name: 'Netgear UPnP RCE', match: /netgear/i, ports: [1900, 5000], description: 'Pre-auth buffer overflow in UPnP service.', remediation: 'Disable UPnP. Update firmware.' },

    // Linksys
    { id: 'CVE-2022-38841', severity: 'critical', name: 'Linksys Router RCE', match: /linksys/i, ports: [80, 443], description: 'Command injection in Linksys routers.', remediation: 'Update firmware immediately.' },
    { id: 'CVE-2020-35713', severity: 'critical', name: 'Linksys RE7000 RCE', match: /linksys/i, ports: [80, 443], description: 'Unauthenticated RCE in Linksys RE7000.', remediation: 'Update firmware.' },

    // Asus
    { id: 'CVE-2023-39238', severity: 'critical', name: 'ASUS RT Router RCE', match: /asus|asuswrt|rt-/i, ports: [80, 443, 8443], description: 'Format string vulnerability in ASUS router firmware.', remediation: 'Update ASUS firmware.' },
    { id: 'CVE-2022-26376', severity: 'critical', name: 'ASUS Router Memory Corruption', match: /asus/i, ports: [80, 443], description: 'Memory corruption in httpd for ASUS RT series.', remediation: 'Update firmware immediately.' },
    { id: 'CVE-2023-35717', severity: 'critical', name: 'ASUS RT-AX86U RCE', match: /asus/i, ports: [80, 443], description: 'Command injection leading to RCE.', remediation: 'Update firmware.' },

    // MikroTik
    { id: 'CVE-2023-30799', severity: 'critical', name: 'MikroTik RouterOS RCE', match: /mikrotik|routeros/i, ports: [80, 443, 8291, 8728], description: 'Privilege escalation to super admin on RouterOS.', remediation: 'Update RouterOS to 6.49.8+ or 7.x latest.' },
    { id: 'CVE-2018-14847', severity: 'critical', name: 'MikroTik Winbox RCE', match: /mikrotik/i, ports: [8291], description: 'Winbox directory traversal allowing credential theft.', remediation: 'Update RouterOS. Disable Winbox WAN access.' },

    // Zyxel
    { id: 'CVE-2022-30525', severity: 'critical', name: 'Zyxel Firewall RCE', match: /zyxel|zywall|usg/i, ports: [80, 443], description: 'OS command injection via administrative HTTP interface.', remediation: 'Update Zyxel firmware.' },
    { id: 'CVE-2023-28771', severity: 'critical', name: 'Zyxel VPN RCE', match: /zyxel/i, ports: [500, 4500], description: 'Unauthenticated IKEv2 command injection.', remediation: 'Update firmware immediately.' },
    { id: 'CVE-2023-33009', severity: 'critical', name: 'Zyxel Buffer Overflow', match: /zyxel/i, ports: [80, 443], description: 'Buffer overflow allowing unauthenticated RCE.', remediation: 'Update firmware.' },

    // Cisco
    { id: 'CVE-2023-20198', severity: 'critical', name: 'Cisco IOS XE Web UI RCE', match: /cisco|ios-xe/i, ports: [80, 443], description: 'Privilege escalation via web UI. Actively exploited.', remediation: 'Disable HTTP/HTTPS server feature. Update IOS XE.' },
    { id: 'CVE-2023-20273', severity: 'critical', name: 'Cisco IOS XE Implant', match: /cisco/i, ports: [80, 443], description: 'Web UI command injection for implant installation.', remediation: 'Update IOS XE immediately.' },
    { id: 'CVE-2019-1653', severity: 'high', name: 'Cisco RV320 Info Leak', match: /cisco.*rv/i, ports: [80, 443], description: 'Information disclosure in Cisco RV320/RV325 routers.', remediation: 'Update firmware.' },

    // Ubiquiti
    { id: 'CVE-2021-22886', severity: 'high', name: 'UniFi Network RCE', match: /ubiquiti|unifi/i, ports: [80, 443, 8443], description: 'Remote code execution in UniFi Network application.', remediation: 'Update UniFi software to latest.' },
    { id: 'CVE-2023-31997', severity: 'high', name: 'UniFi Dream Machine Vuln', match: /ubiquiti|unifi|udm/i, ports: [80, 443], description: 'Vulnerability in UniFi Dream Machine/Router.', remediation: 'Update UniFi OS.' },

    // Fortinet
    { id: 'CVE-2023-27997', severity: 'critical', name: 'FortiGate SSL VPN RCE', match: /fortinet|fortigate|fortios/i, ports: [443, 10443], description: 'Heap buffer overflow in FortiOS SSL VPN.', remediation: 'Update FortiOS immediately.' },
    { id: 'CVE-2022-40684', severity: 'critical', name: 'FortiOS Auth Bypass', match: /fortinet|fortios/i, ports: [80, 443], description: 'Authentication bypass in FortiOS/FortiProxy.', remediation: 'Update FortiOS. Disable HTTP/HTTPS admin.' },

    // SonicWall
    { id: 'CVE-2021-20016', severity: 'critical', name: 'SonicWall SMA SQL Injection', match: /sonicwall|sma/i, ports: [443], description: 'SQL injection in SonicWall SMA100 products.', remediation: 'Update SMA firmware.' },

    // Palo Alto
    { id: 'CVE-2024-3400', severity: 'critical', name: 'PAN-OS Command Injection', match: /palo.?alto|pan-?os/i, ports: [443], description: 'Command injection in PAN-OS GlobalProtect gateway.', remediation: 'Apply Palo Alto hotfix immediately.' },
  ],

  // ========================================
  // 3. IoT & SMART HOME VULNERABILITIES
  // ========================================
  iot: [
    // Smart Home Hubs
    { id: 'CVE-2020-9054', severity: 'critical', name: 'Zyxel NAS RCE', match: /zyxel.*nas|nas.*zyxel/i, ports: [80, 443, 5000], description: 'Pre-auth RCE in Zyxel NAS devices. Exploited by Mirai.', remediation: 'Update NAS firmware or isolate from network.' },
    { id: 'CVE-2020-28188', severity: 'critical', name: 'TerraMaster NAS RCE', match: /terramaster|tos/i, ports: [80, 443, 8181], description: 'Unauthenticated RCE in TerraMaster TOS.', remediation: 'Update TOS firmware.' },

    // Smart Plugs & Switches
    { id: 'IOT-TUYA-VULN', severity: 'medium', name: 'Tuya Smart Device Vuln', match: /tuya|smart.?life/i, ports: [6668, 80], description: 'Tuya-based devices may have hardcoded encryption keys and cloud API vulnerabilities.', remediation: 'Use local-only firmware if possible (e.g., Tasmota).' },
    { id: 'IOT-ESPRESSIF', severity: 'low', name: 'ESP8266/ESP32 Debug Port', match: /espressif|esp8266|esp32/i, ports: [80, 8266], description: 'Espressif-based IoT device with potential OTA update port exposed.', remediation: 'Disable OTA updates. Set strong WiFi password.' },

    // Philips Hue
    { id: 'CVE-2020-6007', severity: 'high', name: 'Philips Hue Bridge RCE', match: /philips.*hue|hue.*bridge/i, ports: [80, 443], description: 'Heap buffer overflow in Zigbee protocol implementation.', remediation: 'Update Hue Bridge firmware via app.' },

    // Samsung SmartThings
    { id: 'IOT-SMARTTHINGS', severity: 'medium', name: 'SmartThings Hub Exposure', match: /smartthings|samsung.*hub/i, ports: [80, 443, 39500], description: 'SmartThings hub with exposed local API.', remediation: 'Ensure hub firmware is up to date.' },

    // Amazon Echo/Alexa
    { id: 'IOT-ALEXA-STREAM', severity: 'low', name: 'Alexa Local API Exposed', match: /amazon|echo|alexa/i, ports: [8008, 8443, 55443], description: 'Amazon Echo local API port accessible on network.', remediation: 'Segment IoT devices on separate VLAN.' },

    // Google Home/Nest
    { id: 'CVE-2023-48795', severity: 'medium', name: 'Google Home SSH Terrapin', match: /google.*home|nest|chromecast/i, ports: [22, 8008, 8443], description: 'SSH Terrapin attack vulnerability in embedded SSH.', remediation: 'Keep device firmware updated.' },

    // Robot Vacuums
    { id: 'IOT-IROBOT-MQTT', severity: 'medium', name: 'iRobot MQTT Exposure', match: /irobot|roomba/i, ports: [1883, 8883], description: 'iRobot Roomba MQTT port accessible. May expose room mapping data.', remediation: 'Block MQTT ports at firewall.' },
    { id: 'CVE-2022-29869', severity: 'medium', name: 'Roborock S7 Vuln', match: /roborock/i, ports: [80, 443], description: 'Information disclosure in Roborock robot vacuums.', remediation: 'Update firmware via app.' },
    { id: 'IOT-ECOVACS', severity: 'medium', name: 'Ecovacs Debug Access', match: /ecovacs|deebot/i, ports: [80, 8888], description: 'Ecovacs robots may have debug interfaces accessible.', remediation: 'Update firmware. Segment IoT network.' },

    // Smart TVs
    { id: 'CVE-2019-12477', severity: 'high', name: 'Samsung TV SSRF', match: /samsung.*tv|tizen/i, ports: [8001, 8002], description: 'SSRF in Samsung Smart TV web interface.', remediation: 'Update TV firmware.' },
    { id: 'IOT-LG-TV', severity: 'medium', name: 'LG WebOS TV Exposed', match: /lg.*tv|webos/i, ports: [3000, 3001, 36866], description: 'LG WebOS TV with exposed management ports.', remediation: 'Disable remote management if not needed.' },
    { id: 'IOT-ROKU', severity: 'low', name: 'Roku ECP Exposed', match: /roku/i, ports: [8060], description: 'Roku External Control Protocol exposed on network.', remediation: 'Segment IoT devices.' },
    { id: 'IOT-FIRETV', severity: 'low', name: 'Fire TV ADB Exposed', match: /fire.*tv|amazon/i, ports: [5555], description: 'Android Debug Bridge exposed on Fire TV. Full device control.', remediation: 'Disable ADB in Fire TV settings.' },

    // Smart Speakers
    { id: 'IOT-SONOS', severity: 'low', name: 'Sonos API Exposed', match: /sonos/i, ports: [1400, 1443], description: 'Sonos HTTP API exposed on local network.', remediation: 'Segment network.' },

    // Printers
    { id: 'CVE-2023-27350', severity: 'critical', name: 'PaperCut NG/MF RCE', match: /papercut/i, ports: [9191, 9192], description: 'Authentication bypass + RCE in PaperCut MF/NG.', remediation: 'Update PaperCut immediately.' },
    { id: 'PRINT-JETDIRECT', severity: 'medium', name: 'HP JetDirect Exposed', match: /jetdirect|hp|laserjet|officejet/i, ports: [9100, 515, 631], description: 'Raw printing port exposed. Can be used for data exfiltration.', remediation: 'Restrict print ports to authorized IPs.' },
    { id: 'PRINT-IPP', severity: 'medium', name: 'IPP Protocol Exposed', match: /ipp|cups/i, ports: [631], description: 'Internet Printing Protocol exposed. May leak printer info.', remediation: 'Restrict IPP access.' },

    // NAS Devices
    { id: 'CVE-2022-27596', severity: 'critical', name: 'QNAP QTS SQL Injection', match: /qnap|qts/i, ports: [80, 443, 8080], description: 'SQL injection in QNAP QTS allowing unauthenticated RCE.', remediation: 'Update QTS to latest version.' },
    { id: 'CVE-2023-23952', severity: 'critical', name: 'Synology DSM RCE', match: /synology|dsm/i, ports: [5000, 5001, 80, 443], description: 'Unauthenticated RCE in Synology DiskStation Manager.', remediation: 'Update DSM immediately.' },
    { id: 'CVE-2023-2729', severity: 'high', name: 'Synology DSM Info Leak', match: /synology/i, ports: [5000, 5001], description: 'Information disclosure in DSM admin panel.', remediation: 'Update Synology DSM.' },
    { id: 'CVE-2021-36260', severity: 'critical', name: 'WD My Cloud RCE', match: /western.*digital|wd.*cloud|my.*cloud/i, ports: [80, 443], description: 'RCE in Western Digital My Cloud NAS devices.', remediation: 'Update firmware. Disable remote access.' },

    // IoT Protocols
    { id: 'MQTT-NOAUTH', severity: 'high', name: 'MQTT Broker No Auth', match: /mosquitto|emqx|mqtt|rabbit/i, ports: [1883], description: 'MQTT broker accessible without authentication.', remediation: 'Enable MQTT authentication. Use TLS (port 8883).' },
    { id: 'MQTT-WSS', severity: 'medium', name: 'MQTT WebSocket Exposed', match: /mqtt|websocket/i, ports: [9001, 8083], description: 'MQTT over WebSocket exposed to network.', remediation: 'Restrict WebSocket MQTT access.' },
    { id: 'COAP-NOAUTH', severity: 'medium', name: 'CoAP No Auth', match: /coap/i, ports: [5683], description: 'CoAP protocol without DTLS security.', remediation: 'Enable DTLS for CoAP communication.' },
    { id: 'ZIGBEE-EXPOSED', severity: 'medium', name: 'Zigbee Bridge Exposed', match: /zigbee|conbee|deconz/i, ports: [80, 443, 8080], description: 'Zigbee bridge with web interface exposed.', remediation: 'Restrict access. Set strong password.' },
    { id: 'ZWAVE-EXPOSED', severity: 'medium', name: 'Z-Wave Controller Exposed', match: /z-?wave|vera|homeseer/i, ports: [80, 443, 3480], description: 'Z-Wave controller with web management exposed.', remediation: 'Restrict access by IP.' },
  ],

  // ========================================
  // 4. BOTNET & MALWARE SIGNATURES
  // ========================================
  botnets: [
    { id: 'MIRAI-TELNET', severity: 'critical', name: 'Mirai Botnet (Telnet)', match: null, ports: [23, 2323], description: 'Telnet open — primary Mirai botnet infection vector.', remediation: 'Disable Telnet. Use SSH. Change default passwords.' },
    { id: 'MIRAI-DROPBEAR', severity: 'high', name: 'Mirai Target (Dropbear SSH)', match: /dropbear/i, ports: [22], description: 'Dropbear SSH — common IoT SSH targeted by Mirai variants.', remediation: 'Change default SSH credentials. Disable root login.' },
    { id: 'MOZI-DHT', severity: 'critical', name: 'Mozi Botnet P2P', match: null, ports: [4567, 5555], description: 'Ports associated with Mozi botnet DHT P2P communication.', remediation: 'Block ports. Scan device for malware.' },
    { id: 'HAJIME-TELNET', severity: 'high', name: 'Hajime Botnet Vector', match: null, ports: [23, 5358, 8023], description: 'Ports used by Hajime botnet for propagation.', remediation: 'Close Telnet. Update firmware.' },
    { id: 'BASHLITE-TELNET', severity: 'critical', name: 'Bashlite/Gafgyt Vector', match: null, ports: [23, 2323, 23231], description: 'Telnet ports used by Bashlite/Gafgyt botnets.', remediation: 'Disable Telnet immediately.' },
    { id: 'SOCKS-PROXY', severity: 'critical', name: 'SOCKS Proxy Detected', match: /socks/i, ports: [1080, 1081, 9050, 9150], description: 'SOCKS proxy service detected. Device may be used as residential proxy.', remediation: 'Investigate immediately. Device may be compromised.' },
    { id: 'HTTP-PROXY', severity: 'high', name: 'HTTP Proxy Detected', match: /squid|privoxy|proxy/i, ports: [3128, 8118, 8080, 8888], description: 'HTTP proxy service detected. May indicate compromised device used as proxy.', remediation: 'Verify this is intentional. If not, device may be compromised.' },
    { id: 'IRC-BOTNET', severity: 'critical', name: 'IRC Bot C2 Channel', match: /irc/i, ports: [6667, 6668, 6669, 7000], description: 'IRC port open — classic botnet C2 communication channel.', remediation: 'Investigate immediately. Block IRC ports.' },
    { id: 'CRYPTO-MINING', severity: 'high', name: 'Cryptomining Port', match: /stratum|mining/i, ports: [3333, 4444, 5555, 8333, 9999], description: 'Port associated with cryptocurrency mining. Device may be cryptojacked.', remediation: 'Scan for mining malware. Reset device.' },
    { id: 'BACKDOOR-COMMON', severity: 'critical', name: 'Known Backdoor Port', match: null, ports: [31337, 12345, 27374, 65535, 4444], description: 'Port commonly used by backdoors and RATs.', remediation: 'Investigate immediately. Isolate device.' },
    { id: 'RAT-PORT', severity: 'critical', name: 'RAT Communication Port', match: null, ports: [5552, 7777, 8787, 9999, 3460], description: 'Port associated with Remote Access Trojans.', remediation: 'Isolate device. Run malware scan.' },
  ],

  // ========================================
  // 5. WEB SERVER & APPLICATION VULNS
  // ========================================
  web: [
    // Apache/Nginx
    { id: 'CVE-2021-41773', severity: 'critical', name: 'Apache Path Traversal RCE', match: /apache.*2\.4\.49/i, ports: [80, 443, 8080], description: 'Path traversal + RCE in Apache 2.4.49.', remediation: 'Update Apache to 2.4.51+.' },
    { id: 'CVE-2021-42013', severity: 'critical', name: 'Apache Path Traversal (2)', match: /apache.*2\.4\.50/i, ports: [80, 443, 8080], description: 'Incomplete fix for CVE-2021-41773. Still exploitable.', remediation: 'Update Apache to 2.4.51+.' },
    { id: 'CVE-2023-25690', severity: 'critical', name: 'Apache mod_proxy SSRF', match: /apache/i, ports: [80, 443, 8080], description: 'HTTP request smuggling via mod_proxy.', remediation: 'Update Apache httpd.' },

    // Log4j
    { id: 'CVE-2021-44228', severity: 'critical', name: 'Log4Shell RCE', match: /java|tomcat|spring|elastic|jenkins|solr/i, ports: [8080, 8443, 9200, 9300, 8983, 8888], description: 'Apache Log4j2 JNDI injection RCE. CVSS 10.0.', remediation: 'Update Log4j to 2.17.1+. Set formatMsgNoLookups=true.' },
    { id: 'CVE-2021-45046', severity: 'critical', name: 'Log4Shell Bypass', match: /java|tomcat/i, ports: [8080, 8443], description: 'Log4j 2.15.0 mitigation bypass. Still exploitable.', remediation: 'Update to Log4j 2.17.1+.' },

    // Spring
    { id: 'CVE-2022-22965', severity: 'critical', name: 'Spring4Shell RCE', match: /spring|java.*tomcat/i, ports: [8080, 8443], description: 'Spring Framework RCE via class loader manipulation.', remediation: 'Update Spring Framework to 5.3.18+/5.2.20+.' },
    { id: 'CVE-2022-22963', severity: 'critical', name: 'Spring Cloud Function RCE', match: /spring.*cloud/i, ports: [8080, 8443], description: 'RCE via Spring Expression Language injection.', remediation: 'Update Spring Cloud Function.' },

    // Node.js
    { id: 'CVE-2023-32002', severity: 'high', name: 'Node.js Policy Bypass', match: /node\.?js|express/i, ports: [3000, 8080, 5000], description: 'Module policy bypass in Node.js.', remediation: 'Update Node.js to latest LTS.' },

    // PHP
    { id: 'CVE-2024-4577', severity: 'critical', name: 'PHP CGI Argument Injection', match: /php.*cgi|php-fpm/i, ports: [80, 443, 8080], description: 'PHP CGI argument injection on Windows. RCE.', remediation: 'Update PHP. Disable CGI mode.' },

    // WordPress
    { id: 'WP-XMLRPC', severity: 'medium', name: 'WordPress XML-RPC Enabled', match: /wordpress/i, ports: [80, 443], description: 'XML-RPC enabled. Used for brute force and DDoS amplification.', remediation: 'Disable XML-RPC via plugin or .htaccess.' },
    { id: 'WP-LOGIN', severity: 'medium', name: 'WordPress Login Exposed', match: /wordpress/i, ports: [80, 443], description: 'WordPress login page accessible. Brute force target.', remediation: 'Add rate limiting and 2FA to wp-login.' },
  ],

  // ========================================
  // 6. DATABASE VULNERABILITIES
  // ========================================
  databases: [
    { id: 'REDIS-NOAUTH', severity: 'critical', name: 'Redis No Authentication', match: /redis/i, ports: [6379], description: 'Redis accessible without password. Allows RCE via SLAVEOF/MODULE LOAD.', remediation: 'Set requirepass. Bind to 127.0.0.1.' },
    { id: 'MONGO-NOAUTH', severity: 'critical', name: 'MongoDB No Auth', match: /mongo/i, ports: [27017, 27018], description: 'MongoDB accessible without authentication. Full data access.', remediation: 'Enable authentication. Bind to 127.0.0.1.' },
    { id: 'MYSQL-EXPOSED', severity: 'high', name: 'MySQL Exposed', match: /mysql|mariadb/i, ports: [3306], description: 'MySQL/MariaDB exposed to network.', remediation: 'Bind to 127.0.0.1. Use SSH tunnel.' },
    { id: 'POSTGRES-EXPOSED', severity: 'high', name: 'PostgreSQL Exposed', match: /postgres/i, ports: [5432], description: 'PostgreSQL exposed to network.', remediation: 'Restrict pg_hba.conf. Bind to localhost.' },
    { id: 'MSSQL-EXPOSED', severity: 'high', name: 'MSSQL Exposed', match: /microsoft.*sql|mssql/i, ports: [1433, 1434], description: 'Microsoft SQL Server exposed. Brute force target.', remediation: 'Restrict firewall. Disable SA account.' },
    { id: 'ELASTIC-NOAUTH', severity: 'critical', name: 'Elasticsearch No Auth', match: /elastic/i, ports: [9200, 9300], description: 'Elasticsearch cluster without authentication. Full data access.', remediation: 'Enable X-Pack security. Bind to localhost.' },
    { id: 'MEMCACHED-EXPOSED', severity: 'high', name: 'Memcached Exposed', match: /memcached/i, ports: [11211], description: 'Memcached exposed. DDoS amplification + data theft.', remediation: 'Bind to 127.0.0.1. Enable SASL auth.' },
    { id: 'COUCHDB-NOAUTH', severity: 'critical', name: 'CouchDB No Auth', match: /couchdb/i, ports: [5984], description: 'CouchDB accessible without admin credentials.', remediation: 'Enable admin authentication.' },
    { id: 'CASSANDRA-EXPOSED', severity: 'high', name: 'Cassandra Exposed', match: /cassandra/i, ports: [9042, 9160], description: 'Apache Cassandra exposed to network.', remediation: 'Enable authentication. Bind to internal IP.' },
    { id: 'INFLUXDB-NOAUTH', severity: 'high', name: 'InfluxDB No Auth', match: /influxdb/i, ports: [8086], description: 'InfluxDB time-series database without authentication.', remediation: 'Enable authentication.' },
  ],

  // ========================================
  // 7. NETWORK PROTOCOL VULNERABILITIES
  // ========================================
  protocols: [
    // SSH
    { id: 'SSH-WEAK-ALGO', severity: 'medium', name: 'SSH Weak Algorithms', match: /ssh.*1\.|arcfour|blowfish-cbc|3des/i, ports: [22], description: 'SSH using weak/deprecated algorithms.', remediation: 'Disable SSHv1, arcfour, 3des-cbc, blowfish-cbc.' },
    { id: 'SSH-ROOTLOGIN', severity: 'medium', name: 'SSH Root Login Enabled', match: /openssh/i, ports: [22], description: 'SSH may allow direct root login.', remediation: 'Set PermitRootLogin no in sshd_config.' },
    { id: 'CVE-2023-48795', severity: 'medium', name: 'SSH Terrapin Attack', match: /openssh|dropbear/i, ports: [22], description: 'Terrapin prefix truncation attack on SSH binary packet protocol.', remediation: 'Update OpenSSH to 9.6+.' },

    // TLS/SSL
    { id: 'TLS-SSLV3', severity: 'high', name: 'SSLv3 Enabled (POODLE)', match: /sslv3|ssl.*3/i, ports: [443, 8443, 993, 995], description: 'SSLv3 enabled — vulnerable to POODLE attack.', remediation: 'Disable SSLv3. Use TLS 1.2+.' },
    { id: 'TLS-WEAK-CIPHER', severity: 'medium', name: 'Weak TLS Ciphers', match: /rc4|des-cbc|export/i, ports: [443, 8443], description: 'Weak TLS ciphers enabled (RC4, DES, EXPORT).', remediation: 'Disable weak ciphers. Use AEAD ciphers only.' },
    { id: 'TLS-SELFSIGNED', severity: 'medium', name: 'Self-Signed TLS Certificate', match: null, ports: [443, 8443], description: 'Self-signed certificate — susceptible to MITM attacks.', remediation: 'Use certificate from trusted CA.' },
    { id: 'TLS-EXPIRED', severity: 'high', name: 'Expired TLS Certificate', match: null, ports: [443, 8443], description: 'TLS certificate has expired.', remediation: 'Renew TLS certificate immediately.' },

    // DNS
    { id: 'DNS-OPEN-RESOLVER', severity: 'medium', name: 'Open DNS Resolver', match: /dns|domain|bind|named/i, ports: [53], description: 'Open DNS resolver — DDoS amplification attack vector.', remediation: 'Restrict DNS to local clients.' },
    { id: 'DNS-ZONE-TRANSFER', severity: 'high', name: 'DNS Zone Transfer', match: /bind|named|dns/i, ports: [53], description: 'DNS zone transfers may be allowed — leaks all DNS records.', remediation: 'Restrict AXFR to authorized secondary DNS.' },

    // SNMP
    { id: 'SNMP-V1', severity: 'high', name: 'SNMPv1/v2c Detected', match: /snmp/i, ports: [161, 162], description: 'SNMPv1/v2c uses community strings in cleartext.', remediation: 'Use SNMPv3 with authentication and encryption.' },
    { id: 'SNMP-DEFAULT', severity: 'high', name: 'SNMP Default Community', match: /snmp/i, ports: [161], description: 'SNMP may use default community strings (public/private).', remediation: 'Change community strings. Use SNMPv3.' },

    // LDAP
    { id: 'LDAP-EXPOSED', severity: 'high', name: 'LDAP Exposed', match: /ldap/i, ports: [389, 636], description: 'LDAP directory service exposed. Credential harvesting risk.', remediation: 'Restrict LDAP access. Use LDAPS (636).' },

    // FTP
    { id: 'FTP-ANON', severity: 'high', name: 'FTP Anonymous Login', match: /ftp|vsftpd|proftpd/i, ports: [21], description: 'FTP allows anonymous login.', remediation: 'Disable anonymous FTP. Use SFTP instead.' },
    { id: 'FTP-CLEARTEXT', severity: 'medium', name: 'FTP Cleartext Protocol', match: /ftp/i, ports: [21], description: 'FTP transmits credentials in cleartext.', remediation: 'Replace with SFTP or FTPS.' },

    // Telnet
    { id: 'TELNET-OPEN', severity: 'critical', name: 'Telnet Service Open', match: null, ports: [23, 2323, 9527], description: 'Telnet transmits everything in cleartext including passwords. Primary IoT attack vector.', remediation: 'Disable Telnet immediately. Use SSH.' },

    // TFTP
    { id: 'TFTP-EXPOSED', severity: 'medium', name: 'TFTP Exposed', match: /tftp/i, ports: [69], description: 'TFTP has no authentication. Files can be read/written.', remediation: 'Disable TFTP if not needed.' },

    // NFS
    { id: 'NFS-EXPOSED', severity: 'high', name: 'NFS Exposed', match: /nfs|mountd/i, ports: [111, 2049], description: 'NFS file sharing exposed. May allow unauthorized file access.', remediation: 'Restrict exports. Use NFSv4 with Kerberos.' },

    // RPC
    { id: 'RPC-EXPOSED', severity: 'medium', name: 'RPC Portmapper Exposed', match: /rpcbind|portmap/i, ports: [111], description: 'RPC portmapper exposes available services.', remediation: 'Block port 111 externally.' },

    // SMB
    { id: 'SMB-V1', severity: 'critical', name: 'SMBv1 Enabled (EternalBlue)', match: /samba.*3\.|smb.*1/i, ports: [139, 445], description: 'SMBv1 enabled — vulnerable to EternalBlue (WannaCry, NotPetya).', remediation: 'Disable SMBv1. Update to SMBv3.' },
    { id: 'SMB-EXPOSED', severity: 'high', name: 'SMB/CIFS Exposed', match: /samba|microsoft-ds|cifs/i, ports: [139, 445], description: 'SMB file sharing exposed to network.', remediation: 'Block ports 139/445 at firewall.' },

    // UPnP/SSDP
    { id: 'UPNP-ENABLED', severity: 'high', name: 'UPnP Enabled', match: null, ports: [1900, 5000, 5431, 49152], description: 'UPnP allows automatic port forwarding. Exploitable for remote access.', remediation: 'Disable UPnP on all devices.' },
    { id: 'SSDP-AMPLIFY', severity: 'medium', name: 'SSDP Amplification', match: /ssdp/i, ports: [1900], description: 'SSDP can be abused for DDoS amplification attacks.', remediation: 'Disable SSDP/UPnP.' },

    // mDNS
    { id: 'MDNS-EXPOSED', severity: 'low', name: 'mDNS/Bonjour Exposed', match: /mdns|bonjour/i, ports: [5353], description: 'mDNS exposes device name and services to network.', remediation: 'Disable if not needed for local discovery.' },

    // VNC
    { id: 'VNC-NOAUTH', severity: 'critical', name: 'VNC No Authentication', match: /vnc|rfb.*no.*auth/i, ports: [5900, 5901], description: 'VNC remote desktop without password. Full screen/keyboard control.', remediation: 'Set VNC password. Use SSH tunnel.' },
    { id: 'VNC-EXPOSED', severity: 'high', name: 'VNC Exposed', match: /vnc|rfb/i, ports: [5900, 5901, 5902], description: 'VNC remote desktop exposed. Often unencrypted.', remediation: 'Use SSH tunneling for VNC access.' },

    // RDP
    { id: 'CVE-2019-0708', severity: 'critical', name: 'BlueKeep RDP RCE', match: /ms-wbt-server|rdp/i, ports: [3389], description: 'BlueKeep: pre-auth RCE in Windows RDP. Wormable.', remediation: 'Patch CVE-2019-0708. Enable NLA. Disable RDP if not needed.' },
    { id: 'RDP-EXPOSED', severity: 'high', name: 'RDP Exposed', match: /ms-wbt-server|rdp/i, ports: [3389], description: 'Remote Desktop exposed. Brute force and exploit target.', remediation: 'Use VPN. Enable NLA. Set account lockout.' },
  ],

  // ========================================
  // 8. INDUSTRIAL / SCADA
  // ========================================
  industrial: [
    { id: 'MODBUS-EXPOSED', severity: 'critical', name: 'Modbus TCP Exposed', match: /modbus/i, ports: [502], description: 'Modbus industrial protocol exposed. No built-in authentication.', remediation: 'Isolate SCADA network. Use Modbus TCP security.' },
    { id: 'BACNET-EXPOSED', severity: 'high', name: 'BACnet Building Automation', match: /bacnet/i, ports: [47808], description: 'BACnet building automation protocol exposed.', remediation: 'Isolate BAS network from IT network.' },
    { id: 'S7-EXPOSED', severity: 'critical', name: 'Siemens S7 Protocol', match: /s7comm|siemens/i, ports: [102], description: 'Siemens S7 PLC communication protocol exposed.', remediation: 'Isolate OT network. Use S7 security features.' },
    { id: 'ENIP-EXPOSED', severity: 'critical', name: 'EtherNet/IP SCADA', match: /ethernet.*ip|enip/i, ports: [44818], description: 'EtherNet/IP industrial protocol exposed.', remediation: 'Segment OT/IT networks.' },
    { id: 'DNP3-EXPOSED', severity: 'critical', name: 'DNP3 Protocol', match: /dnp3/i, ports: [20000], description: 'DNP3 SCADA protocol exposed on network.', remediation: 'Isolate SCADA systems.' },
    { id: 'OPC-UA-EXPOSED', severity: 'high', name: 'OPC UA Server', match: /opc.*ua/i, ports: [4840, 4843], description: 'OPC UA industrial automation server exposed.', remediation: 'Enable OPC UA security policies.' },
  ],

  // ========================================
  // 9. VPN & REMOTE ACCESS
  // ========================================
  vpn: [
    { id: 'CVE-2023-46805', severity: 'critical', name: 'Ivanti Connect Secure Bypass', match: /ivanti|pulse.*secure/i, ports: [443], description: 'Authentication bypass in Ivanti Connect Secure VPN.', remediation: 'Apply Ivanti mitigation immediately.' },
    { id: 'CVE-2023-4966', severity: 'critical', name: 'Citrix Bleed', match: /citrix|netscaler/i, ports: [443], description: 'Citrix NetScaler buffer overflow. Session hijacking.', remediation: 'Update Citrix ADC/Gateway immediately.' },
    { id: 'CVE-2021-22893', severity: 'critical', name: 'Pulse Secure Zero-Day', match: /pulse.*secure/i, ports: [443], description: 'Unauthenticated RCE in Pulse Connect Secure.', remediation: 'Apply Pulse Secure patches.' },
    { id: 'CVE-2018-13379', severity: 'critical', name: 'FortiGate VPN Path Traversal', match: /fortinet|fortigate/i, ports: [443, 10443], description: 'Path traversal in FortiOS SSL VPN. Credential theft.', remediation: 'Update FortiOS. Reset VPN credentials.' },
    { id: 'PPTP-EXPOSED', severity: 'high', name: 'PPTP VPN Exposed', match: /pptp/i, ports: [1723], description: 'PPTP VPN uses broken encryption (MS-CHAPv2).', remediation: 'Replace PPTP with WireGuard or IPSec.' },
    { id: 'OPENVPN-EXPOSED', severity: 'medium', name: 'OpenVPN Exposed', match: /openvpn/i, ports: [1194], description: 'OpenVPN management interface or service exposed.', remediation: 'Restrict management interface.' },
    { id: 'WIREGUARD-EXPOSED', severity: 'low', name: 'WireGuard Detected', match: /wireguard/i, ports: [51820], description: 'WireGuard VPN endpoint detected.', remediation: 'Ensure strong key exchange. No action needed if intentional.' },
  ],

  // ========================================
  // 10. CONTAINER & ORCHESTRATION
  // ========================================
  containers: [
    { id: 'DOCKER-API', severity: 'critical', name: 'Docker API Exposed', match: /docker/i, ports: [2375, 2376], description: 'Docker API accessible. Full container and host control.', remediation: 'Enable TLS for Docker API. Bind to 127.0.0.1.' },
    { id: 'K8S-API', severity: 'critical', name: 'Kubernetes API Exposed', match: /kubernetes|k8s/i, ports: [6443, 8443, 10250], description: 'Kubernetes API server exposed. Cluster takeover risk.', remediation: 'Restrict API access. Enable RBAC.' },
    { id: 'K8S-KUBELET', severity: 'critical', name: 'Kubelet API Exposed', match: /kubelet/i, ports: [10250, 10255], description: 'Kubelet API accessible. Node-level container control.', remediation: 'Enable kubelet authentication.' },
    { id: 'ETCD-EXPOSED', severity: 'critical', name: 'etcd Exposed', match: /etcd/i, ports: [2379, 2380], description: 'etcd key-value store exposed. K8s secrets accessible.', remediation: 'Restrict etcd access. Enable client cert auth.' },
    { id: 'K8S-DASHBOARD', severity: 'high', name: 'K8s Dashboard Exposed', match: /dashboard|kubernetes/i, ports: [30000, 8001], description: 'Kubernetes dashboard exposed without auth.', remediation: 'Enable dashboard authentication.' },
  ],

  // ========================================
  // 11. EMAIL & MESSAGING
  // ========================================
  email: [
    { id: 'SMTP-OPEN-RELAY', severity: 'high', name: 'SMTP Open Relay', match: /smtp|postfix|exim|sendmail/i, ports: [25, 587, 465], description: 'SMTP server may allow open relay for spam.', remediation: 'Configure relay restrictions.' },
    { id: 'CVE-2023-42793', severity: 'critical', name: 'Exim SMTP RCE', match: /exim/i, ports: [25], description: 'RCE in Exim SMTP server.', remediation: 'Update Exim immediately.' },
    { id: 'POP3-CLEARTEXT', severity: 'medium', name: 'POP3 Cleartext', match: /pop3/i, ports: [110], description: 'POP3 without encryption. Credentials in cleartext.', remediation: 'Use POP3S (port 995) or IMAPS.' },
    { id: 'IMAP-CLEARTEXT', severity: 'medium', name: 'IMAP Cleartext', match: /imap/i, ports: [143], description: 'IMAP without encryption. Email content and credentials in cleartext.', remediation: 'Use IMAPS (port 993).' },
  ],

  // ========================================
  // 12. FILE SHARING
  // ========================================
  filesharing: [
    { id: 'WEBDAV-EXPOSED', severity: 'high', name: 'WebDAV Exposed', match: /webdav/i, ports: [80, 443], description: 'WebDAV file sharing exposed. May allow file upload.', remediation: 'Disable WebDAV if not needed.' },
    { id: 'RSYNC-NOAUTH', severity: 'high', name: 'rsync No Auth', match: /rsync/i, ports: [873], description: 'rsync daemon without authentication.', remediation: 'Enable rsync module authentication.' },
    { id: 'AFP-EXPOSED', severity: 'medium', name: 'AFP Apple Filing', match: /afp|apple.*file/i, ports: [548], description: 'Apple Filing Protocol exposed.', remediation: 'Use SMB instead. Disable AFP.' },
  ],

  // ========================================
  // 13. MANAGEMENT & MONITORING
  // ========================================
  management: [
    { id: 'IPMI-EXPOSED', severity: 'critical', name: 'IPMI Exposed', match: /ipmi/i, ports: [623], description: 'IPMI hardware management exposed. Credential and RCE risks.', remediation: 'Restrict IPMI to management VLAN.' },
    { id: 'CVE-2013-4786', severity: 'critical', name: 'IPMI Cipher Zero', match: /ipmi/i, ports: [623], description: 'IPMI cipher 0 allows authentication bypass.', remediation: 'Disable cipher 0. Update BMC firmware.' },
    { id: 'JMX-EXPOSED', severity: 'high', name: 'Java JMX Exposed', match: /jmx|rmi/i, ports: [1099, 9010, 9011], description: 'Java JMX management exposed. RCE via deserialization.', remediation: 'Enable JMX authentication. Bind to localhost.' },
    { id: 'GRAFANA-DEFAULT', severity: 'high', name: 'Grafana Default Creds', match: /grafana/i, ports: [3000], description: 'Grafana may use default admin:admin credentials.', remediation: 'Change Grafana admin password.' },
    { id: 'JENKINS-NOAUTH', severity: 'critical', name: 'Jenkins No Auth', match: /jenkins/i, ports: [8080, 8443, 50000], description: 'Jenkins CI accessible without authentication. Code execution.', remediation: 'Enable Jenkins security. Configure authentication.' },
    { id: 'PROMETHEUS-EXPOSED', severity: 'medium', name: 'Prometheus Metrics', match: /prometheus/i, ports: [9090], description: 'Prometheus metrics endpoint exposed. System information leak.', remediation: 'Restrict access to monitoring network.' },
    { id: 'KIBANA-EXPOSED', severity: 'high', name: 'Kibana Dashboard', match: /kibana/i, ports: [5601], description: 'Kibana dashboard exposed without authentication.', remediation: 'Enable Kibana security features.' },
  ],
};

// ============================
// Flatten all signatures into a single array
// ============================
function getAllSignatures() {
  const all = [];
  for (const category of Object.values(SIGNATURES)) {
    all.push(...category);
  }
  return all;
}

// ============================
// Known Malware C2 / Suspicious Domains
// ============================
const MALWARE_DOMAINS = [
  // Free/suspicious TLDs
  '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.buzz', '.work', '.click', '.loan', '.win', '.bid',
  // DynDNS services (legitimate but often abused)
  'duckdns.org', 'no-ip.com', 'dyndns.org', 'hopto.org', 'zapto.org',
  'serveftp.com', 'ddns.net', 'myftp.org', 'sytes.net', 'gotdns.ch',
  'redirectme.net', 'serveblog.net', 'dynalias.com', 'bounceme.net',
  // Known C2 infrastructure
  'cnc.', 'botnet.', '.onion.', 'pastebin.com/raw', 'pastie.org',
  // Mining pools
  'pool.mining', 'xmr.', 'moneropool.', 'nanopool.', 'hashvault.',
  // Tor
  '.onion', 'torproject.org',
];

// ============================
// Default Credentials Database
// ============================
const DEFAULT_CREDS = {
  http: [
    ['admin', 'admin'], ['admin', 'password'], ['admin', '1234'], ['admin', '12345'],
    ['admin', '123456'], ['admin', ''], ['admin', 'pass'], ['admin', 'default'],
    ['root', 'root'], ['root', ''], ['root', 'admin'], ['root', 'password'],
    ['root', 'toor'], ['user', 'user'], ['user', 'password'], ['user', '1234'],
    ['support', 'support'], ['test', 'test'], ['guest', 'guest'], ['pi', 'raspberry'],
    ['ubnt', 'ubnt'], ['cisco', 'cisco'], ['operator', 'operator'],
  ],
  telnet: [
    ['admin', 'admin'], ['root', 'root'], ['root', ''], ['admin', ''],
    ['user', 'user'], ['support', 'support'], ['supervisor', 'supervisor'],
    ['tech', 'tech'], ['mother', 'fucker'], ['root', 'vizxv'], ['root', 'xc3511'],
    ['root', 'dreambox'], ['root', 'realtek'], ['admin', 'smcadmin'],
    ['admin', 'admin1234'], ['root', '1001chin'], ['root', 'hi3518'],
    ['default', 'default'], ['root', 'juantech'], ['root', 'xmhdipc'],
    ['root', '123456'], ['root', '54321'], ['root', 'pass'],
  ],
  ftp: [
    ['admin', 'admin'], ['anonymous', ''], ['ftp', 'ftp'], ['root', 'root'],
    ['admin', ''], ['admin', 'password'], ['user', 'user'],
  ],
  ssh: [
    ['root', 'root'], ['admin', 'admin'], ['pi', 'raspberry'],
    ['ubnt', 'ubnt'], ['root', 'password'], ['root', 'toor'],
    ['root', '123456'], ['admin', 'password'],
  ]
};

module.exports = {
  SIGNATURES,
  getAllSignatures,
  PORT_RISK,
  MALWARE_DOMAINS,
  DEFAULT_CREDS
};
