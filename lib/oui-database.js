/**
 * OUI (Organizationally Unique Identifier) Database
 * Maps MAC address prefixes to vendor names for device identification.
 * Covers common IoT, smart home, networking, and consumer device manufacturers.
 */

const OUI_DATABASE = {
  // Apple
  '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0A:27': 'Apple', '00:0A:95': 'Apple',
  '00:0D:93': 'Apple', '00:10:FA': 'Apple', '00:11:24': 'Apple', '00:14:51': 'Apple',
  '00:16:CB': 'Apple', '00:17:F2': 'Apple', '00:19:E3': 'Apple', '00:1B:63': 'Apple',
  '00:1C:B3': 'Apple', '00:1D:4F': 'Apple', '00:1E:52': 'Apple', '00:1E:C2': 'Apple',
  '00:1F:5B': 'Apple', '00:1F:F3': 'Apple', '00:21:E9': 'Apple', '00:22:41': 'Apple',
  '00:23:12': 'Apple', '00:23:32': 'Apple', '00:23:6C': 'Apple', '00:23:DF': 'Apple',
  '00:24:36': 'Apple', '00:25:00': 'Apple', '00:25:4B': 'Apple', '00:25:BC': 'Apple',
  '00:26:08': 'Apple', '00:26:4A': 'Apple', '00:26:B0': 'Apple', '00:26:BB': 'Apple',
  '00:C6:10': 'Apple', 'A8:20:66': 'Apple', 'AC:BC:32': 'Apple', 'D0:11:E5': 'Apple',
  
  // Amazon (Echo, Ring, Fire TV, etc.)
  '00:FC:8B': 'Amazon', '0C:47:C9': 'Amazon', '10:30:47': 'Amazon', '14:91:82': 'Amazon',
  '18:74:2E': 'Amazon', '24:4C:E3': 'Amazon', '34:D2:70': 'Amazon', '38:F7:3D': 'Amazon',
  '40:A2:DB': 'Amazon', '44:65:0D': 'Amazon', '4C:EF:C0': 'Amazon', '50:DC:E7': 'Amazon',
  '58:76:75': 'Amazon', '5C:41:5A': 'Amazon', '68:37:E9': 'Amazon', '68:54:FD': 'Amazon',
  '6C:56:97': 'Amazon', '74:C2:46': 'Amazon', '78:E1:03': 'Amazon', '84:D6:D0': 'Amazon',
  'A0:02:DC': 'Amazon', 'AC:63:BE': 'Amazon', 'B0:FC:0D': 'Amazon', 'B4:7C:9C': 'Amazon',
  'CC:F7:35': 'Amazon', 'F0:27:2D': 'Amazon', 'F0:F0:A4': 'Amazon', 'FC:65:DE': 'Amazon',
  
  // Google (Nest, Chromecast, Home)
  '00:1A:11': 'Google', '08:9E:08': 'Google', '1C:F2:9A': 'Google', '20:DF:B9': 'Google',
  '30:FD:38': 'Google', '3C:5A:B4': 'Google', '44:07:0B': 'Google', '48:D6:D5': 'Google',
  '54:60:09': 'Google', '58:CB:52': 'Google', '6C:AD:F8': 'Google', '78:4F:43': 'Google',
  '7C:2E:BD': 'Google', 'A4:77:33': 'Google', 'A4:E4:11': 'Google', 'D8:6C:63': 'Google',
  'E4:F0:42': 'Google', 'F4:F5:D8': 'Google', 'F4:F5:E8': 'Google',
  
  // Samsung
  '00:07:AB': 'Samsung', '00:0D:E5': 'Samsung', '00:12:47': 'Samsung', '00:12:FB': 'Samsung',
  '00:13:77': 'Samsung', '00:15:99': 'Samsung', '00:15:B9': 'Samsung', '00:16:32': 'Samsung',
  '00:16:6B': 'Samsung', '00:16:6C': 'Samsung', '00:17:C9': 'Samsung', '00:17:D5': 'Samsung',
  '00:18:AF': 'Samsung', '00:1A:8A': 'Samsung', '00:1B:98': 'Samsung', '00:1C:43': 'Samsung',
  '00:1D:25': 'Samsung', '00:1D:F6': 'Samsung', '00:1E:E1': 'Samsung', '00:1E:E2': 'Samsung',
  '00:1F:CC': 'Samsung', '00:1F:CD': 'Samsung', '00:21:19': 'Samsung', '00:21:D1': 'Samsung',
  '00:21:D2': 'Samsung', '00:23:39': 'Samsung', '00:23:3A': 'Samsung', '00:23:99': 'Samsung',
  '00:23:D6': 'Samsung', '00:23:D7': 'Samsung', '00:24:54': 'Samsung', '00:24:90': 'Samsung',
  '00:24:91': 'Samsung', '00:24:E9': 'Samsung', '00:25:66': 'Samsung', '00:25:67': 'Samsung',
  '00:26:37': 'Samsung', '00:26:5D': 'Samsung',
  
  // Espressif (ESP8266, ESP32 — very common in DIY IoT)
  '08:3A:F2': 'Espressif', '0C:DC:7E': 'Espressif', '10:52:1C': 'Espressif',
  '18:FE:34': 'Espressif', '24:0A:C4': 'Espressif', '24:62:AB': 'Espressif',
  '24:6F:28': 'Espressif', '24:B2:DE': 'Espressif', '2C:F4:32': 'Espressif',
  '30:AE:A4': 'Espressif', '3C:61:05': 'Espressif', '3C:71:BF': 'Espressif',
  '40:F5:20': 'Espressif', '48:3F:DA': 'Espressif', '4C:11:AE': 'Espressif',
  '4C:EB:D6': 'Espressif', '54:5A:A6': 'Espressif', '5C:CF:7F': 'Espressif',
  '60:01:94': 'Espressif', '68:C6:3A': 'Espressif', '7C:9E:BD': 'Espressif',
  '80:7D:3A': 'Espressif', '84:0D:8E': 'Espressif', '84:CC:A8': 'Espressif',
  '84:F3:EB': 'Espressif', '8C:AA:B5': 'Espressif', '90:97:D5': 'Espressif',
  '94:B5:55': 'Espressif', '94:B9:7E': 'Espressif', '98:CD:AC': 'Espressif',
  'A0:20:A6': 'Espressif', 'A4:7B:9D': 'Espressif', 'A4:CF:12': 'Espressif',
  'AC:67:B2': 'Espressif', 'B4:E6:2D': 'Espressif', 'BC:DD:C2': 'Espressif',
  'C4:4F:33': 'Espressif', 'C4:5B:BE': 'Espressif', 'CC:50:E3': 'Espressif',
  'D8:A0:1D': 'Espressif', 'D8:BF:C0': 'Espressif', 'DC:4F:22': 'Espressif',
  'E0:98:06': 'Espressif', 'E8:DB:84': 'Espressif', 'EC:FA:BC': 'Espressif',
  'F0:08:D1': 'Espressif', 'F4:CF:A2': 'Espressif',
  
  // Tuya (Smart home IoT platform)
  '10:D5:61': 'Tuya', '44:23:7C': 'Tuya', '50:02:91': 'Tuya', '60:01:94': 'Tuya',
  '68:57:2D': 'Tuya', '7C:F6:66': 'Tuya', 'D4:A6:51': 'Tuya', 'D8:1F:12': 'Tuya',
  
  // TP-Link
  '00:23:CD': 'TP-Link', '00:27:19': 'TP-Link', '00:31:92': 'TP-Link',
  '10:FE:ED': 'TP-Link', '14:CC:20': 'TP-Link', '14:CF:92': 'TP-Link',
  '18:A6:F7': 'TP-Link', '1C:3B:F3': 'TP-Link', '24:69:68': 'TP-Link',
  '30:B5:C2': 'TP-Link', '34:E8:94': 'TP-Link', '48:22:54': 'TP-Link',
  '50:C7:BF': 'TP-Link', '54:C8:0F': 'TP-Link', '5C:A6:E6': 'TP-Link',
  '60:32:B1': 'TP-Link', '64:56:01': 'TP-Link', '64:70:02': 'TP-Link',
  '6C:5A:B0': 'TP-Link', '78:8C:B5': 'TP-Link', '84:16:F9': 'TP-Link',
  '90:F6:52': 'TP-Link', '98:DA:C4': 'TP-Link', 'A0:F3:C1': 'TP-Link',
  'AC:84:C6': 'TP-Link', 'B0:95:75': 'TP-Link', 'B0:BE:76': 'TP-Link',
  'B4:B0:24': 'TP-Link', 'C0:06:C3': 'TP-Link', 'C0:25:E9': 'TP-Link',
  'C0:4A:00': 'TP-Link', 'C4:E9:84': 'TP-Link', 'CC:32:E5': 'TP-Link',
  'D4:6E:0E': 'TP-Link', 'D8:07:B6': 'TP-Link', 'E4:C3:2A': 'TP-Link',
  'E8:DE:27': 'TP-Link', 'EC:08:6B': 'TP-Link', 'F4:F2:6D': 'TP-Link',
  'F8:D1:11': 'TP-Link',
  
  // Netgear
  '00:09:5B': 'Netgear', '00:0F:B5': 'Netgear', '00:14:6C': 'Netgear',
  '00:1B:2F': 'Netgear', '00:1E:2A': 'Netgear', '00:1F:33': 'Netgear',
  '00:22:3F': 'Netgear', '00:24:B2': 'Netgear', '00:26:F2': 'Netgear',
  '04:A1:51': 'Netgear', '08:02:8E': 'Netgear', '08:BD:43': 'Netgear',
  '10:0D:7F': 'Netgear', '10:DA:43': 'Netgear', '20:0C:C8': 'Netgear',
  '28:80:88': 'Netgear', '2C:B0:5D': 'Netgear', '30:46:9A': 'Netgear',
  
  // Roku
  '00:0D:4B': 'Roku', '08:05:81': 'Roku', '10:59:32': 'Roku',
  'AC:3A:7A': 'Roku', 'B0:A7:37': 'Roku', 'B8:3E:59': 'Roku',
  'C8:3A:6B': 'Roku', 'D4:E2:2F': 'Roku', 'D8:31:34': 'Roku',
  'DC:3A:5E': 'Roku',
  
  // Sonos
  '00:0E:58': 'Sonos', '09:17:62': 'Sonos', '34:7E:5C': 'Sonos',
  '48:A6:B8': 'Sonos', '54:2A:1B': 'Sonos', '5C:AA:FD': 'Sonos',
  '78:28:CA': 'Sonos', '94:9F:3E': 'Sonos', 'B8:E9:37': 'Sonos',
  
  // Philips (Hue, etc.)
  '00:17:88': 'Philips Hue', '00:1F:E1': 'Philips', 'EC:B5:FA': 'Philips Hue',
  
  // Ring (Amazon)
  '24:43:E2': 'Ring', '34:3E:A4': 'Ring', '44:73:D6': 'Ring',
  '4C:EB:BD': 'Ring', '50:14:79': 'Ring', '8C:FC:A0': 'Ring',
  
  // Xiaomi
  '00:9E:C8': 'Xiaomi', '04:CF:8C': 'Xiaomi', '0C:1D:AF': 'Xiaomi',
  '10:2A:B3': 'Xiaomi', '14:F6:5A': 'Xiaomi', '18:59:36': 'Xiaomi',
  '20:47:DA': 'Xiaomi', '28:6C:07': 'Xiaomi', '28:E3:1F': 'Xiaomi',
  '34:80:B3': 'Xiaomi', '38:A4:ED': 'Xiaomi', '3C:BD:3E': 'Xiaomi',
  '44:23:7C': 'Xiaomi', '50:64:2B': 'Xiaomi', '58:44:98': 'Xiaomi',
  '5C:B1:3E': 'Xiaomi', '64:09:80': 'Xiaomi', '64:B4:73': 'Xiaomi',
  '68:DF:DD': 'Xiaomi', '74:23:44': 'Xiaomi', '78:02:F8': 'Xiaomi',
  '78:11:DC': 'Xiaomi', '7C:1D:D9': 'Xiaomi', '84:F3:EB': 'Xiaomi',
  '8C:DE:52': 'Xiaomi', '98:FA:E3': 'Xiaomi', 'AC:C1:EE': 'Xiaomi',
  'B0:D5:9D': 'Xiaomi', 'C4:0B:CB': 'Xiaomi', 'C4:6A:B7': 'Xiaomi',
  'D4:97:0B': 'Xiaomi', 'E4:46:DA': 'Xiaomi', 'F0:B4:29': 'Xiaomi',
  'F8:A4:5F': 'Xiaomi', 'FC:64:BA': 'Xiaomi',
  
  // Intel
  '00:02:B3': 'Intel', '00:03:47': 'Intel', '00:04:23': 'Intel',
  '00:07:E9': 'Intel', '00:0C:F1': 'Intel', '00:0E:0C': 'Intel',
  '00:0E:35': 'Intel', '00:11:11': 'Intel', '00:12:F0': 'Intel',
  '00:13:02': 'Intel', '00:13:20': 'Intel', '00:13:CE': 'Intel',
  '00:13:E8': 'Intel', '00:15:00': 'Intel', '00:15:17': 'Intel',
  '00:16:6F': 'Intel', '00:16:76': 'Intel', '00:16:EA': 'Intel',
  '00:16:EB': 'Intel', '00:18:DE': 'Intel', '00:19:D1': 'Intel',
  '00:19:D2': 'Intel', '00:1B:21': 'Intel', '00:1B:77': 'Intel',
  '00:1C:BF': 'Intel', '00:1C:C0': 'Intel', '00:1D:E0': 'Intel',
  '00:1D:E1': 'Intel', '00:1E:64': 'Intel', '00:1E:65': 'Intel',
  '00:1F:3B': 'Intel', '00:1F:3C': 'Intel', '00:20:7B': 'Intel',
  '00:21:5C': 'Intel', '00:21:5D': 'Intel', '00:21:6A': 'Intel',
  '00:21:6B': 'Intel', '00:22:FA': 'Intel', '00:22:FB': 'Intel',
  '00:23:14': 'Intel', '00:23:15': 'Intel', '00:24:D6': 'Intel',
  '00:24:D7': 'Intel',
  
  // Microsoft (Xbox, Surface)
  '00:50:F2': 'Microsoft', '28:18:78': 'Microsoft', '58:82:A8': 'Microsoft',
  '60:45:BD': 'Microsoft', '7C:1E:52': 'Microsoft', '7C:ED:8D': 'Microsoft',
  'B4:0E:DE': 'Microsoft', 'C8:3F:26': 'Microsoft', 'D4:3D:7E': 'Microsoft',
  
  // Sony (PlayStation)
  '00:04:1F': 'Sony', '00:13:A9': 'Sony', '00:15:C1': 'Sony',
  '00:19:63': 'Sony', '00:1D:0D': 'Sony', '00:1F:A7': 'Sony',
  '00:24:8D': 'Sony', '28:0D:FC': 'Sony', '2C:CC:44': 'Sony',
  '40:B8:37': 'Sony', '78:C8:81': 'Sony', 'A8:E3:EE': 'Sony',
  'BC:60:A7': 'Sony', 'C8:63:F1': 'Sony', 'F8:46:1C': 'Sony',
  'FC:0F:E6': 'Sony',
  
  // Nintendo
  '00:09:BF': 'Nintendo', '00:16:56': 'Nintendo', '00:17:AB': 'Nintendo',
  '00:19:1D': 'Nintendo', '00:19:FD': 'Nintendo', '00:1A:E9': 'Nintendo',
  '00:1B:EA': 'Nintendo', '00:1C:BE': 'Nintendo', '00:1D:BC': 'Nintendo',
  '00:1E:35': 'Nintendo', '00:1F:32': 'Nintendo', '00:1F:C5': 'Nintendo',
  '00:21:47': 'Nintendo', '00:21:BD': 'Nintendo', '00:22:4C': 'Nintendo',
  '00:22:AA': 'Nintendo', '00:22:D7': 'Nintendo', '00:23:31': 'Nintendo',
  '00:23:CC': 'Nintendo', '00:24:1E': 'Nintendo', '00:24:44': 'Nintendo',
  '00:24:F3': 'Nintendo', '00:25:A0': 'Nintendo', '00:26:59': 'Nintendo',
  '00:27:09': 'Nintendo', '2C:10:C1': 'Nintendo', '34:AF:2C': 'Nintendo',
  '40:D2:8A': 'Nintendo', '58:BD:A3': 'Nintendo', '5C:52:1E': 'Nintendo',
  '7C:BB:8A': 'Nintendo', '8C:CD:E8': 'Nintendo', '98:41:5C': 'Nintendo',
  '98:B6:E9': 'Nintendo', 'A4:5C:27': 'Nintendo', 'A4:C0:E1': 'Nintendo',
  'B8:AE:6E': 'Nintendo', 'CC:FB:65': 'Nintendo', 'D8:6B:F7': 'Nintendo',
  'DC:68:EB': 'Nintendo', 'E0:0C:7F': 'Nintendo', 'E0:E7:51': 'Nintendo',
  'E8:4E:CE': 'Nintendo',
  
  // Raspberry Pi Foundation
  'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi', 'E4:5F:01': 'Raspberry Pi',
  '28:CD:C1': 'Raspberry Pi', 'D8:3A:DD': 'Raspberry Pi',
  
  // Wyze
  '2C:AA:8E': 'Wyze', '7C:78:B2': 'Wyze',
  
  // Wemo (Belkin)
  '08:86:3B': 'Belkin/Wemo', '24:F5:A2': 'Belkin/Wemo', '30:23:03': 'Belkin/Wemo',
  '44:94:FC': 'Belkin/Wemo', '58:EF:68': 'Belkin/Wemo', '94:10:3E': 'Belkin/Wemo',
  'B4:75:0E': 'Belkin/Wemo', 'C0:56:27': 'Belkin/Wemo', 'EC:1A:59': 'Belkin/Wemo',
  
  // Ubiquiti
  '00:15:6D': 'Ubiquiti', '00:27:22': 'Ubiquiti', '04:18:D6': 'Ubiquiti',
  '18:E8:29': 'Ubiquiti', '24:5A:4C': 'Ubiquiti', '44:D9:E7': 'Ubiquiti',
  '68:72:51': 'Ubiquiti', '78:45:58': 'Ubiquiti', '78:8A:20': 'Ubiquiti',
  '80:2A:A8': 'Ubiquiti', 'AC:8B:A9': 'Ubiquiti', 'B4:FB:E4': 'Ubiquiti',
  'D0:21:F9': 'Ubiquiti', 'DC:9F:DB': 'Ubiquiti', 'E0:63:DA': 'Ubiquiti',
  'F0:9F:C2': 'Ubiquiti', 'FC:EC:DA': 'Ubiquiti',
  
  // ASUS
  '00:0C:6E': 'ASUS', '00:0E:A6': 'ASUS', '00:11:2F': 'ASUS',
  '00:11:D8': 'ASUS', '00:13:D4': 'ASUS', '00:15:F2': 'ASUS',
  '00:17:31': 'ASUS', '00:18:F3': 'ASUS', '00:1A:92': 'ASUS',
  '00:1B:FC': 'ASUS', '00:1D:60': 'ASUS', '00:1E:8C': 'ASUS',
  '00:1F:C6': 'ASUS', '00:22:15': 'ASUS', '00:23:54': 'ASUS',
  '00:24:8C': 'ASUS', '00:25:22': 'ASUS', '00:26:18': 'ASUS',
  '04:92:26': 'ASUS', '08:60:6E': 'ASUS', '0C:9D:92': 'ASUS',
  '10:7B:44': 'ASUS', '10:BF:48': 'ASUS', '14:DD:A9': 'ASUS',
  '1C:87:2C': 'ASUS', '2C:4D:54': 'ASUS', '2C:56:DC': 'ASUS',
  '2C:FD:A1': 'ASUS', '30:85:A9': 'ASUS', '30:B5:C2': 'ASUS',
  
  // Linksys
  '00:04:5A': 'Linksys', '00:06:25': 'Linksys', '00:0C:41': 'Linksys',
  '00:0F:66': 'Linksys', '00:12:17': 'Linksys', '00:14:BF': 'Linksys',
  '00:16:B6': 'Linksys', '00:18:39': 'Linksys', '00:18:F8': 'Linksys',
  '00:1A:70': 'Linksys', '00:1C:10': 'Linksys', '00:1D:7E': 'Linksys',
  '00:1E:E5': 'Linksys', '00:21:29': 'Linksys', '00:22:6B': 'Linksys',
  '00:23:69': 'Linksys', '00:25:9C': 'Linksys',
  
  // HP
  '00:01:E6': 'HP', '00:01:E7': 'HP', '00:02:A5': 'HP',
  '00:04:EA': 'HP', '00:08:02': 'HP', '00:08:83': 'HP',
  '00:0A:57': 'HP', '00:0B:CD': 'HP', '00:0D:9D': 'HP',
  '00:0E:7F': 'HP', '00:0F:20': 'HP', '00:0F:61': 'HP',
  '00:10:83': 'HP', '00:10:E3': 'HP', '00:11:0A': 'HP',
  '00:11:85': 'HP', '00:12:79': 'HP', '00:13:21': 'HP',
  '00:14:38': 'HP', '00:14:C2': 'HP', '00:15:60': 'HP',
  '00:16:35': 'HP', '00:17:08': 'HP', '00:17:A4': 'HP',
  '00:18:71': 'HP', '00:18:FE': 'HP', '00:19:BB': 'HP',
  '00:1A:4B': 'HP', '00:1B:78': 'HP', '00:1C:C4': 'HP',
  '00:1E:0B': 'HP', '00:1F:29': 'HP', '00:1F:FE': 'HP',
  '00:21:5A': 'HP', '00:22:64': 'HP', '00:23:7D': 'HP',
  '00:24:81': 'HP', '00:25:B3': 'HP',
  
  // Dell
  '00:06:5B': 'Dell', '00:08:74': 'Dell', '00:0B:DB': 'Dell',
  '00:0D:56': 'Dell', '00:0F:1F': 'Dell', '00:11:43': 'Dell',
  '00:12:3F': 'Dell', '00:13:72': 'Dell', '00:14:22': 'Dell',
  '00:15:C5': 'Dell', '00:16:F0': 'Dell', '00:18:8B': 'Dell',
  '00:19:B9': 'Dell', '00:1A:A0': 'Dell', '00:1C:23': 'Dell',
  '00:1D:09': 'Dell', '00:1E:4F': 'Dell', '00:1E:C9': 'Dell',
  '00:1F:3E': 'Dell', '00:21:70': 'Dell', '00:21:9B': 'Dell',
  '00:22:19': 'Dell', '00:23:AE': 'Dell', '00:24:E8': 'Dell',
  '00:25:64': 'Dell', '00:26:B9': 'Dell',
  
  // Huawei
  '00:1E:10': 'Huawei', '00:18:82': 'Huawei', '00:25:9E': 'Huawei',
  '00:25:68': 'Huawei', '00:46:4B': 'Huawei', '04:02:1F': 'Huawei',
  '04:BD:70': 'Huawei', '04:C0:6F': 'Huawei', '04:F9:38': 'Huawei',
  '08:19:A6': 'Huawei', '08:63:61': 'Huawei', '0C:37:DC': 'Huawei',
  '0C:96:BF': 'Huawei', '10:44:00': 'Huawei', '10:47:80': 'Huawei',
  '14:B9:68': 'Huawei', '20:08:ED': 'Huawei', '20:0B:C7': 'Huawei',
  '20:A6:80': 'Huawei', '24:09:95': 'Huawei', '24:44:27': 'Huawei',
  '28:3C:E4': 'Huawei', '28:6E:D4': 'Huawei',
  
  // LG
  '00:1C:62': 'LG', '00:1E:75': 'LG', '00:1F:6B': 'LG',
  '00:1F:E3': 'LG', '00:21:FB': 'LG', '00:22:A9': 'LG',
  '00:24:83': 'LG', '00:25:E5': 'LG', '00:26:E2': 'LG',
  '10:68:3F': 'LG', '10:F9:6F': 'LG', '14:C9:13': 'LG',
  '20:3D:BD': 'LG', '28:83:35': 'LG', '2C:54:CF': 'LG',
  '30:76:6F': 'LG', '34:4D:F7': 'LG', '38:8C:50': 'LG',
  
  // D-Link
  '00:05:5D': 'D-Link', '00:0D:88': 'D-Link', '00:0F:3D': 'D-Link',
  '00:11:95': 'D-Link', '00:13:46': 'D-Link', '00:15:E9': 'D-Link',
  '00:17:9A': 'D-Link', '00:19:5B': 'D-Link', '00:1B:11': 'D-Link',
  '00:1C:F0': 'D-Link', '00:1E:58': 'D-Link', '00:1F:48': 'D-Link',
  '00:21:91': 'D-Link', '00:22:B0': 'D-Link', '00:24:01': 'D-Link',
  '00:26:5A': 'D-Link',
  
  // Nest Labs (Google)
  '18:B4:30': 'Nest', '64:16:66': 'Nest',
  
  // ecobee
  '44:61:32': 'ecobee',
  
  // iRobot (Roomba)
  '50:14:79': 'iRobot',
  
  // Honeywell
  '00:D0:2D': 'Honeywell', '4C:C9:5E': 'Honeywell',
  
  // Chamberlain / MyQ
  '00:1D:C9': 'Chamberlain/MyQ',
  
  // August (Smart Lock)
  '78:3A:84': 'August Smart Lock',
  
  // Logitech
  '00:04:20': 'Logitech', '00:1F:20': 'Logitech',
  '38:C9:86': 'Logitech', '44:19:B6': 'Logitech',
  '64:4B:F0': 'Logitech', 'B4:7C:9C': 'Logitech',
  'C0:28:8D': 'Logitech',
  
  // Bose
  '04:52:C7': 'Bose', '08:DF:1F': 'Bose', '2C:41:A1': 'Bose',
  '4C:87:5D': 'Bose', '88:C6:26': 'Bose', 'D8:8A:3B': 'Bose',
};

/**
 * Look up vendor by MAC address
 * @param {string} mac - MAC address in any common format (XX:XX:XX:XX:XX:XX or xx-xx-xx-xx-xx-xx)
 * @returns {string} Vendor name or 'Unknown'
 */
function lookupVendor(mac) {
  if (!mac) return 'Unknown';
  
  // Normalize MAC address format to XX:XX:XX
  const normalized = mac
    .toUpperCase()
    .replace(/[.-]/g, ':')
    .substring(0, 8);
  
  return OUI_DATABASE[normalized] || 'Unknown';
}

/**
 * Identify device type based on vendor and hostname
 * @param {string} vendor - Vendor name
 * @param {string} hostname - Device hostname
 * @returns {{ type: string, icon: string }}
 */
function identifyDeviceType(vendor, hostname) {
  const v = (vendor || '').toLowerCase();
  const h = (hostname || '').toLowerCase();
  
  // Router/Gateway
  if (h.includes('gateway') || h.includes('router') || h.includes('modem') ||
      v.includes('netgear') || v.includes('linksys') || v.includes('d-link') ||
      v.includes('asus') && (h.includes('rt-') || h.includes('router')) ||
      v.includes('ubiquiti') || v.includes('tp-link') && h.includes('router')) {
    return { type: 'Router', icon: '📡' };
  }
  
  // Smart Speaker / Voice Assistant
  if (h.includes('echo') || h.includes('alexa') || h.includes('google-home') ||
      h.includes('homepod') || v.includes('sonos') || v.includes('bose') ||
      (v.includes('amazon') && h.includes('echo'))) {
    return { type: 'Smart Speaker', icon: '🔊' };
  }
  
  // Camera / Security
  if (h.includes('camera') || h.includes('cam') || v.includes('ring') ||
      v.includes('wyze') || h.includes('doorbell') || v.includes('nest') && h.includes('cam')) {
    return { type: 'Camera', icon: '📷' };
  }
  
  // Smart Home / IoT Hub
  if (v.includes('philips hue') || v.includes('tuya') || v.includes('belkin') ||
      v.includes('wemo') || v.includes('ecobee') || v.includes('honeywell') ||
      v.includes('august') || v.includes('chamberlain') || h.includes('hub') ||
      h.includes('bridge') || h.includes('smart')) {
    return { type: 'Smart Home', icon: '🏠' };
  }
  
  // IoT / Embedded
  if (v.includes('espressif') || v.includes('raspberry pi') || v.includes('tuya') ||
      v.includes('irobot') || h.includes('esp') || h.includes('tasmota') ||
      h.includes('shelly') || h.includes('iot')) {
    return { type: 'IoT Device', icon: '🔌' };
  }
  
  // Gaming Console
  if (v.includes('nintendo') || v.includes('sony') && (h.includes('ps') || h.includes('playstation')) ||
      v.includes('microsoft') && (h.includes('xbox'))) {
    return { type: 'Gaming Console', icon: '🎮' };
  }
  
  // TV / Streaming
  if (v.includes('roku') || h.includes('roku') || h.includes('firetv') ||
      h.includes('chromecast') || v.includes('lg') && h.includes('tv') ||
      v.includes('samsung') && h.includes('tv') || h.includes('appletv') ||
      h.includes('fire-tv') || h.includes('smart-tv')) {
    return { type: 'TV/Streaming', icon: '📺' };
  }
  
  // Phone/Tablet
  if (h.includes('iphone') || h.includes('ipad') || h.includes('android') ||
      h.includes('galaxy') || h.includes('pixel') || h.includes('phone')) {
    return { type: 'Phone/Tablet', icon: '📱' };
  }
  
  // Computer
  if (v.includes('apple') || v.includes('intel') || v.includes('dell') ||
      v.includes('hp') || v.includes('microsoft') || v.includes('lenovo') ||
      h.includes('macbook') || h.includes('imac') || h.includes('desktop') ||
      h.includes('laptop') || h.includes('pc')) {
    return { type: 'Computer', icon: '💻' };
  }
  
  // Printer
  if (h.includes('printer') || h.includes('print') || v.includes('hp') && h.includes('print') ||
      h.includes('epson') || h.includes('canon') || h.includes('brother')) {
    return { type: 'Printer', icon: '🖨️' };
  }
  
  // Access Point / Networking
  if (v.includes('tp-link') || v.includes('ubiquiti') || v.includes('netgear') ||
      v.includes('asus') || v.includes('d-link') || v.includes('linksys') ||
      h.includes('ap') || h.includes('switch') || h.includes('extender')) {
    return { type: 'Network Device', icon: '🌐' };
  }
  
  return { type: 'Unknown', icon: '❓' };
}

module.exports = { lookupVendor, identifyDeviceType, OUI_DATABASE };
