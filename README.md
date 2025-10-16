# Bug Host Tool – Safe Port Checker (LAN)

Web UI + Node.js server to check if TCP ports are open on hosts inside your LAN.

⚠️ **Note:** Only use this tool on networks/devices you own or have explicit permission.

---

## Features
- Check single TCP port (host + port)
- Scan a port range
- LAN allowlist (default: 127.0.0.1, localhost, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- API key protection
- Simple HTML UI

---

## Installation
1. Install [Node.js](https://nodejs.org/) (>= 18)
2. Clone or download this repository
3. Install dependencies:
   ```bash
   npm install
