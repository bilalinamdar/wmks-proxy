# wmks-proxy

Simple WebMKS proxy for vCenter guest VM console access in Go.

- Lists powered-on VMs (newest first) and opens their **HTML5 WebMKS** console  
- Proxies the console **WebSocket** to the correct ESXi host using a vSphere **ticket**  
- Console header shows **vCenter**, **ESXi host**, and **ticket id**

> Version: **v1.1** • Repo: [github.com/bilalinamdar/wmks-proxy](https://github.com/bilalinamdar/wmks-proxy)

---

## Features

- 🚀 Fast VM list (single vSphere round-trip), newest first  
- 🖥️ WebMKS console with **Ctrl+Alt+Delete** and **Fullscreen**  
- 🎟️ Ticket→ESXi mapping with TTL to avoid stale ticket errors  
- 🔐 Security headers (CSP) tuned for VMware’s `wmks.min.js`  
- ⚙️ Configuration via **environment variables** and `-listen` flag  
- 🐳 Runs standalone (HTTP) or in Docker; use **Nginx/Caddy** for SSL/domain/SSO/rate limits  

---

## Requirements

- vCenter reachable from this proxy host; ESXi hosts reachable on **HTTPS 443**  
- **Name resolution is critical** (on the proxy host/container):
  - the **vCenter FQDN**, and  
  - **every ESXi hostname** returned in WebMKS tickets  

Linux `/etc/hosts` example:
```
10.10.10.5   vc.example.local
10.10.20.11  esx01.lab.local
10.10.20.12  esx02.lab.local
```

> Browsers only connect to this proxy; they **do not** talk to ESXi directly.

---

## Quick Start

### A) Standalone (binary)

1. **Set env first** (export or create `.env` as below)
2. Build & run:
   ```bash
   go mod download && go build -o webmks-proxy .
   ./webmks-proxy -listen :8081
   ```
3. Open: `http://<host>:8081/`

---

### B) Docker

1. **Set env first** (export with `-e` or create a Compose `.env` with `VCENTER_*`)
2. Build & run (pick one):

**Docker Compose**
```bash
docker compose up -d
```

> Put SSL/domain/SSO/rate limits in **Nginx/Caddy** in front of this app;  
> allow WebSocket upgrade and long timeouts for `/ticket/*`.



## Configuration

### Flags

```
-listen ADDRESS   Bind address/port (default ":8081")
--help            Show help and exit
--version         Show version and exit
```

### Environment variables (preferred: `VCENTER_*`)

| Variable             | Description                                          | Example                        |
|----------------------|------------------------------------------------------|--------------------------------|
| `VCENTER_URL`        | vCenter URL (scheme optional; https assumed)         | `https://vc.example.local`     |
| `VCENTER_USER`       | vCenter username                                     | `administrator@vsphere.local`  |
| `VCENTER_PASS`       | vCenter password                                     | `CHANGE_ME`                    |
| `VCENTER_LISTEN`     | Bind addr/port if `-listen` not given                | `:8081`                        |
| `VCENTER_SECURE_TLS` | `true/false` verify ESXi TLS certs (default `false`) | `true`                         |

**Precedence (high → low):** CLI `-listen` → `VCENTER_*` → `VMWARE_*` / `WEBMKS_*` → legacy (`VCENTER`, `VMRC_USER`, etc.) → `.env`

---

### `.env` example

```dotenv
VCENTER_URL=vc.example.local
VCENTER_USER=administrator@vsphere.local
VCENTER_PASS=CHANGE_ME
VCENTER_LISTEN=:8081
VCENTER_SECURE_TLS=false
```

---

## Optional Edge Proxy (SSL/domain)

Terminate TLS and add domain/SSO/rate limits/timeouts in **Nginx/Caddy**, and proxy to this app.  
Ensure **WebSocket Upgrade** and long read timeouts for `/ticket/*`.

**Nginx (skeleton):**

```nginx
location / {
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_set_header Host $host;
  proxy_read_timeout 3600s;
  proxy_send_timeout 3600s;
  proxy_buffering off;
  proxy_pass http://127.0.0.1:8081;
}
```

---

## Troubleshooting

- **Console won’t open** → DNS/hosts for all **ESXi hostnames** on the proxy/container.  
- **`unsupported protocol scheme ""`** → ticket expired/unknown; reload console (tickets are short-lived).  
- **CAD disabled** → enables once WMKS is `CONNECTED`; check WS upgrade in devtools.  

---

## Credits

- Based on / inspired by: [VMWare HTML Console (webmks) Proxy – miles-to-go](https://github.com/miles-to-go/webmks_proxy)  
- Uses VMware **govmomi** and WebMKS bundles  

---

## Author & Contact

- **Creator:** Bilal Inamdar  
- **Email:** [bilalinamdar@gmail.com](mailto:bilalinamdar@gmail.com)  
- **Project Home:** [github.com/bilalinamdar/wmks-proxy](https://github.com/bilalinamdar/wmks-proxy)  

---

## License

Unlicensed
