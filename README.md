<p align="center">
  <a href="https://aegis.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/aegis-logo-dark.png">
      <source media="(prefers-color-scheme: light)" srcset="docs/images/aegis-logo-light.png">
      <img src="docs/images/aegis-logo-light.png" alt="Aegis Logo" width="180">
    </picture>
  </a>
</p>

<h1 align="center">Aegis Community Edition</h1>

<p align="center">
  <strong>Open-Source Web Application Firewall & Edge Security Gateway</strong><br>
  High-performance reverse proxy delivering real-time OWASP CRS threat defense, Layer 7 rate limiting, and dynamic zero-downtime policy control.
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#key-capabilities">Key Capabilities</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#web-console">Web Console</a> •
  <a href="#license">License</a>
</p>

---

<p align="center">
  <img src="docs/images/aegis-hero.png" alt="Aegis — Edge Web Application Firewall" width="100%">
</p>

---

## Overview

Aegis is an open-source, high-performance Web Application Firewall and reverse proxy designed to protect web applications, APIs, and microservices at the network edge. Positioned in front of your upstream services, Aegis inspects incoming HTTP and HTTPS traffic in real time, stopping cyber attacks, malicious bots, and abusive traffic surges before they can reach your backend infrastructure.

All routing rules, firewall policies, rate limits, and SSL certificates are managed dynamically through an integrated web console with zero downtime and no configuration restarts.

---

## Key Capabilities

### Application Firewall

- **OWASP Core Rule Set (CRS) Defense:** Native integration with the OWASP Core Rule Set (CRS) protecting against OWASP Top 10 web threats including SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), SSRF, and unauthorized path traversal.
- **Intelligent Anomaly Scoring:** Evaluates cumulative threat scores across CRS rule matches before taking blocking actions, drastically reducing false positives on legitimate customer traffic.
- **Flexible Inspection Modes:** Tailor protection levels and CRS paranoia levels from baseline monitoring for public web services to strict blocking for critical APIs and payment gateways.
- **Custom Rules & Whitelisting:** Quickly define exceptions, whitelist trusted traffic, and create custom security policies to support unique business requirements.

### Traffic Control & Anti-Abuse

- **Rate Limiting & Anti-Scraping:** Throttles abusive requests to safeguard authentication endpoints, checkout flows, and APIs against automated credential stuffing and scraping.
- **IP Access Control:** Block malicious actors or whitelist partner networks using individual IP addresses or network ranges with immediate policy enforcement.
- **Geo-Blocking:** Allow or deny traffic based on geographic origin to protect applications against unwanted regional traffic or meet regional compliance needs.
- **Connection Protection:** Enforce connection thresholds and timeouts to defend backend infrastructure against volumetric surges and denial-of-service attempts.

### HTTP Hardening & Server Protection

- **Protocol Enforcement:** Restrict acceptable HTTP methods and immediately reject unauthorized or malformed requests before they reach origin servers.
- **Request Size & Payload Limits:** Safeguard backend services against memory exhaustion and buffer attacks by enforcing strict boundaries on headers and payloads.
- **File Upload Protection:** Intercepts multipart uploads and automatically blocks dangerous executable files before they reach file storage or processing pipelines.
- **Automated Security Headers:** Automatically injects enterprise-grade browser protection headers including HSTS, Content Security Policy (CSP), and X-Frame-Options to prevent clickjacking and data injection.
- **Infrastructure Cloaking:** Masks backend server banners, software versions, and internal infrastructure headers to prevent attacker reconnaissance.

### Automated SSL/TLS

- **Automated Certificate Management:** Integrates seamlessly with Let's Encrypt to provision, validate, and auto-renew TLS certificates with zero manual oversight or downtime.
- **Enterprise Certificate Management:** Full support for custom enterprise certificates, wildcard domains, and multi-domain SNI routing for complex environments.
- **Strict Cryptographic Standards:** Enforces modern TLS 1.2 and TLS 1.3 standards with Perfect Forward Secrecy, automatically disabling obsolete protocols and weak ciphers.

### Reverse Proxy & Load Balancing

- **High-Performance Ingress:** Native edge gateway supporting HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) for accelerated content delivery and modern client compatibility.
- **Dynamic Route Management:** Direct traffic based on hostnames, path rules, and request attributes with deterministic priority matching.
- **Load Balancing & High Availability:** Distribute traffic across upstream server clusters with continuous active health monitoring and automatic failover away from unhealthy nodes.

### Management & Monitoring

- **Centralized Operations Console:** Full-featured web management interface providing real-time visibility into traffic trends, threat activity, and instant policy tuning.
- **Enterprise Access Security:** Multi-factor authentication (2FA/TOTP) and isolated management interface binding to keep administrative controls secure from external networks.
- **Monitoring & Observability:** Real-time traffic analytics, threat inspection logs, and centralized telemetry for operational visibility and security reporting.
- **Enterprise Scalability:** High-throughput architecture built for demanding production traffic, delivering deep packet inspection with sub-millisecond overhead.

---

## Quick Start <a id="installation"></a>

### Quick Install

Clone the repository and run the installation script:

```bash
git clone https://github.com/divinelabio/aegis.git
cd aegis
sudo bash install.sh
```

Verify service status:

```bash
sudo systemctl status aegis
```

### Docker

Deploy Aegis container with persistent storage and admin access:

```bash
docker run -d --name aegis_server \
  --restart unless-stopped \
  -p 8080:8080 -p 8081:8081 \
  -v aegis_data:/var/lib/aegis/data \
  -e AEGIS_ADMIN_PASSWORD="ChooseStrongAdminPassword123!" \
  ghcr.io/divinelabio/aegis:latest
```

### Docker Compose

Deploy with persistent storage and dedicated control plane access:

```yaml
version: '3.8'

services:
  aegis:
    image: ghcr.io/divinelabio/aegis:latest
    container_name: aegis_server
    restart: unless-stopped
    ports:
      - "8080:8080" # Ingress Traffic & WAF Proxy
      - "8081:8081" # Web Admin Console & Control API
    environment:
      AEGIS_ADMIN_PASSWORD: ${AEGIS_ADMIN_PASSWORD:-admin}
    volumes:
      - aegis_data:/var/lib/aegis/data

volumes:
  aegis_data:
```

Start the container stack:

```bash
docker compose up -d
```

### Standalone Binary

Download pre-compiled release packages for Linux, macOS, or Windows from the [Releases](https://github.com/divinelabio/aegis/releases) page:

```bash
# Example for Linux x86_64
curl -sSL https://github.com/divinelabio/aegis/releases/latest/download/aegis-linux-amd64.tar.gz | tar -xz
sudo mv aegis-server /usr/local/bin/

# Start Aegis service
aegis-server
```

---

## Web Console

<table width="100%" cellpadding="6">
  <tr>
    <td width="50%" align="center">
      <br>
      <a href="docs/images/aegis-dashboard.png">
        <img src="docs/images/aegis-dashboard.png" alt="Aegis Security Operations Dashboard" width="96%">
      </a>
      <br><br>
    </td>
    <td width="50%" align="center">
      <br>
      <a href="docs/images/waf-rulesets-dashboard.png">
        <img src="docs/images/waf-rulesets-dashboard.png" alt="Aegis Managed Rulesets" width="96%">
      </a>
      <br><br>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <br>
      <a href="docs/images/waf-dashboard.png">
        <img src="docs/images/waf-dashboard.png" alt="Aegis Application Firewall Overview" width="96%">
      </a>
      <br><br>
    </td>
    <td width="50%" align="center">
      <br>
      <a href="docs/images/geo-blocking-dashboard.png">
        <img src="docs/images/geo-blocking-dashboard.png" alt="Aegis Geo-Blocking Traffic Control" width="96%">
      </a>
      <br><br>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <br>
      <a href="docs/images/upload-security-dashboard.png">
        <img src="docs/images/upload-security-dashboard.png" alt="Aegis Upload Security" width="96%">
      </a>
      <br><br>
    </td>
    <td width="50%" align="center">
      <br>
      <a href="docs/images/bot-challenge-dashboard.png">
        <img src="docs/images/bot-challenge-dashboard.png" alt="Aegis Smart Challenge Bot Defense" width="96%">
      </a>
      <br><br>
    </td>
  </tr>
</table>

---

## License

Aegis is licensed under the [Business Source License 1.1 (BSL 1.1)](LICENSE).

* **Free for Production Use:** Free to copy, modify, and deploy across your internal services, APIs, and production workloads.
* **Commercial Restriction:** Offering Aegis as a competing managed cloud service or commercial WAF SaaS requires an enterprise license.

For enterprise licensing, OEM distribution, and production support, visit [divinelab.io](https://divinelab.io) or contact [contact@divinelab.io](mailto:contact@divinelab.io).
