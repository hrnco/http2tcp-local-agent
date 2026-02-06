# HTTP2TCP Local Agent

`hrnco/http2tcp-local-agent` is a lightweight local HTTP server running in Docker that lets web or cloud apps securely communicate with LAN devices over TCP—without opening ports, setting up VPNs, or exposing the LAN to the internet.

Core idea:

> Cloud / Web App → http2tcp-server (crypto/signing) → Browser → http://localhost:<port> → HTTP2TCP Local Agent → TCP → LAN device

The cloud never needs direct access to the customer’s internal network.

---

## Overview

HTTP2TCP Local Agent acts as:

- **HTTP server on localhost** – accepts requests from the browser or a local client
- **TCP client to LAN** – opens outbound TCP connections to devices on the local network (printers, cash registers, terminals, IoT…)
- **cryptographically verifying agent** – accepts only requests authorized by the server (via signature)

The companion server component (`https://github.com/hrnco/http2tcp-signing-server`) serves as:

- holder of the private key (each private key is unique by device ID)
- translator of application requests into a signed form

The server **does not communicate directly with the agent** — the agent communicates only with the browser on localhost.

Typical LAN devices:

- ESC/POS LAN printers (port 9100)
- ZPL label printers (Zebra, port 9100)
- fiscal cash registers (e.g., FiskalPRO API on port 3000)
- specialized TCP devices (scanners, IoT gateways…)

---

## Typical use cases

- Cloud invoicing/POS system that needs to print receipts to a local printer
- Web app that must communicate with a LAN cash register via a proprietary TCP protocol
- Centralized web UI that controls local TCP devices without VPN
- Environments where IT prohibits opening ports or setting up port-forwarding

---

## Architecture (high-level)

Communication flow:

1. **Cloud / Web app** asks the server for a signed/encrypted request
2. **http2tcp-server** creates an envelope (with an authorized signature)
3. **Browser (JS)** sends this envelope to `http://localhost:<port>`
4. **HTTP2TCP Local Agent** verifies the signature and performs the TCP operation
5. **LAN device** processes the TCP communication

Diagram:

```
Cloud / Web App
        |
        |  HTTP (internal CLOUD network)
        v
 http2tcp-server
 (signing/encryption)
        |
        |  HTTPS
        v
   Web Browser
        |
        |  HTTP (localhost)
        v
HTTP2TCP Local Agent
        |
        |  TCP
        v
    LAN Device
```

---

## Security model

### Digital signature

Each request is signed with the server’s private key.

The agent verifies the signature using the stored server public key.

A signature is always required.

---

### Trust On First Use (TOFU)

On the first connection:

1. The server sends a normal message — and its public key
2. The agent stores the public key
3. From then on it trusts only that key

If the agent receives an unsigned request, or one signed with a different key, it rejects it.

---

### Replay attack protection

Each request includes a timestamp.

The agent rejects stale requests.

---

### Payload

- payload is not encrypted
- it is signed
- ensures integrity and authenticity

---

### Tips

- for higher security, restrict LAN device access to the agent IP using firewall or VLAN rules

---

## Quick start (Docker)

Recommended way to run:

```bash
docker run -d --restart=unless-stopped --name http2tcp-agent -p 127.0.0.1:34279:80 hrnco/http2tcp-local-agent
```

After it starts, the agent is available at:

```
http://localhost:34279
```

---

## API core principle

The server creates a cryptographically authorized envelope (serialized parameters) that the browser sends to the agent.

**Input for server (signing):**
- `deviceIp` + `devicePort` (target LAN device host or IP)
- `payloadBase64` (TCP payload in base64/base64url) or an array `payloadBase64` for batch sending

**Output from server:**
- serialized string with parameters `instructions`, `sig`, `kid`, `exp`, `nonce`

**Flow (high-level):**
1. Web/Cloud app calls the signing server (e.g. `POST /api/sign`) and gets signed parameters.
2. Browser forwards the same parameters to the local agent (`GET/POST /api/send`).
3. The agent verifies the signature (TOFU) and performs the TCP request to the LAN device.

**Example (browser POST):**
```js
fetch('http://localhost:34279/api/send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'instructions=...&sig=...&kid=...&exp=...&nonce=...'
});
```
---

## What this project is not

HTTP2TCP Local Agent is not:

- a VPN server or network tunnel
- a universal port-forwarder from the internet into the LAN
- an SSH replacement
- a remote PC management tool

It is a **specialized, local, cryptographically verifying agent** for safe TCP operations.

---

## Acknowledgments

This project was created in response to a specific customer need in the area of LAN device communication.

Thanks to the companies:

Cykloon — https://cykloon.com/

Trialexa — https://trialexa.com/

for consultations, support, and enabling this project to be open-sourced.
