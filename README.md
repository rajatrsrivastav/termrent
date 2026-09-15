# ⚡ termrent

> **Bidirectional, cross-device, zero-config encrypted file exchange CLI.**

Launch a local relay server from your terminal, scan the generated QR code, and seamlessly exchange files end-to-end encrypted right in your browser. Perfect for transferring files between desktop and mobile devices on the same local network.

---

## ✨ Features

- **Zero-config**: Launch instantly from the terminal. No accounts or setup required.
- **E2E Encrypted**: AES-256-GCM end-to-end encryption. WebCrypto is used on secure origins; LAN HTTP mode uses the bundled audited crypto implementation (`@noble/ciphers`) with no CDN dependency. The server *never* sees your keys or plaintext data.
- **Cross-device**: Send files effortlessly between mobile, desktop, and tablet browsers.
- **Auto-discovery**: Connect instantly by scanning the terminal QR code or using mDNS local network discovery.
- **Lightweight**: No databases, CDNs, or external internet connections needed at runtime.

## 🚀 Quick Start

Requires **Node.js 20.19 or newer**.

### Using `npx` (No installation needed)

Run directly from npm:
```sh
npx termrent
```

### Local Installation

Clone the repository and install dependencies:
```sh
git clone https://github.com/rajatrsrivastav/termrent.git
cd termrent
npm install
npm start
```

### Usage

```sh
# Start with default options (random room, random port)
npm start

# Or if installed globally / via npx
termrent --room myfiles --port 8080
```

1. Open the printed link on **both** devices, or simply scan the QR code using your mobile device.
2. Keep both browser tabs open.
3. Select or drop files to transfer. Every connected device in the room with the same key receives the file.

> **Note**: Files are assembled in memory and limited to **64 MiB each**. Transfers do not resume; resend after interruptions. "Sent to relay" means the sender queued the encrypted data, not that every receiver saved it.

## 🛠 Options

```text
termrent [options]

Options:
  -r, --room <id>     Room ID (3–32 chars); random by default
  -p, --port <num>    Port to listen on (0 chooses available port)
  -h, --host <addr>   Bind address (defaults to 0.0.0.0)
      --no-qr         Suppress QR code output
      --help          Show help
```

*Note: For wildcard binds, the CLI chooses the first external IPv4 interface. Firewall rules and Wi-Fi client isolation must allow the chosen TCP port. mDNS advertising is best effort.*

## 🔒 Security & Threat Model

### Cryptography & Execution Contexts

- **Client-Side Encryption**: The CLI generates a random 256-bit AES-GCM key encoded into the URL fragment (`#key=...`). URL fragments are never transmitted to the HTTP server by browsers (RFC 3986 §3.5), and the client script strips the fragment from the URL bar immediately upon loading.
- **Dual-Engine AES-256-GCM**:
  - **Secure Origins (HTTPS / `localhost`)**: Uses native browser WebCrypto (`crypto.subtle`) with non-extractable keys.
  - **LAN HTTP Mode (`http://<ip>:<port>`)**: Modern browsers restrict `crypto.subtle` to secure contexts. When accessed over a typical LAN HTTP address (e.g., `http://192.168.1.42:8080`), termrent detects the absence of `crypto.subtle` and falls back to a locally served, audited pure JavaScript AES-GCM implementation ([`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers)) with zero CDN or external internet dependencies.
- **No Key Persistence**: Keys reside strictly in browser memory and are never written to `localStorage`, cookies, or IndexedDB. Reloading the page requires reopening the original URL.

### Threat Model

Serving executable JavaScript over unauthenticated HTTP carries distinct architectural implications. Termrent explicitly distinguishes between two operating environments:

- **Trusted LAN Mode (Default HTTP)**:
  - **Guarantees**: Protects file contents from the relay server itself and from passive network observation (eavesdropping) on the local network. The relay forwards only opaque binary ciphertext frames and never possesses the decryption key.
  - **Active Attacker Caveat**: Unauthenticated plain HTTP cannot defend against an **active network attacker (MITM)**. An attacker capable of intercepting and modifying LAN network traffic could alter the served JavaScript code in flight before execution and extract the fragment key. This is an inherent property of delivering executable code over unauthenticated HTTP, not a weakness in AES-GCM.
- **Untrusted Network Mode (Trusted HTTPS)**:
  - When transferring files across untrusted, public, or hostile networks, deploy termrent behind a trusted HTTPS reverse proxy (such as Caddy, Nginx, or Cloudflare Tunnel) with a valid TLS certificate and WebSocket upgrade (`wss://`) support. HTTPS provides transport-layer integrity for the client code, neutralizing active in-flight tampering and enabling native WebCrypto.

### Operational Limits

- **Room Authorization**: Room IDs function as routing identifiers, not secrets or authorization tokens. Anyone with the full link (including fragment key) can decrypt and send files within that room.
- **Capacity & Expiry**: By default, the relay allows up to 100 concurrent rooms, 10 peers per room, a 4 MiB WebSocket frame ceiling, and a 30-minute room inactivity timeout. Individual file transfers are buffered in memory up to 64 MiB per file.

## 🏗 Architecture & Workflow

There is no database, persistence layer, or transpilation step.

- `bin/termrent.js`: CLI validation, room/key generation, QR output, and mDNS.
- `lib/server.js`: HTTP asset server and binary WebSocket relay; in-memory room management.
- `lib/crypto-utils.js`: Interoperable Node AES helpers.
- `public/`: Browser UI (`index.html`) and transfer protocol logic (`app.js`).
- `test/`: Core cryptography, network, and CLI regression tests, alongside Playwright end-to-end tests.

### Development Workflow

1. Install dependencies and browser binaries for testing:
   ```sh
   npm ci
   npx playwright install chromium firefox webkit
   ```
2. Start the dev server:
   ```sh
   npm run dev
   ```
3. Run checks and tests:
   ```sh
   npm run check
   ```

`npm run check` runs ESLint, verifies syntax and offline assets without compiling, executes Node.js unit tests, and runs Playwright end-to-end tests across Chromium, Firefox, and WebKit.

## 📄 License

MIT
