# ⚡ termrent

> **Bidirectional, cross-device, zero-config encrypted file exchange CLI.**

Launch a local relay server from your terminal, scan the generated QR code, and seamlessly exchange files end-to-end encrypted right in your browser. Perfect for transferring files between desktop and mobile devices on the same local network.

---

## ✨ Features

- **Zero-config**: Launch instantly from the terminal. No accounts or setup required.
- **E2E Encrypted**: Uses AES-256-GCM in the browser via WebCrypto. The server *never* sees your keys or plaintext data.
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

## 🔒 Security & Limits

- **Client-Side Encryption**: The CLI generates a random AES-256-GCM key that appears in the URL fragment. Browsers do not include fragments in HTTP requests. The browser removes the fragment before importing the key.
- **No Persistence**: Keys are deliberately not persisted. Reopen the original link after reloading. Anyone with the shared link can decrypt and send files. Room IDs are routing identifiers, not authorization.
- **Untrusted Networks**: HTTP LAN mode assumes a trusted network. For untrusted networks, deploy behind a trusted HTTPS reverse proxy supporting WebSocket upgrades.
- **Limits**: By default, there are up to 100 rooms, 10 peers per room, and a 30-minute room inactivity expiry.

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
