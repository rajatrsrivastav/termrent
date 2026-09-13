# ⚡ termrent

Bidirectional encrypted browser file exchange on a local network, launched from a terminal.

## Install and use

Requires Node.js **20.19 or newer**.

```sh
npm install
npm start
# Or, after installing the package globally:
termrent --room myfiles --port 8080
```

Open the printed link on **both** devices (or scan its QR code). Keep both browser tabs open, then select or drop files. Every connected device in the room with the same key receives the file. Use the download link if your browser blocks automatic downloads. Files are limited to **64 MiB each** because receivers assemble them in memory. Transfers do not resume; resend after interruptions. “Sent to relay” means the sender queued the encrypted data, not that every receiver saved it.

```text
termrent [options]
  -r, --room <id>     3–32 letters, digits, underscores or hyphens; random by default
  -p, --port <num>    0–65535; 0 chooses an available port
  -h, --host <addr>   Bind address; defaults to 0.0.0.0
      --no-qr         Suppress QR output
      --help          Show help
```

A specific bind host is used in the printed link. For wildcard binds the CLI chooses the first external IPv4 interface; on a multi-interface computer, replace the address with the interface reachable by the other device. Firewall rules and Wi-Fi client isolation must allow the chosen TCP port. mDNS advertising is best effort; use the link or QR code to connect. Ctrl+C or SIGTERM closes the relay and sockets.

## Security and limits

The CLI generates a random AES-256-GCM key. It appears in the URL fragment, which browsers do not include in HTTP requests. The browser removes the fragment before importing the key. Reopen the original link after reloading; the key is deliberately not persisted. Removing the fragment cannot undo screenshots, copied links, browser synchronization, or other prior exposure.

File metadata, transfer IDs, sequence numbers, and contents are encrypted and authenticated. The relay sees room IDs, connection information, sizes and timing of encrypted frames, but does not receive the key or plaintext through the transfer protocol. Anyone with the shared link can decrypt and send files. Room IDs are routing identifiers, not authorization. This is a broadcast room, not a private one-to-one channel.

**HTTP LAN mode assumes a trusted network and trusted relay host.** Encryption of file frames does not authenticate the JavaScript served over HTTP: an active network attacker or malicious host can replace it and steal the key. For untrusted networks, deploy behind a trusted HTTPS reverse proxy supporting WebSocket upgrades and share an `https://` link with the same fragment. This CLI does not provision certificates or configure a proxy.

WebCrypto is used when available; on insecure HTTP origins the browser loads the installed `@noble/ciphers` modules from the relay itself. No CDN, external font, or internet connection is required at runtime. The Node helper uses the same packet format as the browser:

```text
12-byte random IV | AES-GCM ciphertext | 16-byte authentication tag
```

Encrypted plaintext starts with one byte: `0` for JSON offer/completion messages, or `1` for a chunk containing a 16-byte ASCII transfer ID, a 4-byte big-endian chunk index, and up to 256 KiB of file data. Receivers process frames serially and validate chunk sequence, sizes, and completion before download. Old plaintext-metadata clients are incompatible.

Defaults: 100 rooms, 10 peers per room, 4 MiB maximum WebSocket frame, 8 MiB relay send buffer per peer, 30-minute room inactivity expiry, and a 30-second connection heartbeat. Activity refreshes room expiry. Slow consumers are disconnected. Browsers retain at most four incoming transfers, expire stalled transfers after about one minute, and retain download links for at most ten minutes, 32 files, or 128 MiB. These bounds reduce resource use; the unauthenticated LAN relay is not designed as a public internet service.

## Repository and architecture

- `bin/termrent.js`: CLI validation, random room/key, network address, QR, mDNS and shutdown.
- `lib/server.js`: HTTP assets/health and binary WebSocket relay; in-memory room management.
- `lib/crypto-utils.js`: interoperable Node AES helpers and key/room generation; no CLI-to-CLI transfer command exists.
- `public/index.html`, `public/app.js`: browser UI and transfer protocol.
- `test/core.test.js`: crypto, HTTP, WebSocket, lifecycle and CLI regression tests.
- `test/e2e/`: real-browser upload/download and failure-flow tests.

There is no database, persistence layer, application environment variable, transpilation step, or separate frontend/backend service. `createServer({ port, host, maxPeersPerRoom, maxRooms, roomTtlMs })` resolves to `{ httpServer, wss, rooms, address, close }`; call `await close()` to release resources. `GET /health` returns health and room/peer counts. Room pages are `/r/<id>` and WebSockets are `/ws/<id>`.

## Development and validation

```sh
npm ci
npx playwright install chromium firefox webkit
npm run check
```

`check` runs ESLint, syntax/import/offline-asset build validation, Node unit/integration tests, and Playwright end-to-end tests in Chromium, Firefox and WebKit. This is JavaScript; no standalone static type-check pipeline is configured. `npm run dev` uses port 3000. `npm audit` checks dependency advisories; `npm pack --dry-run` checks package contents. Browser tests require permission to launch browsers and bind local sockets. On macOS 27, Firefox subprocess startup can fail with “Could not find profile folder” due to [Mozilla bug 2060476](https://bugzilla.mozilla.org/show_bug.cgi?id=2060476). Run the full matrix on Linux CI or a host with the required macOS app-data permission; Chromium/WebKit can be checked independently with `npm run test:e2e -- --project=chromium --project=webkit`. The full pipeline deliberately retains Firefox coverage.

## License

MIT
