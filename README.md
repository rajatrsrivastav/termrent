# ⚡ termrent

> Bidirectional, zero-config, **end-to-end encrypted** file exchange between any devices on your local network — entirely from the terminal.

```
$ npx termrent

  ⚡ termrent  encrypted file exchange
  ────────────────────────────────────────────────────────────

  Room     kswwf4
  Server   http://10.0.1.5:49231

  Share this link (key is in the fragment — never sent to server)

  http://10.0.1.5:49231/r/kswwf4#key=GKtS7abcto6vJ-...

    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    █ ▄▄▄▄▄ █▄▀ ▀  ▄▄▀▄▄█▀ █
    █ █   █ █   █▀█▀▀▄█▄█▀ █
    ...

  Scan the QR code or open the link on any device on this network.
  Press Ctrl+C to stop.
```

---

## Security Model

| What | Where it lives | Server can see it? |
|------|----------------|-------------------|
| AES-256-GCM key | URL fragment only (`#key=...`) | **No** — browsers never send fragments |
| File chunks | Encrypted binary WebSocket frames | **No** — opaque bytes |
| File names / sizes | Encrypted JSON offer message | **No** — JSON payload is also encrypted |
| Room ID | URL path + WS path | Yes (routing only) |

The Node server is a **blind relay**: it reads only the WebSocket path to route frames between room peers. It never sees the key or plaintext.

After key import the fragment is wiped from the address bar with `history.replaceState` — it won't appear in browser history, referrer headers, or screen recordings.

---

## How it works

```
Sender browser                 Node server (blind relay)         Receiver browser
──────────────                 ─────────────────────────         ────────────────
1. Read key from #fragment ──────────────────────────────────────────────────────
2. Wipe key from URL bar
3. Connect  ─────── WS /ws/roomId ──────────────────── WS /ws/roomId ──── Connect
4. Drop file
5. file_offer JSON ──── broadcast ──────────────────────────────────────────────▶
6. Encrypt chunk (AES-256-GCM)
7. Binary frame ───────── broadcast ─────────────────────────────────────────────▶
                                                               8. Decrypt chunk
                                                               9. Assemble + download
```

Each chunk wire format:

```
[ 12-byte IV ] [ AES-GCM ciphertext + 16-byte auth tag ]
```

---

## Install

```bash
# Run directly (no install)
npx termrent

# Or install globally
npm install -g termrent
termrent
```

**Requirements:** Node.js ≥ 18

---

## Usage

```
termrent [options]

Options:
  -r, --room <id>     Room ID (default: random 6-char)
  -p, --port <num>    Port to listen on (default: OS-assigned)
  -h, --host <addr>   Bind address (default: 0.0.0.0)
      --no-qr         Suppress QR code output
      --help          Show help
```

### Examples

```bash
# Quickstart — random room, random port
termrent

# Named room on a fixed port (handy for firewall rules)
termrent --room myfiles --port 8080

# Headless (no QR) — pipe the URL to a notifier
termrent --no-qr 2>&1 | grep "http://"
```

---

## File Structure

```
termrent/
├── bin/
│   └── termrent.js       # CLI entry: key gen, QR, mDNS, server boot
├── lib/
│   ├── server.js         # HTTP + WS blind relay, RoomManager
│   └── crypto-utils.js   # Node.js AES-256-GCM utils (CLI ↔ CLI)
├── public/
│   └── index.html        # Zero-dependency browser UI (inline CSS + JS)
└── package.json
```

---

## Architecture Notes

- **RoomManager** — pure in-memory `Map<roomId, Set<WebSocket>>`. No Redis, no DB.
- **Auto-cleanup** — rooms evict after 30 min of inactivity (configurable).
- **Back-pressure** — sender polls `ws.bufferedAmount` before each chunk so it can't flood a slow connection.
- **mDNS** — server advertises itself via `bonjour-service` so iOS/Android can discover it with zero configuration.
- **Max frame** — WebSocket server rejects frames > 4 MiB to prevent memory exhaustion.

---

## License

MIT
