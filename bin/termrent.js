#!/usr/bin/env node

/**
 * termrent — CLI entry point
 *
 * Usage:
 *   termrent                     # random room, random port
 *   termrent --room myroom       # named room
 *   termrent --port 3000         # fixed port
 *   termrent --host 0.0.0.0      # bind address
 *   termrent --no-qr             # suppress QR code
 */

import os from 'node:os';
import { parseArgs } from 'node:util';
import qrcode from 'qrcode-terminal';
import { Bonjour } from 'bonjour-service';

import { generateKey, keyToBase64Url, generateRoomId } from '../lib/crypto-utils.js';
import { createServer } from '../lib/server.js';

/* ── CLI arg parsing ────────────────────────────────────────────────────────── */

const { values: args } = parseArgs({
  options: {
    room:  { type: 'string',  short: 'r' },
    port:  { type: 'string',  short: 'p', default: '0' },
    host:  { type: 'string',  short: 'h', default: '0.0.0.0' },
    'no-qr': { type: 'boolean', default: false },
    help:  { type: 'boolean',  default: false },
  },
  strict: true,
  allowPositionals: false,
});

if (args.help) {
  console.log(`
  termrent — encrypted file exchange

  Usage:
    termrent [options]

  Options:
    -r, --room <id>     Room ID (default: random 6-char)
    -p, --port <num>    Port to listen on (default: random)
    -h, --host <addr>   Bind address (default: 0.0.0.0)
        --no-qr         Suppress QR code output
        --help          Show this help
  `);
  process.exit(0);
}

/* ── Derive room + key ──────────────────────────────────────────────────────── */

const roomId = args.room || generateRoomId();
const aesKey = generateKey();                 // 32 bytes — never sent to server
const keyB64 = keyToBase64Url(aesKey);
const port = Number(args.port);
if (!/^[a-zA-Z0-9_-]{3,32}$/.test(roomId) || !/^\d+$/.test(args.port) || !Number.isInteger(port) || port < 0 || port > 65535 || !args.host) {
  console.error('Invalid room, port, or host. Use --help for usage.');
  process.exit(1);
}

/* ── Resolve local IP ───────────────────────────────────────────────────────── */

function getLocalIP() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

/* ── ANSI helpers ───────────────────────────────────────────────────────────── */

const c = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  cyan:    '\x1b[36m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  magenta: '\x1b[35m',
  white:   '\x1b[97m',
  bgGray:  '\x1b[48;5;236m',
  underline: '\x1b[4m',
};

/* ── Boot ───────────────────────────────────────────────────────────────────── */

try {
  const { close, address } = await createServer({
    port,
    host: args.host,
  });

  const advertisedHost = ['0.0.0.0', '::'].includes(args.host) ? getLocalIP() : args.host;
  const localIP = advertisedHost.includes(':') ? `[${advertisedHost}]` : advertisedHost;
  const actualPort = address.port;
  const shareUrl   = `http://${localIP}:${actualPort}/r/${roomId}#key=${keyB64}`;

  // ── Pretty terminal UI ─────────────────────────────────────────────────

  const line = '─'.repeat(60);

  console.log();
  console.log(`  ${c.cyan}${c.bold}⚡ termrent${c.reset}  ${c.dim}encrypted file exchange${c.reset}`);
  console.log(`  ${c.dim}${line}${c.reset}`);
  console.log();
  console.log(`  ${c.dim}Room    ${c.reset} ${c.bold}${c.white}${roomId}${c.reset}`);
  console.log(`  ${c.dim}Server  ${c.reset} ${c.green}http://${localIP}:${actualPort}${c.reset}`);
  console.log(`  ${c.dim}Peers   ${c.reset} Waiting for connections…`);
  console.log();
  console.log(`  ${c.yellow}${c.bold}Share this link${c.reset} ${c.dim}(key is in the fragment — never sent to server)${c.reset}`);
  console.log();
  console.log(`  ${c.underline}${c.cyan}${shareUrl}${c.reset}`);
  console.log();

  // ── QR Code ──────────────────────────────────────────────────────────────

  if (!args['no-qr']) {
    qrcode.generate(shareUrl, { small: true }, (qr) => {
      const indented = qr
        .split('\n')
        .map((l) => `    ${l}`)
        .join('\n');
      console.log(indented);
      console.log();
      console.log(`  ${c.dim}Scan the QR code or open the link on any device on this network.${c.reset}`);
      console.log(`  ${c.dim}Press Ctrl+C to stop.${c.reset}`);
      console.log();
    });
  }

  // ── mDNS advertisement ──────────────────────────────────────────────────

  let bonjourInstance;
  try {
    bonjourInstance = new Bonjour({}, (err) => console.error(`mDNS unavailable: ${err.message}`));
    bonjourInstance.publish({
      name: `termrent-${roomId}`,
      type: 'http',
      port: actualPort,
      txt: { room: roomId, app: 'termrent' },
    });
  } catch {
    // mDNS is best-effort; don't crash if unavailable
  }

  // ── Graceful shutdown ──────────────────────────────────────────────────

  let stopping = false;
  const shutdown = () => {
    if (stopping) return;
    stopping = true;
    console.log(`\n  ${c.dim}Shutting down…${c.reset}\n`);
    if (bonjourInstance) bonjourInstance.destroy();
    close().then(() => process.exit(0), () => process.exit(1));
    // Force exit after 3s if connections linger
    setTimeout(() => process.exit(0), 3000).unref();
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
} catch (err) {
  console.error(`\n  ${c.bold}Error:${c.reset} ${err.message}\n`);
  process.exit(1);
}
