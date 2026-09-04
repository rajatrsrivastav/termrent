import http from 'node:http';
import fs from 'node:fs';
import { WebSocketServer, WebSocket } from 'ws';

const ROOM_PATH = /^\/ws\/([a-zA-Z0-9_-]{3,32})$/;
const MAX_BUFFER = 8 * 1024 * 1024;

export class RoomManager {
  #rooms = new Map();
  constructor({ maxPeersPerRoom = 10, roomTtlMs = 30 * 60 * 1000, maxRooms = 100 } = {}) {
    for (const value of [maxPeersPerRoom, roomTtlMs, maxRooms]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new RangeError('Room limits must be positive integers');
    }
    this.maxPeersPerRoom = maxPeersPerRoom;
    this.roomTtlMs = roomTtlMs;
    this.maxRooms = maxRooms;
  }
  join(id, peer) {
    let room = this.#rooms.get(id);
    if (!room) {
      if (this.#rooms.size >= this.maxRooms) return false;
      room = { peers: new Set(), touched: Date.now() };
      this.#rooms.set(id, room);
    }
    if (room.peers.size >= this.maxPeersPerRoom) return false;
    room.peers.add(peer);
    room.touched = Date.now();
    this.presence(room);
    return true;
  }
  leave(id, peer) {
    const room = this.#rooms.get(id);
    if (!room || !room.peers.delete(peer)) return;
    if (!room.peers.size) this.#rooms.delete(id);
    else this.presence(room);
  }
  send(peer, data, binary = false) {
    if (peer.readyState !== WebSocket.OPEN) return;
    if (peer.bufferedAmount + Buffer.byteLength(data) > MAX_BUFFER) {
      peer.terminate();
      return;
    }
    peer.send(data, { binary }, (err) => { if (err) peer.terminate(); });
  }
  presence(room) {
    for (const peer of room.peers) this.send(peer, JSON.stringify({ type: 'peer_count', count: room.peers.size }));
  }
  broadcast(id, sender, data) {
    const room = this.#rooms.get(id);
    if (!room || !room.peers.has(sender)) return;
    room.touched = Date.now();
    for (const peer of room.peers) if (peer !== sender) this.send(peer, data, true);
  }
  expire(now = Date.now()) {
    for (const [id, room] of this.#rooms) {
      if (now - room.touched < this.roomTtlMs) continue;
      this.#rooms.delete(id);
      for (const peer of room.peers) {
        peer.close(4001, 'Room expired due to inactivity');
      }
    }
  }
  get stats() {
    return { rooms: this.#rooms.size, peers: [...this.#rooms.values()].reduce((n, r) => n + r.peers.size, 0) };
  }
}

/** Start a local blind relay. Call the returned async close() to release all resources. */
export async function createServer(opts = {}) {
  const rooms = new RoomManager(opts);
  const assets = new Map([
    ['/app.js', [fs.readFileSync(new URL('../public/app.js', import.meta.url)), 'text/javascript']],
  ]);
  const html = fs.readFileSync(new URL('../public/index.html', import.meta.url));
  // Serve installed, locked crypto modules locally: LAN operation needs no CDN.
  const vendorRoot = new URL('.', import.meta.resolve('@noble/ciphers/aes.js'));
  for (const name of fs.readdirSync(vendorRoot).filter(name => /^[\w-]+\.js$/.test(name))) {
    assets.set(`/vendor/${name}`, [fs.readFileSync(new URL(name, vendorRoot)), 'text/javascript']);
  }
  const httpServer = http.createServer((req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    if (!['GET', 'HEAD'].includes(req.method)) {
      res.writeHead(405, { Allow: 'GET, HEAD' }); res.end(); return;
    }
    let pathname;
    try { pathname = new URL(req.url, 'http://localhost').pathname; }
    catch { res.writeHead(400); res.end(); return; }
    let asset = assets.get(pathname);
    if (/^\/r\/[a-zA-Z0-9_-]{3,32}$/.test(pathname)) asset = [html, 'text/html; charset=utf-8'];
    if (pathname === '/health') asset = [JSON.stringify({ ok: true, ...rooms.stats }), 'application/json'];
    if (pathname === '/favicon.ico') { res.writeHead(204); res.end(); return; }
    if (!asset) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': asset[1] });
    res.end(req.method === 'HEAD' ? undefined : asset[0]);
  });
  const wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024, perMessageDeflate: false });
  httpServer.on('upgrade', (req, socket, head) => {
    let match;
    try {
      match = new URL(req.url, 'http://localhost').pathname.match(ROOM_PATH);
      if (!match) throw new Error('Invalid path');
      if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) throw new Error('Invalid origin');
    } catch { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, match[1]));
  });
  wss.on('connection', (ws, id) => {
    ws.on('error', () => {
      rooms.leave(id, ws);
      // ws already starts a protocol close for invalid/oversized frames.
      if (ws.readyState === WebSocket.OPEN) ws.terminate();
    });
    ws.on('close', () => rooms.leave(id, ws));
    ws.alive = true;
    ws.on('pong', () => { ws.alive = true; });
    if (!rooms.join(id, ws)) { ws.close(4002, 'Room or server full'); return; }
    ws.on('message', (data, binary) => {
      // Only encrypted packets are accepted; presence is server-owned.
      if (!binary || data.length < 29) { ws.close(4003, 'Expected encrypted binary packet'); return; }
      rooms.broadcast(id, ws, data);
    });
  });
  const expiry = setInterval(() => rooms.expire(), Math.min(opts.roomTtlMs ?? 30000, 30000));
  const heartbeat = setInterval(() => {
    for (const peer of wss.clients) {
      if (!peer.alive) { peer.terminate(); continue; }
      peer.alive = false;
      peer.ping();
    }
  }, 30000);
  expiry.unref(); heartbeat.unref();
  const cleanup = () => { clearInterval(expiry); clearInterval(heartbeat); };
  httpServer.on('close', cleanup);
  try {
    await new Promise((resolve, reject) => {
      httpServer.once('error', reject);
      httpServer.listen(opts.port ?? 0, opts.host ?? '0.0.0.0', () => {
        httpServer.removeListener('error', reject);
        resolve();
      });
    });
  } catch (err) { cleanup(); wss.close(); throw err; }
  let closing;
  const close = () => closing ??= new Promise((resolve, reject) => {
    cleanup();
    for (const peer of wss.clients) peer.terminate();
    wss.close(() => httpServer.close(err => err ? reject(err) : resolve()));
  });
  return { httpServer, wss, rooms, address: httpServer.address(), close };
}
