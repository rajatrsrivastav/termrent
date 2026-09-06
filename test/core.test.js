import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { execFileSync, spawn } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { gcm } from '@noble/ciphers/aes.js';
import { WebSocket } from 'ws';
import { createServer, RoomManager } from '../lib/server.js';
import { generateKey, encryptChunk, decryptChunk, base64UrlToKey, keyToBase64Url } from '../lib/crypto-utils.js';

test('Node, WebCrypto and offline AES interoperate, including empty data and tampering', async () => {
  const key = generateKey();
  assert.deepEqual(base64UrlToKey(keyToBase64Url(key)), key);
  assert.throws(() => base64UrlToKey('!'.repeat(43)));
  const imported = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
  for (const plain of [Buffer.alloc(0), Buffer.from('private file contents')]) {
    const packet = encryptChunk(plain, key);
    assert.deepEqual(decryptChunk(packet, key), plain);
    assert.deepEqual(Buffer.from(gcm(key, packet.subarray(0, 12)).decrypt(packet.subarray(12))), plain);
    assert.deepEqual(Buffer.from(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: packet.subarray(0, 12) }, imported, packet.subarray(12))), plain);
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, imported, plain);
    assert.deepEqual(decryptChunk(Buffer.concat([iv, Buffer.from(encrypted)]), key), plain);
    packet[packet.length - 1] ^= 1;
    assert.throws(() => decryptChunk(packet, key));
  }
});

test('HTTP assets, isolation, binary relay, plaintext rejection and resource cleanup', async t => {
  const server = await createServer({ host: '127.0.0.1' });
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address.port}`;
  for (const path of ['/r/abc', '/app.js', '/vendor/aes.js', '/vendor/utils.js', '/health']) {
    const res = await fetch(base + path);
    assert.equal(res.status, 200, path);
    assert.ok(res.headers.get('content-security-policy').includes("script-src 'self'"));
  }
  assert.equal((await fetch(base + '/r/abc', { method: 'HEAD' })).headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal((await fetch(base + '/health', { method: 'POST' })).status, 405);
  assert.equal((await fetch(base + '/vendor/package.json')).status, 404);
  const connect = async room => { const ws = new WebSocket(base.replace('http', 'ws') + '/ws/' + room); await once(ws, 'open'); return ws; };
  const a = await connect('abc'); const b = await connect('abc'); const c = await connect('xyz');
  let leaked = false;
  c.on('message', (_, binary) => { if (binary) leaked = true; });
  const packet = encryptChunk(Buffer.from('secret payload'), generateKey());
  const received = new Promise(resolve => b.on('message', (data, binary) => { if (binary) resolve(data); }));
  a.send(packet);
  assert.deepEqual(await received, packet);
  assert.equal(leaked, false);
  const closed = once(a, 'close'); a.send('{"type":"file_offer","fileName":"leak"}');
  assert.equal((await closed)[0], 4003);
  await server.close();
  assert.deepEqual(server.rooms.stats, { rooms: 0, peers: 0 });
});

test('room activity refreshes expiry and slow consumers are disconnected', t => {
  let now = 1000;
  t.mock.method(Date, 'now', () => now);
  const rooms = new RoomManager({ roomTtlMs: 100, maxPeersPerRoom: 2, maxRooms: 1 });
  const peer = () => ({ readyState: 1, bufferedAmount: 0, send(_data, _opts, cb) { cb?.(); }, close() { this.closed = true; }, terminate() { this.terminated = true; } });
  const a = peer(), b = peer();
  assert.equal(rooms.join('abc', a), true);
  assert.equal(rooms.join('abc', b), true);
  assert.equal(rooms.join('abc', peer()), false);
  assert.equal(rooms.join('xyz', peer()), false);
  b.bufferedAmount = 9 * 1024 * 1024;
  now = 1050;
  rooms.broadcast('abc', a, Buffer.alloc(29));
  assert.equal(b.terminated, true);
  rooms.expire(1120);
  assert.equal(rooms.stats.rooms, 1);
  rooms.expire(1151);
  assert.equal(rooms.stats.rooms, 0);
  assert.equal(a.closed, true);
});

test('CLI rejects invalid options and documents help', () => {
  assert.match(execFileSync(process.execPath, ['bin/termrent.js', '--help'], { encoding: 'utf8' }), /Usage/);
  for (const args of [['--port', 'abc'], ['--port', '65536'], ['--room', '../bad'], ['--unknown']]) {
    assert.throws(() => execFileSync(process.execPath, ['bin/termrent.js', ...args], { stdio: 'pipe' }));
  }
});


test('CLI starts on requested host and shuts down with an active browser socket', { timeout: 10000 }, async t => {
  const cli = spawn(process.execPath, ['bin/termrent.js', '--host', '127.0.0.1', '--room', 'clitest', '--no-qr'], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (cli.exitCode === null) cli.kill('SIGKILL'); });
  const link = await new Promise((resolve, reject) => {
    let output = '';
    cli.stdout.on('data', chunk => {
      output += chunk;
      const match = output.match(/http:\/\/127\.0\.0\.1:\d+\/r\/clitest#key=[A-Za-z0-9_-]{43}/);
      if (match) resolve(match[0]);
    });
    cli.once('error', reject);
    cli.once('exit', code => reject(new Error('CLI exited early: ' + code)));
  });
  const url = new URL(link);
  assert.equal((await fetch(url.origin + '/health')).status, 200);
  const ws = new WebSocket(url.origin.replace('http', 'ws') + '/ws/clitest');
  await once(ws, 'open');
  const exited = once(cli, 'exit');
  cli.kill('SIGTERM');
  assert.equal((await exited)[0], 0);
});

test('upgrade origin, room capacity, and oversized frames are rejected', async t => {
  const server = await createServer({ host: '127.0.0.1', maxPeersPerRoom: 1 });
  t.after(() => server.close());
  const url = `ws://127.0.0.1:${server.address.port}/ws/limit`;
  for (const [target, options] of [[url, { origin: 'http://attacker.invalid' }], [url + '/bad', {}]]) {
    const peer = new WebSocket(target, options);
    assert.match((await once(peer, 'error'))[0].message, /403/);
  }
  const a = new WebSocket(url); await once(a, 'open');
  const b = new WebSocket(url);
  assert.equal((await once(b, 'close'))[0], 4002);
  const closed = once(a, 'close');
  a.send(Buffer.alloc(4 * 1024 * 1024 + 1));
  assert.equal((await closed)[0], 1009);
});
