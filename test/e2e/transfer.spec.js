import { test, expect } from '@playwright/test';
import { createServer } from '../../lib/server.js';
import { generateKey, keyToBase64Url, encryptChunk } from '../../lib/crypto-utils.js';
import { WebSocket } from 'ws';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
let server, base;
test.beforeAll(async () => {
  server = await createServer({ host: '127.0.0.1' });
  base = `http://127.0.0.1:${server.address.port}`;
});
test.afterAll(async () => { await server.close(); });

for (const fallback of [false, true]) {
  test(`bidirectional exact downloads, empty files, safe filenames; fallback=${fallback}`, async ({ browser }) => {
    const context = await browser.newContext({ acceptDownloads: true });
    if (fallback) await context.addInitScript(() => Object.defineProperty(window.crypto, 'subtle', { value: undefined }));
    const pages = [await context.newPage(), await context.newPage()];
    const errors = [];
    context.on('weberror', e => errors.push(e.error().message));
    await context.route('**/*', route => route.request().url().startsWith(base) ? route.continue() : route.abort());
    const key = keyToBase64Url(generateKey());
    await Promise.all(pages.map(p => p.goto(`${base}/r/testroom#key=${key}`)));
    for (const p of pages) { await expect(p.locator('#peerCount')).toHaveText('2 peers'); expect(p.url()).not.toContain('#'); }
    for (const [from, to, payload, name] of [
      [pages[0], pages[1], Buffer.alloc(800000, 123), '<img src=x onerror=alert(1)>.bin'],
      [pages[1], pages[0], Buffer.from('reverse transfer'), 'reverse.txt'],
      [pages[0], pages[1], Buffer.alloc(0), 'empty.txt'],
    ]) {
      const download = to.waitForEvent('download');
      await from.locator('#fileInput').setInputFiles({ name, mimeType: 'application/octet-stream', buffer: payload });
      const file = await download;
      expect(await readFile(await file.path())).toEqual(payload);
      await expect(to.locator('.transfer-name').first()).toHaveText(name);
      expect(await to.locator('.transfer-name img').count()).toBe(0);
    }
    expect(errors).toEqual([]);
    await context.close();
  });
}

test('invalid keys, no peers, wrong key and incomplete files fail visibly', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(base + '/r/errors#key=bad');
  await expect(page.locator('#errorText')).toContainText('Invalid encryption key');
  const key = generateKey();
  await page.goto(base + '/r/errors#key=' + keyToBase64Url(key));
  await expect(page.locator('#peerCount')).toHaveText('1 peer');
  await page.locator('#fileInput').setInputFiles({ name: 'alone.txt', mimeType: 'text/plain', buffer: Buffer.from('x') });
  await expect(page.locator('#errorText')).toContainText('Connect another device');
  const ws = new WebSocket(base.replace('http', 'ws') + '/ws/errors');
  await once(ws, 'open');
  const control = (msg, secret = key) => ws.send(encryptChunk(Buffer.concat([Buffer.from([0]), Buffer.from(JSON.stringify(msg))]), secret));
  control({ type: 'file_offer', transferId: '0123456789abcdef', fileName: 'incomplete', fileSize: 3, totalChunks: 1 });
  control({ type: 'file_done', transferId: '0123456789abcdef' });
  await expect(page.locator('#errorText')).toContainText('Incomplete file');
  control({ type: 'file_offer' }, generateKey());
  await expect(page.locator('#errorText')).toContainText('Could not receive transfer');
  await expect(page.locator('#errorText')).not.toContainText('Incomplete file');
  ws.close();
  await context.close();
});


test('concurrent senders retain chunk ordering and disconnect clears partial downloads', async ({ browser }) => {
  const context = await browser.newContext({ acceptDownloads: true });
  const pages = [await context.newPage(), await context.newPage(), await context.newPage()];
  const key = generateKey();
  await Promise.all(pages.map(page => page.goto(base + '/r/concurrent#key=' + keyToBase64Url(key))));
  for (const page of pages) await expect(page.locator('#peerCount')).toHaveText('3 peers');
  const files = [{ name: 'first.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(900000, 17) },
    { name: 'second.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(700000, 83) }];
  const downloads = [];
  pages[2].on('download', download => downloads.push(download));
  await Promise.all(files.map((file, i) => pages[i].locator('#fileInput').setInputFiles(file)));
  await expect.poll(() => downloads.length).toBe(2);
  for (const download of downloads) {
    expect(await readFile(await download.path())).toEqual(files.find(file => file.name === download.suggestedFilename()).buffer);
  }
  const peer = new WebSocket(base.replace('http', 'ws') + '/ws/concurrent');
  await once(peer, 'open');
  peer.send(encryptChunk(Buffer.concat([Buffer.from([0]), Buffer.from(JSON.stringify({ type: 'file_offer',
    transferId: 'abcdef0123456789', fileName: 'interrupted.bin', fileSize: 100, totalChunks: 1 }))]), key));
  await expect(pages[2].locator('.transfer-name').first()).toHaveText('interrupted.bin');
  peer.close();
  await expect(pages[2].locator('.transfer-status').first()).toContainText('disconnected');
  await context.close();
});
