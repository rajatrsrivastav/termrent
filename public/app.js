
/* ═══════════════════════════════════════════════════════════════════════════
 *  termrent — Browser Client
 *
 *  Key security model:
 *  • The AES-256-GCM key is carried ONLY in the URL fragment (#key=...).
 *  • Browsers never send fragments to the server (RFC 3986 §3.5).
 *  • After import, the fragment is wiped via history.replaceState.
 *  • The server is a blind relay — it cannot decrypt anything.
 * ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  const CHUNK_SIZE = 256 * 1024; // 256 KiB per chunk
  const IV_LEN     = 12;
  const TAG_LEN    = 16;         // GCM default auth tag length (bytes)

  /* ── DOM refs ──────────────────────────────────────────────────────────── */
  const $dropzone     = document.getElementById('dropzone');
  const $fileInput    = document.getElementById('fileInput');
  const $transfers    = document.getElementById('transfers');
  const $statusDot    = document.getElementById('statusDot');
  const $statusText   = document.getElementById('statusText');
  const $peerCount    = document.getElementById('peerCount');
  const $errorBanner  = document.getElementById('errorBanner');
  const $errorText    = document.getElementById('errorText');
  const $logEntries   = document.getElementById('logEntries');

  /* ── Utility ───────────────────────────────────────────────────────────── */
  function formatBytes(b) {
    if (b === 0) return '0 B';
    const k = 1024, units = ['B','KB','MB','GB','TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
  }

  function ts() {
    return new Date().toLocaleTimeString('en-GB', { hour12: false });
  }

  function log(msg) {
    const el = document.createElement('div');
    el.className = 'log-entry';
    el.textContent = `${ts()} ${msg}`;
    $logEntries.prepend(el);
    // cap at 50
    while ($logEntries.children.length > 50) $logEntries.lastChild.remove();
  }

  function showError(msg) {
    $errorText.textContent = msg;
    $errorBanner.classList.add('visible');
  }

  function hideError() {
    $errorBanner.classList.remove('visible');
  }

  function genId() {
    return crypto.getRandomValues(new Uint8Array(8))
      .reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
  }

  /* ── Extract room ID from URL pathname ────────────────────────────────── */
  const pathMatch = window.location.pathname.match(/\/r\/([a-zA-Z0-9_-]{3,32})/);
  if (!pathMatch) {
    showError('Invalid room URL. Expected /r/<room-id>');
    throw new Error('No room ID in URL path');
  }
  const ROOM_ID = pathMatch[1];

  /* ══════════════════════════════════════════════════════════════════════════
   *  KEY EXTRACTION & IMPORT
   *
   *  The AES key is in the URL fragment: #key=<base64url>
   *  After importing into WebCrypto, we wipe the fragment from the URL bar
   *  so it won't appear in browser history, referrer headers, or screen shares.
   * ══════════════════════════════════════════════════════════════════════════ */
  let cryptoKey = null;
  let nobleGcm = null;
  let rawKey = null;

  async function importKeyFromFragment() {
    const hash = window.location.hash; // e.g. "#key=abc123..."
    if (!hash || !hash.startsWith('#key=')) {
      showError('Missing encryption key in URL fragment. Cannot proceed.');
      throw new Error('No key in URL fragment');
    }

    history.replaceState(null, '', window.location.pathname + window.location.search);
    const b64url = hash.slice(5);
    if (!/^[A-Za-z0-9_-]{43}$/.test(b64url)) throw new Error('Invalid encryption key'); // strip '#key='

    // base64url → ArrayBuffer
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad  = (4 - (b64.length % 4)) % 4;
    const bin  = atob(b64 + '='.repeat(pad));
    if (btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== b64url) throw new Error('Invalid key encoding');
    rawKey  = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) rawKey[i] = bin.charCodeAt(i);

    if (rawKey.byteLength !== 32) {
      showError('Invalid encryption key length (expected 256 bits).');
      throw new Error(`Bad key length: ${rawKey.byteLength}`);
    }

    if (window.crypto && window.crypto.subtle) {
      // Import as a non-extractable CryptoKey
      cryptoKey = await crypto.subtle.importKey(
        'raw',
        rawKey.buffer,
        { name: 'AES-GCM', length: 256 },
        false,  // NOT extractable — defense in depth
        ['encrypt', 'decrypt']
      );
      rawKey.fill(0);
      rawKey = null;
    } else {
      log('⚠ WebCrypto missing (HTTP). Loading fallback...');
      try {
        const module = await import('/vendor/aes.js');
        nobleGcm = module.gcm;
        log('✅ Loaded JavaScript AES-GCM fallback');
      } catch (err) {
        showError('Browser lacks WebCrypto (HTTP) and fallback failed to load.');
        throw err;
      }
    }

    // Wipe the key from the URL bar immediately
    history.replaceState(null, '', window.location.pathname + window.location.search);

    log('🔐 Encryption key imported & wiped from URL');
    return cryptoKey || rawKey;
  }

  /* ══════════════════════════════════════════════════════════════════════════
   *  AES-256-GCM ENCRYPT / DECRYPT
   *
   *  Wire format per chunk:
   *    [12-byte IV] [ciphertext + 16-byte auth tag appended by WebCrypto]
   *
   *  Note: WebCrypto's AES-GCM automatically appends the auth tag to the
   *  ciphertext, unlike Node's crypto which returns them separately.
   * ══════════════════════════════════════════════════════════════════════════ */

  /**
   * @param {ArrayBuffer} plaintext
   * @returns {Promise<ArrayBuffer>}  — [IV (12)] [ciphertext + tag]
   */
  async function encryptChunk(plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    let ciphertext;

    if (cryptoKey) {
      ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: TAG_LEN * 8 },
        cryptoKey,
        plaintext
      );
    } else {
      const cipher = nobleGcm(rawKey, iv);
      ciphertext = cipher.encrypt(new Uint8Array(plaintext));
    }

    // Prepend IV
    const out = new Uint8Array(IV_LEN + ciphertext.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(ciphertext), IV_LEN);
    return out.buffer;
  }

  /**
   * @param {ArrayBuffer} packet — [IV (12)] [ciphertext + tag]
   * @returns {Promise<ArrayBuffer>} — decrypted plaintext
   */
  async function decryptChunk(packet) {
    const data = new Uint8Array(packet);
    if (data.byteLength < IV_LEN + TAG_LEN) {
      throw new RangeError('Encrypted packet too short');
    }
    const iv         = data.slice(0, IV_LEN);
    const ciphertext = data.slice(IV_LEN); // includes appended tag

    if (cryptoKey) {
      return crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: TAG_LEN * 8 },
        cryptoKey,
        ciphertext
      );
    } else {
      const cipher = nobleGcm(rawKey, iv);
      const decrypted = cipher.decrypt(ciphertext);
      return decrypted.buffer;
    }
  }

  /* ══════════════════════════════════════════════════════════════════════════
   *  TRANSFER UI
   * ══════════════════════════════════════════════════════════════════════════ */

  /**
   * Create a transfer card in the UI and return update callbacks.
   * @param {'upload'|'download'} direction
   * @param {string} fileName
   * @param {number} fileSize
   * @returns {{ setProgress(pct: number): void, setStatus(text: string, cls?: string): void, el: HTMLElement }}
   */
  function createTransferCard(direction, fileName, fileSize) {
    const card = document.createElement('div');
    card.className = 'transfer-card';
    card.innerHTML = `
      <div class="transfer-header">
        <div class="transfer-icon ${direction}">${direction === 'upload' ? '↑' : '↓'}</div>
        <span class="transfer-name" title=""></span>
        <span class="transfer-size">${formatBytes(fileSize)}</span>
      </div>
      <div class="progress-wrap"><div class="progress-bar" style="width:0%"></div></div>
      <div class="transfer-status">Preparing…</div>
    `;
    card.querySelector('.transfer-name').textContent = fileName;
    card.querySelector('.transfer-name').title = fileName;
    $transfers.prepend(card);
    while ($transfers.children.length > 100) $transfers.lastChild.remove();

    const $bar    = card.querySelector('.progress-bar');
    const $status = card.querySelector('.transfer-status');

    return {
      el: card,
      setProgress(pct) {
        const clamped = Math.min(100, Math.max(0, pct));
        $bar.style.width = clamped.toFixed(1) + '%';
        if (clamped >= 100) $bar.classList.add('done');
      },
      setStatus(text, cls) {
        $status.textContent = text;
        $status.className = 'transfer-status' + (cls ? ' ' + cls : '');
      },
      setDownloadLink(url, fileName) {
        $status.className = 'transfer-status done';
        $status.textContent = '✓ Ready — ';
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName;
        link.textContent = 'Click to Save';
        $status.appendChild(link);
      }
    };
  }

  /* ══════════════════════════════════════════════════════════════════════════
   *  WEBSOCKET CONNECTION
   * ══════════════════════════════════════════════════════════════════════════ */

  let ws = null;
  let peerCount = 0;
  let receiveQueue = Promise.resolve();
  let queuedBytes = 0;
  const MAX_FILE_SIZE = 64 * 1024 * 1024;
  const MAX_INCOMING = 4;
  const completedDownloads = new Map();
  function releaseDownload(url) {
    const item = completedDownloads.get(url);
    if (!item) return;
    URL.revokeObjectURL(url);
    clearTimeout(item.timer);
    item.card.setStatus('Download link expired; resend if needed.');
    completedDownloads.delete(url);
  }
  function clearIncoming(reason) {
    for (const state of incomingFiles.values()) state.card.setStatus(reason, 'error');
    incomingFiles.clear();
  }
  let reconnectAttempts = 0;
  const MAX_RECONNECT = 10;
  const RECONNECT_BASE_MS = 1000;

  /** In-flight incoming file state, keyed by transfer ID */
  const incomingFiles = new Map();

  function connectWS() {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url   = `${proto}://${window.location.host}/ws/${ROOM_ID}`;

    ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';

    ws.addEventListener('open', () => {
      reconnectAttempts = 0;
      $statusDot.className = 'status-dot connected';
      $statusText.textContent = 'Connected';
      hideError();
      log('🟢 Connected to relay');
    });

    ws.addEventListener('close', (e) => {
      $statusDot.className = 'status-dot';
      $statusText.textContent = 'Disconnected';
      peerCount = 0;
      $peerCount.textContent = '';
      clearIncoming('Transfer interrupted; please resend.');

      if (e.code === 4001) {
        showError('Room expired due to inactivity.');
        log('🔴 Room expired');
        return;
      }
      if (e.code === 4003) { showError('Incompatible client protocol. Reopen the shared link.'); return; }
      if (e.code === 4002) {
        showError('Room is full.');
        log('🔴 Room full');
        return;
      }

      // Auto-reconnect with exponential backoff
      if (reconnectAttempts < MAX_RECONNECT) {
        const delay = RECONNECT_BASE_MS * Math.pow(1.5, reconnectAttempts);
        reconnectAttempts++;
        $statusText.textContent = `Reconnecting in ${(delay / 1000).toFixed(0)}s…`;
        log(`↻ Reconnecting (attempt ${reconnectAttempts})…`);
        setTimeout(connectWS, delay);
      } else {
        showError('Unable to reconnect. Please reload the page.');
        $statusDot.className = 'status-dot error';
        log('🔴 Max reconnect attempts reached');
      }
    });

    ws.addEventListener('error', () => {
      $statusDot.className = 'status-dot error';
    });

    const connection = ws;
    ws.addEventListener('message', (event) => {
      const size = typeof event.data === 'string' ? event.data.length * 2 : event.data.byteLength;
      if (queuedBytes + size > 8 * 1024 * 1024) {
        connection.close(4003, 'Receive capacity exceeded');
        showError('Receiver overloaded; reopen the link and resend.');
        return;
      }
      queuedBytes += size;
      receiveQueue = receiveQueue.then(async () => {
        if (ws !== connection || connection.readyState !== WebSocket.OPEN) return;
        if (event.data instanceof ArrayBuffer) {
          const plaintext = new Uint8Array(await decryptChunk(event.data));
          if (plaintext[0] === 0) {
            const msg = JSON.parse(new TextDecoder().decode(plaintext.subarray(1)));
            if (msg.type === 'file_offer') handleFileOffer(msg);
            else if (msg.type === 'file_done') handleFileDone(msg);
            else throw new Error('Unknown encrypted message');
          } else if (plaintext[0] === 1) {
            handleBinaryMessage(plaintext.subarray(1));
          } else throw new Error('Unknown packet type');
          return;
        }
        const msg = JSON.parse(event.data);
        if (msg.type === 'peer_count') {
          if (msg.count < peerCount) clearIncoming('Peer disconnected; please resend.');
          peerCount = msg.count;
          $peerCount.style.display = '';
          $peerCount.textContent = msg.count + (msg.count === 1 ? ' peer' : ' peers');
        } else if (msg.type === 'room_expired') showError('Room expired due to inactivity.');
      }).catch((err) => {
        clearIncoming('Invalid or incomplete transfer; please resend.');
        showError('Could not receive transfer: ' + err.message);
      }).finally(() => { queuedBytes -= size; });
    });
  }

  /* ── Handle incoming file offer ─────────────────────────────────────────── */

  function handleFileOffer(msg) {
    const { transferId, fileName, fileSize, totalChunks } = msg;
    if (!/^[a-f0-9]{16}$/.test(transferId) || typeof fileName !== 'string' ||
        fileName.length < 1 || fileName.length > 255 || !Number.isSafeInteger(fileSize) ||
        fileSize < 0 || fileSize > MAX_FILE_SIZE || totalChunks !== Math.ceil(fileSize / CHUNK_SIZE) ||
        incomingFiles.has(transferId) || incomingFiles.size >= MAX_INCOMING) {
      throw new Error('Invalid offer or receive capacity exceeded (4 files, 64 MiB each)');
    }
    log(`📥 Incoming: ${fileName} (${formatBytes(fileSize)})`);

    const card = createTransferCard('download', fileName, fileSize);
    card.setStatus(`0 / ${totalChunks} chunks`);

    incomingFiles.set(transferId, {
      fileName,
      fileSize,
      totalChunks,
      receivedChunks: 0,
      receivedBytes: 0,
      updatedAt: Date.now(),
      parts: [],
      card,
    });
  }

  /* ── Handle binary (encrypted chunk) ────────────────────────────────────── */

  function handleBinaryMessage(view) {
    if (view.byteLength < 20) throw new Error('Malformed chunk');
    const transferId = new TextDecoder().decode(view.subarray(0, 16));
    const index = new DataView(view.buffer, view.byteOffset + 16, 4).getUint32(0);
    const state = incomingFiles.get(transferId);
    if (!state) throw new Error('Unknown transfer');
    const bytes = view.slice(20);
    const expected = Math.min(CHUNK_SIZE, state.fileSize - state.receivedBytes);
    if (index !== state.receivedChunks || state.receivedChunks >= state.totalChunks || bytes.length !== expected) {
      throw new Error('Out-of-order or invalid chunk');
    }
    state.parts.push(bytes);
    state.receivedChunks++;
    state.receivedBytes += bytes.length;
    state.updatedAt = Date.now();
    state.card.setProgress(state.receivedBytes / state.fileSize * 100);
    state.card.setStatus(`${state.receivedChunks} / ${state.totalChunks} chunks`);
  }

  /* ── Handle file_done — assemble & download ─────────────────────────────── */

  function handleFileDone(msg) {
    const state = incomingFiles.get(msg.transferId);
    if (!state) return;

    if (state.receivedChunks !== state.totalChunks || state.receivedBytes !== state.fileSize) {
      throw new Error('Incomplete file');
    }
    // Assemble the file
    const blob = new Blob(state.parts);
    const url  = URL.createObjectURL(blob);

    // Attempt auto-download
    const a    = document.createElement('a');
    a.href     = url;
    a.download = state.fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();

    // Keep URL alive for 10 minutes in case user needs to click it manually
    completedDownloads.set(url, { size: blob.size, card: state.card,
      timer: setTimeout(() => releaseDownload(url), 10 * 60 * 1000) });
    while (completedDownloads.size > 32 || [...completedDownloads.values()].reduce((n, item) => n + item.size, 0) > 128 * 1024 * 1024) {
      releaseDownload(completedDownloads.keys().next().value);
    }

    state.card.setProgress(100);
    // Provide a manual fallback link in the UI
    state.card.setDownloadLink(url, state.fileName);
    log(`✅ ${state.fileName} ready for download`);

    incomingFiles.delete(msg.transferId);
  }

  /* ══════════════════════════════════════════════════════════════════════════
   *  SENDING FILES
   * ══════════════════════════════════════════════════════════════════════════ */

  async function sendFile(file) {
    let card;
    try {
      const connection = ws;
      if (!connection || connection.readyState !== WebSocket.OPEN || peerCount < 2) {
        throw new Error('Connect another device with the same link before sending.');
      }
      if (file.size > MAX_FILE_SIZE) throw new Error('Files are limited to 64 MiB each.');
      if (!cryptoKey && !rawKey) throw new Error('Encryption key not loaded.');
      const transferId = genId();
      const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
      card = createTransferCard('upload', file.name, file.size);
      const send = async (packet) => {
        const encrypted = await encryptChunk(packet);
        const deadline = Date.now() + 30000;
        while (connection.bufferedAmount > 1024 * 1024) {
          if (connection.readyState !== WebSocket.OPEN || Date.now() > deadline) throw new Error('Connection stalled');
          await new Promise(resolve => setTimeout(resolve, 25));
        }
        if (ws !== connection || connection.readyState !== WebSocket.OPEN || peerCount < 2) throw new Error('Peer disconnected');
        connection.send(encrypted);
      };
      const control = (msg) => send(new Uint8Array([0, ...new TextEncoder().encode(JSON.stringify(msg))]));
      await control({ type: 'file_offer', transferId, fileName: file.name, fileSize: file.size, totalChunks });
      for (let index = 0; index < totalChunks; index++) {
        const raw = new Uint8Array(await file.slice(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE).arrayBuffer());
        const packet = new Uint8Array(21 + raw.length);
        packet[0] = 1;
        packet.set(new TextEncoder().encode(transferId), 1);
        new DataView(packet.buffer).setUint32(17, index);
        packet.set(raw, 21);
        await send(packet);
        card.setProgress((index + 1) / totalChunks * 100);
      }
      await control({ type: 'file_done', transferId });
      card.setProgress(100);
      card.setStatus('✓ Sent to relay', 'done');
      log(`✅ ${file.name} sent to relay`);
    } catch (err) {
      if (card) card.setStatus(err.message, 'error');
      showError(err.message);
    }
  }
  let sendQueue = Promise.resolve();
  function queueFile(file) { sendQueue = sendQueue.then(() => sendFile(file)); }
  setInterval(() => {
    for (const [id, state] of incomingFiles) {
      if (Date.now() - state.updatedAt > 60000) {
        state.card.setStatus('Transfer timed out; please resend.', 'error');
        incomingFiles.delete(id);
      }
    }
  }, 10000);

  /* ══════════════════════════════════════════════════════════════════════════
   *  DRAG & DROP / FILE INPUT
   * ══════════════════════════════════════════════════════════════════════════ */

  $dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    $dropzone.classList.add('drag-over');
  });
  $dropzone.addEventListener('dragleave', () => {
    $dropzone.classList.remove('drag-over');
  });
  $dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    $dropzone.classList.remove('drag-over');
    const files = e.dataTransfer?.files;
    if (files) {
      for (const f of files) queueFile(f);
    }
  });

  $fileInput.addEventListener('change', () => {
    const files = $fileInput.files;
    if (files) {
      for (const f of files) queueFile(f);
    }
    $fileInput.value = ''; // reset so same file can be re-selected
  });

  /* ══════════════════════════════════════════════════════════════════════════
   *  BOOT
   * ══════════════════════════════════════════════════════════════════════════ */

  async function boot() {
    try {
      await importKeyFromFragment();
    } catch (err) {
      showError(err.message);
      return; // error already shown in UI
    }
    connectWS();
    log(`🚀 Room: ${ROOM_ID}`);
  }

  window.addEventListener('hashchange', () => {
    if (window.location.hash.startsWith('#key=')) window.location.reload();
  });
  boot();
})();
