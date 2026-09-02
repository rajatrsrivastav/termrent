import crypto from 'node:crypto';

/**
 * AES-256-GCM chunk encryption/decryption for Node.js (CLI-to-CLI transfers).
 *
 * Wire format per encrypted chunk:
 *   [12-byte IV] [ciphertext...] [16-byte auth tag]
 *
 * The AES key is always 32 bytes (256 bits), derived from the base64url-encoded
 * key that lives exclusively in the URL fragment — never sent to the server.
 */

const IV_LENGTH  = 12; // 96-bit IV recommended for GCM
const TAG_LENGTH = 16; // 128-bit authentication tag

/**
 * Generate a cryptographically random 256-bit AES key.
 * @returns {Buffer} 32-byte key
 */
export function generateKey() {
  return crypto.randomBytes(32);
}

/**
 * Encode a raw key buffer to a URL-safe base64 string (no padding).
 * @param {Buffer} keyBuf
 * @returns {string}
 */
export function keyToBase64Url(keyBuf) {
  return keyBuf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a base64url-encoded key string back to a Buffer.
 * @param {string} b64url
 * @returns {Buffer}
 */
export function base64UrlToKey(b64url) {
  if (typeof b64url !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(b64url)) {
    throw new TypeError('Key must be a canonical 256-bit base64url string');
  }
  const key = Buffer.from(b64url, 'base64url');
  if (key.toString('base64url') !== b64url) throw new TypeError('Invalid key encoding');
  return key;
}

/**
 * Encrypt a plaintext chunk using AES-256-GCM.
 *
 * @param {Buffer} plaintext  — the raw chunk bytes
 * @param {Buffer} key        — 32-byte AES key
 * @returns {Buffer}          — [IV (12)] [Ciphertext] [AuthTag (16)]
 */
export function encryptChunk(plaintext, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new TypeError('Key must be a 32-byte Buffer');
  }

  const iv     = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
    authTagLength: TAG_LENGTH,
  });

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag       = cipher.getAuthTag();

  // Wire format: IV || Ciphertext || Tag
  return Buffer.concat([iv, encrypted, tag]);
}

/**
 * Decrypt an AES-256-GCM encrypted chunk.
 *
 * @param {Buffer} packet  — [IV (12)] [Ciphertext] [AuthTag (16)]
 * @param {Buffer} key     — 32-byte AES key
 * @returns {Buffer}       — decrypted plaintext
 * @throws {Error}         — on authentication failure (tampered data)
 */
export function decryptChunk(packet, key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new TypeError('Key must be a 32-byte Buffer');
  }
  if (!Buffer.isBuffer(packet) || packet.length < IV_LENGTH + TAG_LENGTH) {
    throw new RangeError('Encrypted packet too short');
  }

  const iv         = packet.subarray(0, IV_LENGTH);
  const tag        = packet.subarray(-TAG_LENGTH);
  const ciphertext = packet.subarray(IV_LENGTH, -TAG_LENGTH);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {
    authTagLength: TAG_LENGTH,
  });
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('AES-GCM decryption failed — data may be tampered');
  }
}

/**
 * Generate a short, human-friendly room ID.
 * @param {number} [length=6]
 * @returns {string}
 */
export function generateRoomId(length = 6) {
  const alphabet = 'abcdefghijkmnpqrstuvwxyz23456789'; // no ambiguous chars
  let id = '';
  if (!Number.isInteger(length) || length < 3 || length > 32) throw new RangeError('Room length must be 3–32');
  for (let i = 0; i < length; i++) {
    id += alphabet[crypto.randomInt(alphabet.length)];
  }
  return id;
}
