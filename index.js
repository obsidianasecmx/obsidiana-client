"use strict";

/**
 * Obsidiana Client — HTTP and WebSocket client with end-to-end encryption.
 *
 * A zero‑dependency client library built on top of obsidiana-protocol.
 * Provides transparent E2E encryption for HTTP requests and WebSocket
 * connections. Handles the full handshake (PoW + ECDH + ECDSA) automatically,
 * including server identity verification.
 *
 * All requests are encrypted by default. The client manages session keys,
 * nonce tracking, and automatic decryption of responses.
 *
 * @module obsidiana-client
 *
 * @example
 * // HTTP client
 * const { createClient } = require('@obsidianasecmx/obsidiana-server');
 *
 * const client = createClient({ url: 'https://api.example.com' });
 * await client.connect();
 *
 * const user = await client.get('/api/users/42');
 * const created = await client.post('/api/users', { name: 'Kevin' });
 *
 * client.destroy();
 *
 * @example
 * // WebSocket client
 * const { createWSClient } = require('@obsidianasecmx/obsidiana-server');
 *
 * const ws = createWSClient({ url: 'wss://api.example.com/live' });
 * await ws.connect();
 *
 * ws.on('message', (data) => console.log('Received:', data));
 * await ws.send({ event: 'ping' });
 *
 * ws.close();
 */

const { ObsidianaClient } = require("./src/client");
const { ObsidianaWSClient } = require("./src/ws");

/**
 * Creates an encrypted HTTP client.
 *
 * The client handles the full Obsidiana handshake (PoW + ECDH + ECDSA)
 * automatically when `connect()` is called. All subsequent HTTP requests
 * are encrypted using AES-GCM-256 with per-request nonces.
 *
 * @param {object} options - Client configuration
 * @param {string} options.url - Base URL of the Obsidiana server
 * @param {string} [options.serverPublicKey] - Server's ECDSA public key for identity verification
 * @param {number} [options.timeout=30000] - Request timeout in milliseconds
 * @returns {ObsidianaClient} Configured HTTP client instance
 */
function createClient(options) {
  return new ObsidianaClient(options);
}

/**
 * Creates an encrypted WebSocket client.
 *
 * The client performs the Obsidiana handshake over the WebSocket connection
 * automatically. All messages sent via `send()` are encrypted; all received
 * messages are decrypted before being emitted.
 *
 * @param {object} options - Client configuration
 * @param {string} options.url - WebSocket URL of the Obsidiana server
 * @param {string} [options.serverPublicKey] - Server's ECDSA public key for identity verification
 * @param {number} [options.timeout=30000] - Connection timeout in milliseconds
 * @returns {ObsidianaWSClient} Configured WebSocket client instance
 */
function createWSClient(options) {
  return new ObsidianaWSClient(options);
}

/**
 * @exports
 * @property {Function} createClient - Factory for encrypted HTTP client
 * @property {Function} createWSClient - Factory for encrypted WebSocket client
 */
module.exports = { createClient, createWSClient };
