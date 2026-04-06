"use strict";

/**
 * Obsidiana Client — HTTP and WebSocket client with end‑to‑end encryption.
 *
 * Zero‑dependency client library built on obsidiana‑protocol. Provides transparent
 * E2E encryption for HTTP requests and WebSocket connections. Automatically handles
 * handshake (PoW + ECDH + ECDSA) including server identity verification.
 *
 * @module obsidiana-client
 * @public
 */

const { ObsidianaClient } = require("./src/client");
const { ObsidianaWSClient } = require("./src/ws");

/**
 * Creates an encrypted HTTP client.
 *
 * The client performs the full Obsidiana handshake when `connect()` is called.
 * All subsequent HTTP requests are encrypted using AES‑GCM‑256 with per‑request nonces.
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
 * The client performs the Obsidiana handshake over the WebSocket connection.
 * All messages sent via `send()` are encrypted; received messages are decrypted
 * before being emitted.
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

module.exports = { createClient, createWSClient };
