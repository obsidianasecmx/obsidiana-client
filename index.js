"use strict";

/**
 * Obsidiana Client — HTTP and WebSocket client with end-to-end encryption.
 *
 * Provides transparent E2E encryption for HTTP requests and WebSocket
 * connections. Handles the full handshake (PoW + ECDH + ECDSA) automatically,
 * including server identity verification.
 *
 * @module obsidiana-client
 */

const { ObsidianaClient } = require("./src/client");
const { ObsidianaWSClient } = require("./src/ws");

/**
 * Creates an encrypted HTTP client.
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
