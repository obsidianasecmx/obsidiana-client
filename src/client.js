"use strict";

/**
 * Obsidiana HTTP Client — Encrypted HTTP client with automatic handshake.
 *
 * Provides an HTTP client that automatically handles the Obsidiana handshake
 * and encrypts all requests/decrypts all responses using AES-GCM-256.
 *
 * The client runs the cryptographic operations in a Web Worker (or worker_thread)
 * to keep the main thread responsive. All encryption is transparent to the user.
 *
 * @module client
 * @public
 *
 * @example
 * const { createClient } = require('@obsidianasecmx/obsidiana-server');
 *
 * const client = createClient({ url: 'https://api.example.com' });
 * await client.connect();
 *
 * const user = await client.get('/api/users/42');
 * const created = await client.post('/api/users', { name: 'Kevin' });
 * await client.patch('/api/users/42', { active: false });
 * await client.delete('/api/users/42');
 *
 * client.destroy();
 */

const { WorkerBridge } = require("./bridge");

/**
 * Encrypted HTTP client with automatic handshake and request/response encryption.
 *
 * All HTTP methods (GET, POST, PUT, PATCH, DELETE) are supported. The client
 * automatically:
 * - Performs PoW challenge
 * - Verifies server identity via ECDSA
 * - Completes ECDH key exchange
 * - Encrypts all requests with AES-GCM-256
 * - Decrypts all responses
 *
 * @example
 * const client = new ObsidianaClient({ url: 'https://api.example.com' });
 * await client.connect();
 *
 * // All requests are automatically encrypted
 * const data = await client.get('/api/data');
 *
 * // Responses are automatically decrypted
 * console.log(data); // plain JavaScript object
 */
class ObsidianaClient {
  /**
   * Creates a new Obsidiana HTTP client.
   *
   * @param {object} options - Client configuration
   * @param {string} options.url - Base URL of the Obsidiana server (e.g., 'https://api.example.com')
   * @throws {Error} If `url` is not provided
   */
  constructor(options = {}) {
    if (!options.url)
      throw new Error("[obsidian-client] options.url is required");

    /** @private {string} Base URL without trailing slash */
    this._url = options.url.replace(/\/$/, "");
    /** @private {WorkerBridge} Bridge to the crypto worker */
    this._bridge = new WorkerBridge();
    /** @private {boolean} Whether the client is connected and handshake complete */
    this._connected = false;
  }

  /**
   * Connects to the server and performs the full Obsidiana handshake.
   *
   * Steps:
   * 1. Initializes the Web Worker
   * 2. Sends connection request with server URL
   * 3. Worker handles PoW, server verification, and ECDH handshake
   * 4. Session key derived and stored in worker
   *
   * @returns {Promise<this>} Current instance for method chaining
   */
  async connect() {
    await this._bridge.init();
    await this._bridge.send("connect", { url: this._url });
    this._connected = true;
    return this;
  }

  /**
   * Performs an encrypted GET request.
   *
   * @param {string} path - Request path (e.g., '/api/users/42')
   * @returns {Promise<any>} Decrypted response body
   */
  get(path) {
    return this._request("GET", path);
  }

  /**
   * Performs an encrypted POST request.
   *
   * @param {string} path - Request path (e.g., '/api/users')
   * @param {object} [body={}] - Request body (will be encrypted)
   * @returns {Promise<any>} Decrypted response body
   */
  post(path, body = {}) {
    return this._request("POST", path, body);
  }

  /**
   * Performs an encrypted PUT request.
   *
   * @param {string} path - Request path (e.g., '/api/users/42')
   * @param {object} [body={}] - Request body (will be encrypted)
   * @returns {Promise<any>} Decrypted response body
   */
  put(path, body = {}) {
    return this._request("PUT", path, body);
  }

  /**
   * Performs an encrypted PATCH request.
   *
   * @param {string} path - Request path (e.g., '/api/users/42')
   * @param {object} [body={}] - Request body (will be encrypted)
   * @returns {Promise<any>} Decrypted response body
   */
  patch(path, body = {}) {
    return this._request("PATCH", path, body);
  }

  /**
   * Performs an encrypted DELETE request.
   *
   * @param {string} path - Request path (e.g., '/api/users/42')
   * @param {object} [body={}] - Request body (optional, will be encrypted)
   * @returns {Promise<any>} Decrypted response body
   */
  delete(path, body = {}) {
    return this._request("DELETE", path, body);
  }

  /**
   * Internal method to send an encrypted HTTP request via the worker.
   *
   * @param {string} method - HTTP method (GET, POST, etc.)
   * @param {string} path - Request path
   * @param {object} [body={}] - Request body
   * @returns {Promise<any>} Decrypted response body
   * @throws {Error} If client is not connected
   * @private
   */
  _request(method, path, body = {}) {
    this._assertConnected();
    return this._bridge.send("request", { method, path, body });
  }

  /**
   * Asserts that the client is connected.
   *
   * @throws {Error} If `connect()` has not been called or connection failed
   * @private
   */
  _assertConnected() {
    if (!this._connected) {
      throw new Error("[obsidian-client] Not connected. Call connect() first.");
    }
  }

  /**
   * Destroys the client and terminates the worker.
   *
   * Cleans up all resources. The client cannot be reused after this call.
   */
  destroy() {
    this._bridge.terminate();
    this._connected = false;
  }
}

module.exports = { ObsidianaClient };
