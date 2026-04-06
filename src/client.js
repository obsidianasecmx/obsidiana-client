"use strict";

/**
 * Obsidiana HTTP Client — Encrypted HTTP client with automatic handshake.
 *
 * Provides an HTTP client that automatically handles the Obsidiana handshake
 * and encrypts all requests/decrypts all responses using AES-GCM-256.
 *
 * @module client
 * @public
 */

const { WorkerBridge } = require("./bridge");

/**
 * Encrypted HTTP client with automatic handshake and request/response encryption.
 */
class ObsidianaClient {
  /**
   * Creates a new Obsidiana HTTP client.
   *
   * @param {object} options - Client configuration
   * @param {string} options.url - Base URL of the Obsidiana server
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
  get(path, body = {}) {
    return this._request("GET", path, body);
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
    return this._bridge.send("request", { method, path, body: body || {} });
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
   */
  destroy() {
    this._bridge.terminate();
    this._connected = false;
  }
}

module.exports = { ObsidianaClient };
