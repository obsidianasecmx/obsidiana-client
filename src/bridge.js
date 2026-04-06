"use strict";

/**
 * WorkerBridge — communication layer between main thread and crypto worker.
 *
 * Abstracts away the differences between Web Workers (browsers), worker_threads (Node.js),
 * and React Native (inline worker shim). Provides a promise‑based messaging API.
 *
 * @private
 */

function _isReactNative() {
  return (
    typeof navigator !== "undefined" && navigator.product === "ReactNative"
  );
}

class WorkerBridge {
  constructor() {
    /** @private {Worker|null} */
    this._worker = null;
    /** @private {Map<number, { resolve: Function, reject: Function }>} */
    this._pending = new Map();
    /** @private {Map<string, Function[]>} */
    this._handlers = new Map();
    /** @private {number} */
    this._msgId = 0;
  }

  /**
   * Initialises the worker (or inline shim).
   *
   * @returns {Promise<void>}
   */
  init() {
    return new Promise((resolve, reject) => {
      const isNode = typeof process !== "undefined" && process.versions?.node;
      const workerCode = this._getWorkerCode();

      if (_isReactNative()) {
        const { createInlineWorker } = require("./worker-inline");
        this._worker = createInlineWorker();
        this._worker.onmessage = (e) => this._onMessage(e.data);
        resolve();
        return;
      }

      if (!isNode) {
        const blob = new Blob([workerCode], { type: "application/javascript" });
        const url = URL.createObjectURL(blob);
        this._worker = new Worker(url);
        URL.revokeObjectURL(url);
        this._worker.onmessage = (e) => this._onMessage(e.data);
        this._worker.onerror = reject;
        resolve();
        return;
      }

      const workerThreads = require("worker_threads");
      const WorkerConstructor = workerThreads.Worker;
      if (!WorkerConstructor) {
        reject(new Error("worker_threads.Worker not available"));
        return;
      }

      if (workerCode && workerCode.length > 0) {
        this._worker = new WorkerConstructor(workerCode, { eval: true });
      } else {
        const path = require("path");
        this._worker = new WorkerConstructor(path.join(__dirname, "worker.js"));
      }

      this._worker.on("message", (msg) => this._onMessage(msg));
      this._worker.on("error", reject);
      this._worker.on("online", resolve);
    });
  }

  /**
   * Returns the worker code (overridden by build system).
   *
   * @returns {string}
   * @private
   */
  _getWorkerCode() {
    return "";
  }

  /**
   * Sends a message to the worker and returns a promise for the response.
   *
   * @param {string} type - Message type (e.g., "connect", "request", "ws:send")
   * @param {object} payload - Message payload
   * @returns {Promise<any>} Resolves with worker's response
   */
  send(type, payload = {}) {
    return new Promise((resolve, reject) => {
      const id = ++this._msgId;
      this._pending.set(id, { resolve, reject });
      this._worker.postMessage({ id, type, payload });
    });
  }

  /**
   * Registers an event handler for worker‑initiated events (e.g., "ws:message").
   *
   * @param {string} event - Event name
   * @param {Function} fn - Callback receiving the message
   */
  on(event, fn) {
    if (!this._handlers.has(event)) this._handlers.set(event, []);
    this._handlers.get(event).push(fn);
  }

  /**
   * Terminates the worker and cleans up.
   */
  terminate() {
    this._worker?.terminate?.();
    this._worker = null;
  }

  /**
   * Handles incoming messages from the worker.
   *
   * @param {object} msg - Worker message
   * @private
   */
  _onMessage(msg) {
    if (!msg.id) {
      const fns = this._handlers.get(msg.type) ?? [];
      for (const fn of fns) fn(msg);
      return;
    }
    if (msg.type === "ws:ready") {
      const entry = this._pending.get(msg.id);
      if (entry) {
        this._pending.delete(msg.id);
        entry.resolve(msg);
      }
      return;
    }
    const entry = this._pending.get(msg.id);
    if (!entry) return;
    this._pending.delete(msg.id);
    if (msg.ok) {
      entry.resolve(msg.data ?? msg);
    } else {
      const err = new Error(msg.error ?? "Worker error");
      err.status = msg.status;
      err.body = msg.body;
      entry.reject(err);
    }
  }
}

module.exports = { WorkerBridge };
