"use strict";

/**
 * Worker Bridge — Communication layer between main thread and crypto worker.
 *
 * Provides a Promise-based messaging interface to a Web Worker (or worker_thread)
 * that handles all cryptographic operations. The bridge automatically manages
 * message IDs, pending promises, and event routing.
 *
 * @module bridge
 * @private
 */

function _isReactNative() {
  return (
    typeof navigator !== "undefined" && navigator.product === "ReactNative"
  );
}

class WorkerBridge {
  constructor() {
    this._worker = null;
    this._pending = new Map();
    this._handlers = new Map();
    this._msgId = 0;
  }

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

  _getWorkerCode() {
    return "";
  }

  send(type, payload = {}) {
    return new Promise((resolve, reject) => {
      const id = ++this._msgId;
      this._pending.set(id, { resolve, reject });
      this._worker.postMessage({ id, type, payload });
    });
  }

  on(event, fn) {
    if (!this._handlers.has(event)) this._handlers.set(event, []);
    this._handlers.get(event).push(fn);
  }

  terminate() {
    this._worker?.terminate?.();
    this._worker = null;
  }

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
