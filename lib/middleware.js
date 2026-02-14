/**
 * Express Middleware — Standalone middleware export
 * @module mikoshi-sentinel/middleware
 */

import { Sentinel } from './sentinel.js';

/**
 * Create Sentinel middleware with default or custom config
 * @param {Object} config - Sentinel configuration
 * @param {Object} middlewareOptions - Middleware-specific options
 * @returns {Function} Express middleware
 */
export function createMiddleware(config = {}, middlewareOptions = {}) {
  const sentinel = new Sentinel(config);
  return sentinel.middleware(middlewareOptions);
}

export default createMiddleware;
