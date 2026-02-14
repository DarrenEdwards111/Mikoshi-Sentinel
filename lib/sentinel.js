/**
 * Mikoshi Sentinel — Deterministic Action Verification for LLM Agent Security
 *
 * @module mikoshi-sentinel
 * @license Apache-2.0
 * @copyright Mikoshi Ltd
 */

import { parseAction } from './action-parser.js';
import { AuditLogger } from './audit.js';
import { IntentVerifier } from './intent-verifier.js';
import allPolicies from './policies/index.js';

export class Sentinel {
  /**
   * @param {Object} config
   * @param {boolean} config.enableIntentVerification - Enable LLM/heuristic intent checking
   * @param {Function} config.llmFn - Async function for LLM calls: (prompt) => string
   * @param {number} config.intentThreshold - Minimum intent confidence (0-1), default 0.5
   * @param {Object} config.audit - Audit logger options
   * @param {boolean} config.useBuiltinPolicies - Load all built-in policies (default true)
   * @param {Object} config.scope - Scope enforcement config
   * @param {Object} config.rateLimits - Rate limit config
   */
  constructor(config = {}) {
    this.policies = [];
    this.auditLog = new AuditLogger(config.audit || {});
    this.config = config;

    // Intent verifier
    if (config.enableIntentVerification !== false) {
      this.intentVerifier = new IntentVerifier({
        llmFn: config.llmFn || null,
        threshold: config.intentThreshold || 0.5,
      });
    } else {
      this.intentVerifier = null;
    }

    // Load built-in policies
    if (config.useBuiltinPolicies !== false) {
      this.addPolicy('privilegeEscalation', allPolicies.privilegeEscalation);
      this.addPolicy('dataExfiltration', allPolicies.dataExfiltration);
      this.addPolicy('internalAccess', allPolicies.internalAccess);
      this.addPolicy('fileTraversal', allPolicies.fileTraversal);
      this.addPolicy('systemCommands', allPolicies.systemCommands);
      this.addPolicy('intentAlignment', allPolicies.intentAlignment);
      this.addPolicy('rateLimit', allPolicies.rateLimit);
      this.addPolicy('scopeEnforcement', allPolicies.scopeEnforcement);
    }
  }

  /**
   * Register a policy rule (deterministic, code-based)
   * @param {string} name - Policy name
   * @param {Function} checkFn - (action, context) => { pass, reason, severity }
   */
  addPolicy(name, checkFn) {
    if (typeof checkFn !== 'function') {
      throw new Error(`Policy '${name}' must be a function`);
    }
    this.policies.push({ name, check: checkFn });
    return this;
  }

  /**
   * Remove a policy by name
   */
  removePolicy(name) {
    this.policies = this.policies.filter(p => p.name !== name);
    return this;
  }

  /**
   * Main verification pipeline
   * @param {Object} rawAction - The proposed action (tool call)
   * @param {Object} context - Verification context (conversation, scope, etc.)
   * @returns {Promise<Object>} Verdict: { allowed, confidence, violations, intent, audit }
   */
  async verify(rawAction, context = {}) {
    const startTime = performance.now();

    // 1. Parse the proposed action
    const action = parseAction(rawAction, context);

    // 2. Run ALL policy checks (deterministic code, not LLM)
    const violations = [];
    const policyResults = [];

    for (const policy of this.policies) {
      try {
        const result = policy.check(action, context);
        policyResults.push({ policy: policy.name, ...result });
        if (!result.pass) {
          violations.push({
            policy: policy.name,
            reason: result.reason,
            severity: result.severity
          });
        }
      } catch (err) {
        violations.push({
          policy: policy.name,
          reason: `Policy error: ${err.message}`,
          severity: 'high'
        });
      }
    }

    // 3. Check intent alignment (optional, probabilistic)
    let intentResult = null;
    if (this.intentVerifier && violations.length === 0) {
      try {
        intentResult = await this.intentVerifier.verify(action, action.conversationContext);
      } catch (err) {
        intentResult = {
          confidence: 0.5,
          aligned: true,
          method: 'error',
          reason: `Intent verification error: ${err.message}`
        };
      }
    }

    // 4. Determine verdict
    const allowed = violations.length === 0;
    const hasCritical = violations.some(v => v.severity === 'critical');

    // Confidence: 1.0 if no violations (deterministic certainty), 0.0 if critical
    let confidence;
    if (allowed) {
      confidence = intentResult ? intentResult.confidence : 1.0;
    } else if (hasCritical) {
      confidence = 0.0;
    } else {
      confidence = 0.2;
    }

    const elapsed = performance.now() - startTime;

    // 5. Build audit record
    const verdict = {
      allowed,
      confidence,
      violations,
      intent: intentResult,
      policyResults,
      action: {
        type: action.type,
        tool: action.tool,
        args: action.args,
        source: action.source,
        timestamp: action.timestamp
      },
      elapsed: `${elapsed.toFixed(2)}ms`
    };

    // Log to audit
    this.auditLog.log(verdict);

    return verdict;
  }

  /**
   * Express middleware factory
   */
  middleware(options = {}) {
    const sentinel = this;
    const contextExtractor = options.contextExtractor || ((req) => ({
      sessionId: req.sessionID || req.ip,
      scope: req.user?.scope || {},
      conversationHistory: req.body?.messages || [],
    }));

    return async (req, res, next) => {
      // Extract the action from the request
      const rawAction = req.body?.action || req.body?.tool_call || req.body;
      const context = contextExtractor(req);

      try {
        const verdict = await sentinel.verify(rawAction, context);

        // Attach verdict to request
        req.sentinelVerdict = verdict;

        if (!verdict.allowed) {
          const status = options.blockStatus || 403;
          return res.status(status).json({
            error: 'Action blocked by Sentinel',
            violations: verdict.violations,
            confidence: verdict.confidence
          });
        }

        next();
      } catch (err) {
        if (options.failOpen) {
          req.sentinelVerdict = { allowed: true, error: err.message };
          return next();
        }
        return res.status(500).json({ error: 'Sentinel verification failed', message: err.message });
      }
    };
  }

  /**
   * Get audit statistics
   */
  stats() {
    return this.auditLog.stats();
  }

  /**
   * Static reference to built-in policies
   */
  static policies = allPolicies;
}

export default Sentinel;
export { parseAction } from './action-parser.js';
export { AuditLogger } from './audit.js';
export { IntentVerifier } from './intent-verifier.js';
export { allPolicies as policies } from './policies/index.js';
