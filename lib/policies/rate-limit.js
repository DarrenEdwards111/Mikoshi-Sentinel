/**
 * Rate Limit Policy
 * Prevents rapid-fire tool calls that may indicate automated attacks
 */

// In-memory store for rate tracking
const callHistory = new Map();

const DEFAULT_LIMITS = {
  maxCallsPerMinute: 30,
  maxCallsPerSecond: 5,
  maxIdenticalCalls: 3,      // Same tool+args within 10 seconds
  burstWindow: 1000,          // ms
  burstMax: 10,
};

export function rateLimit(action, context = {}) {
  const limits = { ...DEFAULT_LIMITS, ...(context.rateLimits || {}) };
  const now = Date.now();
  const key = context.sessionId || context.userId || 'default';

  // Initialize history for this key
  if (!callHistory.has(key)) {
    callHistory.set(key, []);
  }

  const history = callHistory.get(key);

  // Clean old entries (>60s)
  while (history.length > 0 && now - history[0].timestamp > 60000) {
    history.shift();
  }

  // Check per-minute limit
  if (history.length >= limits.maxCallsPerMinute) {
    return {
      pass: false,
      reason: `Rate limit exceeded: ${history.length} calls in last minute (max: ${limits.maxCallsPerMinute})`,
      severity: 'high'
    };
  }

  // Check per-second limit
  const lastSecond = history.filter(h => now - h.timestamp < 1000);
  if (lastSecond.length >= limits.maxCallsPerSecond) {
    return {
      pass: false,
      reason: `Rate limit exceeded: ${lastSecond.length} calls in last second (max: ${limits.maxCallsPerSecond})`,
      severity: 'high'
    };
  }

  // Check identical calls
  const actionKey = `${action.tool}:${JSON.stringify(action.args)}`;
  const recentIdentical = history.filter(
    h => h.actionKey === actionKey && now - h.timestamp < 10000
  );
  if (recentIdentical.length >= limits.maxIdenticalCalls) {
    return {
      pass: false,
      reason: `Repeated identical action detected (${recentIdentical.length + 1} times in 10s)`,
      severity: 'medium'
    };
  }

  // Check burst
  const burstWindow = history.filter(h => now - h.timestamp < limits.burstWindow);
  if (burstWindow.length >= limits.burstMax) {
    return {
      pass: false,
      reason: `Burst rate exceeded: ${burstWindow.length} calls in ${limits.burstWindow}ms`,
      severity: 'high'
    };
  }

  // Record this call
  history.push({ timestamp: now, actionKey });

  return { pass: true, reason: 'Within rate limits', severity: 'none' };
}

/**
 * Reset rate limit history (for testing)
 */
rateLimit.reset = () => callHistory.clear();

export default rateLimit;
