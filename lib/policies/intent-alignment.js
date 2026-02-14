/**
 * Intent Alignment Policy
 * Uses conversation history to verify proposed action matches user's actual request
 * This is a deterministic heuristic layer — for LLM-based intent checking, see intent-verifier.js
 */

const INJECTION_PATTERNS = [
  /ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|rules?)/i,
  /disregard\s+(previous|all|above|prior)/i,
  /forget\s+(everything|all|previous)/i,
  /new\s+instructions?:/i,
  /system\s*prompt\s*override/i,
  /you\s+are\s+now\s+/i,
  /act\s+as\s+(if|though)\s+/i,
  /pretend\s+(you|that)\s+(are|were|have)\s+/i,
  /bypass\s+(security|filter|safety|restriction)/i,
  /jailbreak/i,
  /DAN\s+mode/i,
  /developer\s+mode\s+(enabled|on|activated)/i,
  /sudo\s+mode/i,
  /admin\s+override/i,
  /\[SYSTEM\]/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /BEGIN\s+OVERRIDE/i,
  /IMPORTANT:\s*NEW\s*INSTRUCTIONS/i,
];

const CONTEXT_SHIFT_PATTERNS = [
  /actually,?\s+(instead|rather|forget\s+that)/i,
  /but\s+first,?\s+(do|execute|run)/i,
  /before\s+(that|responding),?\s+(run|execute|do)/i,
  /one\s+more\s+thing[,:]?\s*(run|execute|do|send)/i,
  /also[,:]?\s*(quickly|silently|secretly)\s+(run|execute|send)/i,
  /by\s+the\s+way[,:]?\s*(run|execute|send|delete)/i,
];

const SOCIAL_ENGINEERING = [
  /this\s+is\s+(an?\s+)?emergency/i,
  /urgent[!:]\s*(run|execute|do)/i,
  /the\s+developer\s+(said|wants|asked)/i,
  /authorized\s+by\s+/i,
  /special\s+permission/i,
  /testing\s+mode/i,
  /debug\s+command/i,
  /maintenance\s+mode/i,
];

export function intentAlignment(action, context = {}) {
  const text = action.metadata?.fullText || '';
  const allStrings = action.metadata?.allStrings || [];
  const conversation = action.conversationContext || [];

  // Check for injection patterns in action args
  for (const str of allStrings) {
    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.test(str)) {
        return {
          pass: false,
          reason: `Prompt injection pattern detected: ${pattern}`,
          severity: 'critical'
        };
      }
    }

    for (const pattern of CONTEXT_SHIFT_PATTERNS) {
      if (pattern.test(str)) {
        return {
          pass: false,
          reason: `Context shift attack detected: ${pattern}`,
          severity: 'high'
        };
      }
    }

    for (const pattern of SOCIAL_ENGINEERING) {
      if (pattern.test(str)) {
        return {
          pass: false,
          reason: `Social engineering pattern detected: ${pattern}`,
          severity: 'medium'
        };
      }
    }
  }

  // Check if action source is suspicious
  if (action.source === 'injected' || action.source === 'data') {
    return {
      pass: false,
      reason: 'Action originated from untrusted source',
      severity: 'critical'
    };
  }

  return { pass: true, reason: 'No intent misalignment detected', severity: 'none' };
}

export default intentAlignment;
