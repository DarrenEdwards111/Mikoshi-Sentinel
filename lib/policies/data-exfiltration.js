/**
 * Data Exfiltration Policy
 * Blocks sending user data to external URLs, detects encoded data in URLs
 */

const SUSPICIOUS_URL_PATTERNS = [
  /\?.*=(eyJ|data:|base64)/i,           // Base64/data in query params
  /webhook\.site/i,                       // Known exfil endpoints
  /requestbin/i,
  /ngrok\.io/i,
  /burpcollaborator/i,
  /interact\.sh/i,
  /pipedream/i,
  /hookbin/i,
  /postb\.in/i,
  /canarytokens/i,
];

const DATA_ENCODING_IN_URL = [
  /%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}/i, // Heavy URL encoding
  /[A-Za-z0-9+/]{40,}={0,2}/,                              // Long base64 in URL
  /&#x?[0-9a-f]+;/i,                                        // HTML entities
];

const EXFIL_COMMANDS = [
  /curl\s+.*-d\s/i,
  /curl\s+.*--data/i,
  /curl\s+.*-X\s*POST/i,
  /wget\s+.*--post/i,
  /nc\s+.*\d+\.\d+\.\d+\.\d+/i,       // netcat to IP
  /ncat\s/i,
  /\.upload\(/i,
  /fetch\(.*method.*POST/i,
  /XMLHttpRequest/i,
];

const SENSITIVE_DATA_PATTERNS = [
  /password/i,
  /api[_-]?key/i,
  /secret/i,
  /token/i,
  /private[_-]?key/i,
  /credit[_-]?card/i,
  /ssn/i,
  /social[_-]?security/i,
];

export function dataExfiltration(action, context = {}) {
  const text = action.metadata?.fullText || '';
  const urls = action.metadata?.urls || [];
  const encodings = action.metadata?.encodings || [];

  // Check for suspicious exfil endpoints
  for (const url of urls) {
    for (const pattern of SUSPICIOUS_URL_PATTERNS) {
      if (pattern.test(url)) {
        return {
          pass: false,
          reason: `Potential data exfiltration endpoint: ${url}`,
          severity: 'critical'
        };
      }
    }

    // Check for encoded data in URLs
    for (const pattern of DATA_ENCODING_IN_URL) {
      if (pattern.test(url)) {
        return {
          pass: false,
          reason: `Encoded data detected in URL: possible exfiltration`,
          severity: 'high'
        };
      }
    }
  }

  // Check for exfil commands
  for (const pattern of EXFIL_COMMANDS) {
    if (pattern.test(text)) {
      // Check if sending to external URL (not localhost)
      const hasExternalUrl = urls.some(u => {
        try {
          const host = new URL(u).hostname;
          return !['localhost', '127.0.0.1', '::1'].includes(host) &&
                 !host.startsWith('192.168.') && !host.startsWith('10.');
        } catch { return true; }
      });

      if (hasExternalUrl || !urls.length) {
        return {
          pass: false,
          reason: `Data exfiltration command detected: matches ${pattern}`,
          severity: 'critical'
        };
      }
    }
  }

  // Check for sensitive data being sent externally
  if (urls.length > 0) {
    for (const pattern of SENSITIVE_DATA_PATTERNS) {
      if (pattern.test(text)) {
        const hasExternal = urls.some(u => {
          try {
            const host = new URL(u).hostname;
            return !['localhost', '127.0.0.1'].includes(host);
          } catch { return true; }
        });
        if (hasExternal) {
          return {
            pass: false,
            reason: `Sensitive data may be sent to external URL`,
            severity: 'high'
          };
        }
      }
    }
  }

  return { pass: true, reason: 'No data exfiltration detected', severity: 'none' };
}

export default dataExfiltration;
