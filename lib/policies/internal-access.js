/**
 * Internal Access Policy
 * Blocks access to localhost, private IPs, and internal network addresses (SSRF prevention)
 */

const INTERNAL_HOSTS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '[::1]',
  '0177.0.0.1',        // Octal
  '2130706433',         // Decimal
  '0x7f000001',         // Hex
  'metadata.google.internal',
  'metadata.aws.internal',
  '169.254.169.254',    // Cloud metadata
  'instance-data',
];

const INTERNAL_IP_PATTERNS = [
  /^10\.\d+\.\d+\.\d+/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  /^192\.168\.\d+\.\d+/,
  /^fc[0-9a-f]{2}:/i,    // IPv6 ULA
  /^fd[0-9a-f]{2}:/i,    // IPv6 ULA
  /^fe80:/i,              // IPv6 link-local
  /^127\./,               // Loopback range
  /^0\./,                 // 0.0.0.0/8
];

const INTERNAL_URL_SCHEMES = [
  /^file:\/\//i,
  /^gopher:\/\//i,
  /^dict:\/\//i,
  /^ftp:\/\//i,
  /^ldap:\/\//i,
  /^tftp:\/\//i,
];

export function internalAccess(action, context = {}) {
  const urls = action.metadata?.urls || [];
  const text = action.metadata?.fullText || '';

  for (const url of urls) {
    let hostname;
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      // If URL parsing fails, check raw text
      hostname = url.toLowerCase();
    }

    // Direct host match
    if (INTERNAL_HOSTS.includes(hostname)) {
      return {
        pass: false,
        reason: `Internal network access blocked: ${hostname}`,
        severity: 'critical'
      };
    }

    // IP range match
    for (const pattern of INTERNAL_IP_PATTERNS) {
      if (pattern.test(hostname)) {
        return {
          pass: false,
          reason: `Private IP access blocked: ${hostname}`,
          severity: 'critical'
        };
      }
    }
  }

  // Check for internal URL schemes
  for (const pattern of INTERNAL_URL_SCHEMES) {
    if (pattern.test(text)) {
      return {
        pass: false,
        reason: `Internal URL scheme detected: ${pattern}`,
        severity: 'high'
      };
    }
  }

  // Check for cloud metadata access patterns
  if (/metadata.*(?:latest|v1|computeMetadata)/i.test(text)) {
    return {
      pass: false,
      reason: 'Cloud metadata endpoint access attempt detected',
      severity: 'critical'
    };
  }

  // Check for DNS rebinding indicators
  if (/\.nip\.io|\.sslip\.io|\.xip\.io/i.test(text)) {
    return {
      pass: false,
      reason: 'DNS rebinding service detected',
      severity: 'high'
    };
  }

  return { pass: true, reason: 'No internal access attempts detected', severity: 'none' };
}

export default internalAccess;
