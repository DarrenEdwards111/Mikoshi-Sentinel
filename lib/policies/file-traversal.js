/**
 * File Traversal Policy
 * Blocks path traversal attacks including ../, ~/, symlink attacks, null bytes
 */

const TRAVERSAL_PATTERNS = [
  /\.\.\//,                    // Standard traversal
  /\.\.\\/,                    // Windows traversal
  /\.\.%2[fF]/,               // URL-encoded traversal
  /\.\.%5[cC]/,               // URL-encoded backslash
  /%2[eE]%2[eE]/,             // Double URL-encoded dots
  /\.\.[;|&]/,                // Traversal with command injection
  /\.\.%00/,                  // Null byte traversal
  /\.\.%0[dDaA]/,             // CR/LF traversal
];

const DANGEROUS_PATHS = [
  /^~\//,                      // Home directory reference
  /^\/etc\//,                  // System config
  /^\/proc\//,                 // Process info
  /^\/sys\//,                  // Kernel info
  /^\/dev\//,                  // Devices
  /^\/root\//,                 // Root home
  /^\/var\/log\//,             // System logs
  /^\/boot\//,                 // Boot partition
  /^\/mnt\//,                  // Mounted drives
  /^[A-Z]:\\/i,               // Windows absolute paths
];

const NULL_BYTE_PATTERNS = [
  /\x00/,                     // Literal null byte
  /%00/,                      // URL-encoded null
  /\0/,                       // String null
  /\\0/,                      // Escaped null
];

const SYMLINK_PATTERNS = [
  /ln\s+-s/i,                 // Creating symlinks
  /symlink\(/i,               // Node symlink
  /readlink/i,                // Reading symlinks
];

export function fileTraversal(action, context = {}) {
  const text = action.metadata?.fullText || '';
  const paths = action.metadata?.paths || [];
  const allStrings = action.metadata?.allStrings || [];

  // Check all strings for traversal patterns
  for (const str of [...allStrings, text]) {
    for (const pattern of TRAVERSAL_PATTERNS) {
      if (pattern.test(str)) {
        return {
          pass: false,
          reason: `Path traversal detected: ${pattern}`,
          severity: 'critical'
        };
      }
    }

    // Null byte injection
    for (const pattern of NULL_BYTE_PATTERNS) {
      if (pattern.test(str)) {
        return {
          pass: false,
          reason: 'Null byte injection detected in path',
          severity: 'critical'
        };
      }
    }
  }

  // Check extracted paths
  for (const p of paths) {
    for (const pattern of DANGEROUS_PATHS) {
      if (pattern.test(p)) {
        // Allow if explicitly in user's allowed paths
        const allowedPaths = context.allowedPaths || [];
        if (!allowedPaths.some(ap => p.startsWith(ap))) {
          return {
            pass: false,
            reason: `Access to restricted path: ${p}`,
            severity: 'high'
          };
        }
      }
    }
  }

  // Check for symlink creation
  if (action.type === 'system_command' || action.type === 'file_operation') {
    for (const pattern of SYMLINK_PATTERNS) {
      if (pattern.test(text)) {
        return {
          pass: false,
          reason: `Symlink manipulation detected: ${pattern}`,
          severity: 'medium'
        };
      }
    }
  }

  return { pass: true, reason: 'No file traversal detected', severity: 'none' };
}

export default fileTraversal;
