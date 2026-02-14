/**
 * Scope Enforcement Policy
 * Ensures actions stay within user's granted permissions/scope
 */

const DEFAULT_SCOPE = {
  allowedTools: null,          // null = all allowed, array = whitelist
  blockedTools: [],            // Explicit blacklist
  allowedPaths: [],            // File paths the user can access
  allowedHosts: [],            // Network hosts the user can access
  maxFileSize: 10 * 1024 * 1024, // 10MB default
  allowSystemCommands: true,
  allowNetworkAccess: true,
  allowFileWrite: true,
  allowFileRead: true,
};

export function scopeEnforcement(action, context = {}) {
  const scope = { ...DEFAULT_SCOPE, ...(context.scope || {}) };

  // Check tool whitelist
  if (scope.allowedTools !== null) {
    if (!scope.allowedTools.includes(action.tool)) {
      return {
        pass: false,
        reason: `Tool '${action.tool}' is not in allowed tools list`,
        severity: 'high'
      };
    }
  }

  // Check tool blacklist
  if (scope.blockedTools.includes(action.tool)) {
    return {
      pass: false,
      reason: `Tool '${action.tool}' is explicitly blocked`,
      severity: 'high'
    };
  }

  // Check system command permission
  if (action.type === 'system_command' && !scope.allowSystemCommands) {
    return {
      pass: false,
      reason: 'System commands are not allowed in current scope',
      severity: 'high'
    };
  }

  // Check network access permission
  if (action.type === 'network_request' && !scope.allowNetworkAccess) {
    return {
      pass: false,
      reason: 'Network access is not allowed in current scope',
      severity: 'medium'
    };
  }

  // Check file write permission
  if (action.type === 'file_operation' && !scope.allowFileWrite) {
    const writeOps = ['write', 'edit', 'delete', 'mkdir', 'writeFile'];
    if (writeOps.includes(action.tool)) {
      return {
        pass: false,
        reason: 'File write operations are not allowed in current scope',
        severity: 'medium'
      };
    }
  }

  // Check file read permission
  if (action.type === 'file_operation' && !scope.allowFileRead) {
    const readOps = ['read', 'readFile'];
    if (readOps.includes(action.tool)) {
      return {
        pass: false,
        reason: 'File read operations are not allowed in current scope',
        severity: 'medium'
      };
    }
  }

  // Check allowed paths
  if (scope.allowedPaths.length > 0 && action.metadata?.paths?.length > 0) {
    for (const path of action.metadata.paths) {
      const isAllowed = scope.allowedPaths.some(ap => path.startsWith(ap));
      if (!isAllowed) {
        return {
          pass: false,
          reason: `Path '${path}' is outside allowed scope`,
          severity: 'high'
        };
      }
    }
  }

  // Check allowed hosts
  if (scope.allowedHosts.length > 0 && action.metadata?.urls?.length > 0) {
    for (const url of action.metadata.urls) {
      try {
        const host = new URL(url).hostname;
        const isAllowed = scope.allowedHosts.some(ah =>
          host === ah || host.endsWith('.' + ah)
        );
        if (!isAllowed) {
          return {
            pass: false,
            reason: `Host '${host}' is not in allowed hosts list`,
            severity: 'medium'
          };
        }
      } catch {
        // If URL parsing fails, block it
        return {
          pass: false,
          reason: `Unparseable URL: ${url}`,
          severity: 'medium'
        };
      }
    }
  }

  return { pass: true, reason: 'Action within allowed scope', severity: 'none' };
}

export default scopeEnforcement;
