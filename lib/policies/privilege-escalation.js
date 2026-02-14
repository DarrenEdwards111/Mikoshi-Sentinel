/**
 * Privilege Escalation Policy
 * Detects attempts to spawn agents, access admin routes, modify configs, escalate permissions
 */

const ADMIN_PATTERNS = [
  /sudo\s/i,
  /su\s+-?\s*root/i,
  /chmod\s+[0-7]*7[0-7]*/i,
  /chown\s+root/i,
  /usermod\s/i,
  /adduser\s/i,
  /useradd\s/i,
  /passwd\s/i,
  /visudo/i,
  /\/etc\/sudoers/i,
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /setuid/i,
  /setgid/i,
  /capability\s+add/i,
  /--privileged/i,
  /--cap-add/i,
];

const AGENT_SPAWN_PATTERNS = [
  /spawn\s+agent/i,
  /create\s+agent/i,
  /fork\s+process/i,
  /child_process/i,
  /cluster\.fork/i,
  /worker_threads/i,
];

const CONFIG_PATTERNS = [
  /\/etc\/ssh/i,
  /\.ssh\/authorized_keys/i,
  /\.bashrc/i,
  /\.profile/i,
  /\.env/i,
  /config\.(json|yaml|yml|toml|ini)/i,
  /\.git\/config/i,
  /crontab/i,
  /systemctl\s+(enable|start|restart)/i,
];

const ADMIN_ROUTE_PATTERNS = [
  /\/admin\//i,
  /\/api\/admin/i,
  /\/internal\//i,
  /\/management\//i,
  /\/actuator\//i,
  /\/debug\//i,
  /\/console\//i,
];

export function privilegeEscalation(action, context = {}) {
  const text = action.metadata?.fullText || '';
  const urls = action.metadata?.urls || [];

  // Check command patterns
  for (const pattern of ADMIN_PATTERNS) {
    if (pattern.test(text)) {
      return {
        pass: false,
        reason: `Privilege escalation detected: matches pattern ${pattern}`,
        severity: 'critical'
      };
    }
  }

  // Check agent spawning
  for (const pattern of AGENT_SPAWN_PATTERNS) {
    if (pattern.test(text)) {
      return {
        pass: false,
        reason: `Agent spawn attempt detected: matches pattern ${pattern}`,
        severity: 'high'
      };
    }
  }

  // Check config modification
  if (action.type === 'file_operation' || action.type === 'system_command') {
    for (const pattern of CONFIG_PATTERNS) {
      if (pattern.test(text)) {
        return {
          pass: false,
          reason: `Configuration modification attempt: matches pattern ${pattern}`,
          severity: 'high'
        };
      }
    }
  }

  // Check admin route access
  for (const url of urls) {
    for (const pattern of ADMIN_ROUTE_PATTERNS) {
      if (pattern.test(url)) {
        return {
          pass: false,
          reason: `Admin route access attempt: ${url}`,
          severity: 'high'
        };
      }
    }
  }

  return { pass: true, reason: 'No privilege escalation detected', severity: 'none' };
}

export default privilegeEscalation;
