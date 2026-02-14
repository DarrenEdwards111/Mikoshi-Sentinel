/**
 * System Commands Policy
 * Blocks dangerous system commands: rm -rf, shutdown, chmod 777, curl | bash, etc.
 */

const DESTRUCTIVE_COMMANDS = [
  /rm\s+(-[a-z]*f[a-z]*\s+)?(-[a-z]*r[a-z]*\s+)?\//i,   // rm -rf /
  /rm\s+(-[a-z]*r[a-z]*\s+)?(-[a-z]*f[a-z]*\s+)?\//i,   // rm -fr /
  /rm\s+-rf\s/i,
  /mkfs\./i,                     // Format filesystem
  /dd\s+if=.*of=\/dev\//i,       // Overwrite devices
  /shutdown/i,
  /reboot/i,
  /halt\b/i,
  /poweroff/i,
  /init\s+[06]/i,
  /systemctl\s+(poweroff|reboot|halt)/i,
];

const PERMISSION_COMMANDS = [
  /chmod\s+777/,
  /chmod\s+666/,
  /chmod\s+[0-7]*s/i,           // Setuid/setgid
  /chmod\s+a\+[rwx]/i,          // World-writable
  /chattr\s/i,
];

const PIPE_EXECUTION = [
  /curl\s.*\|\s*(ba)?sh/i,       // curl | bash
  /wget\s.*\|\s*(ba)?sh/i,       // wget | bash
  /curl\s.*\|\s*python/i,
  /curl\s.*\|\s*perl/i,
  /curl\s.*\|\s*ruby/i,
  /wget\s.*-O\s*-\s*\|/i,
  /\|\s*bash\s*$/i,
  /\|\s*sh\s*$/i,
];

const REVERSE_SHELL = [
  /\/dev\/tcp\//i,
  /bash\s+-i\s+>&/i,
  /nc\s+.*-e\s+\/bin/i,
  /ncat\s+.*-e\s+\/bin/i,
  /python.*socket.*connect/i,
  /perl.*socket.*INET/i,
  /ruby.*TCPSocket/i,
  /php.*fsockopen/i,
  /mkfifo/i,
];

const FORK_BOMB = [
  /:\(\)\{\s*:\|:&\s*\};:/,     // Classic fork bomb
  /\.\/\s*&\s*\.\//,
  /while\s*true.*fork/i,
];

const HISTORY_TAMPERING = [
  /history\s+-c/i,
  /unset\s+HISTFILE/i,
  /export\s+HISTSIZE=0/i,
  /shred.*\.bash_history/i,
];

export function systemCommands(action, context = {}) {
  const text = action.metadata?.fullText || '';

  if (action.type !== 'system_command' && action.type !== 'tool_call') {
    // Only check system-relevant actions
    if (!text) return { pass: true, reason: 'Not a system command', severity: 'none' };
  }

  const allChecks = [
    { patterns: DESTRUCTIVE_COMMANDS, label: 'Destructive command', severity: 'critical' },
    { patterns: PERMISSION_COMMANDS, label: 'Dangerous permission change', severity: 'high' },
    { patterns: PIPE_EXECUTION, label: 'Pipe-to-shell execution', severity: 'critical' },
    { patterns: REVERSE_SHELL, label: 'Reverse shell attempt', severity: 'critical' },
    { patterns: FORK_BOMB, label: 'Fork bomb detected', severity: 'critical' },
    { patterns: HISTORY_TAMPERING, label: 'History tampering', severity: 'high' },
  ];

  for (const { patterns, label, severity } of allChecks) {
    for (const pattern of patterns) {
      if (pattern.test(text)) {
        return {
          pass: false,
          reason: `${label}: matches ${pattern}`,
          severity
        };
      }
    }
  }

  return { pass: true, reason: 'No dangerous system commands detected', severity: 'none' };
}

export default systemCommands;
