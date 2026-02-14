/**
 * Custom Policy Example — Mikoshi Sentinel
 *
 * Shows how to write and register custom policies.
 */

import { Sentinel } from '../lib/sentinel.js';

// Create sentinel without built-in policies
const sentinel = new Sentinel({
  useBuiltinPolicies: false,
  enableIntentVerification: false
});

// Custom policy: block any action targeting production databases
sentinel.addPolicy('noProductionDB', (action, context) => {
  const text = action.metadata?.fullText || '';
  const urls = action.metadata?.urls || [];

  const prodPatterns = [
    /prod.*\.database/i,
    /production.*db/i,
    /master\.postgres/i,
    /main\.mongodb/i,
  ];

  for (const pattern of prodPatterns) {
    if (pattern.test(text) || urls.some(u => pattern.test(u))) {
      return {
        pass: false,
        reason: `Production database access blocked: ${pattern}`,
        severity: 'critical'
      };
    }
  }

  return { pass: true, reason: 'No production DB access detected', severity: 'none' };
});

// Custom policy: require MFA for destructive operations
sentinel.addPolicy('requireMFA', (action, context) => {
  const destructiveTools = ['delete', 'drop', 'truncate', 'exec'];
  if (destructiveTools.includes(action.tool) && !context.mfaVerified) {
    return {
      pass: false,
      reason: 'MFA required for destructive operations',
      severity: 'high'
    };
  }
  return { pass: true, reason: 'MFA not required or already verified', severity: 'none' };
});

// Custom policy: business hours only
sentinel.addPolicy('businessHours', (action, context) => {
  const hour = new Date().getHours();
  if (hour < 9 || hour > 17) {
    if (action.type === 'system_command') {
      return {
        pass: false,
        reason: `System commands blocked outside business hours (current: ${hour}:00)`,
        severity: 'medium'
      };
    }
  }
  return { pass: true, reason: 'Within business hours or non-restricted action', severity: 'none' };
});

// Test the custom policies
console.log('=== Custom Policy Tests ===\n');

const test1 = await sentinel.verify(
  { tool: 'exec', args: { command: 'SELECT * FROM prod.database.users' } }
);
console.log('Prod DB access:', test1.allowed ? 'ALLOWED' : 'BLOCKED', test1.violations);

const test2 = await sentinel.verify(
  { tool: 'delete', args: { table: 'users' } },
  { mfaVerified: false }
);
console.log('Delete without MFA:', test2.allowed ? 'ALLOWED' : 'BLOCKED', test2.violations);

const test3 = await sentinel.verify(
  { tool: 'delete', args: { table: 'users' } },
  { mfaVerified: true }
);
console.log('Delete with MFA:', test3.allowed ? 'ALLOWED' : 'BLOCKED', test3.violations);

const test4 = await sentinel.verify(
  { tool: 'read', args: { path: './data.json' } }
);
console.log('Safe read:', test4.allowed ? 'ALLOWED' : 'BLOCKED', test4.violations);
