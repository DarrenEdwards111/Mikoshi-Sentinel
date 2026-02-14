/**
 * Built-in Policies Index
 * @module mikoshi-sentinel/policies
 */

export { privilegeEscalation } from './privilege-escalation.js';
export { dataExfiltration } from './data-exfiltration.js';
export { internalAccess } from './internal-access.js';
export { fileTraversal } from './file-traversal.js';
export { systemCommands } from './system-commands.js';
export { intentAlignment } from './intent-alignment.js';
export { rateLimit } from './rate-limit.js';
export { scopeEnforcement } from './scope-enforcement.js';

import { privilegeEscalation } from './privilege-escalation.js';
import { dataExfiltration } from './data-exfiltration.js';
import { internalAccess } from './internal-access.js';
import { fileTraversal } from './file-traversal.js';
import { systemCommands } from './system-commands.js';
import { intentAlignment } from './intent-alignment.js';
import { rateLimit } from './rate-limit.js';
import { scopeEnforcement } from './scope-enforcement.js';

export const allPolicies = {
  privilegeEscalation,
  dataExfiltration,
  internalAccess,
  fileTraversal,
  systemCommands,
  intentAlignment,
  rateLimit,
  scopeEnforcement,
};

export default allPolicies;
