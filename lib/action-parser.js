/**
 * Action Parser — Parses tool calls into structured actions
 * @module mikoshi-sentinel/action-parser
 */

/**
 * @typedef {Object} ParsedAction
 * @property {string} type - Action type (tool_call, api_request, file_operation, network_request, system_command)
 * @property {string} tool - Tool name
 * @property {Object} args - Tool arguments
 * @property {string} source - Who initiated (assistant, user, system)
 * @property {Array} conversationContext - Recent conversation messages
 * @property {Date} timestamp - When the action was proposed
 * @property {Object} metadata - Extracted metadata for policy checks
 */

/**
 * Extract URLs from a string
 */
function extractUrls(str) {
  if (typeof str !== 'string') return [];
  const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
  return str.match(urlRegex) || [];
}

/**
 * Extract file paths from a string
 */
function extractPaths(str) {
  if (typeof str !== 'string') return [];
  const pathRegex = /(?:\/[\w.\-~]+)+|(?:\.\.\/[\w.\-~\/]*)|(?:~\/[\w.\-~\/]*)/g;
  return str.match(pathRegex) || [];
}

/**
 * Detect if a string contains encoded content
 */
function detectEncoding(str) {
  if (typeof str !== 'string') return [];
  const encodings = [];
  // Base64
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(str.trim())) {
    encodings.push('base64');
  }
  // URL encoding
  if (/%[0-9A-Fa-f]{2}/.test(str)) {
    encodings.push('url-encoded');
  }
  // Unicode escapes
  if (/\\u[0-9A-Fa-f]{4}/.test(str)) {
    encodings.push('unicode-escaped');
  }
  // Hex encoding
  if (/^[0-9A-Fa-f]{20,}$/.test(str.trim())) {
    encodings.push('hex');
  }
  return encodings;
}

/**
 * Classify the action type based on tool and args
 */
function classifyAction(tool, args) {
  const toolLower = (tool || '').toLowerCase();

  if (['exec', 'shell', 'bash', 'terminal', 'run'].includes(toolLower)) {
    return 'system_command';
  }
  if (['read', 'write', 'edit', 'delete', 'mkdir', 'readFile', 'writeFile'].includes(toolLower)) {
    return 'file_operation';
  }
  if (['fetch', 'http', 'request', 'curl', 'web_fetch', 'web_search'].includes(toolLower)) {
    return 'network_request';
  }
  if (['browser', 'navigate', 'open'].includes(toolLower)) {
    return 'browser_action';
  }
  return 'tool_call';
}

/**
 * Extract all string values from a nested object
 */
function flattenArgs(obj, depth = 0) {
  if (depth > 10) return [];
  const strings = [];
  if (typeof obj === 'string') {
    strings.push(obj);
  } else if (Array.isArray(obj)) {
    for (const item of obj) {
      strings.push(...flattenArgs(item, depth + 1));
    }
  } else if (obj && typeof obj === 'object') {
    for (const val of Object.values(obj)) {
      strings.push(...flattenArgs(val, depth + 1));
    }
  }
  return strings;
}

/**
 * Parse a raw tool call into a structured action
 */
export function parseAction(rawAction, context = {}) {
  const tool = rawAction.tool || rawAction.name || rawAction.function || 'unknown';
  const args = rawAction.args || rawAction.arguments || rawAction.parameters || {};
  const source = rawAction.source || 'assistant';
  const conversationContext = context.conversationHistory || context.messages || [];

  // Flatten all string values from args for analysis
  const allStrings = flattenArgs(args);
  const fullText = allStrings.join(' ');

  // Extract metadata
  const urls = [];
  const paths = [];
  const encodings = [];
  for (const s of allStrings) {
    urls.push(...extractUrls(s));
    paths.push(...extractPaths(s));
    encodings.push(...detectEncoding(s));
  }

  return {
    type: classifyAction(tool, args),
    tool,
    args,
    source,
    conversationContext,
    timestamp: new Date(),
    metadata: {
      urls: [...new Set(urls)],
      paths: [...new Set(paths)],
      encodings: [...new Set(encodings)],
      fullText,
      allStrings,
      rawAction
    }
  };
}

export default { parseAction };
