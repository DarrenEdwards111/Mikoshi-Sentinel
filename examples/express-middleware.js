/**
 * Express Middleware Example — Mikoshi Sentinel
 *
 * Protects an Express API endpoint with Sentinel verification.
 * Run: npm install express && node examples/express-middleware.js
 */

import express from 'express';
import { Sentinel } from '../lib/sentinel.js';

const app = express();
app.use(express.json());

// Create sentinel
const sentinel = new Sentinel({
  enableIntentVerification: true,
  audit: { console: true, verbose: true }
});

// Apply sentinel middleware to tool-calling endpoint
app.use('/api/tools', sentinel.middleware({
  blockStatus: 403,
  contextExtractor: (req) => ({
    sessionId: req.headers['x-session-id'] || req.ip,
    conversationHistory: req.body?.messages || [],
    scope: {
      allowSystemCommands: false,
      allowedTools: ['read', 'write', 'fetch'],
    }
  })
}));

// Tool execution endpoint (protected by sentinel)
app.post('/api/tools', (req, res) => {
  // If we reach here, sentinel approved the action
  res.json({
    status: 'executed',
    verdict: req.sentinelVerdict
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', stats: sentinel.stats() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🛡️  Sentinel-protected API running on port ${PORT}`);
  console.log(`Try: curl -X POST http://localhost:${PORT}/api/tools -H 'Content-Type: application/json' -d '{"tool":"exec","args":{"command":"rm -rf /"}}'`);
});
