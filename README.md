<p align="center">
  <img src="https://raw.githubusercontent.com/DarrenEdwards111/Mikoshi-Sentinel/main/logo.jpg" alt="Mikoshi Sentinel" width="200" />
</p>

<h1 align="center">Mikoshi Sentinel</h1>

<p align="center">
  <strong>Deterministic action verification for LLM agent security</strong>
</p>

> Prompt injection is unsolved because LLMs process instructions and data in the same channel. Sentinel solves this by verifying *actions*, not prompts — using deterministic code that can't be manipulated by clever input.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/mikoshi-sentinel.svg)](https://www.npmjs.com/package/mikoshi-sentinel)

---

## The Problem

Every current defence against prompt injection — input filtering, system prompt hardening, dual-LLM checking — is **probabilistic**. An LLM-based check can be fooled by the same techniques it's trying to detect, because it processes instructions and data in a shared context.

## The Solution

**Separate the decision from the enforcement.** Let the LLM decide what to do. Let deterministic code decide whether it's *allowed* to do it.

Sentinel sits between the LLM and the tools. Every proposed action passes through a pipeline of **deterministic policy checks** (pure code, not prompts) before execution. Code doesn't hallucinate. Code can't be prompt-injected.

```
┌──────────┐     ┌──────────────┐     ┌──────────┐     ┌──────────┐
│   LLM    │────▶│   Sentinel   │────▶│ Verdict  │────▶│ Execute  │
│ (Propose)│     │  (Verify)    │     │ Allow/   │     │ (or      │
│          │     │              │     │ Block    │     │  Block)  │
└──────────┘     │ ┌──────────┐ │     └──────────┘     └──────────┘
                 │ │ Policies │ │
                 │ │ (Code)   │ │
                 │ ├──────────┤ │
                 │ │ Intent   │ │
                 │ │ Verifier │ │
                 │ ├──────────┤ │
                 │ │ Audit    │ │
                 │ │ Logger   │ │
                 │ └──────────┘ │
                 └──────────────┘
```

## Quick Start

```bash
npm install mikoshi-sentinel
```

```javascript
import { Sentinel } from 'mikoshi-sentinel';

const sentinel = new Sentinel();

// Verify an action before executing it
const verdict = await sentinel.verify({
  tool: 'exec',
  args: { command: 'rm -rf /' }
});

console.log(verdict.allowed);    // false
console.log(verdict.violations); // [{ policy: 'systemCommands', reason: '...', severity: 'critical' }]
```

## How It Works

### The Propose → Verify → Execute Pipeline

1. **Propose** — The LLM decides on an action (tool call)
2. **Verify** — Sentinel runs the action through deterministic policy checks
3. **Execute** — Only if all policies pass does the action execute

### Built-in Policies

| Policy | What it blocks | Severity |
|--------|---------------|----------|
| **Privilege Escalation** | sudo, admin routes, config modifications | Critical |
| **Data Exfiltration** | Sending data to external URLs, webhook.site, ngrok | Critical |
| **Internal Access** | localhost, private IPs, cloud metadata (SSRF) | Critical |
| **File Traversal** | ../, ~/, null bytes, symlink attacks | Critical |
| **System Commands** | rm -rf, curl\|bash, reverse shells, fork bombs | Critical |
| **Intent Alignment** | Prompt injection patterns, DAN mode, context shifts | Critical |
| **Rate Limiting** | Rapid-fire tool calls, repeated identical actions | High |
| **Scope Enforcement** | Tool whitelists, path restrictions, permission scoping | High |

### Custom Policies

```javascript
sentinel.addPolicy('noWeekends', (action, context) => {
  const day = new Date().getDay();
  if (day === 0 || day === 6) {
    return { pass: false, reason: 'No deployments on weekends', severity: 'medium' };
  }
  return { pass: true, reason: 'Weekday', severity: 'none' };
});
```

### Express Middleware

```javascript
import express from 'express';
import { Sentinel } from 'mikoshi-sentinel';

const app = express();
const sentinel = new Sentinel();

app.use('/api/tools', sentinel.middleware());

app.post('/api/tools', (req, res) => {
  // Only reaches here if Sentinel approved the action
  res.json({ status: 'executed', verdict: req.sentinelVerdict });
});
```

### Intent Verification

Optional LLM-backed or heuristic intent checking:

```javascript
const sentinel = new Sentinel({
  enableIntentVerification: true,
  llmFn: async (prompt) => await myLLM.complete(prompt), // Optional
});

const verdict = await sentinel.verify(action, {
  conversationHistory: messages // Recent conversation for context
});

console.log(verdict.intent); // { confidence: 0.95, aligned: true, method: 'heuristic' }
```

## API

### `new Sentinel(config)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `useBuiltinPolicies` | boolean | `true` | Load all 8 built-in policies |
| `enableIntentVerification` | boolean | `true` | Enable intent alignment checking |
| `llmFn` | function | `null` | Async LLM function for intent verification |
| `intentThreshold` | number | `0.5` | Minimum intent confidence score |
| `audit` | object | `{}` | Audit logger options |
| `scope` | object | `{}` | Default scope restrictions |

### `sentinel.verify(action, context)`

Returns:
```javascript
{
  allowed: boolean,        // Final verdict
  confidence: number,      // 0.0 - 1.0
  violations: [{           // Policy violations (empty if allowed)
    policy: string,
    reason: string,
    severity: 'critical' | 'high' | 'medium' | 'low'
  }],
  intent: {                // Intent verification result (if enabled)
    confidence: number,
    aligned: boolean,
    method: 'heuristic' | 'llm',
    reason: string
  },
  elapsed: string          // Verification time
}
```

## Performance

- **Policy checks:** <5ms (deterministic function calls)
- **Intent verification (heuristic):** ~2ms
- **Intent verification (LLM-backed):** ~200ms
- **Overhead:** Negligible for the security guarantee

## Research Paper

The architecture and evaluation of Mikoshi Sentinel is described in our paper:

> *Mikoshi Sentinel: Deterministic Action Verification as a Defence Against Prompt Injection in LLM Agents* — Mikoshi Research, 2025

See [`paper/mikoshi-sentinel.tex`](paper/mikoshi-sentinel.tex)

## Landing Page

🌐 [mikoshi.co.uk/sentinel](https://mikoshi.co.uk/sentinel)

## License

[Apache 2.0](LICENSE) — Built by [Mikoshi Ltd](https://mikoshi.co.uk)

## Contact

📧 mikoshiuk@gmail.com
