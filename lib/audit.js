/**
 * Audit Logger — Logs every verification decision with full context
 * @module mikoshi-sentinel/audit
 */

import { writeFileSync, appendFileSync, existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

export class AuditLogger {
  constructor(options = {}) {
    this.entries = [];
    this.outputFile = options.outputFile || null;
    this.console = options.console !== false;
    this.maxEntries = options.maxEntries || 10000;
    this.verbose = options.verbose || false;

    if (this.outputFile) {
      const dir = dirname(this.outputFile);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    }
  }

  /**
   * Log a verification decision
   */
  log(entry) {
    const record = {
      id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: new Date().toISOString(),
      ...entry
    };

    this.entries.push(record);

    // Trim old entries
    if (this.entries.length > this.maxEntries) {
      this.entries = this.entries.slice(-this.maxEntries);
    }

    // Console output
    if (this.console && this.verbose) {
      const icon = record.allowed ? '✅' : '🚫';
      console.log(`${icon} [Sentinel] ${record.action?.tool || 'unknown'} — ${record.allowed ? 'ALLOWED' : 'BLOCKED'}`);
      if (record.violations?.length) {
        for (const v of record.violations) {
          console.log(`   ⚠️  ${v.policy}: ${v.reason} (${v.severity})`);
        }
      }
    }

    // File output
    if (this.outputFile) {
      try {
        appendFileSync(this.outputFile, JSON.stringify(record) + '\n');
      } catch (err) {
        console.error(`[Sentinel Audit] Failed to write to ${this.outputFile}:`, err.message);
      }
    }

    return record;
  }

  /**
   * Get recent audit entries
   */
  getRecent(count = 50) {
    return this.entries.slice(-count);
  }

  /**
   * Get entries matching a filter
   */
  query(filter = {}) {
    return this.entries.filter(entry => {
      if (filter.allowed !== undefined && entry.allowed !== filter.allowed) return false;
      if (filter.tool && entry.action?.tool !== filter.tool) return false;
      if (filter.since && new Date(entry.timestamp) < new Date(filter.since)) return false;
      if (filter.policy && !entry.violations?.some(v => v.policy === filter.policy)) return false;
      return true;
    });
  }

  /**
   * Get statistics
   */
  stats() {
    const total = this.entries.length;
    const blocked = this.entries.filter(e => !e.allowed).length;
    const allowed = total - blocked;
    const byPolicy = {};
    for (const entry of this.entries) {
      for (const v of (entry.violations || [])) {
        byPolicy[v.policy] = (byPolicy[v.policy] || 0) + 1;
      }
    }
    return { total, allowed, blocked, byPolicy };
  }

  /**
   * Clear all entries
   */
  clear() {
    this.entries = [];
  }

  /**
   * Export all entries as JSON
   */
  export() {
    return JSON.stringify(this.entries, null, 2);
  }
}

export default AuditLogger;
