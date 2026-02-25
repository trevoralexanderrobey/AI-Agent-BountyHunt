const { spawn } = require('node:child_process');
const net = require('node:net');

const { BaseToolAdapter } = require('../base-adapter.js');

const ALLOWED_TYPES = new Set(['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']);

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isValidDomain(domain) {
  if (typeof domain !== 'string') {
    return false;
  }
  const value = domain.trim();
  if (!value || value.length > 253) {
    return false;
  }
  if (value.includes('..')) {
    return false;
  }
  const labels = value.split('.');
  if (labels.length < 2) {
    return false;
  }
  return labels.every((label) => /^[a-zA-Z0-9-]{1,63}$/.test(label) && !label.startsWith('-') && !label.endsWith('-'));
}

function parseNslookupAnswers(stdout, recordType) {
  const answers = [];
  const lines = String(stdout || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  let inAnswerSection = false;

  for (const line of lines) {
    if (/^non-authoritative answer:?$/i.test(line) || /^authoritative answers can be found from:/i.test(line)) {
      inAnswerSection = true;
      continue;
    }

    if (/^name:\s+/i.test(line)) {
      inAnswerSection = true;
      continue;
    }

    if (!inAnswerSection && /^address:\s+/i.test(line)) {
      // Skip server block addresses before the answer section.
      continue;
    }

    if ((recordType === 'A' || recordType === 'AAAA') && /^address:\s+/i.test(line)) {
      const value = line.replace(/^address:\s+/i, '').trim();
      if (value && !value.includes('#')) {
        answers.push({ type: recordType, value });
      }
      continue;
    }

    const hasAddress = line.match(/\s+has\s+address\s+(.+)$/i);
    if (recordType === 'A' && hasAddress) {
      answers.push({ type: 'A', value: hasAddress[1].trim() });
      continue;
    }

    const hasIpv6 = line.match(/\s+has\s+IPv6\s+address\s+(.+)$/i);
    if (recordType === 'AAAA' && hasIpv6) {
      answers.push({ type: 'AAAA', value: hasIpv6[1].trim() });
      continue;
    }

    const mx = line.match(/mail exchanger =\s*(.+)$/i);
    if (recordType === 'MX' && mx) {
      answers.push({ type: 'MX', value: mx[1].trim() });
      continue;
    }

    const ns = line.match(/nameserver =\s*(.+)$/i);
    if (recordType === 'NS' && ns) {
      answers.push({ type: 'NS', value: ns[1].trim() });
      continue;
    }

    const txt = line.match(/text =\s*"?(.+?)"?$/i);
    if (recordType === 'TXT' && txt) {
      answers.push({ type: 'TXT', value: txt[1].trim() });
      continue;
    }

    if (recordType === 'SOA' && /\s*=\s*/.test(line)) {
      answers.push({ type: 'SOA', value: line.trim() });
    }
  }

  return answers;
}

class NslookupAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'nslookup',
      slug: 'nslookup',
      description: 'Perform DNS lookups for domain names',
    });
  }

  async validateInput(params) {
    const errors = [];
    if (!isPlainObject(params)) {
      return {
        valid: false,
        errors: ['Params must be an object'],
      };
    }

    if (!isValidDomain(params.domain)) {
      errors.push('domain is required and must be a valid hostname/domain');
    }

    const recordType = (typeof params.recordType === 'string' ? params.recordType : 'A').toUpperCase();
    if (!ALLOWED_TYPES.has(recordType)) {
      errors.push('recordType must be one of A, AAAA, MX, NS, TXT, SOA');
    }

    if (typeof params.server !== 'undefined') {
      if (typeof params.server !== 'string' || net.isIP(params.server.trim()) === 0) {
        errors.push('server must be a valid IP address when provided');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  async executeImpl(input) {
    const params = input.params || {};
    const recordType = (typeof params.recordType === 'string' ? params.recordType : 'A').toUpperCase();
    const timeoutMs = Math.min(this.getResourceLimits().timeoutMs, Number(input.timeout) > 0 ? Number(input.timeout) : this.getResourceLimits().timeoutMs);
    const args = [`-type=${recordType}`, params.domain];
    if (typeof params.server === 'string' && params.server.trim()) {
      args.push(params.server.trim());
    }

    return new Promise((resolve, reject) => {
      const child = spawn('nslookup', args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const killTimer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString('utf8');
      });

      child.stderr.on('data', (chunk) => {
        stderr += chunk.toString('utf8');
      });

      child.on('error', (error) => {
        clearTimeout(killTimer);
        reject(this.makeError('TOOL_EXECUTION_ERROR', error.message || 'Failed to execute nslookup'));
      });

      child.on('close', (code) => {
        clearTimeout(killTimer);
        if (timedOut) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'nslookup execution timed out'));
          return;
        }

        if (code !== 0 && stdout.trim().length === 0) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', stderr.trim() || `nslookup exited with code ${code}`));
          return;
        }

        resolve({
          domain: params.domain,
          recordType,
          stdout,
          stderr: stderr.trim(),
        });
      });
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);
    const domain = typeof payload.domain === 'string' ? payload.domain : '';
    const recordType = typeof payload.recordType === 'string' ? payload.recordType : 'A';
    const answers = parseNslookupAnswers(payload.stdout || '', recordType);

    return {
      domain,
      record_type: recordType,
      answers,
    };
  }

  getResourceLimits() {
    return {
      timeoutMs: 10000,
      memoryMb: 128,
      maxOutputBytes: 1024 * 1024,
    };
  }
}

module.exports = {
  NslookupAdapter,
};
