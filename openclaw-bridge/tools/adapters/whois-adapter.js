const { spawn } = require('node:child_process');
const net = require('node:net');

const { BaseToolAdapter } = require('../base-adapter.js');

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isValidDomain(domain) {
  if (typeof domain !== 'string') {
    return false;
  }
  const value = domain.trim();
  if (!value || value.length > 253 || value.includes('..')) {
    return false;
  }
  const labels = value.split('.');
  if (labels.length < 2) {
    return false;
  }
  return labels.every((label) => /^[a-zA-Z0-9-]{1,63}$/.test(label) && !label.startsWith('-') && !label.endsWith('-'));
}

function isValidHostname(hostname) {
  if (typeof hostname !== 'string') {
    return false;
  }
  const value = hostname.trim();
  if (!value || value.length > 253 || value.includes('..')) {
    return false;
  }
  const labels = value.split('.');
  if (labels.length < 2) {
    return false;
  }
  return labels.every((label) => /^[a-zA-Z0-9-]{1,63}$/.test(label) && !label.startsWith('-') && !label.endsWith('-'));
}

function extractField(lines, patterns) {
  for (const line of lines) {
    if (!line.includes(':')) {
      continue;
    }
    const idx = line.indexOf(':');
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    for (const pattern of patterns) {
      if (pattern.test(key) && value) {
        return value;
      }
    }
  }
  return '';
}

function truncateText(value, maxChars) {
  if (typeof value !== 'string') {
    return '';
  }
  if (value.length <= maxChars) {
    return value;
  }
  return value.slice(0, maxChars) + '\n...[truncated]';
}

class WhoisAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'whois',
      slug: 'whois',
      description: 'Query WHOIS database for domain/IP information',
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

    if (typeof params.query !== 'string' || params.query.trim().length === 0) {
      errors.push('query is required and must be a non-empty string');
    } else {
      const query = params.query.trim();
      if (net.isIP(query) === 0 && !isValidDomain(query)) {
        errors.push('query must be a valid domain or IP address');
      }
    }

    if (typeof params.server !== 'undefined') {
      if (typeof params.server !== 'string' || !isValidHostname(params.server)) {
        errors.push('server must be a valid hostname when provided');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  async executeImpl(input) {
    const params = input.params || {};
    const timeoutMs = Math.min(this.getResourceLimits().timeoutMs, Number(input.timeout) > 0 ? Number(input.timeout) : this.getResourceLimits().timeoutMs);
    const args = [];
    if (typeof params.server === 'string' && params.server.trim()) {
      args.push('-h', params.server.trim());
    }
    args.push(params.query.trim());

    return new Promise((resolve, reject) => {
      const child = spawn('whois', args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let outputBytes = 0;
      const maxCapture = this.getResourceLimits().maxOutputBytes + 256 * 1024;

      const killTimer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString('utf8');
        outputBytes += Buffer.byteLength(chunk);
        if (outputBytes > maxCapture) {
          child.kill('SIGKILL');
        }
      });

      child.stderr.on('data', (chunk) => {
        stderr += chunk.toString('utf8');
      });

      child.on('error', (error) => {
        clearTimeout(killTimer);
        reject(this.makeError('TOOL_EXECUTION_ERROR', error.message || 'Failed to execute whois'));
      });

      child.on('close', (code) => {
        clearTimeout(killTimer);
        if (timedOut) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'whois execution timed out'));
          return;
        }

        if (outputBytes > maxCapture) {
          reject(this.makeError('TOOL_OUTPUT_TOO_LARGE', 'whois output exceeded maximum allowed size'));
          return;
        }

        if (code !== 0 && stdout.trim().length === 0) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', stderr.trim() || `whois exited with code ${code}`));
          return;
        }

        resolve({
          query: params.query.trim(),
          stdout,
          stderr: stderr.trim(),
        });
      });
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);
    const stdout = typeof payload.stdout === 'string' ? payload.stdout : '';
    const query = typeof payload.query === 'string' ? payload.query : '';
    const lines = stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    const registrar = extractField(lines, [/^registrar$/i, /^sponsoring registrar$/i]);
    const created = extractField(lines, [/^creation date$/i, /^created on$/i, /^domain registration date$/i, /^registered on$/i]);
    const expires = extractField(lines, [/^registry expiry date$/i, /^expiration date$/i, /^expiry date$/i, /^expires on$/i, /^registrar registration expiration date$/i]);

    const nameservers = [];
    for (const line of lines) {
      if (!line.includes(':')) {
        continue;
      }
      const idx = line.indexOf(':');
      const key = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      if (/^name server$/i.test(key) && value) {
        nameservers.push(value.toLowerCase());
      }
    }

    return {
      query,
      registrar: registrar || undefined,
      created,
      expires,
      nameservers: Array.from(new Set(nameservers)),
      raw: truncateText(stdout, 10000),
    };
  }

  getResourceLimits() {
    return {
      timeoutMs: 15000,
      memoryMb: 256,
      maxOutputBytes: 2 * 1024 * 1024,
    };
  }
}

module.exports = {
  WhoisAdapter,
};
