const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { BaseToolAdapter } = require('../base-adapter.js');

const ALLOWED_METHODS = new Set(['GET', 'POST']);
const TECHNIQUE_PATTERN = /^[BEUST]+$/;

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function sanitizeText(text) {
  return String(text || '')
    .replace(/\/Users\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/home\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/tmp\/[\w.-/]+/g, '<tmp_redacted>');
}

function tryParseUrl(rawUrl) {
  try {
    return new URL(rawUrl);
  } catch {
    return null;
  }
}

function getSqlmapInvocation() {
  const candidates = [
    { command: 'python3', argsPrefix: ['/usr/share/sqlmap/sqlmap.py'] },
    { command: 'python3', argsPrefix: ['/opt/homebrew/Cellar/sqlmap/sqlmap.py'] },
    { command: 'sqlmap', argsPrefix: [] },
  ];

  for (const candidate of candidates) {
    if (candidate.command === 'sqlmap') {
      return candidate;
    }
    if (candidate.argsPrefix.length > 0 && fs.existsSync(path.resolve(candidate.argsPrefix[0]))) {
      return candidate;
    }
  }

  return candidates[candidates.length - 1];
}

function parseInjectionPoints(outputText) {
  const points = [];
  const lines = String(outputText || '').split(/\r?\n/);
  let current = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    const parameterMatch = line.match(/^Parameter:\s*([^\s(]+)\s*\(([^)]+)\)/i);
    if (parameterMatch) {
      if (current) {
        points.push(current);
      }
      current = {
        parameter: parameterMatch[1],
        type: parameterMatch[2],
        payload: '',
      };
      continue;
    }

    const payloadMatch = line.match(/^Payload:\s*(.+)$/i);
    if (payloadMatch && current) {
      current.payload = payloadMatch[1].trim();
    }
  }

  if (current) {
    points.push(current);
  }

  return points;
}

function parseDbms(outputText) {
  const text = String(outputText || '');
  const patterns = [/back-end DBMS:\s*(.+)$/im, /the back-end DBMS is\s+(.+)$/im];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match[1]) {
      return match[1].trim();
    }
  }
  return '';
}

class SqlmapAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'sqlmap',
      slug: 'sqlmap',
      description: 'Automated SQL injection detection and exploitation tool',
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

    const url = typeof params.url === 'string' ? params.url.trim() : '';
    const parsed = tryParseUrl(url);
    if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) {
      errors.push('url is required and must be a valid http/https URL');
    }

    const method = (typeof params.method === 'string' ? params.method : 'GET').toUpperCase();
    if (!ALLOWED_METHODS.has(method)) {
      errors.push('method must be GET or POST');
    }

    if (method === 'POST' && typeof params.data !== 'undefined' && typeof params.data !== 'string') {
      errors.push('data must be a string when provided');
    }

    const level = typeof params.level === 'undefined' ? 1 : Number(params.level);
    if (!Number.isInteger(level) || level < 1 || level > 5) {
      errors.push('level must be an integer between 1 and 5');
    }

    const risk = typeof params.risk === 'undefined' ? 1 : Number(params.risk);
    if (!Number.isInteger(risk) || risk < 1 || risk > 3) {
      errors.push('risk must be an integer between 1 and 3');
    }

    const technique = typeof params.technique === 'string' ? params.technique.toUpperCase() : 'BEUST';
    if (!TECHNIQUE_PATTERN.test(technique)) {
      errors.push('technique must only include characters B, E, U, S, T');
    }

    const maxRuntime = typeof params.maxRuntime === 'undefined' ? 120 : Number(params.maxRuntime);
    if (!Number.isFinite(maxRuntime) || maxRuntime <= 0 || maxRuntime > 300) {
      errors.push('maxRuntime must be a positive number <= 300 seconds');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  async executeImpl(input) {
    const params = input.params || {};
    const url = String(params.url || '').trim();
    const method = (typeof params.method === 'string' ? params.method : 'GET').toUpperCase();
    const level = typeof params.level === 'undefined' ? 1 : Number(params.level);
    const risk = typeof params.risk === 'undefined' ? 1 : Number(params.risk);
    const technique = typeof params.technique === 'string' ? params.technique.toUpperCase() : 'BEUST';
    const maxRuntime = Math.min(
      300,
      Math.max(1, Number.isFinite(Number(params.maxRuntime)) ? Number(params.maxRuntime) : Math.floor((Number(input.timeout) || this.getResourceLimits().timeoutMs) / 1000)),
    );

    const invocation = getSqlmapInvocation();
    const args = [
      ...invocation.argsPrefix,
      '-u',
      url,
      '--batch',
      `--level=${level}`,
      `--risk=${risk}`,
      `--technique=${technique}`,
      '--timeout=15',
      `--time-limit=${maxRuntime}`,
      '--fresh-queries',
      '--flush-session',
    ];

    if (method === 'POST') {
      args.push('--method=POST');
      if (typeof params.data === 'string' && params.data.length > 0) {
        args.push(`--data=${params.data}`);
      }
    }

    const timeoutMs = Math.min(this.getResourceLimits().timeoutMs, maxRuntime * 1000);
    const maxCapture = this.getResourceLimits().maxOutputBytes;

    return new Promise((resolve, reject) => {
      const child = spawn(invocation.command, args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let outputBytes = 0;
      let timedOut = false;
      let overflowed = false;
      const startedAt = Date.now();

      const killTimer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout.on('data', (chunk) => {
        const text = chunk.toString('utf8');
        stdout += text;
        outputBytes += Buffer.byteLength(text, 'utf8');
        if (outputBytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.stderr.on('data', (chunk) => {
        const text = chunk.toString('utf8');
        stderr += text;
        outputBytes += Buffer.byteLength(text, 'utf8');
        if (outputBytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.on('error', (error) => {
        clearTimeout(killTimer);
        reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(error.message || 'Failed to execute sqlmap')));
      });

      child.on('close', (code) => {
        clearTimeout(killTimer);

        if (overflowed) {
          reject(this.makeError('TOOL_OUTPUT_TOO_LARGE', 'sqlmap output exceeded maximum allowed size'));
          return;
        }

        if (timedOut) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'sqlmap execution timed out'));
          return;
        }

        const combined = `${stdout}\n${stderr}`;
        const vulnerable = /is vulnerable|identified the following injection point/i.test(combined);
        const status = vulnerable ? 'vulnerable' : code === 0 ? 'not_vulnerable' : 'error';

        if (status === 'error' && !vulnerable) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(stderr.trim() || stdout.trim() || `sqlmap exited with code ${code}`)));
          return;
        }

        resolve({
          url,
          output: sanitizeText(combined),
          vulnerable,
          status,
          runtimeSeconds: Math.max(0, Math.round((Date.now() - startedAt) / 1000)),
        });
      });
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);
    const output = typeof payload.output === 'string' ? payload.output : '';
    const injectionPoints = parseInjectionPoints(output);
    const vulnerable = Boolean(payload.vulnerable) || injectionPoints.length > 0;
    const dbms = parseDbms(output);

    const normalized = {
      url: typeof payload.url === 'string' ? payload.url : '',
      vulnerable,
      injection_points: injectionPoints,
      runtime_seconds: Number.isFinite(Number(payload.runtimeSeconds)) ? Number(payload.runtimeSeconds) : 0,
      status: typeof payload.status === 'string' ? payload.status : vulnerable ? 'vulnerable' : 'not_vulnerable',
    };

    if (dbms) {
      normalized.dbms = dbms;
    }

    return normalized;
  }

  getResourceLimits() {
    return {
      timeoutMs: 300000,
      memoryMb: 512,
      maxOutputBytes: 5 * 1024 * 1024,
    };
  }
}

module.exports = {
  SqlmapAdapter,
};
