const net = require('node:net');
const { spawn } = require('node:child_process');

const { BaseToolAdapter } = require('../base-adapter.js');

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isValidHostname(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const host = value.trim();
  if (!host || host.length > 253 || host.includes('..')) {
    return false;
  }
  const labels = host.split('.');
  return labels.every((label) => /^[a-zA-Z0-9-]{1,63}$/.test(label) && !label.startsWith('-') && !label.endsWith('-'));
}

function isValidHost(value) {
  if (typeof value !== 'string') {
    return false;
  }
  const host = value.trim();
  if (!host) {
    return false;
  }
  if (net.isIP(host) !== 0) {
    return true;
  }
  return isValidHostname(host);
}

function sanitizeText(text) {
  return String(text || '')
    .replace(/\/Users\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/home\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/tmp\/[\w.-/]+/g, '<tmp_redacted>');
}

function parseNiktoText(outputText) {
  const vulnerabilities = [];
  const headers = {};
  const lines = String(outputText || '').split(/\r?\n/);
  let server = '';

  for (const raw of lines) {
    const line = raw.trim();

    const serverMatch = line.match(/^\+\s*Server:\s*(.+)$/i);
    if (serverMatch && serverMatch[1]) {
      server = serverMatch[1].trim();
      continue;
    }

    const headerMatch = line.match(/^\+\s*\/?:?\s*([A-Za-z0-9-]+):\s*(.+)$/);
    if (headerMatch && headerMatch[1] && headerMatch[2]) {
      headers[headerMatch[1].toLowerCase()] = headerMatch[2].trim();
    }

    const vulnMatch = line.match(/^\+\s*(?:OSVDB-(\d+):\s*)?([^:]+):\s*(.+)$/);
    if (vulnMatch) {
      const id = vulnMatch[1] ? `OSVDB-${vulnMatch[1]}` : 'NIKTO';
      const uri = (vulnMatch[2] || '').trim();
      const description = (vulnMatch[3] || '').trim();
      if (description && !/target ip|target hostname|start time|end time|items checked/i.test(description)) {
        vulnerabilities.push({
          id,
          description,
          uri,
          method: 'GET',
        });
      }
    }
  }

  return {
    vulnerabilities,
    server,
    headers,
  };
}

function parseNiktoJson(outputText) {
  try {
    const parsed = JSON.parse(outputText);
    const findings = [];
    const top = parsed || {};
    const candidates = Array.isArray(top.vulnerabilities)
      ? top.vulnerabilities
      : Array.isArray(top.vulns)
      ? top.vulns
      : Array.isArray(top.results)
      ? top.results
      : [];

    for (const item of candidates) {
      if (!item || typeof item !== 'object') {
        continue;
      }
      findings.push({
        id: String(item.id || item.osvdb || item.msgid || 'NIKTO'),
        description: String(item.description || item.msg || item.output || ''),
        uri: String(item.uri || item.path || '/'),
        method: String(item.method || 'GET').toUpperCase(),
      });
    }

    const serverInfo = top.server || top.banner || '';
    const headers = top.headers && typeof top.headers === 'object' && !Array.isArray(top.headers) ? top.headers : {};

    return {
      vulnerabilities: findings.filter((f) => f.description.length > 0),
      server: typeof serverInfo === 'string' ? serverInfo : '',
      headers,
    };
  } catch {
    return null;
  }
}

class NiktoAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'nikto',
      slug: 'nikto',
      description: 'Web server vulnerability scanner',
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

    if (!isValidHost(params.host)) {
      errors.push('host is required and must be a valid hostname or IP address');
    }

    const port = typeof params.port === 'undefined' ? 80 : Number(params.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      errors.push('port must be an integer between 1 and 65535');
    }

    if (typeof params.ssl !== 'undefined' && typeof params.ssl !== 'boolean') {
      errors.push('ssl must be a boolean when provided');
    }

    if (typeof params.tuning !== 'undefined') {
      if (typeof params.tuning !== 'string' || !/^[0-9abcx]+$/i.test(params.tuning.trim())) {
        errors.push('tuning must contain only 0-9 and a/b/c/x characters');
      }
    }

    const maxRuntime = typeof params.maxRuntime === 'undefined' ? 300 : Number(params.maxRuntime);
    if (!Number.isFinite(maxRuntime) || maxRuntime <= 0 || maxRuntime > 600) {
      errors.push('maxRuntime must be a positive number <= 600 seconds');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  async executeImpl(input) {
    const params = input.params || {};
    const host = String(params.host || '').trim();
    const port = typeof params.port === 'undefined' ? 80 : Number(params.port);
    const ssl = params.ssl === true;
    const tuning = typeof params.tuning === 'string' ? params.tuning.trim() : '';
    const maxRuntime = Math.min(
      600,
      Math.max(1, Number.isFinite(Number(params.maxRuntime)) ? Number(params.maxRuntime) : Math.floor((Number(input.timeout) || this.getResourceLimits().timeoutMs) / 1000)),
    );

    const args = ['-h', host, '-p', String(port), '-maxtime', `${maxRuntime}s`, '-Format', 'json', '-output', '-'];
    if (ssl) {
      args.push('-ssl');
    }
    if (tuning) {
      args.push('-Tuning', tuning);
    }

    const timeoutMs = Math.min(this.getResourceLimits().timeoutMs, maxRuntime * 1000);
    const maxCapture = this.getResourceLimits().maxOutputBytes;

    return new Promise((resolve, reject) => {
      const child = spawn('nikto', args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let bytes = 0;
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
        bytes += Buffer.byteLength(text, 'utf8');
        if (bytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.stderr.on('data', (chunk) => {
        const text = chunk.toString('utf8');
        stderr += text;
        bytes += Buffer.byteLength(text, 'utf8');
        if (bytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.on('error', (error) => {
        clearTimeout(killTimer);
        reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(error.message || 'Failed to execute nikto')));
      });

      child.on('close', (code) => {
        clearTimeout(killTimer);

        if (overflowed) {
          reject(this.makeError('TOOL_OUTPUT_TOO_LARGE', 'nikto output exceeded maximum allowed size'));
          return;
        }

        if (timedOut) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'nikto execution timed out'));
          return;
        }

        const combined = sanitizeText(`${stdout}\n${stderr}`);

        if (code !== 0 && !stdout.trim()) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(stderr.trim() || `nikto exited with code ${code}`)));
          return;
        }

        resolve({
          host,
          port,
          ssl,
          output: combined,
          runtimeSeconds: Math.max(0, Math.round((Date.now() - startedAt) / 1000)),
          status: code === 0 ? 'completed' : 'error',
        });
      });
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);
    const output = typeof payload.output === 'string' ? payload.output : '';
    const parsedJson = parseNiktoJson(output);
    const parsed = parsedJson || parseNiktoText(output);

    const result = {
      host: typeof payload.host === 'string' ? payload.host : '',
      port: Number.isFinite(Number(payload.port)) ? Number(payload.port) : 80,
      ssl: Boolean(payload.ssl),
      vulnerabilities: Array.isArray(parsed.vulnerabilities) ? parsed.vulnerabilities : [],
      runtime_seconds: Number.isFinite(Number(payload.runtimeSeconds)) ? Number(payload.runtimeSeconds) : 0,
      status: typeof payload.status === 'string' ? payload.status : 'completed',
    };

    if (parsed.server || (parsed.headers && Object.keys(parsed.headers).length > 0)) {
      result.server_info = {
        server: parsed.server || '',
        headers: parsed.headers && typeof parsed.headers === 'object' ? parsed.headers : {},
      };
    }

    return result;
  }

  getResourceLimits() {
    return {
      timeoutMs: 600000,
      memoryMb: 512,
      maxOutputBytes: 10 * 1024 * 1024,
    };
  }
}

module.exports = {
  NiktoAdapter,
};
