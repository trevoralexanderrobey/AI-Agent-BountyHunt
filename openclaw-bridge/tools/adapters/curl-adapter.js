const { spawn } = require('node:child_process');

const { BaseToolAdapter } = require('../base-adapter.js');

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'HEAD']);
const RESERVED_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'x-api-key', 'proxy-authorization']);

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function toStringValue(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return '';
}

function parseLastHttpResponse(text) {
  const source = typeof text === 'string' ? text : '';
  const matches = [];
  const regex = /HTTP\/[0-9.]+\s+\d{3}[^\r\n]*\r?\n(?:[^\r\n]*\r?\n)*?\r?\n/g;
  let match = regex.exec(source);
  while (match) {
    matches.push({ index: match.index, headerBlock: match[0] });
    match = regex.exec(source);
  }

  if (matches.length === 0) {
    return {
      statusCode: 0,
      headers: {},
      body: source,
    };
  }

  const last = matches[matches.length - 1];
  const statusLine = last.headerBlock.split(/\r?\n/)[0] || '';
  const statusCodeMatch = statusLine.match(/HTTP\/[0-9.]+\s+(\d{3})/i);
  const statusCode = statusCodeMatch ? Number(statusCodeMatch[1]) : 0;

  const headers = {};
  const headerLines = last.headerBlock.split(/\r?\n/).slice(1);
  for (const line of headerLines) {
    if (!line || !line.includes(':')) {
      continue;
    }
    const idx = line.indexOf(':');
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!key) {
      continue;
    }
    headers[key.toLowerCase()] = value;
  }

  const bodyStart = last.index + last.headerBlock.length;
  const body = source.slice(bodyStart);

  return {
    statusCode,
    headers,
    body,
  };
}

class CurlAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'curl',
      slug: 'curl',
      description: 'Make HTTP requests and retrieve content',
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

    if (typeof params.url !== 'string' || params.url.trim().length === 0) {
      errors.push('url is required and must be a non-empty string');
    }

    let parsedUrl = null;
    if (typeof params.url === 'string' && params.url.trim().length > 0) {
      try {
        parsedUrl = new URL(params.url);
      } catch {
        errors.push('url must be a valid URL');
      }
    }

    if (parsedUrl && !['http:', 'https:'].includes(parsedUrl.protocol)) {
      errors.push('url protocol must be http or https');
    }

    const method = (typeof params.method === 'string' ? params.method : 'GET').toUpperCase();
    if (!ALLOWED_METHODS.has(method)) {
      errors.push('method must be one of GET, POST, PUT, DELETE, HEAD');
    }

    if (typeof params.headers !== 'undefined') {
      if (!isPlainObject(params.headers)) {
        errors.push('headers must be an object');
      } else {
        for (const headerName of Object.keys(params.headers)) {
          if (!headerName || headerName.includes('\n') || headerName.includes('\r')) {
            errors.push('headers contain invalid header name');
            continue;
          }
          if (RESERVED_HEADERS.has(headerName.trim().toLowerCase())) {
            errors.push(`header '${headerName}' is reserved and not allowed`);
          }
        }
      }
    }

    if (typeof params.body !== 'undefined') {
      if (typeof params.body !== 'string') {
        errors.push('body must be a string when provided');
      }
      if (!['POST', 'PUT'].includes(method)) {
        errors.push('body is only allowed with POST or PUT methods');
      }
    }

    if (typeof params.timeout !== 'undefined') {
      const timeout = Number(params.timeout);
      if (!Number.isFinite(timeout) || timeout <= 0) {
        errors.push('timeout must be a positive number');
      } else if (timeout > 30000) {
        errors.push('timeout must be <= 30000 ms');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  async executeImpl(input) {
    const params = input.params || {};
    const method = (typeof params.method === 'string' ? params.method : 'GET').toUpperCase();
    const timeoutMs = Math.min(
      Number.isFinite(Number(params.timeout)) ? Number(params.timeout) : this.getResourceLimits().timeoutMs,
      this.getResourceLimits().timeoutMs,
    );
    const args = ['-sS', '-i', '-L', '-X', method, params.url, '--max-time', String(Math.max(1, Math.ceil(timeoutMs / 1000)))];

    if (isPlainObject(params.headers)) {
      for (const [key, value] of Object.entries(params.headers)) {
        args.push('-H', `${key}: ${toStringValue(value)}`);
      }
    }

    if (typeof params.body === 'string' && ['POST', 'PUT'].includes(method)) {
      args.push('--data', params.body);
    }

    const maxCapture = this.getResourceLimits().maxOutputBytes + 512 * 1024;

    return new Promise((resolve, reject) => {
      const child = spawn('curl', args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let timedOut = false;
      let overflowed = false;

      const killTimer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString('utf8');
        stdoutBytes += Buffer.byteLength(chunk);
        if (stdoutBytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.stderr.on('data', (chunk) => {
        stderr += chunk.toString('utf8');
        stderrBytes += Buffer.byteLength(chunk);
        if (stderrBytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.on('error', (error) => {
        clearTimeout(killTimer);
        reject(this.makeError('TOOL_EXECUTION_ERROR', error.message || 'Failed to execute curl'));
      });

      child.on('close', (code) => {
        clearTimeout(killTimer);

        if (timedOut) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'curl execution timed out'));
          return;
        }

        if (overflowed) {
          reject(this.makeError('TOOL_OUTPUT_TOO_LARGE', 'curl output exceeded maximum allowed size'));
          return;
        }

        if (code !== 0) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', stderr.trim() || `curl exited with code ${code}`));
          return;
        }

        const parsed = parseLastHttpResponse(stdout);
        resolve({
          statusCode: parsed.statusCode,
          headers: parsed.headers,
          body: parsed.body,
          stderr: stderr.trim(),
        });
      });
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);
    const body = typeof payload.body === 'string' ? payload.body : '';

    return {
      status: Number.isFinite(Number(payload.statusCode)) ? Number(payload.statusCode) : 0,
      headers: isPlainObject(payload.headers) ? payload.headers : {},
      body,
      size_bytes: Buffer.byteLength(body, 'utf8'),
    };
  }

  getResourceLimits() {
    return {
      timeoutMs: 30000,
      memoryMb: 256,
      maxOutputBytes: 5 * 1024 * 1024,
    };
  }
}

module.exports = {
  CurlAdapter,
};
