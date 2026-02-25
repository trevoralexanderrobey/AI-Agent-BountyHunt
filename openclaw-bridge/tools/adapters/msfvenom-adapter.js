const net = require('node:net');
const { spawn } = require('node:child_process');

const { BaseToolAdapter } = require('../base-adapter.js');

const PAYLOAD_WHITELIST = new Set([
  'windows/meterpreter/reverse_tcp',
  'windows/shell_reverse_tcp',
  'linux/x86/meterpreter/reverse_tcp',
  'linux/x64/shell_reverse_tcp',
  'php/meterpreter/reverse_tcp',
  'python/meterpreter/reverse_tcp',
  'cmd/unix/reverse_bash',
]);

const FORMAT_WHITELIST = new Set(['exe', 'elf', 'raw', 'c', 'py', 'php', 'asp', 'aspx', 'jsp', 'war', 'ps1', 'sh', 'bash']);
const TEXT_FORMATS = new Set(['c', 'py', 'php', 'asp', 'aspx', 'jsp', 'ps1', 'sh', 'bash']);

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function sanitizeText(text) {
  return String(text || '')
    .replace(/\/Users\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/home\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/tmp\/[\w.-/]+/g, '<tmp_redacted>');
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
  return /^[a-zA-Z0-9.-]{1,253}$/.test(host) && !host.includes('..') && !host.startsWith('.') && !host.endsWith('.');
}

class MsfvenomAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'msfvenom',
      slug: 'msfvenom',
      description: 'Metasploit payload generation for security testing',
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

    const payload = typeof params.payload === 'string' ? params.payload.trim() : '';
    if (!PAYLOAD_WHITELIST.has(payload)) {
      errors.push('payload is required and must be in whitelist');
    }

    const format = typeof params.format === 'string' ? params.format.trim().toLowerCase() : '';
    if (!FORMAT_WHITELIST.has(format)) {
      errors.push('format is required and must be in whitelist');
    }

    if (typeof params.lhost !== 'undefined' && !isValidHost(params.lhost)) {
      errors.push('lhost must be a valid IP/hostname when provided');
    }

    if (typeof params.lport !== 'undefined') {
      const lport = Number(params.lport);
      if (!Number.isInteger(lport) || lport < 1024 || lport > 65535) {
        errors.push('lport must be an integer between 1024 and 65535');
      }
    }

    if (typeof params.platform !== 'undefined' && (typeof params.platform !== 'string' || !/^[a-zA-Z0-9._-]{1,32}$/.test(params.platform))) {
      errors.push('platform contains unsupported characters');
    }

    if (typeof params.arch !== 'undefined' && (typeof params.arch !== 'string' || !/^[a-zA-Z0-9._-]{1,32}$/.test(params.arch))) {
      errors.push('arch contains unsupported characters');
    }

    if (typeof params.encoder !== 'undefined' && (typeof params.encoder !== 'string' || !/^[a-zA-Z0-9_/-]{1,64}$/.test(params.encoder))) {
      errors.push('encoder contains unsupported characters');
    }

    if (typeof params.iterations !== 'undefined') {
      const iterations = Number(params.iterations);
      if (!Number.isInteger(iterations) || iterations < 1 || iterations > 10) {
        errors.push('iterations must be an integer between 1 and 10');
      }
    }

    if (typeof params.badchars !== 'undefined') {
      if (typeof params.badchars !== 'string' || params.badchars.length > 256) {
        errors.push('badchars must be a string <= 256 chars');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  async executeImpl(input) {
    const params = input.params || {};
    const payload = String(params.payload || '').trim();
    const format = String(params.format || '').trim().toLowerCase();

    const args = ['-p', payload, '-f', format];
    if (typeof params.lhost === 'string' && params.lhost.trim()) {
      args.push(`LHOST=${params.lhost.trim()}`);
    }
    if (typeof params.lport !== 'undefined') {
      args.push(`LPORT=${Number(params.lport)}`);
    }
    if (typeof params.platform === 'string' && params.platform.trim()) {
      args.push('--platform', params.platform.trim());
    }
    if (typeof params.arch === 'string' && params.arch.trim()) {
      args.push('-a', params.arch.trim());
    }
    if (typeof params.encoder === 'string' && params.encoder.trim()) {
      args.push('-e', params.encoder.trim());
    }
    if (typeof params.iterations !== 'undefined') {
      args.push('-i', String(Number(params.iterations)));
    }
    if (typeof params.badchars === 'string' && params.badchars.length > 0) {
      args.push('-b', params.badchars);
    }

    const timeoutMs = Math.min(this.getResourceLimits().timeoutMs, Number(input.timeout) > 0 ? Number(input.timeout) : this.getResourceLimits().timeoutMs);
    const maxCapture = this.getResourceLimits().maxOutputBytes;

    return new Promise((resolve, reject) => {
      const child = spawn('msfvenom', args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const stdoutChunks = [];
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
        stdoutChunks.push(Buffer.from(chunk));
        bytes += chunk.length;
        if (bytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.stderr.on('data', (chunk) => {
        const text = chunk.toString('utf8');
        stderr += text;
      });

      child.on('error', (error) => {
        clearTimeout(killTimer);
        reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(error.message || 'Failed to execute msfvenom')));
      });

      child.on('close', (code) => {
        clearTimeout(killTimer);

        if (overflowed) {
          reject(this.makeError('TOOL_OUTPUT_TOO_LARGE', 'msfvenom output exceeded maximum allowed size'));
          return;
        }

        if (timedOut) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'msfvenom execution timed out'));
          return;
        }

        if (code !== 0) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(stderr.trim() || `msfvenom exited with code ${code}`)));
          return;
        }

        const payloadBuffer = Buffer.concat(stdoutChunks);
        const payloadData = TEXT_FORMATS.has(format) ? payloadBuffer.toString('utf8') : payloadBuffer.toString('base64');

        resolve({
          payload,
          format,
          encoded: typeof params.encoder === 'string' && params.encoder.trim().length > 0,
          encoder: typeof params.encoder === 'string' ? params.encoder.trim() : '',
          iterations: typeof params.iterations !== 'undefined' ? Number(params.iterations) : undefined,
          sizeBytes: payloadBuffer.length,
          payloadData,
          runtimeSeconds: Math.max(0, Math.round((Date.now() - startedAt) / 1000)),
          status: 'generated',
        });
      });
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);

    const result = {
      payload: typeof payload.payload === 'string' ? payload.payload : '',
      format: typeof payload.format === 'string' ? payload.format : '',
      size_bytes: Number.isFinite(Number(payload.sizeBytes)) ? Number(payload.sizeBytes) : 0,
      encoded: Boolean(payload.encoded),
      payload_data: typeof payload.payloadData === 'string' ? payload.payloadData : '',
      runtime_seconds: Number.isFinite(Number(payload.runtimeSeconds)) ? Number(payload.runtimeSeconds) : 0,
      status: typeof payload.status === 'string' ? payload.status : 'generated',
    };

    if (result.encoded && typeof payload.encoder === 'string' && payload.encoder) {
      result.encoder = payload.encoder;
    }

    if (typeof payload.iterations !== 'undefined' && Number.isFinite(Number(payload.iterations))) {
      result.iterations = Number(payload.iterations);
    }

    return result;
  }

  getResourceLimits() {
    return {
      timeoutMs: 120000,
      memoryMb: 1024,
      maxOutputBytes: 10 * 1024 * 1024,
    };
  }
}

module.exports = {
  MsfvenomAdapter,
};
