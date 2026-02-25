const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { BaseToolAdapter } = require('../base-adapter.js');

const BUILTIN_WORDLISTS = Object.freeze({
  common: '/usr/share/seclists/Discovery/Web-Content/common.txt',
  'dirb-small': '/usr/share/dirb/wordlists/small.txt',
  'dirb-medium': '/usr/share/dirb/wordlists/common.txt',
  params: '/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
  subdomains: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt',
});

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']);
const RESERVED_HEADERS = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization']);

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function sanitizeText(text) {
  return String(text || '')
    .replace(/\/Users\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/home\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/tmp\/[\w.-/]+/g, '<tmp_redacted>');
}

function parseUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function parseCodeArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item) => Number(item))
    .filter((code) => Number.isInteger(code) && code >= 100 && code <= 599);
}

function validateHeaders(headers, errors) {
  if (typeof headers === 'undefined') {
    return;
  }
  if (!isPlainObject(headers)) {
    errors.push('headers must be an object when provided');
    return;
  }
  for (const [key] of Object.entries(headers)) {
    const lower = key.trim().toLowerCase();
    if (!lower || lower.includes('\n') || lower.includes('\r')) {
      errors.push('headers contain invalid header names');
      continue;
    }
    if (RESERVED_HEADERS.has(lower)) {
      errors.push(`header '${key}' is reserved and not allowed`);
    }
  }
}

class FfufAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'ffuf',
      slug: 'ffuf',
      description: 'Fast web fuzzer for directory/file discovery and parameter fuzzing',
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

    const urlValue = typeof params.url === 'string' ? params.url.trim() : '';
    const parsed = parseUrl(urlValue);
    if (!parsed || !['http:', 'https:'].includes(parsed.protocol)) {
      errors.push('url is required and must be a valid http/https URL');
    }
    if (!urlValue.includes('FUZZ')) {
      errors.push('url must include FUZZ placeholder');
    }

    const wordlist = typeof params.wordlist === 'string' ? params.wordlist.trim() : '';
    if (!wordlist) {
      errors.push('wordlist is required');
    } else if (wordlist !== 'custom' && !Object.prototype.hasOwnProperty.call(BUILTIN_WORDLISTS, wordlist)) {
      errors.push(`wordlist must be one of: ${Object.keys(BUILTIN_WORDLISTS).join(', ')}, custom`);
    }

    if (wordlist === 'custom') {
      if (!Array.isArray(params.customWords) || params.customWords.length === 0) {
        errors.push('customWords must be a non-empty array when wordlist is custom');
      } else {
        if (params.customWords.length > 10000) {
          errors.push('customWords must contain <= 10000 entries');
        }
        const invalid = params.customWords.some((item) => typeof item !== 'string' || !item.trim() || item.length > 256);
        if (invalid) {
          errors.push('customWords entries must be non-empty strings <= 256 chars');
        }
      }
    }

    const method = (typeof params.method === 'string' ? params.method : 'GET').toUpperCase();
    if (!ALLOWED_METHODS.has(method)) {
      errors.push('method must be one of GET, POST, PUT, DELETE, HEAD, OPTIONS');
    }

    validateHeaders(params.headers, errors);

    if (typeof params.data !== 'undefined' && typeof params.data !== 'string') {
      errors.push('data must be a string when provided');
    }

    if (typeof params.filterCodes !== 'undefined' && parseCodeArray(params.filterCodes).length !== params.filterCodes.length) {
      errors.push('filterCodes must be an array of valid HTTP status codes');
    }

    if (typeof params.matchCodes !== 'undefined' && parseCodeArray(params.matchCodes).length !== params.matchCodes.length) {
      errors.push('matchCodes must be an array of valid HTTP status codes');
    }

    const threads = typeof params.threads === 'undefined' ? 10 : Number(params.threads);
    if (!Number.isInteger(threads) || threads < 1 || threads > 50) {
      errors.push('threads must be an integer between 1 and 50');
    }

    const rate = typeof params.rate === 'undefined' ? 50 : Number(params.rate);
    if (!Number.isFinite(rate) || rate <= 0 || rate > 100) {
      errors.push('rate must be a number between 0 and 100');
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
    const url = String(params.url || '').trim();
    const method = (typeof params.method === 'string' ? params.method : 'GET').toUpperCase();
    const threads = typeof params.threads === 'undefined' ? 10 : Number(params.threads);
    const rate = typeof params.rate === 'undefined' ? 50 : Number(params.rate);
    const maxRuntime = Math.min(
      600,
      Math.max(
        1,
        Number.isFinite(Number(params.maxRuntime))
          ? Number(params.maxRuntime)
          : Math.floor((Number(input.timeout) || this.getResourceLimits().timeoutMs) / 1000),
      ),
    );

    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'openclaw-ffuf-'));
    const outputPath = path.join(tempDir, 'ffuf-output.json');
    let wordlistPath = '';

    const wordlist = String(params.wordlist || '').trim();
    if (wordlist === 'custom') {
      const customPath = path.join(tempDir, 'custom-wordlist.txt');
      const words = (params.customWords || []).map((word) => String(word).trim()).filter(Boolean);
      await fs.writeFile(customPath, `${words.join('\n')}\n`, 'utf8');
      wordlistPath = customPath;
    } else {
      wordlistPath = BUILTIN_WORDLISTS[wordlist];
    }

    const args = [
      '-u',
      url,
      '-w',
      wordlistPath,
      '-X',
      method,
      '-t',
      String(threads),
      '-rate',
      String(rate),
      '-o',
      outputPath,
      '-of',
      'json',
      '-maxtime',
      String(maxRuntime),
    ];

    if (isPlainObject(params.headers)) {
      for (const [key, value] of Object.entries(params.headers)) {
        args.push('-H', `${key}: ${String(value)}`);
      }
    }

    if (typeof params.data === 'string' && params.data.length > 0) {
      args.push('-d', params.data);
    }

    const matchCodes = parseCodeArray(params.matchCodes);
    if (matchCodes.length > 0) {
      args.push('-mc', matchCodes.join(','));
    }

    const filterCodes = parseCodeArray(params.filterCodes);
    if (filterCodes.length > 0) {
      args.push('-fc', filterCodes.join(','));
    }

    const timeoutMs = Math.min(this.getResourceLimits().timeoutMs, maxRuntime * 1000);
    const maxCapture = this.getResourceLimits().maxOutputBytes;

    return new Promise((resolve, reject) => {
      const child = spawn('ffuf', args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stderr = '';
      let stdout = '';
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

      child.on('error', async (error) => {
        clearTimeout(killTimer);
        await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
        reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(error.message || 'Failed to execute ffuf')));
      });

      child.on('close', async (code) => {
        clearTimeout(killTimer);

        if (overflowed) {
          await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
          reject(this.makeError('TOOL_OUTPUT_TOO_LARGE', 'ffuf output exceeded maximum allowed size'));
          return;
        }

        if (timedOut) {
          await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'ffuf execution timed out'));
          return;
        }

        let jsonText = '';
        try {
          jsonText = await fs.readFile(outputPath, 'utf8');
        } catch {
          jsonText = stdout;
        }

        await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});

        if (code !== 0 && !jsonText.trim()) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(stderr.trim() || `ffuf exited with code ${code}`)));
          return;
        }

        resolve({
          url,
          output: sanitizeText(jsonText),
          runtimeSeconds: Math.max(0, Math.round((Date.now() - startedAt) / 1000)),
          status: code === 0 ? 'completed' : 'error',
        });
      });
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);
    const url = typeof payload.url === 'string' ? payload.url : '';
    const runtimeSeconds = Number.isFinite(Number(payload.runtimeSeconds)) ? Number(payload.runtimeSeconds) : 0;
    const status = typeof payload.status === 'string' ? payload.status : 'completed';

    let parsedOutput = {};
    try {
      parsedOutput = JSON.parse(typeof payload.output === 'string' ? payload.output : '{}');
    } catch {
      parsedOutput = {};
    }

    const results = Array.isArray(parsedOutput.results)
      ? parsedOutput.results.map((item) => ({
          input: item && item.input && typeof item.input === 'object' ? String(Object.values(item.input)[0] || '') : String((item && item.input) || ''),
          url: item && typeof item.url === 'string' ? item.url : '',
          status: item && Number.isFinite(Number(item.status)) ? Number(item.status) : 0,
          size: item && Number.isFinite(Number(item.length)) ? Number(item.length) : 0,
          words: item && Number.isFinite(Number(item.words)) ? Number(item.words) : 0,
          lines: item && Number.isFinite(Number(item.lines)) ? Number(item.lines) : 0,
        }))
      : [];

    const totalRequests = Number.isFinite(Number(parsedOutput.position))
      ? Number(parsedOutput.position)
      : Number.isFinite(Number(parsedOutput.requests))
      ? Number(parsedOutput.requests)
      : 0;

    return {
      url,
      total_requests: totalRequests,
      successful_matches: results.length,
      results,
      runtime_seconds: runtimeSeconds,
      status,
    };
  }

  getResourceLimits() {
    return {
      timeoutMs: 600000,
      memoryMb: 512,
      maxOutputBytes: 20 * 1024 * 1024,
    };
  }
}

module.exports = {
  FfufAdapter,
};
