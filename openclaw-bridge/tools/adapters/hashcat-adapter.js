const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { BaseToolAdapter } = require('../base-adapter.js');

const SUPPORTED_HASH_TYPES = new Map([
  [0, { name: 'MD5', validator: /^[a-fA-F0-9]{32}$/ }],
  [100, { name: 'SHA1', validator: /^[a-fA-F0-9]{40}$/ }],
  [1000, { name: 'NTLM', validator: /^[a-fA-F0-9]{32}$/ }],
  [1400, { name: 'SHA256', validator: /^[a-fA-F0-9]{64}$/ }],
  [1700, { name: 'SHA512', validator: /^[a-fA-F0-9]{128}$/ }],
  [1800, { name: 'sha512crypt', validator: /^\$6\$[^\s]+$/ }],
  [3200, { name: 'bcrypt', validator: /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/ }],
]);

const ALLOWED_ATTACK_MODES = new Set([0, 3]);
const WORDLISTS = Object.freeze({
  'rockyou-mini': '/usr/share/wordlists/rockyou.txt',
  'top-1000': '/usr/share/seclists/Passwords/Common-Credentials/top-1000.txt',
  'common-passwords': '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
});

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function sanitizeOutputText(text) {
  return String(text || '')
    .replace(/\/Users\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/home\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/tmp\/[\w.-/]+/g, '<tmp_redacted>');
}

function resolveHashcatStatus(stdout, stderr, timedOut, cracked) {
  if (timedOut) {
    return 'timeout';
  }
  const text = `${stdout}\n${stderr}`.toLowerCase();
  if (cracked) {
    return 'cracked';
  }
  if (text.includes('exhausted')) {
    return 'exhausted';
  }
  if (text.includes('error') || text.includes('failed')) {
    return 'error';
  }
  return 'exhausted';
}

class HashcatAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'hashcat',
      slug: 'hashcat',
      description: 'Password recovery and hash cracking tool',
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

    if (typeof params.hash !== 'string' || params.hash.trim().length === 0) {
      errors.push('hash is required and must be a non-empty string');
    }

    const hashType = Number(params.hashType);
    if (!Number.isInteger(hashType) || !SUPPORTED_HASH_TYPES.has(hashType)) {
      errors.push('hashType is required and must be one of: 0, 100, 1000, 1400, 1700, 1800, 3200');
    }

    const attackMode = typeof params.attackMode === 'undefined' ? 0 : Number(params.attackMode);
    if (!Number.isInteger(attackMode) || !ALLOWED_ATTACK_MODES.has(attackMode)) {
      errors.push('attackMode must be 0 (dictionary) or 3 (brute-force)');
    }

    const wordlist = typeof params.wordlist === 'string' ? params.wordlist.trim() : 'rockyou-mini';
    if (attackMode === 0 && !Object.prototype.hasOwnProperty.call(WORDLISTS, wordlist || 'rockyou-mini')) {
      errors.push(`wordlist must be one of: ${Object.keys(WORDLISTS).join(', ')}`);
    }

    const maxRuntime = typeof params.maxRuntime === 'undefined' ? 60 : Number(params.maxRuntime);
    if (!Number.isFinite(maxRuntime) || maxRuntime <= 0 || maxRuntime > 300) {
      errors.push('maxRuntime must be a positive number <= 300 seconds');
    }

    if (typeof params.hash === 'string' && Number.isInteger(hashType) && SUPPORTED_HASH_TYPES.has(hashType)) {
      const validator = SUPPORTED_HASH_TYPES.get(hashType).validator;
      if (!validator.test(params.hash.trim())) {
        errors.push(`hash format does not match expected ${SUPPORTED_HASH_TYPES.get(hashType).name} format`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  async executeImpl(input) {
    const params = input.params || {};
    const hash = String(params.hash || '').trim();
    const hashType = Number(params.hashType);
    const attackMode = typeof params.attackMode === 'undefined' ? 0 : Number(params.attackMode);
    const maxRuntime = Math.min(
      300,
      Math.max(
        1,
        Number.isFinite(Number(params.maxRuntime)) ? Number(params.maxRuntime) : Math.floor((Number(input.timeout) || this.getResourceLimits().timeoutMs) / 1000),
      ),
    );

    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'openclaw-hashcat-'));
    const outFile = path.join(tempDir, 'cracked.txt');

    const args = ['-m', String(hashType), '-a', String(attackMode), '--quiet', '--potfile-disable', '--runtime', String(maxRuntime), '--outfile', outFile, '--outfile-format', '2', hash];

    if (attackMode === 0) {
      const wordlistName = typeof params.wordlist === 'string' && params.wordlist.trim() ? params.wordlist.trim() : 'rockyou-mini';
      args.push(WORDLISTS[wordlistName]);
    } else {
      const mask = typeof params.mask === 'string' && params.mask.trim() ? params.mask.trim() : '?a?a?a?a?a?a';
      args.push(mask);
    }

    const timeoutMs = Math.min(this.getResourceLimits().timeoutMs, maxRuntime * 1000);
    const maxCapture = this.getResourceLimits().maxOutputBytes;

    return new Promise((resolve, reject) => {
      const child = spawn('hashcat', args, {
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
        const chunkText = chunk.toString('utf8');
        stdout += chunkText;
        outputBytes += Buffer.byteLength(chunkText, 'utf8');
        if (outputBytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.stderr.on('data', (chunk) => {
        const chunkText = chunk.toString('utf8');
        stderr += chunkText;
        outputBytes += Buffer.byteLength(chunkText, 'utf8');
        if (outputBytes > maxCapture) {
          overflowed = true;
          child.kill('SIGKILL');
        }
      });

      child.on('error', async (error) => {
        clearTimeout(killTimer);
        await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
        reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeOutputText(error.message || 'Failed to execute hashcat')));
      });

      child.on('close', async (code) => {
        clearTimeout(killTimer);
        let password = '';
        try {
          const out = await fs.readFile(outFile, 'utf8');
          password = out.split(/\r?\n/).map((line) => line.trim()).find(Boolean) || '';
        } catch {}

        const runtimeSeconds = Math.max(0, Math.round((Date.now() - startedAt) / 1000));

        await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});

        if (overflowed) {
          reject(this.makeError('TOOL_OUTPUT_TOO_LARGE', 'hashcat output exceeded maximum allowed size'));
          return;
        }

        if (timedOut) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'hashcat execution timed out'));
          return;
        }

        if (code !== 0 && !password) {
          const message = sanitizeOutputText(stderr.trim() || stdout.trim() || `hashcat exited with code ${code}`);
          reject(this.makeError('TOOL_EXECUTION_ERROR', message));
          return;
        }

        const cracked = Boolean(password);
        resolve({
          hash,
          password,
          cracked,
          runtimeSeconds,
          status: resolveHashcatStatus(stdout, stderr, false, cracked),
        });
      });
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);
    const hash = typeof payload.hash === 'string' ? payload.hash : '';
    const cracked = Boolean(payload.cracked);
    const status = typeof payload.status === 'string' ? payload.status : cracked ? 'cracked' : 'exhausted';

    const normalized = {
      hash,
      cracked,
      runtime_seconds: Number.isFinite(Number(payload.runtimeSeconds)) ? Number(payload.runtimeSeconds) : 0,
      status,
    };

    if (cracked && typeof payload.password === 'string' && payload.password.length > 0) {
      normalized.password = payload.password;
    }

    return normalized;
  }

  getResourceLimits() {
    return {
      timeoutMs: 300000,
      memoryMb: 1024,
      maxOutputBytes: 1024 * 1024,
    };
  }
}

module.exports = {
  HashcatAdapter,
};
