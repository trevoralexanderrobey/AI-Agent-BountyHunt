const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { BaseToolAdapter } = require('../base-adapter.js');

const BSSID_PATTERN = /^(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$/;
const KEY_TYPES = new Set(['wep', 'wpa']);
const WORDLISTS = Object.freeze({
  'rockyou-mini': '/usr/share/wordlists/rockyou.txt',
  'top-1000': '/usr/share/seclists/Passwords/Common-Credentials/top-1000.txt',
  'common-passwords': '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
});

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function sanitizeText(text) {
  return String(text || '')
    .replace(/\/Users\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/home\/[\w.-]+\//g, '<redacted_path>/')
    .replace(/\/tmp\/[\w.-/]+/g, '<tmp_redacted>');
}

function resolveAllowedCaptureRoots() {
  const configured = typeof process.env.OPENCLAW_AIRCRACK_CAPTURE_DIR === 'string' ? process.env.OPENCLAW_AIRCRACK_CAPTURE_DIR : '';
  const roots = [];

  if (configured.trim()) {
    for (const entry of configured.split(',')) {
      const value = entry.trim();
      if (value) {
        roots.push(path.resolve(value));
      }
    }
  }

  roots.push(path.resolve('/data/captures'));
  roots.push(path.resolve(__dirname, '../../data/captures'));

  return Array.from(new Set(roots));
}

function isPathInRoots(targetPath, roots) {
  const resolvedTarget = path.resolve(targetPath);
  return roots.some((root) => resolvedTarget === root || resolvedTarget.startsWith(`${root}${path.sep}`));
}

function parseKeysTested(output) {
  const match = String(output || '').match(/([0-9][0-9,]*)\s+keys tested/i);
  if (!match || !match[1]) {
    return 0;
  }
  const value = Number(match[1].replace(/,/g, ''));
  return Number.isFinite(value) ? value : 0;
}

function parseCrackedKey(output) {
  const keyFoundMatch = String(output || '').match(/KEY FOUND!\s*\[\s*(.*?)\s*\]/i);
  if (keyFoundMatch && keyFoundMatch[1]) {
    return keyFoundMatch[1].trim();
  }
  return '';
}

class AircrackAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: 'aircrack-ng',
      slug: 'aircrack',
      description: 'Wireless network security assessment and WPA/WPA2 cracking',
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

    const capturePath = typeof params.capturePath === 'string' ? params.capturePath.trim() : '';
    if (!capturePath) {
      errors.push('capturePath is required and must be a string');
    } else {
      const ext = path.extname(capturePath).toLowerCase();
      if (!['.cap', '.pcap'].includes(ext)) {
        errors.push('capturePath must point to a .cap or .pcap file');
      }
      const roots = resolveAllowedCaptureRoots();
      if (!isPathInRoots(capturePath, roots)) {
        errors.push('capturePath must be inside an allowed capture directory');
      } else {
        try {
          await fs.access(path.resolve(capturePath));
        } catch {
          errors.push('capturePath does not exist or is not readable');
        }
      }
    }

    if (typeof params.bssid !== 'undefined') {
      if (typeof params.bssid !== 'string' || !BSSID_PATTERN.test(params.bssid.trim())) {
        errors.push('bssid must match XX:XX:XX:XX:XX:XX format');
      }
    }

    if (typeof params.essid !== 'undefined') {
      if (typeof params.essid !== 'string' || params.essid.trim().length === 0 || params.essid.length > 64) {
        errors.push('essid must be a non-empty string <= 64 characters');
      }
    }

    const keyType = typeof params.keyType === 'string' ? params.keyType.trim().toLowerCase() : 'wpa';
    if (!KEY_TYPES.has(keyType)) {
      errors.push('keyType must be one of: wep, wpa');
    }

    const wordlistName = typeof params.wordlist === 'string' ? params.wordlist.trim() : 'rockyou-mini';
    if (!Object.prototype.hasOwnProperty.call(WORDLISTS, wordlistName || 'rockyou-mini')) {
      errors.push(`wordlist must be one of: ${Object.keys(WORDLISTS).join(', ')}`);
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
    const capturePath = path.resolve(String(params.capturePath || '').trim());
    const bssid = typeof params.bssid === 'string' ? params.bssid.trim().toUpperCase() : '';
    const essid = typeof params.essid === 'string' ? params.essid.trim() : '';
    const keyType = typeof params.keyType === 'string' ? params.keyType.trim().toLowerCase() : 'wpa';
    const wordlistName = typeof params.wordlist === 'string' && params.wordlist.trim() ? params.wordlist.trim() : 'rockyou-mini';
    const maxRuntime = Math.min(
      600,
      Math.max(
        1,
        Number.isFinite(Number(params.maxRuntime))
          ? Number(params.maxRuntime)
          : Math.floor((Number(input.timeout) || this.getResourceLimits().timeoutMs) / 1000),
      ),
    );

    const args = ['-w', WORDLISTS[wordlistName], capturePath];
    if (bssid) {
      args.splice(2, 0, '-b', bssid);
    }
    if (essid) {
      args.splice(2, 0, '-e', essid);
    }

    const timeoutMs = Math.min(this.getResourceLimits().timeoutMs, maxRuntime * 1000);
    const maxCapture = this.getResourceLimits().maxOutputBytes;

    return new Promise((resolve, reject) => {
      const child = spawn('aircrack-ng', args, {
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
        reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(error.message || 'Failed to execute aircrack-ng')));
      });

      child.on('close', (code) => {
        clearTimeout(killTimer);

        if (overflowed) {
          reject(this.makeError('TOOL_OUTPUT_TOO_LARGE', 'aircrack-ng output exceeded maximum allowed size'));
          return;
        }

        if (timedOut) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', 'aircrack-ng execution timed out'));
          return;
        }

        const combined = sanitizeText(`${stdout}\n${stderr}`);
        const crackedKey = parseCrackedKey(combined);
        const cracked = Boolean(crackedKey);
        const exhausted = /passphrase not in dictionary|keys tested|exhausted/i.test(combined) && !cracked;

        if (code !== 0 && !cracked && !exhausted) {
          reject(this.makeError('TOOL_EXECUTION_ERROR', sanitizeText(stderr.trim() || stdout.trim() || `aircrack-ng exited with code ${code}`)));
          return;
        }

        resolve({
          bssid,
          essid,
          keyType,
          cracked,
          key: crackedKey,
          keysTested: parseKeysTested(combined),
          runtimeSeconds: Math.max(0, Math.round((Date.now() - startedAt) / 1000)),
          status: cracked ? 'cracked' : exhausted ? 'exhausted' : 'error',
        });
      });
    });
  }

  async executeContainerImpl(input) {
    const params = input && input.params && typeof input.params === 'object' ? { ...input.params } : {};
    const rawCapturePath = typeof params.capturePath === 'string' ? params.capturePath.trim() : '';
    if (!rawCapturePath) {
      throw this.makeError('INVALID_TOOL_INPUT', 'capturePath is required for aircrack container execution');
    }

    const captureBasename = path.basename(rawCapturePath);
    const containerCapturePath = `/scratch/captures/${captureBasename}`;
    params.capturePath = containerCapturePath;

    const requestPayload = {
      slug: this.slug,
      params,
      timeout: input.timeout,
      requestId: input.requestId,
    };

    return this.buildContainerInvocation({
      params,
      timeout: input.timeout,
      requestId: input.requestId,
      inputArtifacts: [
        {
          kind: 'hostPath',
          sourcePath: rawCapturePath,
          targetPath: containerCapturePath,
        },
        {
          kind: 'inlineText',
          contents: JSON.stringify(requestPayload),
          targetPath: '/scratch/request.json',
        },
      ],
    });
  }

  async normalizeOutput(rawOutput) {
    const payload = this.parseJson(rawOutput);
    const cracked = Boolean(payload.cracked);
    const output = {
      bssid: typeof payload.bssid === 'string' ? payload.bssid : '',
      key_type: typeof payload.keyType === 'string' ? payload.keyType : 'wpa',
      cracked,
      keys_tested: Number.isFinite(Number(payload.keysTested)) ? Number(payload.keysTested) : 0,
      runtime_seconds: Number.isFinite(Number(payload.runtimeSeconds)) ? Number(payload.runtimeSeconds) : 0,
      status: typeof payload.status === 'string' ? payload.status : cracked ? 'cracked' : 'exhausted',
    };

    if (typeof payload.essid === 'string' && payload.essid) {
      output.essid = payload.essid;
    }

    if (cracked && typeof payload.key === 'string' && payload.key) {
      output.key = payload.key;
    }

    return output;
  }

  getResourceLimits() {
    return {
      timeoutMs: 600000,
      memoryMb: 1024,
      maxOutputBytes: 5 * 1024 * 1024,
    };
  }
}

module.exports = {
  AircrackAdapter,
};
