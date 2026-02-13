const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Try to load the secret key, otherwise fall back to a public dev key
let LICENSE_SECRET;
try {
  LICENSE_SECRET = require('./key.js');
} catch (e) {
  LICENSE_SECRET = 'OPEN-SOURCE-DEV-KEY-DO-NOT-USE-IN-PRODUCTION';
  if (process.env.NODE_ENV !== 'production') {
    console.warn('⚠️  Warning: Using default development license key. Official keys will not validate.');
  }
}

const TIERS = {
  0: { name: 'Personal', label: 'Personal — Build from Source', color: '#8b949e' },
  1: { name: 'Paid', label: 'IVGB Patcher+', color: '#58a6ff' },
};

class LicenseManager {
  constructor() {
    this.licenseDir = path.join(os.homedir(), '.ivgb-patcher-plus');
    this.licenseFile = path.join(this.licenseDir, 'license.json');
    this.currentLicense = null;
    this._ensureDir();
    this._loadSaved();
  }

  _ensureDir() {
    if (!fs.existsSync(this.licenseDir)) {
      fs.mkdirSync(this.licenseDir, { recursive: true });
    }
  }

  getMachineId() {
    const data = [
      os.hostname(),
      os.platform(),
      os.arch(),
      os.cpus()[0]?.model || '',
      os.totalmem().toString(),
      ...Object.values(os.networkInterfaces())
        .flat()
        .filter(i => !i.internal && i.mac && i.mac !== '00:00:00:00:00:00')
        .map(i => i.mac)
        .slice(0, 2),
    ].join('|');
    return crypto.createHash('sha256').update(data).digest('hex').slice(0, 16);
  }

  // ─── Generate keys (YOUR side only) ───────────────────────────────────

  generateKey(options = {}) {
    const {
      email = '',
      expiryDays = 0,     // 0 = perpetual (lifetime)
    } = options;

    const payload = {
      t: 1,               // always tier 1 (paid) — you never generate tier 0 keys
      e: email ? this._hashEmail(email) : '',
      x: expiryDays > 0
        ? Math.floor(Date.now() / 1000) + (expiryDays * 86400)
        : 0,
      c: Date.now(),
    };

    const payloadStr = JSON.stringify(payload);
    const payloadB64 = Buffer.from(payloadStr).toString('base64url');
    const signature = this._sign(payloadB64);
    const raw = `${payloadB64}.${signature}`;
    const hex = Buffer.from(raw).toString('hex');
    return this._formatKey(hex);
  }

  generateKeys(count, options = {}) {
    const keys = [];
    for (let i = 0; i < count; i++) keys.push(this.generateKey(options));
    return keys;
  }

  // ─── Validate (runs in app) ───────────────────────────────────────────

  validateKey(key) {
    try {
      const cleaned = key.replace(/[^a-fA-F0-9]/g, '');
      const raw = Buffer.from(cleaned, 'hex').toString('utf8');
      const [payloadB64, signature] = raw.split('.');

      if (!payloadB64 || !signature) {
        return { valid: false, error: 'Invalid key format' };
      }

      const expectedSig = this._sign(payloadB64);
      if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
        return { valid: false, error: 'Invalid license key' };
      }

      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

      // Check expiry
      if (payload.x > 0 && Math.floor(Date.now() / 1000) > payload.x) {
        return {
          valid: false,
          error: 'License has expired',
          expired: true,
          expiredAt: new Date(payload.x * 1000).toISOString(),
        };
      }

      return {
        valid: true,
        tier: 1,
        tierName: 'Paid',
        tierLabel: 'IVGB Patcher+',
        tierColor: '#58a6ff',
        perpetual: payload.x === 0,
        expiresAt: payload.x > 0 ? new Date(payload.x * 1000).toISOString() : null,
        createdAt: new Date(payload.c).toISOString(),
      };

    } catch (err) {
      return { valid: false, error: 'Invalid license key' };
    }
  }

  activate(key) {
    const result = this.validateKey(key);
    if (result.valid) {
      const data = {
        key: key.trim(),
        activatedAt: new Date().toISOString(),
        machineId: this.getMachineId(),
        ...result,
      };
      this.currentLicense = data;
      this._save(data);
    }
    return result;
  }

  deactivate() {
    this.currentLicense = null;
    try { if (fs.existsSync(this.licenseFile)) fs.unlinkSync(this.licenseFile); }
    catch (e) { }
    return { success: true };
  }

  getStatus() {
    if (!this.currentLicense) {
      return {
        licensed: false,
        tier: 0,
        tierName: 'Personal',
        tierLabel: 'Personal — Non-Commercial',
        tierColor: '#8b949e',
      };
    }

    const recheck = this.validateKey(this.currentLicense.key);
    if (!recheck.valid) {
      this.currentLicense = null;
      return {
        licensed: false,
        tier: 0,
        tierName: 'Personal',
        tierLabel: 'Personal — Non-Commercial',
        tierColor: '#8b949e',
        expired: recheck.expired || false,
        error: recheck.error,
      };
    }

    return {
      licensed: true,
      ...recheck,
      activatedAt: this.currentLicense.activatedAt,
    };
  }

  // ─── Internal ─────────────────────────────────────────────────────────

  _sign(data) {
    return crypto
      .createHmac('sha256', LICENSE_SECRET)
      .update(data)
      .digest('base64url')
      .slice(0, 16);
  }

  _hashEmail(email) {
    return crypto
      .createHash('sha256')
      .update(email.toLowerCase().trim())
      .digest('hex')
      .slice(0, 12);
  }

  _formatKey(hex) {
    const chunks = [];
    for (let i = 0; i < hex.length; i += 4) {
      chunks.push(hex.slice(i, i + 4).toUpperCase());
    }
    return 'IVGB-' + chunks.join('-');
  }

  _save(data) {
    try { fs.writeFileSync(this.licenseFile, JSON.stringify(data, null, 2), 'utf8'); }
    catch (e) { }
  }

  _loadSaved() {
    try {
      if (fs.existsSync(this.licenseFile)) {
        const data = JSON.parse(fs.readFileSync(this.licenseFile, 'utf8'));
        if (data.key) {
          const check = this.validateKey(data.key);
          if (check.valid) this.currentLicense = data;
          else this.currentLicense = null;
        }
      }
    } catch (e) { this.currentLicense = null; }
  }
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

if (require.main === module) {
  const args = process.argv.slice(2);
  const lm = new LicenseManager();

  if (args[0] === 'generate') {
    let email = '';
    let count = 1;
    let expiryDays = 0;

    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--email' && args[i + 1]) email = args[++i];
      if (args[i] === '--count' && args[i + 1]) count = parseInt(args[++i]);
      if (args[i] === '--expiry' && args[i + 1]) expiryDays = parseInt(args[++i]);
    }

    console.log('');
    console.log('IVGB Patcher+ — Key Generator');
    console.log('═════════════════════════════');
    console.log(`Email:   ${email || '(none)'}`);
    console.log(`Expiry:  ${expiryDays > 0 ? `${expiryDays} days` : 'Lifetime'}`);
    console.log(`Count:   ${count}`);
    console.log('');

    const keys = [];
    for (let i = 0; i < count; i++) {
      const key = lm.generateKey({ email, expiryDays });
      keys.push(key);
      const check = lm.validateKey(key);
      console.log(`  ${key}`);
      console.log(`    ✅ ${check.tierLabel} ${check.perpetual ? '(lifetime)' : `(expires ${check.expiresAt})`}`);
      console.log('');
    }

    if (count > 1) {
      fs.writeFileSync('keys.txt', keys.join('\n'), 'utf8');
      console.log(`Saved ${count} keys to keys.txt`);
    }

  } else if (args[0] === 'validate') {
    const key = args.slice(1).join(' ').trim();
    if (!key) { console.log('Usage: node license-manager.js validate IVGB-XXXX-...'); process.exit(1); }
    console.log('');
    const result = lm.validateKey(key);
    if (result.valid) {
      console.log(`✅ Valid — ${result.tierLabel}`);
      console.log(`   ${result.perpetual ? 'Lifetime license' : `Expires: ${result.expiresAt}`}`);
    } else {
      console.log(`❌ Invalid — ${result.error}`);
    }

  } else if (args[0] === 'machine-id') {
    console.log('Machine ID:', lm.getMachineId());

  } else {
    console.log('');
    console.log('IVGB Patcher+ — License Key Tool');
    console.log('');
    console.log('  node license-manager.js generate');
    console.log('  node license-manager.js generate --email buyer@email.com');
    console.log('  node license-manager.js generate --count 50');
    console.log('  node license-manager.js generate --expiry 365');
    console.log('  node license-manager.js validate IVGB-XXXX-XXXX-...');
    console.log('  node license-manager.js machine-id');
  }
}

module.exports = { LicenseManager, TIERS };
