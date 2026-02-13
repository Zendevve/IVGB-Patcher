const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ─── License Key Format ──────────────────────────────────────────────────────
//
//  IVGB-XXXX-XXXX-XXXX-XXXX
//
//  Encoded inside:
//    - Tier (personal/supporter/pro/team)
//    - Expiry or perpetual
//    - Machine fingerprint binding (optional)
//    - HMAC signature to prevent forgery
//
// ─────────────────────────────────────────────────────────────────────────────

// IMPORTANT: In production, move this to a server or obfuscate.
// This is the seed for HMAC signing. Change this to YOUR secret.
const LICENSE_SECRET = 'IVGB-PATCHER-PLUS-LICENSE-SECRET-CHANGE-ME-2024';

const TIERS = {
  0: { name: 'Personal', label: 'Free — Non-Commercial', color: '#8b949e', commercial: false },
  1: { name: 'Supporter', label: 'Supporter', color: '#3fb950', commercial: false },
  2: { name: 'Pro', label: 'Pro — Commercial Use', color: '#58a6ff', commercial: true },
  3: { name: 'Team', label: 'Team / Studio', color: '#bc8cff', commercial: true },
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

  // ─── Machine Fingerprint ──────────────────────────────────────────────

  getMachineId() {
    const data = [
      os.hostname(),
      os.platform(),
      os.arch(),
      os.cpus()[0]?.model || '',
      os.totalmem().toString(),
      // Get first non-internal MAC address
      ...Object.values(os.networkInterfaces())
        .flat()
        .filter(i => !i.internal && i.mac && i.mac !== '00:00:00:00:00:00')
        .map(i => i.mac)
        .slice(0, 2),
    ].join('|');

    return crypto.createHash('sha256').update(data).digest('hex').slice(0, 16);
  }

  // ─── Key Generation (YOUR side — run this to create keys for buyers) ──

  /**
   * Generate a license key.
   * Run this yourself to create keys for customers.
   *
   * Usage:
   *   const lm = new LicenseManager();
   *   const key = lm.generateKey({ tier: 2, email: 'buyer@email.com' });
   *   console.log(key);  // IVGB-XXXX-XXXX-XXXX-XXXX
   */
  generateKey(options = {}) {
    const {
      tier = 0,                          // 0=personal, 1=supporter, 2=pro, 3=team
      email = '',                        // buyer email
      expiryDays = 0,                    // 0 = perpetual
      machineId = '',                    // empty = not machine-locked
    } = options;

    // Build payload
    const payload = {
      t: tier,                           // tier
      e: email ? this._hashEmail(email) : '', // hashed email
      x: expiryDays > 0                 // expiry timestamp
        ? Math.floor(Date.now() / 1000) + (expiryDays * 86400)
        : 0,
      m: machineId,                      // machine lock
      c: Date.now(),                     // creation timestamp
    };

    // Serialize and encode
    const payloadStr = JSON.stringify(payload);
    const payloadB64 = Buffer.from(payloadStr).toString('base64url');

    // Sign
    const signature = this._sign(payloadB64);

    // Combine: payload.signature
    const raw = `${payloadB64}.${signature}`;

    // Format as IVGB-XXXX-XXXX-XXXX-XXXX...
    const hex = Buffer.from(raw).toString('hex');
    return this._formatKey(hex);
  }

  /**
   * Generate multiple keys (batch)
   */
  generateKeys(count, options = {}) {
    const keys = [];
    for (let i = 0; i < count; i++) {
      keys.push(this.generateKey(options));
    }
    return keys;
  }

  // ─── Key Validation (runs in the app) ─────────────────────────────────

  /**
   * Validate and activate a license key
   */
  validateKey(key) {
    try {
      // Clean and parse
      const cleaned = key.replace(/[^a-fA-F0-9]/g, '');
      const raw = Buffer.from(cleaned, 'hex').toString('utf8');

      const [payloadB64, signature] = raw.split('.');
      if (!payloadB64 || !signature) {
        return { valid: false, error: 'Invalid key format' };
      }

      // Verify signature
      const expectedSig = this._sign(payloadB64);
      if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
        return { valid: false, error: 'Invalid license key' };
      }

      // Decode payload
      const payloadStr = Buffer.from(payloadB64, 'base64url').toString('utf8');
      const payload = JSON.parse(payloadStr);

      // Check expiry
      if (payload.x > 0) {
        const now = Math.floor(Date.now() / 1000);
        if (now > payload.x) {
          return {
            valid: false,
            error: 'License has expired',
            expired: true,
            expiredAt: new Date(payload.x * 1000).toISOString(),
          };
        }
      }

      // Check machine lock
      if (payload.m && payload.m.length > 0) {
        const currentMachine = this.getMachineId();
        if (payload.m !== currentMachine) {
          return {
            valid: false,
            error: 'License is locked to a different machine',
            machineLocked: true,
          };
        }
      }

      // Valid!
      const tier = TIERS[payload.t] || TIERS[0];

      return {
        valid: true,
        tier: payload.t,
        tierName: tier.name,
        tierLabel: tier.label,
        tierColor: tier.color,
        commercial: tier.commercial,
        perpetual: payload.x === 0,
        expiresAt: payload.x > 0 ? new Date(payload.x * 1000).toISOString() : null,
        machineLocked: !!(payload.m && payload.m.length > 0),
        createdAt: new Date(payload.c).toISOString(),
      };
    } catch (err) {
      return { valid: false, error: 'Invalid license key' };
    }
  }

  // ─── Activation / Storage ─────────────────────────────────────────────

  /**
   * Activate a license key (validate + save)
   */
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

  /**
   * Deactivate / remove license
   */
  deactivate() {
    this.currentLicense = null;
    try {
      if (fs.existsSync(this.licenseFile)) {
        fs.unlinkSync(this.licenseFile);
      }
    } catch (e) { }
    return { success: true };
  }

  /**
   * Get current license status
   */
  getStatus() {
    if (!this.currentLicense) {
      return {
        licensed: false,
        tier: 0,
        tierName: 'Personal',
        tierLabel: 'Free — Non-Commercial',
        tierColor: '#8b949e',
        commercial: false,
      };
    }

    // Re-validate stored key (check expiry)
    const recheck = this.validateKey(this.currentLicense.key);
    if (!recheck.valid) {
      // License expired or invalid
      this.currentLicense = null;
      return {
        licensed: false,
        tier: 0,
        tierName: 'Personal',
        tierLabel: 'Free — Non-Commercial',
        tierColor: '#8b949e',
        commercial: false,
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
    // IVGB-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
    const chunks = [];
    for (let i = 0; i < hex.length; i += 4) {
      chunks.push(hex.slice(i, i + 4).toUpperCase());
    }
    return 'IVGB-' + chunks.join('-');
  }

  _save(data) {
    try {
      fs.writeFileSync(this.licenseFile, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
      // Silent fail — license still works in memory
    }
  }

  _loadSaved() {
    try {
      if (fs.existsSync(this.licenseFile)) {
        const raw = fs.readFileSync(this.licenseFile, 'utf8');
        const data = JSON.parse(raw);
        if (data.key) {
          const check = this.validateKey(data.key);
          if (check.valid) {
            this.currentLicense = data;
          } else {
            // Invalid or expired — clean up
            this.currentLicense = null;
          }
        }
      }
    } catch (e) {
      this.currentLicense = null;
    }
  }
}

// ─── CLI Key Generator ──────────────────────────────────────────────────────
// Run: node license-manager.js generate --tier 2 --email buyer@email.com

if (require.main === module) {
  const args = process.argv.slice(2);

  if (args[0] === 'generate') {
    const lm = new LicenseManager();

    let tier = 0;
    let email = '';
    let count = 1;
    let expiryDays = 0;

    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--tier' && args[i + 1]) tier = parseInt(args[++i]);
      if (args[i] === '--email' && args[i + 1]) email = args[++i];
      if (args[i] === '--count' && args[i + 1]) count = parseInt(args[++i]);
      if (args[i] === '--expiry' && args[i + 1]) expiryDays = parseInt(args[++i]);
    }

    console.log('');
    console.log('IVGB Patcher+ — License Key Generator');
    console.log('══════════════════════════════════════');
    console.log(`Tier:    ${TIERS[tier]?.name || 'Unknown'} (${tier})`);
    console.log(`Email:   ${email || '(none)'}`);
    console.log(`Expiry:  ${expiryDays > 0 ? `${expiryDays} days` : 'Perpetual'}`);
    console.log(`Count:   ${count}`);
    console.log('');

    for (let i = 0; i < count; i++) {
      const key = lm.generateKey({ tier, email, expiryDays });
      console.log(`  ${key}`);

      // Verify it works
      const check = lm.validateKey(key);
      console.log(`    ✅ Valid: ${check.tierLabel}${check.perpetual ? ' (perpetual)' : ` (expires ${check.expiresAt})`}`);
      console.log('');
    }
  } else if (args[0] === 'validate') {
    const lm = new LicenseManager();
    const key = args.slice(1).join(' ');
    console.log('');
    console.log('Validating:', key);
    const result = lm.validateKey(key);
    console.log(JSON.stringify(result, null, 2));
  } else if (args[0] === 'machine-id') {
    const lm = new LicenseManager();
    console.log('Machine ID:', lm.getMachineId());
  } else {
    console.log('');
    console.log('IVGB Patcher+ — License Key Tool');
    console.log('');
    console.log('Usage:');
    console.log('  node license-manager.js generate --tier 2 --email buyer@email.com');
    console.log('  node license-manager.js generate --tier 1 --count 10');
    console.log('  node license-manager.js generate --tier 3 --expiry 365');
    console.log('  node license-manager.js validate IVGB-XXXX-XXXX-...');
    console.log('  node license-manager.js machine-id');
    console.log('');
    console.log('Tiers:');
    for (const [id, t] of Object.entries(TIERS)) {
      console.log(`  ${id} = ${t.name} (${t.label})`);
    }
  }
}

module.exports = { LicenseManager, TIERS };
