const fs = require('fs');
const path = require('path');
const log = require('electron-log');
const { PEParser } = require('./pe-parser.js');
const { PEPatcher } = require('./pe-patcher.js');

class BatchProcessor {
  constructor() {
    this.results = [];
  }

  async scanAndReport(directory, recursive) {
    log.info(`Batch scanning directory: ${directory} (recursive: ${recursive})`);

    if (!fs.existsSync(directory)) throw new Error(`Directory not found: ${directory}`);

    const peFiles = await this.findPEFiles(directory, recursive);
    const results = [];
    const summary = {
      ok: 0, errors: 0,
      withLAA: 0, withoutLAA: 0,
      withASLR: 0, withDEP: 0, withCFG: 0,
      pe32: 0, pe32plus: 0
    };

    for (const filePath of peFiles) {
      try {
        const buffer = fs.readFileSync(filePath);
        const parser = new PEParser(buffer);
        const analysis = parser.getFullAnalysis();

        analysis.file.name = path.basename(filePath);
        analysis.file.path = filePath;

        results.push({
          status: 'ok',
          path: filePath,
          name: path.basename(filePath),
          analysis
        });

        summary.ok++;
        if (analysis.summary.isLAA) summary.withLAA++; else summary.withoutLAA++;
        if (analysis.summary.isASLR) summary.withASLR++;
        if (analysis.summary.isDEP) summary.withDEP++;
        if (analysis.summary.isCFG) summary.withCFG++;
        if (analysis.summary.format === 'PE32') summary.pe32++;
        if (analysis.summary.format === 'PE32+') summary.pe32plus++;

      } catch (err) {
        log.error(`Batch scan error for ${filePath}:`, err);
        results.push({
          status: 'error',
          path: filePath,
          name: path.basename(filePath),
          error: err.message
        });
        summary.errors++;
      }
    }

    return { totalFiles: peFiles.length, summary, results };
  }

  async batchPatch(files, flags, options = {}) {
    log.info(`Batch patching ${files.length} files`);
    const results = [];

    for (const filePath of files) {
      try {
        if (!fs.existsSync(filePath)) {
          results.push({ name: path.basename(filePath), status: 'error', error: 'File not found' });
          continue;
        }

        const buffer = fs.readFileSync(filePath);
        const patcher = new PEPatcher(buffer);

        const flagResults = patcher.applyFlagChanges(flags);
        const changed = flagResults.some(r => r.changed);

        if (!changed) {
          results.push({ name: path.basename(filePath), status: 'skipped', error: 'No changes needed' });
          continue;
        }

        if (options.recalcChecksum !== false) {
          patcher.recalculateChecksum();
        }

        let backupPath = null;
        if (options.createBackup !== false) {
          const ext = path.extname(filePath);
          const base = filePath.slice(0, -ext.length);
          backupPath = `${base}.backup${ext}`;
          let c = 1;
          while (fs.existsSync(backupPath)) {
            backupPath = `${base}.backup${c}${ext}`;
            c++;
          }
          fs.copyFileSync(filePath, backupPath);
        }

        fs.writeFileSync(filePath, patcher.getBuffer());

        results.push({
          name: path.basename(filePath),
          status: 'patched',
          backupPath
        });

        log.info(`Batch patched: ${filePath}`);

      } catch (err) {
        log.error(`Batch patch error for ${filePath}:`, err);
        results.push({ name: path.basename(filePath), status: 'error', error: err.message });
      }
    }

    return results;
  }

  async findPEFiles(directory, recursive) {
    const peFiles = [];
    const items = fs.readdirSync(directory);

    for (const item of items) {
      const fullPath = path.join(directory, item);
      let stats;

      try { stats = fs.statSync(fullPath); }
      catch (e) { continue; }

      if (stats.isFile()) {
        const ext = path.extname(item).toLowerCase();
        if (['.exe', '.dll', '.sys', '.scr', '.ocx', '.drv', '.cpl', '.efi'].includes(ext)) {
          peFiles.push(fullPath);
        }
      } else if (stats.isDirectory() && recursive) {
        peFiles.push(...(await this.findPEFiles(fullPath, true)));
      }
    }

    return peFiles;
  }
}

module.exports = { BatchProcessor };
