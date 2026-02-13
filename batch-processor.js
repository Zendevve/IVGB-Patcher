const fs = require('fs');
const path = require('path');
const log = require('electron-log');
const PEParser = require('./pe-parser.js');
const PEPatcher = require('./pe-patcher.js');

class BatchProcessor {
  constructor(files, options = {}) {
    this.files = files;
    this.options = {
      applyLAA: options.applyLAA || false,
      toggleASLR: options.toggleASLR || null, // true, false, or null (no change)
      toggleDEP: options.toggleDEP || null,
      toggleCFG: options.toggleCFG || null,
      removeSecurity: options.removeSecurity || false,
      createBackup: options.createBackup !== false,
      outputDir: options.outputDir || null,
      recursive: options.recursive || false,
      ...options
    };

    this.results = [];
    this.progress = 0;
    this.total = files.length;
  }

  async process() {
    log.info(`Starting batch processing of ${this.files.length} files`);

    for (const filePath of this.files) {
      try {
        const result = await this.processFile(filePath);
        this.results.push(result);
      } catch (error) {
        log.error(`Error processing ${filePath}:`, error);
        this.results.push({
          file: filePath,
          success: false,
          error: error.message
        });
      }

      this.progress++;
    }

    log.info('Batch processing complete');
    return this.getSummary();
  }

  async processFile(filePath) {
    const result = {
      file: filePath,
      fileName: path.basename(filePath),
      success: false,
      operations: []
    };

    try {
      // Verify file exists
      if (!fs.existsSync(filePath)) {
        throw new Error('File not found');
      }

      // Verify it's a PE file
      const stats = fs.statSync(filePath);
      if (!stats.isFile()) {
        throw new Error('Not a file');
      }

      // Parse the PE file first to get info
      const parser = new PEParser(filePath);
      const peData = await parser.parse();

      result.peInfo = {
        architecture: peData.coffHeader.Machine === 0x8664 ? 'x64' : 'x86',
        subsystem: peData.optionalHeader.Subsystem,
        imageBase: peData.optionalHeader.ImageBase.toString(),
        entryPoint: peData.optionalHeader.AddressOfEntryPoint.toString(16),
        sections: peData.sections.length,
        imports: peData.imports ? peData.imports.length : 0,
        exports: peData.exports ? peData.exports.functions.length : 0
      };

      // Handle output path
      let outputPath = filePath;
      if (this.options.outputDir) {
        const fileName = path.basename(filePath);
        outputPath = path.join(this.options.outputDir, fileName);

        // Create output directory if it doesn't exist
        if (!fs.existsSync(this.options.outputDir)) {
          fs.mkdirSync(this.options.outputDir, { recursive: true });
        }

        // Copy file to output directory if different
        if (outputPath !== filePath) {
          fs.copyFileSync(filePath, outputPath);
        }
      }

      // Create backup if requested
      if (this.options.createBackup) {
        const backupPath = outputPath + '.backup';
        fs.copyFileSync(outputPath, backupPath);
        result.backup = backupPath;
      }

      // Apply patches
      const patcher = new PEPatcher(outputPath);

      if (this.options.applyLAA) {
        await patcher.applyLAA();
        result.operations.push({ operation: 'LAA', success: true });
        log.info(`Applied LAA to: ${filePath}`);
      }

      if (this.options.toggleASLR !== null) {
        const currentFlags = await patcher.getSecurityFlags();

        // Toggle to the opposite of current if needed
        if ((this.options.toggleASLR && !currentFlags.aslr) ||
          (!this.options.toggleASLR && currentFlags.aslr)) {
          await patcher.toggleASLR();
          result.operations.push({ operation: 'ASLR', success: true, enabled: !currentFlags.aslr });
          log.info(`Toggled ASLR for: ${filePath}`);
        }
      }

      if (this.options.toggleDEP !== null) {
        const currentFlags = await patcher.getSecurityFlags();

        if ((this.options.toggleDEP && !currentFlags.dep) ||
          (!this.options.toggleDEP && currentFlags.dep)) {
          await patcher.toggleDEP();
          result.operations.push({ operation: 'DEP', success: true, enabled: !currentFlags.dep });
          log.info(`Toggled DEP for: ${filePath}`);
        }
      }

      if (this.options.toggleCFG !== null) {
        const currentFlags = await patcher.getSecurityFlags();

        if ((this.options.toggleCFG && !currentFlags.cfg) ||
          (!this.options.toggleCFG && currentFlags.cfg)) {
          await patcher.toggleCFG();
          result.operations.push({ operation: 'CFG', success: true, enabled: !currentFlags.cfg });
          log.info(`Toggled CFG for: ${filePath}`);
        }
      }

      if (this.options.removeSecurity) {
        await patcher.removeSecurity();
        result.operations.push({ operation: 'RemoveSecurity', success: true });
        log.info(`Removed security from: ${filePath}`);
      }

      // Verify the changes
      const newParser = new PEParser(outputPath);
      const newPeData = await newParser.parse();

      result.newFlags = {
        largeAddressAware: newPeData.characteristics.includes('LARGE_ADDRESS_AWARE'),
        aslr: newPeData.dllCharacteristics.includes('DYNAMIC_BASE'),
        dep: newPeData.dllCharacteristics.includes('NX_COMPAT'),
        cfg: newPeData.dllCharacteristics.includes('GUARD_CF')
      };

      result.success = true;
      result.message = 'Processed successfully';

    } catch (error) {
      result.success = false;
      result.error = error.message;
      result.message = `Error: ${error.message}`;
      log.error(`Failed to process ${filePath}:`, error);
    }

    return result;
  }

  getSummary() {
    const successCount = this.results.filter(r => r.success).length;
    const failureCount = this.results.filter(r => !r.success).length;

    const summary = {
      total: this.total,
      success: successCount,
      failed: failureCount,
      results: this.results,
      timestamp: new Date().toISOString()
    };

    // Generate text summary
    let textSummary = 'PE Editor Batch Processing Report\n';
    textSummary += '='.repeat(50) + '\n\n';
    textSummary += `Total Files: ${this.total}\n`;
    textSummary += `Successful: ${successCount}\n`;
    textSummary += `Failed: ${failureCount}\n\n`;
    textSummary += 'Results:\n';
    textSummary += '-'.repeat(50) + '\n';

    for (const result of this.results) {
      textSummary += `\nFile: ${result.fileName}\n`;
      textSummary += `Status: ${result.success ? 'SUCCESS' : 'FAILED'}\n`;

      if (result.success) {
        if (result.operations && result.operations.length > 0) {
          textSummary += 'Operations:\n';
          for (const op of result.operations) {
            textSummary += `  - ${op.operation}: ${op.success ? 'OK' : 'FAILED'}\n`;
          }
        }

        if (result.newFlags) {
          textSummary += 'New Flags:\n';
          textSummary += `  LAA: ${result.newFlags.largeAddressAware}\n`;
          textSummary += `  ASLR: ${result.newFlags.aslr}\n`;
          textSummary += `  DEP: ${result.newFlags.dep}\n`;
          textSummary += `  CFG: ${result.newFlags.cfg}\n`;
        }
      } else {
        textSummary += `Error: ${result.error}\n`;
      }
    }

    summary.textSummary = textSummary;

    return summary;
  }

  getJSONReport() {
    return JSON.stringify(this.getSummary(), null, 2);
  }

  getTextReport() {
    return this.getSummary().textSummary;
  }

  async saveReport(outputPath, format = 'txt') {
    const report = format === 'json' ? this.getJSONReport() : this.getTextReport();
    fs.writeFileSync(outputPath, report);
    log.info(`Report saved to: ${outputPath}`);
  }

  getProgress() {
    return {
      current: this.progress,
      total: this.total,
      percentage: Math.round((this.progress / this.total) * 100)
    };
  }

  // Find all PE files in a directory
  static async findPEFiles(directory, recursive = false) {
    const peFiles = [];

    const items = fs.readdirSync(directory);

    for (const item of items) {
      const fullPath = path.join(directory, item);
      const stats = fs.statSync(fullPath);

      if (stats.isFile()) {
        const ext = path.extname(item).toLowerCase();
        if (['.exe', '.dll', '.sys', '.ocx'].includes(ext)) {
          peFiles.push(fullPath);
        }
      } else if (stats.isDirectory() && recursive) {
        const subFiles = await this.findPEFiles(fullPath, true);
        peFiles.push(...subFiles);
      }
    }

    return peFiles;
  }
}

module.exports = BatchProcessor;
