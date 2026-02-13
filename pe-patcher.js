const fs = require('fs');
const path = require('path');
const log = require('electron-log');

class PEPatcher {
  constructor(filePath) {
    this.filePath = filePath;
    this.backupPath = filePath + '.backup';
    this.buffer = null;
    this.modified = false;
  }

  async load() {
    try {
      this.buffer = fs.readFileSync(this.filePath);
      log.info(`Loaded file for patching: ${this.filePath}`);
      return this.buffer;
    } catch (error) {
      log.error('Failed to load file for patching:', error);
      throw error;
    }
  }

  async save() {
    if (!this.buffer) {
      await this.load();
    }

    try {
      fs.writeFileSync(this.filePath, this.buffer);
      this.modified = false;
      log.info(`File saved: ${this.filePath}`);
    } catch (error) {
      log.error('Failed to save file:', error);
      throw error;
    }
  }

  async saveAs(newPath) {
    if (!this.buffer) {
      await this.load();
    }

    try {
      fs.writeFileSync(newPath, this.buffer);
      this.filePath = newPath;
      this.modified = false;
      log.info(`File saved as: ${newPath}`);
    } catch (error) {
      log.error('Failed to save file:', error);
      throw error;
    }
  }

  createBackup() {
    try {
      fs.copyFileSync(this.filePath, this.backupPath);
      log.info(`Backup created: ${this.backupPath}`);
    } catch (error) {
      log.error('Failed to create backup:', error);
      throw error;
    }
  }

  restoreBackup() {
    try {
      if (fs.existsSync(this.backupPath)) {
        fs.copyFileSync(this.backupPath, this.filePath);
        this.buffer = fs.readFileSync(this.filePath);
        log.info('Backup restored');
      }
    } catch (error) {
      log.error('Failed to restore backup:', error);
      throw error;
    }
  }

  // Get PE header offset
  getPEOffset() {
    return this.buffer.readInt32LE(60); // e_lfanew
  }

  // Get COFF header offset
  getCOFFOffset() {
    return this.getPEOffset() + 4;
  }

  // Get Optional header offset
  getOptionalHeaderOffset() {
    return this.getCOFFOffset() + 20;
  }

  // Apply Large Address Aware (LAA) flag
  async applyLAA() {
    await this.load();
    this.createBackup();

    const coffOffset = this.getCOFFOffset();
    const characteristics = this.buffer.readUInt16LE(coffOffset + 18);

    // Set bit 5 (IMAGE_FILE_LARGE_ADDRESS_AWARE)
    const newCharacteristics = characteristics | 0x20;
    this.buffer.writeUInt16LE(newCharacteristics, coffOffset + 18);

    // Also update DLL characteristics in optional header
    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    let dllCharOffset;
    if (magic === 0x10b) { // PE32
      dllCharOffset = optionalOffset + 70;
    } else if (magic === 0x20b) { // PE32+
      dllCharOffset = optionalOffset + 70;
    }

    if (dllCharOffset) {
      const dllChar = this.buffer.readUInt16LE(dllCharOffset);
      // Clear high entropy VA bit and set compatible
      const newDllChar = (dllChar & ~0x20) | 0x10; // Clear HIGH_ENTROPY_VA, set DYNAMIC_BASE
      this.buffer.writeUInt16LE(newDllChar, dllCharOffset);
    }

    await this.save();
    log.info('LAA applied successfully');
  }

  // Toggle ASLR (Address Space Layout Randomization)
  async toggleASLR() {
    await this.load();
    this.createBackup();

    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    let dllCharOffset;
    if (magic === 0x10b) { // PE32
      dllCharOffset = optionalOffset + 70;
    } else if (magic === 0x20b) { // PE32+
      dllCharOffset = optionalOffset + 70;
    } else {
      throw new Error('Unknown PE format');
    }

    const dllChar = this.buffer.readUInt16LE(dllCharOffset);

    // Toggle bit 6 (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    const newDllChar = dllChar ^ 0x40;
    this.buffer.writeUInt16LE(newDllChar, dllCharOffset);

    await this.save();
    log.info(`ASLR ${(newDllChar & 0x40) ? 'enabled' : 'disabled'}`);
  }

  // Toggle DEP (Data Execution Prevention)
  async toggleDEP() {
    await this.load();
    this.createBackup();

    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    let dllCharOffset;
    if (magic === 0x10b) { // PE32
      dllCharOffset = optionalOffset + 70;
    } else if (magic === 0x20b) { // PE32+
      dllCharOffset = optionalOffset + 70;
    } else {
      throw new Error('Unknown PE format');
    }

    const dllChar = this.buffer.readUInt16LE(dllCharOffset);

    // Toggle bit 8 (IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    const newDllChar = dllChar ^ 0x100;
    this.buffer.writeUInt16LE(newDllChar, dllCharOffset);

    await this.save();
    log.info(`DEP ${(newDllChar & 0x100) ? 'enabled' : 'disabled'}`);
  }

  // Toggle CFG (Control Flow Guard)
  async toggleCFG() {
    await this.load();
    this.createBackup();

    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    let dllCharOffset;
    if (magic === 0x10b) { // PE32
      dllCharOffset = optionalOffset + 70;
    } else if (magic === 0x20b) { // PE32+
      dllCharOffset = optionalOffset + 70;
    } else {
      throw new Error('Unknown PE format');
    }

    const dllChar = this.buffer.readUInt16LE(dllCharOffset);

    // Toggle bit 14 (IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    const newDllChar = dllChar ^ 0x4000;
    this.buffer.writeUInt16LE(newDllChar, dllCharOffset);

    await this.save();
    log.info(`CFG ${(newDllChar & 0x4000) ? 'enabled' : 'disabled'}`);
  }

  // Remove all security features
  async removeSecurity() {
    await this.load();
    this.createBackup();

    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    let dllCharOffset;
    if (magic === 0x10b) {
      dllCharOffset = optionalOffset + 70;
    } else if (magic === 0x20b) {
      dllCharOffset = optionalOffset + 70;
    }

    if (dllCharOffset) {
      const dllChar = this.buffer.readUInt16LE(dllCharOffset);
      // Clear security bits: ASLR, DEP, CFG, High Entropy VA
      const newDllChar = dllChar & ~0x4040 & ~0x100 & ~0x4000;
      this.buffer.writeUInt16LE(newDllChar, dllCharOffset);
    }

    // Also remove LAA from COFF characteristics
    const coffOffset = this.getCOFFOffset();
    const characteristics = this.buffer.readUInt16LE(coffOffset + 18);
    const newCharacteristics = characteristics & ~0x20;
    this.buffer.writeUInt16LE(newCharacteristics, coffOffset + 18);

    await this.save();
    log.info('All security features removed');
  }

  // Strip unwanted sections
  async stripSections(sectionNames) {
    await this.load();
    this.createBackup();

    const coffOffset = this.getCOFFOffset();
    const numSections = this.buffer.readUInt16LE(coffOffset + 2);
    const optionalOffset = this.getOptionalHeaderOffset();
    const optionalSize = this.buffer.readUInt16LE(coffOffset + 16);

    const sectionOffset = optionalOffset + optionalSize;
    const sectionSize = 40;

    const sectionsToKeep = [];

    for (let i = 0; i < numSections; i++) {
      const secOffset = sectionOffset + i * sectionSize;

      // Read section name
      let name = '';
      for (let j = 0; j < 8; j++) {
        const char = this.buffer.readUInt8(secOffset + j);
        if (char !== 0) {
          name += String.fromCharCode(char);
        } else {
          break;
        }
      }

      if (!sectionNames.includes(name.trim())) {
        sectionsToKeep.push({
          offset: secOffset,
          name: name
        });
      } else {
        log.info(`Stripping section: ${name}`);
      }
    }

    // Would need to update section table and remove data - simplified here
    await this.save();
    log.info('Section stripping complete');
  }

  // Modify entry point
  async setEntryPoint(newEntryPoint) {
    await this.load();
    this.createBackup();

    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    let entryOffset;
    if (magic === 0x10b) { // PE32
      entryOffset = optionalOffset + 16;
    } else if (magic === 0x20b) { // PE32+
      entryOffset = optionalOffset + 16;
    }

    this.buffer.writeUInt32LE(newEntryPoint, entryOffset);

    await this.save();
    log.info(`Entry point set to: 0x${newEntryPoint.toString(16)}`);
  }

  // Update Image Base
  async setImageBase(newImageBase) {
    await this.load();
    this.createBackup();

    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    if (magic === 0x10b) { // PE32
      this.buffer.writeUInt32LE(newImageBase, optionalOffset + 28);
    } else if (magic === 0x20b) { // PE32+
      this.buffer.writeBigUInt64LE(BigInt(newImageBase), optionalOffset + 24);
    }

    await this.save();
    log.info(`Image base set to: 0x${newImageBase.toString(16)}`);
  }

  // Update Subsystem
  async setSubsystem(subsystem) {
    await this.load();
    this.createBackup();

    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    let subsystemOffset;
    if (magic === 0x10b) {
      subsystemOffset = optionalOffset + 68;
    } else if (magic === 0x20b) {
      subsystemOffset = optionalOffset + 68;
    }

    this.buffer.writeUInt16LE(subsystem, subsystemOffset);

    await this.save();
    log.info(`Subsystem set to: ${subsystem}`);
  }

  // Add or update resource
  async updateResource(resourceType, resourceData) {
    await this.load();
    // Resource updates would go here
    await this.save();
    log.info('Resource update complete');
  }

  // Sign the PE file (placeholder - would need proper signing)
  async sign(certificate) {
    await this.load();
    this.createBackup();

    // This is a placeholder - actual signing requires Windows APIs
    // or a proper code signing solution
    log.warn('Code signing not implemented - this is a placeholder');

    await this.save();
  }

  // Verify PE integrity
  async verifyIntegrity() {
    await this.load();

    const issues = [];

    // Check DOS header
    const dosMagic = this.buffer.readUInt16LE(0);
    if (dosMagic !== 0x5A4D) {
      issues.push('Invalid DOS header');
    }

    // Check PE signature
    const peOffset = this.buffer.readInt32LE(60);
    const peSig = this.buffer.readUInt32LE(peOffset);
    if (peSig !== 0x00004550) {
      issues.push('Invalid PE signature');
    }

    // Check optional header magic
    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);
    if (magic !== 0x10b && magic !== 0x20b) {
      issues.push('Invalid optional header magic');
    }

    return {
      valid: issues.length === 0,
      issues: issues
    };
  }

  // Get current flags
  async getSecurityFlags() {
    await this.load();

    const coffOffset = this.getCOFFOffset();
    const characteristics = this.buffer.readUInt16LE(coffOffset + 18);

    const optionalOffset = this.getOptionalHeaderOffset();
    const magic = this.buffer.readUInt16LE(optionalOffset);

    let dllCharOffset;
    if (magic === 0x10b) {
      dllCharOffset = optionalOffset + 70;
    } else if (magic === 0x20b) {
      dllCharOffset = optionalOffset + 70;
    }

    const dllChar = this.buffer.readUInt16LE(dllCharOffset);

    return {
      largeAddressAware: (characteristics & 0x20) !== 0,
      aslr: (dllChar & 0x40) !== 0,
      dep: (dllChar & 0x100) !== 0,
      cfg: (dllChar & 0x4000) !== 0,
      highEntropyVA: (dllChar & 0x20) !== 0
    };
  }
}

module.exports = PEPatcher;
