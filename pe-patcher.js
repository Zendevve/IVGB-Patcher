const crypto = require('crypto');

class PEPatcher {
  constructor(buffer) {
    if (!Buffer.isBuffer(buffer)) throw new Error('PEPatcher requires a Buffer');
    // Work on a copy of the buffer
    this.originalBuffer = buffer;
    this.buffer = Buffer.from(buffer);

    this.peOffset = this.buffer.readUInt32LE(60);
    this.coffOffset = this.peOffset + 4;
    this.optOffset = this.peOffset + 24;
    this.magic = this.buffer.readUInt16LE(this.optOffset);
    this.dllCharOffset = this.optOffset + 70;
  }

  applyFlagChanges(flags) {
    const results = [];

    // COFF Characteristics (LAA)
    if (flags.laa !== undefined) {
      const chars = this.buffer.readUInt16LE(this.coffOffset + 18);
      const isSet = (chars & 0x20) !== 0;
      if (isSet !== flags.laa) {
        this.buffer.writeUInt16LE(flags.laa ? (chars | 0x20) : (chars & ~0x20), this.coffOffset + 18);
        results.push({ name: 'LARGE_ADDRESS_AWARE', changed: true, oldValue: isSet, newValue: flags.laa });
      }
    }

    // DLL Characteristics
    const dllMap = {
      highEntropyVA: 0x0020,
      aslr: 0x0040,
      forceIntegrity: 0x0080,
      dep: 0x0100,
      noSEH: 0x0400,
      appContainer: 0x1000,
      cfg: 0x4000,
      terminalServerAware: 0x8000
    };

    const dllChars = this.buffer.readUInt16LE(this.dllCharOffset);
    let newDllChars = dllChars;

    for (const [key, bit] of Object.entries(dllMap)) {
      if (flags[key] !== undefined) {
        const isSet = (dllChars & bit) !== 0;
        if (isSet !== flags[key]) {
          if (flags[key]) newDllChars |= bit;
          else newDllChars &= ~bit;
          results.push({ name: key, changed: true, oldValue: isSet, newValue: flags[key] });
        }
      }
    }

    if (dllChars !== newDllChars) {
      this.buffer.writeUInt16LE(newDllChars, this.dllCharOffset);
    }

    return results;
  }

  recalculateChecksum() {
    const oldSum = this.buffer.readUInt32LE(this.optOffset + 64);

    // Clear checksum to 0 before calculating
    this.buffer.writeUInt32LE(0, this.optOffset + 64);

    let sum = 0n;
    const len = this.buffer.length;

    // Read 16-bit words (pad with 0 if odd length)
    for (let i = 0; i < len; i += 2) {
      let word = this.buffer[i];
      if (i + 1 < len) word |= (this.buffer[i + 1] << 8);

      sum += BigInt(word);
      if (sum > 0xFFFFFFFFn) {
        sum = (sum & 0xFFFFFFFFn) + (sum >> 32n);
      }
    }

    // Fold to 16 bits
    sum = (sum & 0xFFFFn) + (sum >> 16n);
    sum = (sum + (sum >> 16n)) & 0xFFFFn;

    const newSum = Number(sum) + len;

    // Write new checksum
    this.buffer.writeUInt32LE(newSum, this.optOffset + 64);

    return { old: oldSum, new: newSum };
  }

  getHexDiff() {
    const changes = [];
    const changedOffsets = [];
    const len = Math.max(this.originalBuffer.length, this.buffer.length);

    for (let i = 0; i < len; i++) {
      const ob = i < this.originalBuffer.length ? this.originalBuffer[i] : null;
      const nb = i < this.buffer.length ? this.buffer[i] : null;

      if (ob !== nb) {
        changes.push({
          offset: i,
          offsetHex: '0x' + i.toString(16).toUpperCase().padStart(8, '0'),
          oldHex: ob !== null ? ob.toString(16).toUpperCase().padStart(2, '0') : '--',
          newHex: nb !== null ? nb.toString(16).toUpperCase().padStart(2, '0') : '--',
          description: this.getChangeDescription(i)
        });
        changedOffsets.push(i);
      }
    }

    return {
      totalChangedBytes: changes.length,
      changes,
      blocks: this.groupDiffBlocks(changedOffsets)
    };
  }

  getChangeDescription(offset) {
    if (offset === this.coffOffset + 18 || offset === this.coffOffset + 19) return 'COFF Characteristics';
    if (offset === this.dllCharOffset || offset === this.dllCharOffset + 1) return 'DLL Characteristics';
    if (offset >= this.optOffset + 64 && offset < this.optOffset + 68) return 'PE Checksum';
    return 'Unknown';
  }

  groupDiffBlocks(changedOffsets) {
    if (!changedOffsets.length) return [];

    const blocks = [];
    let currentBlock = null;

    // Group by 16-byte rows
    const changedRows = new Set(changedOffsets.map(o => Math.floor(o / 16) * 16));
    const sortedRows = Array.from(changedRows).sort((a, b) => a - b);

    for (const rowOffset of sortedRows) {
      if (!currentBlock || rowOffset > currentBlock.lastRow + 32) {
        // Start new block if gap is > 2 rows
        currentBlock = {
          startRow: rowOffset,
          lastRow: rowOffset,
          rows: [],
          changedOffsets: []
        };
        blocks.push(currentBlock);
      } else {
        currentBlock.lastRow = rowOffset;
      }

      // Include context rows
      currentBlock.changedOffsets.push(...changedOffsets.filter(o => o >= rowOffset && o < rowOffset + 16));
      currentBlock.rows.push(this.formatDiffRow(rowOffset, changedOffsets));
    }

    return blocks;
  }

  formatDiffRow(rowOffset, changedOffsets) {
    const ob = this.originalBuffer;
    const nb = this.buffer;
    const oldHex = [], newHex = [], oldAscii = [], newAscii = [], changed = [];
    let hasChanges = false;

    for (let i = 0; i < 16; i++) {
      const idx = rowOffset + i;
      const o = idx < ob.length ? ob[idx] : null;
      const n = idx < nb.length ? nb[idx] : null;

      oldHex.push(o !== null ? o.toString(16).toUpperCase().padStart(2, '0') : '  ');
      newHex.push(n !== null ? n.toString(16).toUpperCase().padStart(2, '0') : '  ');

      oldAscii.push(o >= 32 && o < 127 ? String.fromCharCode(o) : '.');
      newAscii.push(n >= 32 && n < 127 ? String.fromCharCode(n) : '.');

      const isChanged = changedOffsets.includes(idx);
      changed.push(isChanged);
      if (isChanged) hasChanges = true;
    }

    return {
      offsetHex: '0x' + rowOffset.toString(16).toUpperCase().padStart(8, '0'),
      oldHex,
      newHex,
      oldAscii: oldAscii.join(''),
      newAscii: newAscii.join(''),
      changed,
      hasChanges
    };
  }

  getHashes() {
    return {
      md5: crypto.createHash('md5').update(this.buffer).digest('hex'),
      sha1: crypto.createHash('sha1').update(this.buffer).digest('hex'),
      sha256: crypto.createHash('sha256').update(this.buffer).digest('hex')
    };
  }

  getBuffer() {
    return this.buffer;
  }
}

module.exports = { PEPatcher };
