const crypto = require('crypto');

class PEParser {
  constructor(buffer) {
    if (!Buffer.isBuffer(buffer)) throw new Error('PEParser requires a Buffer');
    this.buffer = buffer;
    this.fileSize = buffer.length;
  }

  getFullAnalysis() {
    this.verifySignatures();
    const dosHeader = this.parseDOSHeader();
    const peOffset = dosHeader.e_lfanew;
    const coffHeader = this.parseCOFFHeader(peOffset + 4);
    const optionalHeader = this.parseOptionalHeader(peOffset + 24, coffHeader);
    const sections = this.parseSections(peOffset + 24 + coffHeader.SizeOfOptionalHeader, coffHeader.NumberOfSections);
    const dataDirectories = this.parseDataDirectories(optionalHeader, peOffset);
    const imports = this.parseImports(optionalHeader, dataDirectories, sections);
    const exports = this.parseExports(optionalHeader, dataDirectories, sections);

    return {
      file: {
        name: 'unknown', // Set by caller
        path: '',        // Set by caller
        size: this.fileSize,
        sizeFormatted: this.formatSize(this.fileSize),
        md5: this.hash('md5'),
        sha1: this.hash('sha1'),
        sha256: this.hash('sha256')
      },
      summary: this.buildSummary(coffHeader, optionalHeader, sections, imports, exports),
      coffHeader,
      optionalHeader,
      sections,
      imports,
      exports: exports || { dllName: null, functions: [] },
      dataDirectories
    };
  }

  verifySignatures() {
    if (this.buffer.length < 64) throw new Error('File too small');
    if (this.buffer.readUInt16LE(0) !== 0x5A4D) throw new Error('Invalid DOS magic');
    const peOffset = this.buffer.readUInt32LE(60);
    if (peOffset + 4 > this.buffer.length) throw new Error('PE offset out of bounds');
    if (this.buffer.readUInt32LE(peOffset) !== 0x00004550) throw new Error('Invalid PE signature');
  }

  formatSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024, sizes = ['Bytes', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  hash(algo) { return crypto.createHash(algo).update(this.buffer).digest('hex'); }

  parseDOSHeader() { return { e_lfanew: this.buffer.readUInt32LE(60) }; }

  parseCOFFHeader(offset) {
    const chars = this.buffer.readUInt16LE(offset + 18);
    return {
      Machine: this.buffer.readUInt16LE(offset),
      NumberOfSections: this.buffer.readUInt16LE(offset + 2),
      TimeDateStamp: this.buffer.readUInt32LE(offset + 4),
      SizeOfOptionalHeader: this.buffer.readUInt16LE(offset + 16),
      Characteristics: chars,
      CharacteristicsFlags: this.getCoffFlags(chars)
    };
  }

  parseOptionalHeader(offset, coff) {
    const magic = this.buffer.readUInt16LE(offset);
    const isPE32Plus = magic === 0x020B;
    const dllChars = this.buffer.readUInt16LE(offset + 70);

    return {
      magic: isPE32Plus ? 'PE32+' : 'PE32',
      Magic: magic,
      LinkerVersion: `${this.buffer.readUInt8(offset + 2)}.${this.buffer.readUInt8(offset + 3)}`,
      AddressOfEntryPoint: this.buffer.readUInt32LE(offset + 16),
      ImageBase: isPE32Plus ? '0x' + this.buffer.readBigUInt64LE(offset + 24).toString(16).toUpperCase() : '0x' + this.buffer.readUInt32LE(offset + 28).toString(16).toUpperCase(),
      SectionAlignment: this.buffer.readUInt32LE(offset + 32),
      FileAlignment: this.buffer.readUInt32LE(offset + 36),
      Subsystem: this.buffer.readUInt16LE(offset + 68),
      DllCharacteristics: dllChars,
      DllCharacteristicsFlags: this.getDllFlags(dllChars),
      CheckSum: this.buffer.readUInt32LE(offset + 64),
      NumberOfRvaAndSizes: this.buffer.readUInt32LE(offset + (isPE32Plus ? 108 : 92))
    };
  }

  parseSections(offset, count) {
    const sections = [];
    for (let i = 0; i < count; i++) {
      const secOff = offset + i * 40;
      if (secOff + 40 > this.buffer.length) break;
      let name = '';
      for (let j = 0; j < 8; j++) {
        const c = this.buffer[secOff + j];
        if (c === 0) break;
        name += String.fromCharCode(c);
      }
      const rawSize = this.buffer.readUInt32LE(secOff + 16);
      const rawPtr = this.buffer.readUInt32LE(secOff + 20);
      const chars = this.buffer.readUInt32LE(secOff + 36);

      const r = (chars & 0x40000000) ? 'R' : '-';
      const w = (chars & 0x80000000) ? 'W' : '-';
      const x = (chars & 0x20000000) ? 'X' : '-';

      sections.push({
        index: i + 1,
        name,
        VirtualSize: this.buffer.readUInt32LE(secOff + 8),
        VirtualAddress: this.buffer.readUInt32LE(secOff + 12),
        SizeOfRawData: rawSize,
        PointerToRawData: rawPtr,
        Characteristics: chars,
        CharacteristicsFlags: this.getSectionFlags(chars),
        Entropy: this.calculateEntropy(rawPtr, rawSize),
        Permissions: r + w + x
      });
    }
    return sections;
  }

  parseDataDirectories(opt, peOff) {
    const names = ['Export Table', 'Import Table', 'Resource Table', 'Exception Table', 'Certificate Table', 'Base Relocation Table', 'Debug', 'Architecture', 'Global Ptr', 'TLS Table', 'Load Config Table', 'Bound Import', 'IAT', 'Delay Import Descriptor', 'COM Descriptor', 'Reserved'];
    const dirs = [];
    const dirOffset = peOff + 24 + (opt.magic === 'PE32+' ? 112 : 96);
    const count = Math.min(16, opt.NumberOfRvaAndSizes);

    for (let i = 0; i < count; i++) {
      const off = dirOffset + i * 8;
      if (off + 8 > this.buffer.length) break;
      const rva = this.buffer.readUInt32LE(off);
      const size = this.buffer.readUInt32LE(off + 4);
      dirs.push({
        index: i,
        name: names[i] || `Directory ${i}`,
        VirtualAddress: rva,
        Size: size,
        rvaHex: '0x' + rva.toString(16).toUpperCase(),
        sizeHex: '0x' + size.toString(16).toUpperCase(),
        present: rva !== 0 && size !== 0
      });
    }
    return dirs;
  }

  parseImports(opt, dirs, sections) {
    const impDir = dirs.find(d => d.index === 1);
    if (!impDir || !impDir.present) return [];

    const impOff = this.rvaToOffset(impDir.VirtualAddress, sections);
    if (impOff === null || impOff > this.buffer.length) return [];

    const imports = [];
    let idx = 0;
    while (true) {
      const entryOff = impOff + idx * 20;
      if (entryOff + 20 > this.buffer.length) break;
      const lookupRVA = this.buffer.readUInt32LE(entryOff);
      const nameRVA = this.buffer.readUInt32LE(entryOff + 12);
      const thunkRVA = this.buffer.readUInt32LE(entryOff + 16);
      if (lookupRVA === 0 && nameRVA === 0) break;

      const nameOff = this.rvaToOffset(nameRVA, sections);
      const dllName = nameOff !== null ? this.readString(nameOff) : 'Unknown';

      const funcs = [];
      const funcRVA = thunkRVA !== 0 ? thunkRVA : lookupRVA;
      const funcOff = this.rvaToOffset(funcRVA, sections);

      if (funcOff !== null) {
        let fIdx = 0;
        const step = opt.magic === 'PE32+' ? 8 : 4;
        while (true) {
          const fEntryOff = funcOff + fIdx * step;
          if (fEntryOff + step > this.buffer.length) break;
          const val = opt.magic === 'PE32+' ? this.buffer.readBigUInt64LE(fEntryOff) : BigInt(this.buffer.readUInt32LE(fEntryOff));
          if (val === 0n) break;

          const isOrdinal = opt.magic === 'PE32+' ? (val & 0x8000000000000000n) !== 0n : (val & 0x80000000n) !== 0n;
          if (isOrdinal) {
            funcs.push({ ordinal: Number(val & 0xFFFFn), isOrdinal: true });
          } else {
            const fNameOff = this.rvaToOffset(Number(val & 0x7FFFFFFFn), sections);
            if (fNameOff !== null && fNameOff + 2 < this.buffer.length) {
              funcs.push({
                hint: this.buffer.readUInt16LE(fNameOff),
                name: this.readString(fNameOff + 2),
                isOrdinal: false
              });
            }
          }
          fIdx++;
        }
      }
      imports.push({ dllName, functionCount: funcs.length, functions: funcs });
      idx++;
    }
    return imports;
  }

  parseExports(opt, dirs, sections) {
    const expDir = dirs.find(d => d.index === 0);
    if (!expDir || !expDir.present) return null;

    const expOff = this.rvaToOffset(expDir.VirtualAddress, sections);
    if (expOff === null || expOff + 40 > this.buffer.length) return null;

    const nameRVA = this.buffer.readUInt32LE(expOff + 12);
    const ordinalBase = this.buffer.readUInt32LE(expOff + 16);
    const addrEntries = this.buffer.readUInt32LE(expOff + 20);
    const namePtrs = this.buffer.readUInt32LE(expOff + 24);
    const expAddrRVA = this.buffer.readUInt32LE(expOff + 28);
    const namePtrRVA = this.buffer.readUInt32LE(expOff + 32);
    const ordTableRVA = this.buffer.readUInt32LE(expOff + 36);

    const dllNameOff = this.rvaToOffset(nameRVA, sections);
    const dllName = dllNameOff !== null ? this.readString(dllNameOff) : 'Unknown';

    const funcs = [];
    const expAddrOff = this.rvaToOffset(expAddrRVA, sections);
    const namePtrOff = this.rvaToOffset(namePtrRVA, sections);
    const ordOff = this.rvaToOffset(ordTableRVA, sections);

    if (expAddrOff !== null && namePtrOff !== null && ordOff !== null) {
      for (let i = 0; i < addrEntries; i++) {
        const funcRVA = this.buffer.readUInt32LE(expAddrOff + i * 4);
        if (funcRVA === 0) continue;
        const ordinal = this.buffer.readUInt16LE(ordOff + i * 2);

        let name = null;
        if (i < namePtrs) {
          const nRVA = this.buffer.readUInt32LE(namePtrOff + i * 4);
          const nOff = this.rvaToOffset(nRVA, sections);
          if (nOff !== null) name = this.readString(nOff);
        }

        const isFwd = funcRVA >= expDir.VirtualAddress && funcRVA < expDir.VirtualAddress + expDir.Size;
        let forwarder = null;
        if (isFwd) {
          const fwdOff = this.rvaToOffset(funcRVA, sections);
          if (fwdOff !== null) forwarder = this.readString(fwdOff);
        }

        funcs.push({ ordinal: ordinalBase + ordinal, address: funcRVA, rva: funcRVA, name, isForwarded: isFwd, forwarder });
      }
    }
    return { dllName, functions: funcs };
  }

  rvaToOffset(rva, sections) {
    const sec = sections.find(s => rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.max(s.VirtualSize, s.SizeOfRawData));
    if (sec) return sec.PointerToRawData + (rva - sec.VirtualAddress);
    return null; // Return null if invalid RVA
  }

  readString(offset) {
    let str = '';
    while (offset < this.buffer.length && this.buffer[offset] !== 0) str += String.fromCharCode(this.buffer[offset++]);
    return str;
  }

  calculateEntropy(offset, size) {
    if (size === 0 || offset + size > this.buffer.length) return 0;
    const counts = new Uint32Array(256);
    for (let i = 0; i < size; i++) counts[this.buffer[offset + i]]++;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (counts[i] === 0) continue;
      const p = counts[i] / size;
      entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(2));
  }

  buildSummary(coff, opt, sections, imports, exports) {
    const m = coff.Machine;
    const mach = m === 0x8664 ? 'x64' : m === 0x014C ? 'x86' : m === 0xAA64 ? 'ARM64' : 'Unknown';
    const s = opt.Subsystem;
    const subsys = s === 2 ? 'GUI' : s === 3 ? 'CUI' : s === 1 ? 'Native' : 'Unknown';
    const isLAA = (coff.Characteristics & 0x20) !== 0;
    const isASLR = (opt.DllCharacteristics & 0x40) !== 0;
    const isDEP = (opt.DllCharacteristics & 0x100) !== 0;
    const isCFG = (opt.DllCharacteristics & 0x4000) !== 0;
    const isHEVA = (opt.DllCharacteristics & 0x20) !== 0;
    const isDLL = (coff.Characteristics & 0x2000) !== 0;

    return {
      format: opt.magic,
      machine: mach,
      subsystem: subsys,
      isDLL,
      isLAA,
      isASLR,
      isDEP,
      isCFG,
      isHighEntropyVA: isHEVA,
      entryPoint: '0x' + opt.AddressOfEntryPoint.toString(16).toUpperCase(),
      imageBase: opt.ImageBase,
      sectionCount: sections.length,
      importCount: imports.length,
      totalImportedFunctions: imports.reduce((sum, imp) => sum + imp.functionCount, 0),
      exportCount: exports ? exports.functions.length : 0,
      isDotNet: dirs => dirs.find(d => d.index === 14)?.present ?? false, // COM Descriptor
    };
  }

  getCoffFlags(c) {
    return [
      { name: 'RELOCS_STRIPPED', bitHex: '0x0001', enabled: !!(c & 0x1), description: 'Relocation info stripped' },
      { name: 'EXECUTABLE_IMAGE', bitHex: '0x0002', enabled: !!(c & 0x2), description: 'File is executable' },
      { name: 'LINE_NUMS_STRIPPED', bitHex: '0x0004', enabled: !!(c & 0x4), description: 'Line numbers stripped' },
      { name: 'LOCAL_SYMS_STRIPPED', bitHex: '0x0008', enabled: !!(c & 0x8), description: 'Local symbols stripped' },
      { name: 'LARGE_ADDRESS_AWARE', bitHex: '0x0020', enabled: !!(c & 0x20), description: 'App can handle >2GB addresses' },
      { name: '32BIT_MACHINE', bitHex: '0x0100', enabled: !!(c & 0x100), description: 'Machine is based on 32-bit-word architecture' },
      { name: 'DEBUG_STRIPPED', bitHex: '0x0200', enabled: !!(c & 0x200), description: 'Debugging info stripped' },
      { name: 'SYSTEM', bitHex: '0x1000', enabled: !!(c & 0x1000), description: 'System file' },
      { name: 'DLL', bitHex: '0x2000', enabled: !!(c & 0x2000), description: 'File is a DLL' }
    ];
  }

  getDllFlags(c) {
    return [
      { name: 'HIGH_ENTROPY_VA', bitHex: '0x0020', enabled: !!(c & 0x20), description: 'Image can handle a high entropy 64-bit virtual address space' },
      { name: 'DYNAMIC_BASE', bitHex: '0x0040', enabled: !!(c & 0x40), description: 'Relocatable at load time (ASLR)' },
      { name: 'FORCE_INTEGRITY', bitHex: '0x0080', enabled: !!(c & 0x80), description: 'Code integrity checks enforced' },
      { name: 'NX_COMPAT', bitHex: '0x0100', enabled: !!(c & 0x100), description: 'Compatible with Data Execution Prevention (DEP)' },
      { name: 'NO_ISOLATION', bitHex: '0x0200', enabled: !!(c & 0x200), description: 'Image understands isolation and doesn\'t want it' },
      { name: 'NO_SEH', bitHex: '0x0400', enabled: !!(c & 0x400), description: 'Image does not use SEH. No SE handler may reside in this image' },
      { name: 'NO_BIND', bitHex: '0x0800', enabled: !!(c & 0x800), description: 'Do not bind this image' },
      { name: 'APPCONTAINER', bitHex: '0x1000', enabled: !!(c & 0x1000), description: 'Image should execute in an AppContainer' },
      { name: 'WDM_DRIVER', bitHex: '0x2000', enabled: !!(c & 0x2000), description: 'Driver uses WDM model' },
      { name: 'GUARD_CF', bitHex: '0x4000', enabled: !!(c & 0x4000), description: 'Image supports Control Flow Guard' },
      { name: 'TERMINAL_SERVER_AWARE', bitHex: '0x8000', enabled: !!(c & 0x8000), description: 'Terminal Server aware' }
    ];
  }

  getSectionFlags(c) {
    const f = [];
    if (c & 0x00000020) f.push('CODE');
    if (c & 0x00000040) f.push('INITIALIZED_DATA');
    if (c & 0x00000080) f.push('UNINITIALIZED_DATA');
    if (c & 0x02000000) f.push('DISCARDABLE');
    if (c & 0x04000000) f.push('NOT_CACHED');
    if (c & 0x08000000) f.push('NOT_PAGED');
    if (c & 0x10000000) f.push('SHARED');
    if (c & 0x20000000) f.push('EXECUTE');
    if (c & 0x40000000) f.push('READ');
    if (c & 0x80000000) f.push('WRITE');
    return f;
  }
}

module.exports = { PEParser };
