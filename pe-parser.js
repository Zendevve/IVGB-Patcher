const fs = require('fs');
const path = require('path');
const log = require('electron-log');

class PEParser {
  constructor(filePath) {
    this.filePath = filePath;
    this.buffer = null;
    this.fileSize = 0;
  }

  async parse() {
    try {
      log.info(`Parsing PE file: ${this.filePath}`);

      this.buffer = fs.readFileSync(this.filePath);
      this.fileSize = this.buffer.length;

      // Verify DOS header
      const dosHeader = this.parseDOSHeader();
      if (dosHeader.e_magic !== 0x5A4D) { // "MZ"
        throw new Error('Invalid DOS header signature');
      }

      // Get PE header offset
      const peOffset = dosHeader.e_lfanew;

      // Verify PE signature
      const peSignature = this.buffer.readUInt32LE(peOffset);
      if (peSignature !== 0x00004550) { // "PE\0\0"
        throw new Error('Invalid PE signature');
      }

      // Parse COFF header
      const coffHeader = this.parseCOFFHeader(peOffset + 4);

      // Parse Optional header
      const optionalHeader = this.parseOptionalHeader(peOffset + 4 + 20, coffHeader);

      // Parse sections
      const sections = this.parseSections(peOffset + 4 + 20 + coffHeader.SizeOfOptionalHeader, coffHeader.NumberOfSections);

      // Parse data directories if PE32+
      const dataDirectories = this.parseDataDirectories(optionalHeader, peOffset);

      // Parse imports if present
      const imports = this.parseImports(dataDirectories, optionalHeader);

      // Parse exports if present
      const exports = this.parseExports(dataDirectories, optionalHeader);

      const result = {
        filePath: this.filePath,
        fileName: path.basename(this.filePath),
        fileSize: this.fileSize,
        dosHeader,
        coffHeader,
        optionalHeader,
        sections,
        dataDirectories,
        imports,
        exports,
        characteristics: this.parseCharacteristics(coffHeader.Characteristics),
        dllCharacteristics: this.parseDllCharacteristics(optionalHeader.DllCharacteristics)
      };

      log.info('PE file parsed successfully');
      return result;

    } catch (error) {
      log.error('PE parsing error:', error);
      throw error;
    }
  }

  parseDOSHeader() {
    return {
      e_magic: this.buffer.readUInt16LE(0),
      e_cblp: this.buffer.readUInt16LE(2),
      e_cp: this.buffer.readUInt16LE(4),
      e_crlc: this.buffer.readUInt16LE(6),
      e_cparhdr: this.buffer.readUInt16LE(8),
      e_minalloc: this.buffer.readUInt16LE(10),
      e_maxalloc: this.buffer.readUInt16LE(12),
      e_ss: this.buffer.readUInt16LE(14),
      e_sp: this.buffer.readUInt16LE(16),
      e_csum: this.buffer.readUInt16LE(18),
      e_ip: this.buffer.readUInt16LE(20),
      e_cs: this.buffer.readUInt16LE(22),
      e_lfarlc: this.buffer.readUInt16LE(24),
      e_ovno: this.buffer.readUInt16LE(28),
      e_res: this.buffer.slice(32, 48),
      e_oemid: this.buffer.readUInt16LE(48),
      e_oeminfo: this.buffer.readUInt16LE(50),
      e_res2: this.buffer.slice(52, 64),
      e_lfanew: this.buffer.readInt32LE(60)
    };
  }

  parseCOFFHeader(offset) {
    return {
      Machine: this.buffer.readUInt16LE(offset),
      NumberOfSections: this.buffer.readUInt16LE(offset + 2),
      TimeDateStamp: this.buffer.readUInt32LE(offset + 4),
      PointerToSymbolTable: this.buffer.readUInt32LE(offset + 8),
      NumberOfSymbols: this.buffer.readUInt32LE(offset + 12),
      SizeOfOptionalHeader: this.buffer.readUInt16LE(offset + 16),
      Characteristics: this.buffer.readUInt16LE(offset + 18)
    };
  }

  parseOptionalHeader(offset, coffHeader) {
    const magic = this.buffer.readUInt16LE(offset);

    let optionalHeader;

    if (magic === 0x10b) { // PE32
      optionalHeader = {
        magic: 'PE32',
        Magic: magic,
        MajorLinkerVersion: this.buffer.readUInt8(offset + 2),
        MinorLinkerVersion: this.buffer.readUInt8(offset + 3),
        SizeOfCode: this.buffer.readUInt32LE(offset + 4),
        SizeOfInitializedData: this.buffer.readUInt32LE(offset + 8),
        SizeOfUninitializedData: this.buffer.readUInt32LE(offset + 12),
        AddressOfEntryPoint: this.buffer.readUInt32LE(offset + 16),
        BaseOfCode: this.buffer.readUInt32LE(offset + 20),
        BaseOfData: this.buffer.readUInt32LE(offset + 24),
        ImageBase: this.buffer.readUInt32LE(offset + 28),
        SectionAlignment: this.buffer.readUInt32LE(offset + 32),
        FileAlignment: this.buffer.readUInt32LE(offset + 36),
        MajorOperatingSystemVersion: this.buffer.readUInt16LE(offset + 40),
        MinorOperatingSystemVersion: this.buffer.readUInt16LE(offset + 42),
        MajorImageVersion: this.buffer.readUInt16LE(offset + 44),
        MinorImageVersion: this.buffer.readUInt16LE(offset + 46),
        MajorSubsystemVersion: this.buffer.readUInt16LE(offset + 48),
        MinorSubsystemVersion: this.buffer.readUInt16LE(offset + 50),
        Win32VersionValue: this.buffer.readUInt32LE(offset + 52),
        SizeOfImage: this.buffer.readUInt32LE(offset + 56),
        SizeOfHeaders: this.buffer.readUInt32LE(offset + 60),
        CheckSum: this.buffer.readUInt32LE(offset + 64),
        Subsystem: this.buffer.readUInt16LE(offset + 68),
        DllCharacteristics: this.buffer.readUInt16LE(offset + 70),
        SizeOfStackReserve: this.buffer.readUInt32LE(offset + 72),
        SizeOfStackCommit: this.buffer.readUInt32LE(offset + 76),
        SizeOfHeapReserve: this.buffer.readUInt32LE(offset + 80),
        SizeOfHeapCommit: this.buffer.readUInt32LE(offset + 84),
        LoaderFlags: this.buffer.readUInt32LE(offset + 88),
        NumberOfRvaAndSizes: this.buffer.readUInt32LE(offset + 92),
        DataDirectory: this.parseDataDirectoryArray(offset + 96, 16)
      };
    } else if (magic === 0x20b) { // PE32+
      optionalHeader = {
        magic: 'PE32+',
        Magic: magic,
        MajorLinkerVersion: this.buffer.readUInt8(offset + 2),
        MinorLinkerVersion: this.buffer.readUInt8(offset + 3),
        SizeOfCode: this.buffer.readUInt32LE(offset + 4),
        SizeOfInitializedData: this.buffer.readUInt32LE(offset + 8),
        SizeOfUninitializedData: this.buffer.readUInt32LE(offset + 12),
        AddressOfEntryPoint: this.buffer.readUInt32LE(offset + 16),
        BaseOfCode: this.buffer.readUInt32LE(offset + 20),
        ImageBase: this.buffer.readBigUInt64LE(offset + 24),
        SectionAlignment: this.buffer.readUInt32LE(offset + 32),
        FileAlignment: this.buffer.readUInt32LE(offset + 36),
        MajorOperatingSystemVersion: this.buffer.readUInt16LE(offset + 40),
        MinorOperatingSystemVersion: this.buffer.readUInt16LE(offset + 42),
        MajorImageVersion: this.buffer.readUInt16LE(offset + 44),
        MinorImageVersion: this.buffer.readUInt16LE(offset + 46),
        MajorSubsystemVersion: this.buffer.readUInt16LE(offset + 48),
        MinorSubsystemVersion: this.buffer.readUInt16LE(offset + 50),
        Win32VersionValue: this.buffer.readUInt32LE(offset + 52),
        SizeOfImage: this.buffer.readUInt32LE(offset + 56),
        SizeOfHeaders: this.buffer.readUInt32LE(offset + 60),
        CheckSum: this.buffer.readUInt32LE(offset + 64),
        Subsystem: this.buffer.readUInt16LE(offset + 68),
        DllCharacteristics: this.buffer.readUInt16LE(offset + 70),
        SizeOfStackReserve: this.buffer.readBigUInt64LE(offset + 72),
        SizeOfStackCommit: this.buffer.readBigUInt64LE(offset + 80),
        SizeOfHeapReserve: this.buffer.readBigUInt64LE(offset + 88),
        SizeOfHeapCommit: this.buffer.readBigUInt64LE(offset + 96),
        LoaderFlags: this.buffer.readUInt32LE(offset + 104),
        NumberOfRvaAndSizes: this.buffer.readUInt32LE(offset + 108),
        DataDirectory: this.parseDataDirectoryArray(offset + 112, 16)
      };
    } else {
      throw new Error(`Unknown PE format: 0x${magic.toString(16)}`);
    }

    return optionalHeader;
  }

  parseDataDirectoryArray(offset, count) {
    const directories = [];
    for (let i = 0; i < count; i++) {
      directories.push({
        VirtualAddress: this.buffer.readUInt32LE(offset + i * 8),
        Size: this.buffer.readUInt32LE(offset + i * 8 + 4)
      });
    }
    return directories;
  }

  parseSections(offset, numberOfSections) {
    const sections = [];
    const sectionSize = 40; // Size of IMAGE_SECTION_HEADER

    for (let i = 0; i < numberOfSections; i++) {
      const sectionOffset = offset + i * sectionSize;

      // Read name (8 bytes, may not be null-terminated)
      let name = '';
      for (let j = 0; j < 8; j++) {
        const char = this.buffer.readUInt8(sectionOffset + j);
        if (char !== 0) {
          name += String.fromCharCode(char);
        } else {
          break;
        }
      }

      sections.push({
        Name: name,
        VirtualSize: this.buffer.readUInt32LE(sectionOffset + 8),
        VirtualAddress: this.buffer.readUInt32LE(sectionOffset + 12),
        SizeOfRawData: this.buffer.readUInt32LE(sectionOffset + 16),
        PointerToRawData: this.buffer.readUInt32LE(sectionOffset + 20),
        PointerToRelocations: this.buffer.readUInt32LE(sectionOffset + 24),
        PointerToLinenumbers: this.buffer.readUInt32LE(sectionOffset + 28),
        NumberOfRelocations: this.buffer.readUInt16LE(sectionOffset + 32),
        NumberOfLinenumbers: this.buffer.readUInt16LE(sectionOffset + 34),
        Characteristics: this.buffer.readUInt32LE(sectionOffset + 36),
        characteristics: this.parseSectionCharacteristics(this.buffer.readUInt32LE(sectionOffset + 36))
      });
    }

    return sections;
  }

  parseDataDirectories(optionalHeader, peOffset) {
    const names = [
      'Export Table',
      'Import Table',
      'Resource Table',
      'Exception Table',
      'Certificate Table',
      'Base Relocation Table',
      'Debug',
      'Architecture',
      'Global Ptr',
      'TLS Table',
      'Load Config Table',
      'Bound Import',
      'IAT',
      'Delay Import Descriptor',
      'COM Descriptor',
      'Reserved'
    ];

    const directories = [];
    const dataDirOffset = optionalHeader.DataDirectory ? 0 : (optionalHeader.magic === 'PE32+' ? 112 : 96);

    for (let i = 0; i < 16; i++) {
      const offset = peOffset + 4 + 20 + optionalHeader.SizeOfOptionalHeader + i * 8;

      if (offset + 8 <= this.buffer.length) {
        directories.push({
          name: names[i],
          index: i,
          VirtualAddress: this.buffer.readUInt32LE(offset),
          Size: this.buffer.readUInt32LE(offset + 4)
        });
      }
    }

    return directories;
  }

  parseImports(dataDirectories, optionalHeader) {
    const importDir = dataDirectories.find(d => d.index === 1); // Import Table
    if (!importDir || importDir.VirtualAddress === 0) {
      return null;
    }

    try {
      const rvaToFileOffset = this.getRvaToFileOffset(optionalHeader);
      const importOffset = rvaToFileOffset(importDir.VirtualAddress);

      const imports = [];
      let entryIndex = 0;

      while (true) {
        const entryOffset = importOffset + entryIndex * 20;

        if (entryOffset + 20 > this.buffer.length) break;

        const lookupTableRVA = this.buffer.readUInt32LE(entryOffset);
        const timestamp = this.buffer.readUInt32LE(entryOffset + 4);
        const forwarderChain = this.buffer.readUInt32LE(entryOffset + 8);
        const nameRVA = this.buffer.readUInt32LE(entryOffset + 12);
        const thunkTableRVA = this.buffer.readUInt32LE(entryOffset + 16);

        if (lookupTableRVA === 0 && nameRVA === 0) {
          break;
        }

        // Get DLL name
        const dllNameOffset = rvaToFileOffset(nameRVA);
        let dllName = '';
        if (dllNameOffset > 0 && dllNameOffset < this.buffer.length) {
          let i = 0;
          while (this.buffer[dllNameOffset + i] !== 0) {
            dllName += String.fromCharCode(this.buffer[dllNameOffset + i]);
            i++;
          }
        }

        // Get functions
        const functions = [];
        const funcRVA = thunkTableRVA !== 0 ? thunkTableRVA : lookupTableRVA;
        const funcOffset = rvaToFileOffset(funcRVA);

        if (funcOffset > 0 && funcOffset < this.buffer.length) {
          let funcIndex = 0;
          while (true) {
            const funcEntryOffset = funcOffset + funcIndex * (optionalHeader.magic === 'PE32+' ? 8 : 4);

            if (funcEntryOffset + (optionalHeader.magic === 'PE32+' ? 8 : 4) > this.buffer.length) break;

            let funcAddr;
            if (optionalHeader.magic === 'PE32+') {
              funcAddr = this.buffer.readBigUInt64LE(funcEntryOffset);
            } else {
              funcAddr = this.buffer.readUInt32LE(funcEntryOffset);
            }

            if (Number(funcAddr) === 0) break;

            // Check if ordinal or name
            if (optionalHeader.magic === 'PE32+') {
              if ((funcAddr & 0x8000000000000000n) !== 0n) {
                functions.push({
                  ordinal: Number(funcAddr & 0xFFFFFFFFn),
                  type: 'ordinal'
                });
              } else {
                const nameOffset = rvaToFileOffset(Number(funcAddr));
                if (nameOffset > 0 && nameOffset < this.buffer.length) {
                  let name = '';
                  let i = 0;
                  while (this.buffer[nameOffset + 2 + i] !== 0) {
                    name += String.fromCharCode(this.buffer[nameOffset + 2 + i]);
                    i++;
                  }
                  functions.push({
                    name: name,
                    hint: this.buffer.readUInt16LE(nameOffset),
                    type: 'name'
                  });
                }
              }
            } else {
              if ((funcAddr & 0x80000000) !== 0) {
                functions.push({
                  ordinal: funcAddr & 0xFFFF,
                  type: 'ordinal'
                });
              } else {
                const nameOffset = rvaToFileOffset(funcAddr);
                if (nameOffset > 0 && nameOffset < this.buffer.length) {
                  let name = '';
                  let i = 0;
                  while (this.buffer[nameOffset + 2 + i] !== 0) {
                    name += String.fromCharCode(this.buffer[nameOffset + 2 + i]);
                    i++;
                  }
                  functions.push({
                    name: name,
                    hint: this.buffer.readUInt16LE(nameOffset),
                    type: 'name'
                  });
                }
              }
            }

            funcIndex++;
          }
        }

        imports.push({
          dllName: dllName,
          timestamp: timestamp,
          functions: functions
        });

        entryIndex++;
      }

      return imports;

    } catch (error) {
      log.error('Error parsing imports:', error);
      return null;
    }
  }

  parseExports(dataDirectories, optionalHeader) {
    const exportDir = dataDirectories.find(d => d.index === 0); // Export Table
    if (!exportDir || exportDir.VirtualAddress === 0) {
      return null;
    }

    try {
      const rvaToFileOffset = this.getRvaToFileOffset(optionalHeader);
      const exportOffset = rvaToFileOffset(exportDir.VirtualAddress);

      if (exportOffset + 40 > this.buffer.length) {
        return null;
      }

      const characteristics = this.buffer.readUInt32LE(exportOffset);
      const timeDateStamp = this.buffer.readUInt32LE(exportOffset + 4);
      const majorVersion = this.buffer.readUInt16LE(exportOffset + 8);
      const minorVersion = this.buffer.readUInt16LE(exportOffset + 10);
      const nameRVA = this.buffer.readUInt32LE(exportOffset + 12);
      const ordinalBase = this.buffer.readUInt32LE(exportOffset + 16);
      const addressTableEntries = this.buffer.readUInt32LE(exportOffset + 20);
      const numberOfNamePointers = this.buffer.readUInt32LE(exportOffset + 24);
      const exportAddressTableRVA = this.buffer.readUInt32LE(exportOffset + 28);
      const namePointerRVA = this.buffer.readUInt32LE(exportOffset + 32);
      const ordinalTableRVA = this.buffer.readUInt32LE(exportOffset + 36);

      // Get DLL name
      const dllNameOffset = rvaToFileOffset(nameRVA);
      let dllName = '';
      if (dllNameOffset > 0) {
        let i = 0;
        while (this.buffer[dllNameOffset + i] !== 0) {
          dllName += String.fromCharCode(this.buffer[dllNameOffset + i]);
          i++;
        }
      }

      // Get exported functions
      const functions = [];
      const exportAddrOffset = rvaToFileOffset(exportAddressTableRVA);
      const namePtrOffset = rvaToFileOffset(namePointerRVA);
      const ordinalOffset = rvaToFileOffset(ordinalTableRVA);

      for (let i = 0; i < addressTableEntries; i++) {
        const funcRVA = this.buffer.readUInt32LE(exportAddrOffset + i * 4);
        const ordinal = this.buffer.readUInt16LE(ordinalOffset + i * 2);

        let name = null;
        if (i < numberOfNamePointers) {
          const nameRVA = this.buffer.readUInt32LE(namePtrOffset + i * 4);
          const nameOffset = rvaToFileOffset(nameRVA);
          if (nameOffset > 0) {
            name = '';
            let j = 0;
            while (this.buffer[nameOffset + j] !== 0) {
              name += String.fromCharCode(this.buffer[nameOffset + j]);
              j++;
            }
          }
        }

        functions.push({
          ordinal: ordinalBase + ordinal,
          address: funcRVA,
          name: name,
          isForwarded: funcRVA >= exportDir.VirtualAddress && funcRVA < exportDir.VirtualAddress + exportDir.Size
        });
      }

      return {
        dllName: dllName,
        timestamp: timeDateStamp,
        version: `${majorVersion}.${minorVersion}`,
        ordinalBase: ordinalBase,
        functions: functions
      };

    } catch (error) {
      log.error('Error parsing exports:', error);
      return null;
    }
  }

  getRvaToFileOffset(optionalHeader) {
    const sections = this.parseSections(
      this.buffer.readInt32LE(60) + 4 + 20 + optionalHeader.SizeOfOptionalHeader,
      this.buffer.readUInt16LE(this.buffer.readInt32LE(60) + 4 + 2)
    );

    return (rva) => {
      for (const section of sections) {
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize) {
          return section.PointerToRawData + (rva - section.VirtualAddress);
        }
      }
      return rva; // Fallback to RVA
    };
  }

  parseCharacteristics(characteristics) {
    const flags = [];
    const flagMap = [
      { bit: 0, name: 'RELOCS_STRIPPED' },
      { bit: 1, name: 'EXECUTABLE_IMAGE' },
      { bit: 2, name: 'LINE_NUMS_STRIPPED' },
      { bit: 3, name: 'LOCAL_SYMS_STRIPPED' },
      { bit: 4, name: 'AGGRESSIVE_WS_TRIM' },
      { bit: 5, name: 'LARGE_ADDRESS_AWARE' },
      { bit: 6, name: 'RESERVED' },
      { bit: 7, name: 'BYTES_REVERSED_LO' },
      { bit: 8, name: '32BIT_MACHINE' },
      { bit: 9, name: 'DEBUG_STRIPPED' },
      { bit: 10, name: 'REMOVABLE_RUN_FROM_SWAP' },
      { bit: 11, name: 'NET_RUN_FROM_SWAP' },
      { bit: 12, name: 'SYSTEM' },
      { bit: 13, name: 'DLL' },
      { bit: 14, name: 'UP_SYSTEM_ONLY' },
      { bit: 15, name: 'BYTES_REVERSED_HI' }
    ];

    for (const flag of flagMap) {
      if ((characteristics & (1 << flag.bit)) !== 0) {
        flags.push(flag.name);
      }
    }

    return flags;
  }

  parseDllCharacteristics(dllCharacteristics) {
    const flags = [];
    const flagMap = [
      { bit: 0, name: 'RESERVED' },
      { bit: 1, name: 'RESERVED' },
      { bit: 2, name: 'RESERVED' },
      { bit: 3, name: 'RESERVED' },
      { bit: 4, name: 'RESERVED' },
      { bit: 5, name: 'HIGH_ENTROPY_VA' },
      { bit: 6, name: 'DYNAMIC_BASE' }, // ASLR
      { bit: 7, name: 'FORCE_INTEGRITY' },
      { bit: 8, name: 'NX_COMPAT' }, // DEP
      { bit: 9, name: 'NO_ISOLATION' },
      { bit: 10, name: 'NO_SEH' },
      { bit: 11, name: 'NO_BIND' },
      { bit: 12, name: 'APPCONTAINER' },
      { bit: 13, name: 'WDM_DRIVER' },
      { bit: 14, name: 'GUARD_CF' }, // CFG
      { bit: 15, name: 'TERMINAL_SERVER_AWARE' }
    ];

    for (const flag of flagMap) {
      if ((dllCharacteristics & (1 << flag.bit)) !== 0) {
        flags.push(flag.name);
      }
    }

    return flags;
  }

  parseSectionCharacteristics(characteristics) {
    const flags = [];
    const flagMap = [
      { bit: 0, name: 'TYPE_REG' },
      { bit: 1, name: 'TYPE_DSECT' },
      { bit: 2, name: 'TYPE_NOLOAD' },
      { bit: 3, name: 'TYPE_GROUP' },
      { bit: 4, name: 'TYPE_NO_PAD' },
      { bit: 5, name: 'TYPE_CNT_CODE' },
      { bit: 6, name: 'TYPE_CNT_INITIALIZED_DATA' },
      { bit: 7, name: 'TYPE_CNT_UNINITIALIZED_DATA' },
      { bit: 8, name: 'TYPE_LNK_INFO' },
      { bit: 9, name: 'TYPE_LNK_REMOVE' },
      { bit: 10, name: 'TYPE_LNK_COMDAT' },
      { bit: 11, name: 'RESERVED' },
      { bit: 12, name: 'TYPE_NO_DEFER_SPEC_EXC' },
      { bit: 14, name: 'TYPE_GPREL' },
      { bit: 15, name: 'TYPE_MEM_FAR_CODE' },
      { bit: 16, name: 'TYPE_MEM_Purgeable' },
      { bit: 17, name: 'TYPE_MEM_16BIT' },
      { bit: 18, name: 'TYPE_MEM_LOCKED' },
      { bit: 19, name: 'TYPE_MEM_PRELOAD' },
      { bit: 20, name: 'ALIGN_1BYTES' },
      { bit: 21, name: 'ALIGN_2BYTES' },
      { bit: 22, name: 'ALIGN_4BYTES' },
      { bit: 23, name: 'ALIGN_8BYTES' },
      { bit: 24, name: 'ALIGN_16BYTES' },
      { bit: 25, name: 'ALIGN_32BYTES' },
      { bit: 26, name: 'ALIGN_64BYTES' },
      { bit: 27, name: 'ALIGN_128BYTES' },
      { bit: 28, name: 'ALIGN_256BYTES' },
      { bit: 29, name: 'ALIGN_512BYTES' },
      { bit: 30, name: 'ALIGN_1024BYTES' },
      { bit: 31, name: 'ALIGN_2048BYTES' }
    ];

    // Handle alignment bits
    const alignBits = (characteristics >> 20) & 0xF;
    const alignValues = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384];
    if (alignBits < alignValues.length && alignValues[alignBits] > 0) {
      flags.push(`ALIGN_${alignValues[alignBits]}BYTES`);
    }

    for (const flag of flagMap) {
      if ((characteristics & (1 << flag.bit)) !== 0) {
        flags.push(flag.name);
      }
    }

    return flags;
  }

  async readHex(offset, length) {
    try {
      if (!this.buffer) {
        this.buffer = fs.readFileSync(this.filePath);
      }

      const start = Math.max(0, offset);
      const end = Math.min(this.buffer.length, offset + length);
      const data = this.buffer.slice(start, end);

      const hexLines = [];
      for (let i = 0; i < data.length; i += 16) {
        const lineOffset = start + i;
        const lineData = data.slice(i, i + 16);

        let hex = '';
        let ascii = '';

        for (let j = 0; j < 16; j++) {
          if (j < lineData.length) {
            hex += lineData[j].toString(16).padStart(2, '0') + ' ';
            ascii += (lineData[j] >= 32 && lineData[j] <= 126)
              ? String.fromCharCode(lineData[j])
              : '.';
          } else {
            hex += '   ';
            ascii += ' ';
          }

          if (j === 7) hex += ' ';
        }

        hexLines.push({
          offset: lineOffset.toString(16).padStart(8, '0'),
          hex: hex,
          ascii: ascii
        });
      }

      return hexLines;

    } catch (error) {
      log.error('Error reading hex:', error);
      throw error;
    }
  }
}

module.exports = PEParser;
