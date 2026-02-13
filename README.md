# PE Editor

Advanced PE Executable Editor — LAA/ASLR/DEP/CFG patcher with hex diff, import/export viewer, and batch processing.

![PE Editor Screenshot](docs/screenshot.png)

## Features

- **PE Parsing** — Full DOS/COFF/Optional header parsing, sections, imports, exports, data directories
- **Security Flags** — Toggle LAA, ASLR, DEP, CFG, High Entropy VA with one click
- **Section Viewer** — View all sections with entropy visualization and permissions
- **Import/Export Tables** — Searchable tree view of imported DLLs and exported functions
- **Hex Diff** — Visual byte-level comparison between original and modified file
- **Batch Processing** — Scan directories and patch multiple files at once
- **System Tray** — Minimizes to tray, runs in background
- **Native Dialogs** — Open, Save, Save As with native file dialogs
- **Auto Backup** — Creates `.backup` files before overwriting
- **PE Checksum** — Automatically recalculated on save

## Pre-built Installers

**[Buy on Gumroad →](https://gumroad.com/pe-editor)**

Pre-built installers include:
- Windows NSIS installer with desktop/start menu shortcuts
- Portable executable (no installation needed)
- Priority support

## Building from Source

### Prerequisites

- Node.js 18+
- npm 9+

### Build Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/pe-editor.git
cd pe-editor

# Install dependencies
npm install

# Run in development mode
npm start

# Build for production
npm run build        # Current platform
npm run build:win    # Windows only
npm run build:linux  # Linux only
npm run build:mac    # macOS only
```

### Build Output

After running `npm run build`, you'll find:
- `dist/PE Editor Setup x.x.x.exe` — NSIS installer
- `dist/win-unpacked/` — Portable version

## Usage

### Opening Files

- **Drag & Drop** — Drop .exe/.dll files onto the window
- **File Menu** — File → Open PE File (Ctrl+O)
- **Multiple Files** — File → Open Multiple Files (Ctrl+Shift+O)
- **Command Line** — `pe-editor.exe path/to/file.exe`

### Patching Flags

1. Open a PE file
2. Go to **Flags & Patching** tab (Ctrl+2)
3. Toggle the desired flags:
   - **LAA** — Large Address Aware (4GB memory for 32-bit apps)
   - **ASLR** — Address Space Layout Randomization
   - **DEP** — Data Execution Prevention (NX compatible)
   - **CFG** — Control Flow Guard
4. Click **Apply Changes** (Ctrl+Enter)
5. Save the file (Ctrl+S)

### Batch Processing

1. Go to **Batch** tab (Ctrl+8)
2. Enter a directory path or click Browse
3. Click **Scan** to find all PE files
4. Select files to patch
5. Choose flags to apply
6. Click **Patch Selected**

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+O | Open file |
| Ctrl+Shift+O | Open multiple files |
| Ctrl+S | Save |
| Ctrl+Shift+S | Save As |
| Ctrl+Enter | Apply changes |
| Ctrl+Z | Reset to original |
| Ctrl+B | Batch scan directory |
| Ctrl+1-8 | Switch tabs |

## Supported File Types

- `.exe` — Executable
- `.dll` — Dynamic Link Library
- `.sys` — Kernel driver
- `.scr` — Screen saver
- `.ocx` — ActiveX control
- `.drv` — Driver
- `.cpl` — Control Panel applet
- `.efi` — EFI executable

## Technical Details

- **Pure Node.js** — No native dependencies for PE parsing
- **Electron 28** — Modern Chromium and Node.js
- **Context Isolation** — Secure renderer process
- **No Telemetry** — Everything runs locally

## License

**Source Available License**

- ✅ View and study the source code
- ✅ Modify for personal use
- ✅ Build from source for personal use
- ❌ Redistribute pre-built binaries
- ❌ Use for commercial purposes without license

Pre-built installers are available for purchase on [Gumroad](https://gumroad.com/pe-editor).

See [LICENSE](LICENSE) for full terms.

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

- **Issues** — [GitHub Issues](https://github.com/yourusername/pe-editor/issues)
- **Email** — support@example.com

---

Made with ⚙️ by PE Editor
