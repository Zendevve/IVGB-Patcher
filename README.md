<div align="center">

# IVGB Patcher+

### Advanced PE Executable Editor & Security Flag Toolkit

**IV** (Roman numeral 4) **GB Patcher** — and then some.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

[Download](#download) • [Features](#features) • [Screenshots](#screenshots) • [Building](#building) • [License](#license)

</div>

---

## What is this?

The original 4GB Patch by NTCore does one thing: flips a single bit in a PE header.

**IVGB Patcher+** does that and everything else you've ever wanted from a PE editor — in a clean desktop app with a dark UI.

## Features

| Feature | Description |
|---|---|
| 🎯 **LAA (4GB) Patching** | Set/clear LARGE_ADDRESS_AWARE — the classic 4GB patch |
| 🔐 **ASLR Toggling** | Enable/disable DYNAMIC_BASE |
| 🛡️ **DEP Toggling** | Enable/disable NX_COMPAT |
| 🔒 **CFG Toggling** | Enable/disable Control Flow Guard |
| 🏷️ **All PE Flags** | HIGH_ENTROPY_VA, FORCE_INTEGRITY, NO_SEH, APPCONTAINER, TERMINAL_SERVER_AWARE |
| 📦 **Section Viewer** | Names, permissions, entropy visualization |
| 📥 **Import Table** | Collapsible DLL tree, searchable |
| 📤 **Export Table** | With forwarder detection |
| 📁 **Data Directories** | All 16 PE data directories |
| 🔍 **Hex Diff** | Byte-level visual diff — see exactly what changed |
| 📂 **Batch Processing** | Scan directories, patch hundreds of files at once |
| 💾 **Auto Backup** | Creates .backup before overwriting |
| 🔢 **PE Checksum** | Automatically recalculated after patching |
| 🔑 **File Hashes** | MD5, SHA-1, SHA-256 |
| 🖱️ **Drag & Drop** | Drop files directly onto the window |
| ⌨️ **Keyboard Shortcuts** | Ctrl+O, Ctrl+S, Ctrl+1-8, Ctrl+Enter |
| 🖥️ **System Tray** | Minimize to tray |
| 🌙 **Dark Theme** | Easy on the eyes |

## Download

**[Get IVGB Patcher+ on itch.io →](https://your-link-here.itch.io/ivgb-patcher-plus)**

| Tier | Price | Details |
|---|---|---|
| **Personal** | Free | Full app, non-commercial use |
| **Supporter** | $5+ | Same app + name in credits |
| **Pro License** | $15 | Commercial use permitted |
| **Team / Studio** | $50 | Studio-wide commercial license |

## Building From Source

```bash
git clone https://github.com/yourname/ivgb-patcher-plus.git
cd ivgb-patcher-plus
npm install
npm start          # Run in dev mode
npm run build:win  # Build Windows installer
```

## License

**PolyForm Noncommercial 1.0.0** — See [LICENSE.md](LICENSE.md)

- ✅ View source, learn, modify for personal use
- ✅ Use for personal, educational, non-commercial purposes
- ❌ Cannot sell, redistribute commercially, or rebrand

Commercial license available — see pricing above.

## Support Development

- ☕ [Ko-fi](https://ko-fi.com/yourname)
- 💖 [GitHub Sponsors](https://github.com/sponsors/yourname)

---

<div align="center">
  <sub>IVGB Patcher+ — because one bit shouldn't require a whole app, but here we are making it beautiful anyway.</sub>
</div>
