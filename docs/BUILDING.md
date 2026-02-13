# Building from Source

> **Note**: For the best experience, we recommend using the pre-built installers available [on itch.io](https://your-link-here.itch.io/ivgb-patcher-plus).

## Prerequisites

- Node.js 18+
- npm 9+

## Build Steps

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

## Build Output

After running `npm run build`, you'll find:
- `dist/PE Editor Setup x.x.x.exe` — NSIS installer
- `dist/win-unpacked/` — Portable version
