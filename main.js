const {
  app, BrowserWindow, ipcMain, dialog, Menu, Tray, shell, nativeTheme,
} = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const { PEParser } = require('./pe-parser');
const { PEPatcher } = require('./pe-patcher');
const { BatchProcessor } = require('./batch-processor');
const { LicenseManager } = require('./license-manager');

let mainWindow = null;
let tray = null;
const fileStore = new Map();
const isDev = process.argv.includes('--dev');
const licenseManager = new LicenseManager();

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) { app.quit(); }
else {
  app.on('second-instance', (event, argv) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
      const fp = argv.find(a => ['.exe', '.dll', '.sys', '.scr', '.ocx', '.drv'].includes(path.extname(a).toLowerCase()));
      if (fp && fs.existsSync(fp)) loadFileFromPath(fp);
    }
  });
}

function createWindow() {
  nativeTheme.themeSource = 'dark';
  mainWindow = new BrowserWindow({
    width: 1400, height: 900, minWidth: 900, minHeight: 600,
    title: 'IVGB Patcher+',
    backgroundColor: '#0d1117',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, nodeIntegration: false, sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (isDev) mainWindow.webContents.openDevTools();
  });

  mainWindow.on('close', (e) => {
    if (tray && !app.isQuitting) { e.preventDefault(); mainWindow.hide(); }
  });
  mainWindow.on('closed', () => { mainWindow = null; });
  buildMenu();
}

function buildMenu() {
  const template = [
    {
      label: 'File',
      submenu: [
        { label: 'Open PE File...', accelerator: 'CmdOrCtrl+O', click: () => openFileDialog() },
        { label: 'Open Multiple...', accelerator: 'CmdOrCtrl+Shift+O', click: () => openMultipleFilesDialog() },
        { type: 'separator' },
        { label: 'Save', accelerator: 'CmdOrCtrl+S', click: () => mainWindow?.webContents.send('menu-action', 'save') },
        { label: 'Save As...', accelerator: 'CmdOrCtrl+Shift+S', click: () => mainWindow?.webContents.send('menu-action', 'save-as') },
        { type: 'separator' },
        { label: 'Batch Scan...', accelerator: 'CmdOrCtrl+B', click: () => openBatchDirectoryDialog() },
        { type: 'separator' },
        { label: 'Exit', accelerator: 'Alt+F4', click: () => { app.isQuitting = true; app.quit(); } },
      ],
    },
    {
      label: 'Edit',
      submenu: [
        { label: 'Apply Changes', accelerator: 'CmdOrCtrl+Enter', click: () => mainWindow?.webContents.send('menu-action', 'apply') },
        { label: 'Reset to Original', accelerator: 'CmdOrCtrl+Z', click: () => mainWindow?.webContents.send('menu-action', 'reset') },
      ],
    },
    {
      label: 'View',
      submenu: [
        { label: 'Overview', accelerator: 'CmdOrCtrl+1', click: () => mainWindow?.webContents.send('menu-action', 'tab-overview') },
        { label: 'Flags', accelerator: 'CmdOrCtrl+2', click: () => mainWindow?.webContents.send('menu-action', 'tab-flags') },
        { label: 'Sections', accelerator: 'CmdOrCtrl+3', click: () => mainWindow?.webContents.send('menu-action', 'tab-sections') },
        { label: 'Imports', accelerator: 'CmdOrCtrl+4', click: () => mainWindow?.webContents.send('menu-action', 'tab-imports') },
        { label: 'Exports', accelerator: 'CmdOrCtrl+5', click: () => mainWindow?.webContents.send('menu-action', 'tab-exports') },
        { label: 'Directories', accelerator: 'CmdOrCtrl+6', click: () => mainWindow?.webContents.send('menu-action', 'tab-directories') },
        { label: 'Hex Diff', accelerator: 'CmdOrCtrl+7', click: () => mainWindow?.webContents.send('menu-action', 'tab-hexdiff') },
        { label: 'Batch', accelerator: 'CmdOrCtrl+8', click: () => mainWindow?.webContents.send('menu-action', 'tab-batch') },
        { type: 'separator' },
        { role: 'toggleDevTools' }, { role: 'reload' },
      ],
    },
    {
      label: 'License',
      submenu: [
        { label: 'Enter License Key...', click: () => mainWindow?.webContents.send('menu-action', 'show-license') },
        { label: 'Deactivate License', click: () => mainWindow?.webContents.send('menu-action', 'deactivate-license') },
        { type: 'separator' },
        {
          label: 'Buy Pro License',
          click: () => shell.openExternal('https://your-link-here.itch.io/ivgb-patcher-plus'),
        },
      ],
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'About IVGB Patcher+',
          click: () => {
            const status = licenseManager.getStatus();
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'IVGB Patcher+',
              message: 'IVGB Patcher+ v2.0.0',
              detail: [
                'Advanced PE Editor & Security Flag Toolkit',
                '',
                `License: ${status.tierLabel}`,
                status.licensed ? `Activated: ${status.activatedAt}` : '',
                '',
                '© 2024 YOUR NAME HERE',
                'Licensed under PolyForm Noncommercial 1.0.0',
              ].filter(Boolean).join('\n'),
            });
          },
        },
        { type: 'separator' },
        { label: 'Support (Ko-fi)', click: () => shell.openExternal('https://ko-fi.com/yourname') },
        { label: 'GitHub', click: () => shell.openExternal('https://github.com/yourname/ivgb-patcher-plus') },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function createTray() {
  const { nativeImage } = require('electron');
  const size = 16;
  const buf = Buffer.alloc(size * size * 4, 0);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;
      const cx = x - 7.5, cy = y - 7.5;
      const dist = Math.sqrt(cx * cx + cy * cy);
      if (dist >= 3 && dist <= 7) {
        buf[idx] = 88; buf[idx + 1] = 166; buf[idx + 2] = 255; buf[idx + 3] = 255;
      }
    }
  }
  const icon = nativeImage.createFromBuffer(buf, { width: size, height: size });
  tray = new Tray(icon);
  tray.setToolTip('IVGB Patcher+');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Show IVGB Patcher+', click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } } },
    { label: 'Open File...', click: () => { if (mainWindow) mainWindow.show(); openFileDialog(); } },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.isQuitting = true; app.quit(); } },
  ]));
  tray.on('double-click', () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } });
}

// ─── File Operations ─────────────────────────────────────────────────────────

async function openFileDialog() {
  if (!mainWindow) return;
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Open PE Executable',
    filters: [
      { name: 'PE Executables', extensions: ['exe', 'dll', 'sys', 'scr', 'ocx', 'drv', 'cpl', 'efi'] },
      { name: 'All Files', extensions: ['*'] },
    ],
    properties: ['openFile'],
  });
  if (!result.canceled && result.filePaths.length > 0) loadFileFromPath(result.filePaths[0]);
}

async function openMultipleFilesDialog() {
  if (!mainWindow) return;
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Open PE Executables',
    filters: [
      { name: 'PE Executables', extensions: ['exe', 'dll', 'sys', 'scr', 'ocx', 'drv', 'cpl', 'efi'] },
      { name: 'All Files', extensions: ['*'] },
    ],
    properties: ['openFile', 'multiSelections'],
  });
  if (!result.canceled && result.filePaths.length > 0) {
    const files = result.filePaths.map(fp => {
      try { return loadFileEntry(fp); }
      catch (err) { return { fileId: null, filename: path.basename(fp), error: err.message, status: 'error' }; }
    });
    mainWindow.webContents.send('files-loaded', files);
  }
}

async function openBatchDirectoryDialog() {
  if (!mainWindow) return;
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select Directory to Scan', properties: ['openDirectory'],
  });
  if (!result.canceled && result.filePaths.length > 0)
    mainWindow.webContents.send('batch-directory-selected', result.filePaths[0]);
}

function loadFileEntry(filePath) {
  const buffer = fs.readFileSync(filePath);
  const fileId = crypto.randomBytes(16).toString('hex');
  const parser = new PEParser(buffer);
  const analysis = parser.getFullAnalysis();
  analysis.file.name = path.basename(filePath);
  analysis.file.path = filePath;

  fileStore.set(fileId, {
    buffer: Buffer.from(buffer), originalBuffer: Buffer.from(buffer),
    filename: path.basename(filePath), filePath, analysis, timestamp: Date.now(),
  });

  return { fileId, filename: path.basename(filePath), filePath, analysis, status: 'ok' };
}

function loadFileFromPath(filePath) {
  try {
    const entry = loadFileEntry(filePath);
    mainWindow.webContents.send('files-loaded', [entry]);
  } catch (err) { dialog.showErrorBox('Failed to load', err.message); }
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

ipcMain.handle('open-file-dialog', () => openFileDialog());
ipcMain.handle('open-multiple-dialog', () => openMultipleFilesDialog());
ipcMain.handle('open-batch-directory-dialog', async () => {
  const r = await dialog.showOpenDialog(mainWindow, { title: 'Select Directory', properties: ['openDirectory'] });
  return r.canceled ? null : r.filePaths[0];
});

ipcMain.handle('load-dropped-files', (e, paths) => {
  return paths.map(fp => {
    try { return loadFileEntry(fp); }
    catch (err) { return { fileId: null, filename: path.basename(fp), filePath: fp, error: err.message, status: 'error' }; }
  });
});

ipcMain.handle('get-analysis', (e, fileId) => {
  const entry = fileStore.get(fileId);
  if (!entry) throw new Error('File not found');
  const parser = new PEParser(entry.buffer);
  const analysis = parser.getFullAnalysis();
  analysis.file.name = entry.filename;
  analysis.file.path = entry.filePath;
  return analysis;
});

ipcMain.handle('apply-patch', (e, fileId, flags, recalcChecksum) => {
  const entry = fileStore.get(fileId);
  if (!entry) throw new Error('File not found');

  const patcher = new PEPatcher(entry.buffer);
  const flagResults = patcher.applyFlagChanges(flags);
  let checksumResult = null;
  if (recalcChecksum !== false) checksumResult = patcher.recalculateChecksum();

  const hexDiff = patcher.getHexDiff();
  const hashes = patcher.getHashes();
  entry.buffer = patcher.getBuffer();
  entry.timestamp = Date.now();

  const parser = new PEParser(entry.buffer);
  const analysis = parser.getFullAnalysis();
  analysis.file.name = entry.filename;
  analysis.file.path = entry.filePath;
  entry.analysis = analysis;

  return { flagResults, checksumResult, hexDiff, hashes, analysis };
});

ipcMain.handle('reset-file', (e, fileId) => {
  const entry = fileStore.get(fileId);
  if (!entry) throw new Error('File not found');
  entry.buffer = Buffer.from(entry.originalBuffer);
  const parser = new PEParser(entry.buffer);
  const analysis = parser.getFullAnalysis();
  analysis.file.name = entry.filename;
  analysis.file.path = entry.filePath;
  entry.analysis = analysis;
  return analysis;
});

ipcMain.handle('save-file', (e, fileId) => {
  const entry = fileStore.get(fileId);
  if (!entry) throw new Error('File not found');
  if (!entry.filePath) throw new Error('No file path');

  const ext = path.extname(entry.filePath);
  const base = entry.filePath.slice(0, -ext.length);
  let bp = `${base}.backup${ext}`;
  let c = 1;
  while (fs.existsSync(bp)) { bp = `${base}.backup${c}${ext}`; c++; }
  fs.copyFileSync(entry.filePath, bp);
  fs.writeFileSync(entry.filePath, entry.buffer);
  return { savedPath: entry.filePath, backupPath: bp };
});

ipcMain.handle('save-file-as', async (e, fileId) => {
  const entry = fileStore.get(fileId);
  if (!entry) throw new Error('File not found');
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Save Modified PE File', defaultPath: entry.filename,
    filters: [{ name: 'PE Executables', extensions: ['exe', 'dll', 'sys'] }, { name: 'All Files', extensions: ['*'] }],
  });
  if (result.canceled) return null;
  fs.writeFileSync(result.filePath, entry.buffer);
  return { savedPath: result.filePath };
});

ipcMain.handle('get-hex-data', (e, fileId, offset, length) => {
  const entry = fileStore.get(fileId);
  if (!entry) throw new Error('File not found');
  const safeLen = Math.min(length || 256, 4096);
  const safeOff = Math.max(0, Math.min(offset, entry.buffer.length - 1));
  const end = Math.min(safeOff + safeLen, entry.buffer.length);
  const slice = entry.buffer.slice(safeOff, end);
  const rows = [];
  for (let i = 0; i < slice.length; i += 16) {
    const rb = slice.slice(i, Math.min(i + 16, slice.length));
    const hex = [], ascii = [];
    for (let j = 0; j < 16; j++) {
      if (j < rb.length) { hex.push(rb[j].toString(16).toUpperCase().padStart(2, '0')); ascii.push(rb[j] >= 32 && rb[j] < 127 ? String.fromCharCode(rb[j]) : '.'); }
      else { hex.push('  '); ascii.push(' '); }
    }
    rows.push({ offset: safeOff + i, offsetHex: '0x' + (safeOff + i).toString(16).toUpperCase().padStart(8, '0'), hex, ascii: ascii.join('') });
  }
  return { offset: safeOff, length: end - safeOff, fileSize: entry.buffer.length, rows };
});

ipcMain.handle('get-diff', (e, fileId) => {
  const entry = fileStore.get(fileId);
  if (!entry) throw new Error('File not found');
  const diffs = [];
  for (let i = 0; i < Math.max(entry.originalBuffer.length, entry.buffer.length); i++) {
    const ob = i < entry.originalBuffer.length ? entry.originalBuffer[i] : null;
    const nb = i < entry.buffer.length ? entry.buffer[i] : null;
    if (ob !== nb) diffs.push({ offset: i, offsetHex: '0x' + i.toString(16).toUpperCase().padStart(8, '0'), oldByte: ob, newByte: nb, oldHex: ob !== null ? ob.toString(16).toUpperCase().padStart(2, '0') : '--', newHex: nb !== null ? nb.toString(16).toUpperCase().padStart(2, '0') : '--' });
  }
  return { totalChangedBytes: diffs.length, diffs, isModified: diffs.length > 0 };
});

ipcMain.handle('batch-scan', (e, dir, recursive) => {
  if (!fs.existsSync(dir)) throw new Error(`Directory not found: ${dir}`);
  return new BatchProcessor().scanAndReport(dir, recursive);
});

ipcMain.handle('batch-patch', (e, files, flags, options) => {
  return new BatchProcessor().batchPatch(files, flags, options);
});

ipcMain.handle('reveal-in-explorer', (e, fp) => shell.showItemInFolder(fp));

// ─── License IPC ─────────────────────────────────────────────────────────────

ipcMain.handle('license-get-status', () => licenseManager.getStatus());

ipcMain.handle('license-activate', (e, key) => {
  const result = licenseManager.activate(key);
  if (result.valid) buildMenu(); // Refresh menu
  return result;
});

ipcMain.handle('license-deactivate', () => {
  const result = licenseManager.deactivate();
  buildMenu();
  return result;
});

ipcMain.handle('license-get-machine-id', () => licenseManager.getMachineId());

// ─── App Lifecycle ───────────────────────────────────────────────────────────

app.whenReady().then(() => {
  createWindow();
  createTray();

  const fp = process.argv.find(a => ['.exe', '.dll', '.sys', '.scr', '.ocx', '.drv'].includes(path.extname(a).toLowerCase()));
  if (fp && fs.existsSync(fp)) {
    mainWindow.webContents.once('did-finish-load', () => loadFileFromPath(fp));
  }

  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { /* stay in tray */ });
app.on('before-quit', () => { app.isQuitting = true; });
app.on('open-file', (event, fp) => { event.preventDefault(); if (mainWindow) loadFileFromPath(fp); });
