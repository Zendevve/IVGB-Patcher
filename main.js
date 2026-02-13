const { app, BrowserWindow, ipcMain, dialog, Menu, Tray, shell, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const log = require('electron-log');
const PEParser = require('./pe-parser.js');
const PEPatcher = require('./pe-patcher.js');
const BatchProcessor = require('./batch-processor.js');

// Configure logging
log.transports.file.level = 'info';
log.transports.file.maxSize = 10 * 1024 * 1024; // 10MB
log.transports.console.level = 'debug';

// Global exception handler
process.on('uncaughtException', (error) => {
  log.error('Uncaught Exception:', error);
  if (dialog) {
    dialog.showErrorBox('Fatal Error', `An unexpected error occurred:\n${error.message}`);
  }
  app.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  log.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

let mainWindow = null;
let tray = null;
let currentFile = null;
let peParser = null;
let pePatcher = null;
let batchProcessor = null;

function createWindow() {
  log.info('Creating main window');

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
    backgroundColor: '#1a1a2e',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    },
    show: false
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    log.info('Main window shown');
  });

  mainWindow.on('close', (event) => {
    if (tray) {
      event.preventDefault();
      mainWindow.hide();
      log.info('Window hidden to tray');
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  createMenu();
  createTray();
}

function createMenu() {
  const template = [
    {
      label: 'File',
      submenu: [
        {
          label: 'Open PE File',
          accelerator: 'CmdOrCtrl+O',
          click: () => openFileDialog()
        },
        {
          label: 'Save',
          accelerator: 'CmdOrCtrl+S',
          click: () => saveFile()
        },
        {
          label: 'Save As...',
          accelerator: 'CmdOrCtrl+Shift+S',
          click: () => saveFileAs()
        },
        { type: 'separator' },
        {
          label: 'Batch Process',
          click: () => openBatchDialog()
        },
        { type: 'separator' },
        {
          label: 'Exit',
          accelerator: 'Alt+F4',
          click: () => {
            tray = null;
            app.quit();
          }
        }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        {
          label: 'Apply Large Address Aware',
          click: () => applyLAA()
        },
        {
          label: 'Toggle ASLR',
          click: () => toggleASLR()
        },
        {
          label: 'Toggle DEP',
          click: () => toggleDEP()
        },
        {
          label: 'Toggle CFG',
          click: () => toggleCFG()
        },
        { type: 'separator' },
        {
          label: 'Hex Diff',
          click: () => showHexDiff()
        }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'About PE Editor',
          click: () => showAbout()
        },
        {
          label: 'View Logs',
          click: () => shell.openPath(log.transports.file.getFile().path)
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

function createTray() {
  try {
    const iconPath = path.join(__dirname, 'build', 'icon.png');
    let trayIcon;

    if (fs.existsSync(iconPath)) {
      trayIcon = nativeImage.createFromPath(iconPath);
    } else {
      trayIcon = nativeImage.createEmpty();
    }

    tray = new Tray(trayIcon);

    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Show PE Editor',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        }
      },
      { type: 'separator' },
      {
        label: 'Open File',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
          openFileDialog();
        }
      },
      { type: 'separator' },
      {
        label: 'Exit',
        click: () => {
          tray = null;
          app.quit();
        }
      }
    ]);

    tray.setToolTip('PE Editor');
    tray.setContextMenu(contextMenu);

    tray.on('double-click', () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
      }
    });

    log.info('Tray created successfully');
  } catch (error) {
    log.error('Failed to create tray:', error);
  }
}

async function openFileDialog() {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select PE File',
    filters: [
      { name: 'Executable Files', extensions: ['exe', 'dll', 'sys', 'ocx'] },
      { name: 'All Files', extensions: ['*'] }
    ],
    properties: ['openFile']
  });

  if (!result.canceled && result.filePaths.length > 0) {
    await loadPEFile(result.filePaths[0]);
  }
}

async function loadPEFile(filePath) {
  try {
    log.info(`Loading PE file: ${filePath}`);
    currentFile = filePath;

    peParser = new PEParser(filePath);
    const peData = await peParser.parse();

    pePatcher = new PEPatcher(filePath);

    mainWindow.webContents.send('file-loaded', {
      path: filePath,
      data: peData
    });

    log.info('PE file loaded successfully');
  } catch (error) {
    log.error('Failed to load PE file:', error);
    dialog.showErrorBox('Load Error', `Failed to load PE file:\n${error.message}`);
  }
}

async function saveFile() {
  if (!currentFile) {
    return saveFileAs();
  }

  try {
    if (pePatcher) {
      await pePatcher.save();
      log.info('File saved successfully');
      mainWindow.webContents.send('file-saved', { path: currentFile });
    }
  } catch (error) {
    log.error('Failed to save file:', error);
    dialog.showErrorBox('Save Error', `Failed to save file:\n${error.message}`);
  }
}

async function saveFileAs() {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Save PE File As',
    defaultPath: currentFile || 'output.exe',
    filters: [
      { name: 'Executable Files', extensions: ['exe', 'dll'] },
      { name: 'All Files', extensions: ['*'] }
    ]
  });

  if (!result.canceled && result.filePath) {
    try {
      if (pePatcher) {
        await pePatcher.saveAs(result.filePath);
        currentFile = result.filePath;
        log.info(`File saved as: ${result.filePath}`);
        mainWindow.webContents.send('file-saved', { path: currentFile });
      }
    } catch (error) {
      log.error('Failed to save file:', error);
      dialog.showErrorBox('Save Error', `Failed to save file:\n${error.message}`);
    }
  }
}

async function openBatchDialog() {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select Files for Batch Processing',
    filters: [
      { name: 'Executable Files', extensions: ['exe', 'dll'] },
      { name: 'All Files', extensions: ['*'] }
    ],
    properties: ['openFile', 'multiSelections']
  });

  if (!result.canceled && result.filePaths.length > 0) {
    mainWindow.webContents.send('batch-files-selected', result.filePaths);
  }
}

async function applyLAA() {
  if (!pePatcher) {
    dialog.showErrorBox('Error', 'No file loaded');
    return;
  }

  try {
    await pePatcher.applyLAA();
    log.info('LAA applied successfully');
    mainWindow.webContents.send('patch-applied', { type: 'LAA' });

    await loadPEFile(currentFile);
  } catch (error) {
    log.error('Failed to apply LAA:', error);
    dialog.showErrorBox('Patch Error', `Failed to apply LAA:\n${error.message}`);
  }
}

async function toggleASLR() {
  if (!pePatcher) {
    dialog.showErrorBox('Error', 'No file loaded');
    return;
  }

  try {
    await pePatcher.toggleASLR();
    log.info('ASLR toggled successfully');
    mainWindow.webContents.send('patch-applied', { type: 'ASLR' });

    await loadPEFile(currentFile);
  } catch (error) {
    log.error('Failed to toggle ASLR:', error);
    dialog.showErrorBox('Patch Error', `Failed to toggle ASLR:\n${error.message}`);
  }
}

async function toggleDEP() {
  if (!pePatcher) {
    dialog.showErrorBox('Error', 'No file loaded');
    return;
  }

  try {
    await pePatcher.toggleDEP();
    log.info('DEP toggled successfully');
    mainWindow.webContents.send('patch-applied', { type: 'DEP' });

    await loadPEFile(currentFile);
  } catch (error) {
    log.error('Failed to toggle DEP:', error);
    dialog.showErrorBox('Patch Error', `Failed to toggle DEP:\n${error.message}`);
  }
}

async function toggleCFG() {
  if (!pePatcher) {
    dialog.showErrorBox('Error', 'No file loaded');
    return;
  }

  try {
    await pePatcher.toggleCFG();
    log.info('CFG toggled successfully');
    mainWindow.webContents.send('patch-applied', { type: 'CFG' });

    await loadPEFile(currentFile);
  } catch (error) {
    log.error('Failed to toggle CFG:', error);
    dialog.showErrorBox('Patch Error', `Failed to toggle CFG:\n${error.message}`);
  }
}

async function showHexDiff() {
  if (!currentFile) {
    dialog.showErrorBox('Error', 'No file loaded');
    return;
  }

  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select File to Compare',
    filters: [
      { name: 'Executable Files', extensions: ['exe', 'dll'] },
      { name: 'All Files', extensions: ['*'] }
    ],
    properties: ['openFile']
  });

  if (!result.canceled && result.filePaths.length > 0) {
    try {
      const parser1 = new PEParser(currentFile);
      const parser2 = new PEParser(result.filePaths[0]);

      const data1 = await parser1.parse();
      const data2 = await parser2.parse();

      mainWindow.webContents.send('hex-diff', {
        file1: { path: currentFile, data: data1 },
        file2: { path: result.filePaths[0], data: data2 }
      });

      log.info('Hex diff displayed');
    } catch (error) {
      log.error('Failed to show hex diff:', error);
      dialog.showErrorBox('Error', `Failed to compare files:\n${error.message}`);
    }
  }
}

function showAbout() {
  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'About PE Editor',
    message: 'PE Editor v1.0.0',
    detail: 'Advanced PE Editor for Windows Executables\n\nFeatures:\n- PE parsing (DOS, COFF, Optional headers)\n- Section management\n- Import/Export tables\n- LAA, ASLR, DEP, CFG patching\n- Hex diff\n- Batch processing\n- System tray support'
  });
}

// IPC Handlers
ipcMain.handle('open-file', async () => {
  await openFileDialog();
});

ipcMain.handle('save-file', async () => {
  await saveFile();
});

ipcMain.handle('save-file-as', async () => {
  await saveFileAs();
});

ipcMain.handle('load-file', async (event, filePath) => {
  await loadPEFile(filePath);
});

ipcMain.handle('apply-laa', async () => {
  await applyLAA();
});

ipcMain.handle('toggle-aslr', async () => {
  await toggleASLR();
});

ipcMain.handle('toggle-dep', async () => {
  await toggleDEP();
});

ipcMain.handle('toggle-cfg', async () => {
  await toggleCFG();
});

ipcMain.handle('show-hex-diff', async () => {
  await showHexDiff();
});

ipcMain.handle('batch-process', async (event, { files, options }) => {
  try {
    batchProcessor = new BatchProcessor(files, options);
    const results = await batchProcessor.process();

    mainWindow.webContents.send('batch-complete', results);

    return results;
  } catch (error) {
    log.error('Batch processing failed:', error);
    throw error;
  }
});

ipcMain.handle('get-file-info', async (event, filePath) => {
  try {
    const stats = fs.statSync(filePath);
    return {
      size: stats.size,
      created: stats.birthtime,
      modified: stats.mtime
    };
  } catch (error) {
    log.error('Failed to get file info:', error);
    throw error;
  }
});

ipcMain.handle('read-hex', async (event, { filePath, offset, length }) => {
  try {
    const parser = new PEParser(filePath);
    return await parser.readHex(offset, length);
  } catch (error) {
    log.error('Failed to read hex:', error);
    throw error;
  }
});

ipcMain.handle('export-report', async (event, { data, format }) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Report',
    defaultPath: 'pe-report.txt',
    filters: [
      { name: 'Text Files', extensions: ['txt'] },
      { name: 'JSON Files', extensions: ['json'] }
    ]
  });

  if (!result.canceled && result.filePath) {
    try {
      if (format === 'json') {
        fs.writeFileSync(result.filePath, JSON.stringify(data, null, 2));
      } else {
        fs.writeFileSync(result.filePath, data);
      }
      log.info(`Report exported to: ${result.filePath}`);
    } catch (error) {
      log.error('Failed to export report:', error);
      throw error;
    }
  }
});

// App lifecycle
app.whenReady().then(() => {
  log.info('App starting');
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    if (!tray) {
      app.quit();
    }
  }
});

app.on('before-quit', () => {
  log.info('App quitting');
  tray = null;
});

log.info('Main process initialized');
