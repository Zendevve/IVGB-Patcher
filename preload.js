const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('peAPI', {
  // File operations
  openFileDialog: () => ipcRenderer.invoke('open-file-dialog'),
  openMultipleDialog: () => ipcRenderer.invoke('open-multiple-dialog'),
  loadDroppedFiles: (paths) => ipcRenderer.invoke('load-dropped-files', paths),

  // Analysis
  getAnalysis: (fileId) => ipcRenderer.invoke('get-analysis', fileId),

  // Patching
  applyPatch: (fileId, flags, recalc) => ipcRenderer.invoke('apply-patch', fileId, flags, recalc),
  resetFile: (fileId) => ipcRenderer.invoke('reset-file', fileId),
  closeFile: (fileId) => ipcRenderer.invoke('close-file', fileId),

  // Save
  saveFile: (fileId) => ipcRenderer.invoke('save-file', fileId),
  saveFileAs: (fileId) => ipcRenderer.invoke('save-file-as', fileId),

  // Hex
  getHexData: (fileId, offset, length) => ipcRenderer.invoke('get-hex-data', fileId, offset, length),
  getDiff: (fileId) => ipcRenderer.invoke('get-diff', fileId),

  // Batch
  openBatchDirectoryDialog: () => ipcRenderer.invoke('open-batch-directory-dialog'),
  batchScan: (dir, recursive) => ipcRenderer.invoke('batch-scan', dir, recursive),
  batchPatch: (files, flags, options) => ipcRenderer.invoke('batch-patch', files, flags, options),

  // Util
  revealInExplorer: (fp) => ipcRenderer.invoke('reveal-in-explorer', fp),

  // License
  getLicenseStatus: () => ipcRenderer.invoke('license-get-status'),
  activateLicense: (key) => ipcRenderer.invoke('license-activate', key),
  deactivateLicense: () => ipcRenderer.invoke('license-deactivate'),
  getMachineId: () => ipcRenderer.invoke('license-get-machine-id'),

  // Events from main
  onFilesLoaded: (cb) => ipcRenderer.on('files-loaded', (e, d) => cb(d)),
  onMenuAction: (cb) => ipcRenderer.on('menu-action', (e, a) => cb(a)),
  onBatchDirectorySelected: (cb) => ipcRenderer.on('batch-directory-selected', (e, d) => cb(d)),
});
