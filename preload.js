const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods to the renderer process
contextBridge.exposeInMainWorld('peEditor', {
  // File operations
  openFile: () => ipcRenderer.invoke('open-file'),
  saveFile: () => ipcRenderer.invoke('save-file'),
  saveFileAs: () => ipcRenderer.invoke('save-file-as'),
  loadFile: (filePath) => ipcRenderer.invoke('load-file', filePath),
  getFileInfo: (filePath) => ipcRenderer.invoke('get-file-info', filePath),

  // Patching operations
  applyLAA: () => ipcRenderer.invoke('apply-laa'),
  toggleASLR: () => ipcRenderer.invoke('toggle-aslr'),
  toggleDEP: () => ipcRenderer.invoke('toggle-dep'),
  toggleCFG: () => ipcRenderer.invoke('toggle-cfg'),

  // Analysis
  showHexDiff: () => ipcRenderer.invoke('show-hex-diff'),
  readHex: (filePath, offset, length) => ipcRenderer.invoke('read-hex', { filePath, offset, length }),

  // Batch processing
  batchProcess: (files, options) => ipcRenderer.invoke('batch-process', { files, options }),

  // Export
  exportReport: (data, format) => ipcRenderer.invoke('export-report', { data, format }),

  // Event listeners
  onFileLoaded: (callback) => {
    ipcRenderer.on('file-loaded', (event, data) => callback(data));
  },
  onFileSaved: (callback) => {
    ipcRenderer.on('file-saved', (event, data) => callback(data));
  },
  onPatchApplied: (callback) => {
    ipcRenderer.on('patch-applied', (event, data) => callback(data));
  },
  onBatchFilesSelected: (callback) => {
    ipcRenderer.on('batch-files-selected', (event, files) => callback(files));
  },
  onBatchComplete: (callback) => {
    ipcRenderer.on('batch-complete', (event, results) => callback(results));
  },
  onHexDiff: (callback) => {
    ipcRenderer.on('hex-diff', (event, data) => callback(data));
  },

  // Remove listeners
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});

// Log that preload is loaded
console.log('Preload script loaded');
