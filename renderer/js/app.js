// PE Editor - Renderer Process

// State
let currentPEData = null;
let currentFilePath = null;
let batchFiles = [];

// DOM Elements
const elements = {
  // Buttons
  btnOpen: document.getElementById('btn-open'),
  btnSave: document.getElementById('btn-save'),
  btnSaveAs: document.getElementById('btn-save-as'),
  btnLAA: document.getElementById('btn-laa'),
  btnASLR: document.getElementById('btn-aslr'),
  btnDEP: document.getElementById('btn-dep'),
  btnCFG: document.getElementById('btn-cfg'),
  btnHexDiff: document.getElementById('btn-hex-diff'),
  btnBatch: document.getElementById('btn-batch'),
  btnExport: document.getElementById('btn-export'),
  btnWelcomeOpen: document.getElementById('btn-welcome-open'),

  // Panels
  welcomeScreen: document.getElementById('welcome-screen'),
  peInfoPanel: document.getElementById('pe-info-panel'),

  // Status
  statusText: document.getElementById('status-text'),
  currentFilePath: document.getElementById('current-file-path'),

  // Security Flags
  flagLAA: document.getElementById('flag-laa'),
  flagASLR: document.getElementById('flag-aslr'),
  flagDEP: document.getElementById('flag-dep'),
  flagCFG: document.getElementById('flag-cfg'),

  // Modals
  batchModal: document.getElementById('batch-modal'),
  hexDiffModal: document.getElementById('hex-diff-modal'),

  // Loading
  loadingOverlay: document.getElementById('loading-overlay'),
  loadingText: document.getElementById('loading-text')
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  console.log('PE Editor initialized');
  setupEventListeners();
  setupIPCListeners();
});

function setupEventListeners() {
  // File operations
  elements.btnOpen.addEventListener('click', () => window.peEditor.openFile());
  elements.btnSave.addEventListener('click', () => window.peEditor.saveFile());
  elements.btnSaveAs.addEventListener('click', () => window.peEditor.saveFileAs());
  elements.btnWelcomeOpen.addEventListener('click', () => window.peEditor.openFile());

  // Patching operations
  elements.btnLAA.addEventListener('click', () => window.peEditor.applyLAA());
  elements.btnASLR.addEventListener('click', () => window.peEditor.toggleASLR());
  elements.btnDEP.addEventListener('click', () => window.peEditor.toggleDEP());
  elements.btnCFG.addEventListener('click', () => window.peEditor.toggleCFG());
  elements.btnHexDiff.addEventListener('click', () => window.peEditor.showHexDiff());

  // Batch operations
  elements.btnBatch.addEventListener('click', () => showBatchModal());
  document.getElementById('batch-modal-close').addEventListener('click', () => hideBatchModal());
  document.getElementById('batch-cancel').addEventListener('click', () => hideBatchModal());
  document.getElementById('batch-start').addEventListener('click', () => startBatchProcessing());

  // Hex diff modal
  document.getElementById('hex-modal-close').addEventListener('click', () => hideHexDiffModal());

  // Export
  elements.btnExport.addEventListener('click', () => exportReport());

  // Tab navigation
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
}

function setupIPCListeners() {
  // File loaded
  window.peEditor.onFileLoaded((data) => {
    console.log('File loaded:', data.path);
    currentPEData = data.data;
    currentFilePath = data.path;

    displayPEInfo(data.data);
    updateSecurityFlags(data.data);
    enableControls(true);

    elements.welcomeScreen.classList.add('hidden');
    elements.peInfoPanel.classList.remove('hidden');

    elements.currentFilePath.textContent = data.path;
    setStatus('File loaded successfully');
  });

  // File saved
  window.peEditor.onFileSaved((data) => {
    setStatus(`File saved: ${data.path}`);
  });

  // Patch applied
  window.peEditor.onPatchApplied((data) => {
    setStatus(`${data.type} patch applied successfully`);
  });

  // Batch files selected
  window.peEditor.onBatchFilesSelected((files) => {
    batchFiles = files;
    displayBatchFiles(files);
    showBatchModal();
  });

  // Batch complete
  window.peEditor.onBatchComplete((results) => {
    displayBatchResults(results);
  });

  // Hex diff
  window.peEditor.onHexDiff((data) => {
    displayHexDiff(data);
  });
}

// Display Functions
function displayPEInfo(data) {
  // File Info
  const fileInfo = document.getElementById('file-info');
  fileInfo.innerHTML = `
        <div class="info-item">
            <span class="info-label">File Name</span>
            <span class="info-value">${data.fileName}</span>
        </div>
        <div class="info-item">
            <span class="info-label">File Size</span>
            <span class="info-value">${formatBytes(data.fileSize)}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Machine</span>
            <span class="info-value">${getMachineType(data.coffHeader.Machine)}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Subsystem</span>
            <span class="info-value">${getSubsystemType(data.optionalHeader.Subsystem)}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Entry Point</span>
            <span class="info-value">0x${data.optionalHeader.AddressOfEntryPoint.toString(16).toUpperCase()}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Image Base</span>
            <span class="info-value">0x${data.optionalHeader.ImageBase.toString(16).toUpperCase()}</span>
        </div>
        <div class="info-item">
            <span class="info-label">PE Format</span>
            <span class="info-value">${data.optionalHeader.magic}</span>
        </div>
        <div class="info-item">
            <span class="info-label">Sections</span>
            <span class="info-value">${data.sections.length}</span>
        </div>
    `;

  // DOS Header
  const dosHeaderTable = document.getElementById('dos-header-table');
  dosHeaderTable.innerHTML = createKeyValueTable(data.dosHeader, [
    'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr',
    'e_minalloc', 'e_maxalloc', 'e_ss', 'e_sp', 'e_csum',
    'e_ip', 'e_cs', 'e_lfarlc', 'e_lfanew'
  ]);

  // COFF Header
  const coffHeaderTable = document.getElementById('coff-header-table');
  const coffDisplay = {
    Machine: data.coffHeader.Machine,
    NumberOfSections: data.coffHeader.NumberOfSections,
    TimeDateStamp: new Date(data.coffHeader.TimeDateStamp * 1000).toLocaleString(),
    PointerToSymbolTable: `0x${data.coffHeader.PointerToSymbolTable.toString(16)}`,
    NumberOfSymbols: data.coffHeader.NumberOfSymbols,
    SizeOfOptionalHeader: data.coffHeader.SizeOfOptionalHeader,
    Characteristics: data.characteristics.join(', ')
  };
  coffHeaderTable.innerHTML = createKeyValueTable(coffDisplay);

  // Optional Header
  const optionalHeaderTable = document.getElementById('optional-header-table');
  const optionalDisplay = {
    Magic: `0x${data.optionalHeader.Magic.toString(16)} (${data.optionalHeader.magic})`,
    MajorLinkerVersion: `${data.optionalHeader.MajorLinkerVersion}.${data.optionalHeader.MinorLinkerVersion}`,
    SizeOfCode: formatBytes(data.optionalHeader.SizeOfCode),
    SizeOfInitializedData: formatBytes(data.optionalHeader.SizeOfInitializedData),
    SizeOfUninitializedData: formatBytes(data.optionalHeader.SizeOfUninitializedData),
    AddressOfEntryPoint: `0x${data.optionalHeader.AddressOfEntryPoint.toString(16)}`,
    BaseOfCode: `0x${data.optionalHeader.BaseOfCode.toString(16)}`,
    ImageBase: `0x${data.optionalHeader.ImageBase.toString(16)}`,
    SectionAlignment: formatBytes(data.optionalHeader.SectionAlignment),
    FileAlignment: formatBytes(data.optionalHeader.FileAlignment),
    SizeOfImage: formatBytes(data.optionalHeader.SizeOfImage),
    SizeOfHeaders: formatBytes(data.optionalHeader.SizeOfHeaders),
    CheckSum: `0x${data.optionalHeader.CheckSum.toString(16)}`,
    Subsystem: getSubsystemType(data.optionalHeader.Subsystem),
    DllCharacteristics: data.dllCharacteristics.join(', ')
  };
  optionalHeaderTable.innerHTML = createKeyValueTable(optionalDisplay);

  // Sections
  const sectionsTbody = document.getElementById('sections-tbody');
  sectionsTbody.innerHTML = '';
  data.sections.forEach(section => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
            <td>${section.Name}</td>
            <td>0x${section.VirtualSize.toString(16).toUpperCase()}</td>
            <td>0x${section.VirtualAddress.toString(16).toUpperCase()}</td>
            <td>0x${section.SizeOfRawData.toString(16).toUpperCase()}</td>
            <td>0x${section.PointerToRawData.toString(16).toUpperCase()}</td>
            <td>${section.characteristics.map(c => `<span class="char-tag">${c}</span>`).join('')}</td>
        `;
    sectionsTbody.appendChild(tr);
  });

  // Imports
  const importsContainer = document.getElementById('imports-container');
  if (data.imports && data.imports.length > 0) {
    importsContainer.innerHTML = '';
    data.imports.forEach(imp => {
      const dllDiv = document.createElement('div');
      dllDiv.className = 'import-dll';
      dllDiv.innerHTML = `
                <div class="import-dll-header">
                    <span class="import-dll-name">${imp.dllName}</span>
                    <span>${imp.functions.length} functions</span>
                </div>
                <div class="import-functions">
                    ${imp.functions.slice(0, 50).map(f => `
                        <div class="import-function">
                            ${f.type === 'ordinal' ? `[${f.ordinal}]` : `${f.name} (hint: ${f.hint})`}
                        </div>
                    `).join('')}
                    ${imp.functions.length > 50 ? `<div class="import-function">... and ${imp.functions.length - 50} more</div>` : ''}
                </div>
            `;
      importsContainer.appendChild(dllDiv);
    });
  } else {
    importsContainer.innerHTML = '<p>No imports found</p>';
  }

  // Exports
  const exportsContainer = document.getElementById('exports-container');
  if (data.exports && data.exports.functions.length > 0) {
    exportsContainer.innerHTML = `
            <div class="exports-info">
                <div class="info-item">
                    <span class="info-label">DLL Name</span>
                    <span class="info-value">${data.exports.dllName}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Timestamp</span>
                    <span class="info-value">${new Date(data.exports.timestamp * 1000).toLocaleString()}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Ordinal Base</span>
                    <span class="info-value">${data.exports.ordinalBase}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Total Functions</span>
                    <span class="info-value">${data.exports.functions.length}</span>
                </div>
            </div>
            <div class="exports-list">
                ${data.exports.functions.map(f => `
                    <div class="export-function">
                        <span class="export-ordinal">Ordinal: ${f.ordinal}</span>
                        <span class="export-name">${f.name || '(unnamed)'}</span>
                    </div>
                `).join('')}
            </div>
        `;
  } else {
    exportsContainer.innerHTML = '<p>No exports found</p>';
  }

  // Data Directories
  const directoriesTbody = document.getElementById('directories-tbody');
  directoriesTbody.innerHTML = '';
  data.dataDirectories.forEach(dir => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
            <td>${dir.index}</td>
            <td>${dir.name}</td>
            <td>0x${dir.VirtualAddress.toString(16).toUpperCase()}</td>
            <td>0x${dir.Size.toString(16).toUpperCase()}</td>
        `;
    directoriesTbody.appendChild(tr);
  });
}

function updateSecurityFlags(data) {
  const laaEnabled = data.characteristics.includes('LARGE_ADDRESS_AWARE');
  const aslrEnabled = data.dllCharacteristics.includes('DYNAMIC_BASE');
  const depEnabled = data.dllCharacteristics.includes('NX_COMPAT');
  const cfgEnabled = data.dllCharacteristics.includes('GUARD_CF');

  updateFlagStatus(elements.flagLAA, laaEnabled);
  updateFlagStatus(elements.flagASLR, aslrEnabled);
  updateFlagStatus(elements.flagDEP, depEnabled);
  updateFlagStatus(elements.flagCFG, cfgEnabled);
}

function updateFlagStatus(element, enabled) {
  element.textContent = enabled ? 'ON' : 'OFF';
  element.className = 'flag-status ' + (enabled ? 'enabled' : 'disabled');
}

// Helper Functions
function createKeyValueTable(obj, keys = null) {
  const rows = keys || Object.keys(obj);
  return rows.map(key => {
    if (obj[key] === undefined || obj[key] === null) return '';
    return `
            <tr>
                <th>${key}</th>
                <td>${obj[key]}</td>
            </tr>
        `;
  }).join('');
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getMachineType(machine) {
  const types = {
    0x014c: 'i386',
    0x8664: 'AMD64',
    0x01c0: 'ARM',
    0xaa64: 'ARM64',
    0x0200: 'IA64'
  };
  return types[machine] || `Unknown (0x${machine.toString(16)})`;
}

function getSubsystemType(subsystem) {
  const types = {
    1: 'Native',
    2: 'Windows GUI',
    3: 'Windows CUI',
    5: 'OS/2 CUI',
    7: 'POSIX CUI',
    9: 'Windows CE GUI',
    10: 'EFI Application',
    11: 'EFI Boot Service Driver',
    12: 'EFI Runtime Driver',
    13: 'EFI ROM',
    14: 'XBOX',
    16: 'Windows Boot Application'
  };
  return types[subsystem] || `Unknown (${subsystem})`;
}

function enableControls(enabled) {
  elements.btnSave.disabled = !enabled;
  elements.btnSaveAs.disabled = !enabled;
  elements.btnLAA.disabled = !enabled;
  elements.btnASLR.disabled = !enabled;
  elements.btnDEP.disabled = !enabled;
  elements.btnCFG.disabled = !enabled;
  elements.btnHexDiff.disabled = !enabled;
  elements.btnExport.disabled = !enabled;
}

function setStatus(text) {
  elements.statusText.textContent = text;
  console.log('Status:', text);
}

function showLoading(text = 'Loading...') {
  elements.loadingText.textContent = text;
  elements.loadingOverlay.classList.remove('hidden');
}

function hideLoading() {
  elements.loadingOverlay.classList.add('hidden');
}

// Tab Navigation
function switchTab(tabName) {
  // Update buttons
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });

  // Update panes
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabName}`);
  });
}

// Batch Modal
function showBatchModal() {
  elements.batchModal.classList.remove('hidden');
  if (batchFiles.length > 0) {
    displayBatchFiles(batchFiles);
  }
}

function hideBatchModal() {
  elements.batchModal.classList.add('hidden');
  // Reset
  batchFiles = [];
  document.getElementById('batch-file-list').innerHTML = '';
  document.getElementById('batch-progress').classList.add('hidden');
  document.getElementById('batch-results').classList.add('hidden');
  document.getElementById('batch-start').disabled = false;
}

function displayBatchFiles(files) {
  const list = document.getElementById('batch-file-list');
  list.innerHTML = files.map(f => `<li>${f}</li>`).join('');
}

async function startBatchProcessing() {
  const options = {
    applyLAA: document.getElementById('batch-laa').checked,
    toggleASLR: document.getElementById('batch-aslr').checked ? true : null,
    toggleDEP: document.getElementById('batch-dep').checked ? true : null,
    toggleCFG: document.getElementById('batch-cfg').checked ? true : null,
    removeSecurity: document.getElementById('batch-remove-security').checked,
    createBackup: document.getElementById('batch-backup').checked
  };

  document.getElementById('batch-start').disabled = true;
  document.getElementById('batch-progress').classList.remove('hidden');

  try {
    const results = await window.peEditor.batchProcess(batchFiles, options);
    displayBatchResults(results);
  } catch (error) {
    console.error('Batch processing error:', error);
    setStatus(`Batch processing failed: ${error.message}`);
  }
}

function displayBatchResults(results) {
  const progressFill = document.getElementById('batch-progress-fill');
  const progressText = document.getElementById('batch-progress-text');

  progressFill.style.width = '100%';
  progressText.textContent = 'Complete!';

  const summary = document.getElementById('batch-results-summary');
  summary.innerHTML = `
        <p><strong>Total:</strong> ${results.total}</p>
        <p><strong>Success:</strong> ${results.success}</p>
        <p><strong>Failed:</strong> ${results.failed}</p>
    `;

  document.getElementById('batch-results').classList.remove('hidden');
  setStatus(`Batch processing complete: ${results.success} succeeded, ${results.failed} failed`);
}

// Hex Diff
function showHexDiffModal() {
  elements.hexDiffModal.classList.remove('hidden');
}

function hideHexDiffModal() {
  elements.hexDiffModal.classList.add('hidden');
}

function displayHexDiff(data) {
  showHexDiffModal();

  const container = document.getElementById('hex-diff-container');
  container.innerHTML = `
        <div class="hex-file">
            <div class="hex-file-header">${data.file1.path}</div>
            <div class="hex-content">
                ${generateHexDump(data.file1.data)}
            </div>
        </div>
        <div class="hex-file">
            <div class="hex-file-header">${data.file2.path}</div>
            <div class="hex-content">
                ${generateHexDump(data.file2.data)}
            </div>
        </div>
    `;
}

function generateHexDump(data) {
  // Simplified hex dump
  let html = '';

  // DOS Header
  html += `<div class="hex-line"><span class="hex-offset">00000000</span><span class="hex-bytes">4D 5A</span><span class="hex-ascii">MZ</span></div>`;

  // Show key differences in headers
  if (data.coffHeader.Machine !== data.coffHeader.Machine) {
    html += `<div class="hex-line"><span class="hex-offset">PE+0004</span><span class="hex-bytes">Machine: ${data.coffHeader.Machine}</span></div>`;
  }

  return html;
}

// Export Report
async function exportReport() {
  if (!currentPEData) return;

  const report = generateReport(currentPEData);
  await window.peEditor.exportReport(report, 'txt');
}

function generateReport(data) {
  let report = 'PE Editor Analysis Report\n';
  report += '='.repeat(50) + '\n\n';

  report += 'File Information:\n';
  report += '-'.repeat(30) + '\n';
  report += `File: ${data.fileName}\n`;
  report += `Size: ${formatBytes(data.fileSize)}\n`;
  report += `Machine: ${getMachineType(data.coffHeader.Machine)}\n`;
  report += `Subsystem: ${getSubsystemType(data.optionalHeader.Subsystem)}\n\n`;

  report += 'Headers:\n';
  report += '-'.repeat(30) + '\n';
  report += `Entry Point: 0x${data.optionalHeader.AddressOfEntryPoint.toString(16)}\n`;
  report += `Image Base: 0x${data.optionalHeader.ImageBase.toString(16)}\n`;
  report += `PE Format: ${data.optionalHeader.magic}\n\n`;

  report += 'Security Flags:\n';
  report += '-'.repeat(30) + '\n';
  report += `LAA: ${data.characteristics.includes('LARGE_ADDRESS_AWARE') ? 'Enabled' : 'Disabled'}\n`;
  report += `ASLR: ${data.dllCharacteristics.includes('DYNAMIC_BASE') ? 'Enabled' : 'Disabled'}\n`;
  report += `DEP: ${data.dllCharacteristics.includes('NX_COMPAT') ? 'Enabled' : 'Disabled'}\n`;
  report += `CFG: ${data.dllCharacteristics.includes('GUARD_CF') ? 'Enabled' : 'Disabled'}\n\n`;

  report += 'Sections:\n';
  report += '-'.repeat(30) + '\n';
  data.sections.forEach(s => {
    report += `${s.Name.padEnd(8)} VirtSize: 0x${s.VirtualSize.toString(16).padStart(8, '0')} RawSize: 0x${s.SizeOfRawData.toString(16).padStart(8, '0')}\n`;
  });

  return report;
}

// Handle errors
window.onerror = function (message, source, lineno, colno, error) {
  console.error('Error:', message, error);
  setStatus(`Error: ${message}`);
  hideLoading();
};

window.onunhandledrejection = function (event) {
  console.error('Unhandled rejection:', event.reason);
  setStatus(`Error: ${event.reason}`);
  hideLoading();
};
