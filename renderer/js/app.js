const api = window.peAPI;

const state = {
  files: [],
  activeFileId: null,
  activeAnalysis: null,
  lastPatchResult: null,
  license: null,
};

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

function showLoading(t = 'Processing...') { $('#loadingText').textContent = t; $('#loadingOverlay').classList.add('active'); }
function hideLoading() { $('#loadingOverlay').classList.remove('active'); }

function toast(msg, type = 'info') {
  const c = $('#toastContainer');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span>${type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️'}</span><span>${msg}</span>`;
  c.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 300ms'; setTimeout(() => el.remove(), 300); }, 4000);
}

function fmtHex(n, pad = 8) { return n == null ? '—' : '0x' + n.toString(16).toUpperCase().padStart(pad, '0'); }

// ── License ──────────────────────────────────────────────────────────────────

async function initLicense() {
  state.license = await api.getLicenseStatus();
  renderLicenseUI();
}

function renderLicenseUI() {
  const s = state.license;
  const label = $('#licenseLabel');
  const footer = $('#footerLicense');

  if (s.licensed) {
    label.textContent = s.tierLabel;
    label.style.color = s.tierColor;
    footer.textContent = `Licensed: ${s.tierName}`;
    footer.style.color = s.tierColor;
  } else {
    label.textContent = 'Free — Non-Commercial';
    label.style.color = '#8b949e';
    footer.textContent = 'Unlicensed — Personal use only';
    footer.style.color = '#8b949e';
  }

  renderLicenseModal();
}

function renderLicenseModal() {
  const s = state.license;
  const statusArea = $('#licenseStatusArea');

  const tierIcons = { 0: '🆓', 1: '💚', 2: '💎', 3: '👑' };
  const icon = tierIcons[s.tier] || '🆓';

  statusArea.innerHTML = `
    <div class="license-status ${s.licensed ? 'active' : ''}" style="border-left-color:${s.tierColor}">
      <span class="tier-badge">${icon}</span>
      <div class="tier-info">
        <div class="tier-name" style="color:${s.tierColor}">${s.tierLabel}</div>
        <div class="tier-detail">
          ${s.licensed
      ? `Activated${s.perpetual ? ' — Perpetual' : ` — Expires ${s.expiresAt}`}`
      : 'Enter a license key below to activate'}
        </div>
        ${s.commercial
      ? '<div class="tier-detail" style="color:var(--green)">✅ Commercial use permitted</div>'
      : '<div class="tier-detail" style="color:var(--yellow)">⚠️ Non-commercial use only</div>'
    }
      </div>
    </div>
  `;

  $('#btnDeactivate').style.display = s.licensed ? '' : 'none';
}

function initLicenseUI() {
  // Open modal
  $('#btnLicense').addEventListener('click', () => {
    $('#licenseModal').classList.add('active');
    renderLicenseModal();
  });

  // Close modal
  $('#licenseModalClose').addEventListener('click', () => {
    $('#licenseModal').classList.remove('active');
  });

  $('#licenseModal').addEventListener('click', (e) => {
    if (e.target === $('#licenseModal')) $('#licenseModal').classList.remove('active');
  });

  // Activate
  $('#btnActivate').addEventListener('click', async () => {
    const key = $('#licenseKeyInput').value.trim();
    if (!key) { toast('Enter a license key', 'error'); return; }

    const result = await api.activateLicense(key);

    if (result.valid) {
      state.license = await api.getLicenseStatus();
      renderLicenseUI();
      toast(`License activated: ${result.tierLabel}`, 'success');
      $('#licenseError').style.display = 'none';
      $('#licenseKeyInput').value = '';
    } else {
      $('#licenseError').textContent = result.error;
      $('#licenseError').style.display = 'block';
      toast(result.error, 'error');
    }
  });

  // Deactivate
  $('#btnDeactivate').addEventListener('click', async () => {
    await api.deactivateLicense();
    state.license = await api.getLicenseStatus();
    renderLicenseUI();
    toast('License deactivated', 'info');
  });

  // Buy link
  $('#btnBuyLicense').addEventListener('click', (e) => {
    e.preventDefault();
    // This opens in the system browser via main process
    // For now just show a toast
    toast('Opening store page...', 'info');
  });
}

// ── Drop Zone ────────────────────────────────────────────────────────────────

function initDropZone() {
  const zone = $('#dropZone');
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', async (e) => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const paths = Array.from(e.dataTransfer.files).map(f => f.path).filter(Boolean);
    if (paths.length > 0) await loadFilesFromPaths(paths);
  });
  zone.addEventListener('click', () => api.openFileDialog());
  $('#btnOpenFile').addEventListener('click', () => api.openFileDialog());
  $('#btnOpenMultiple').addEventListener('click', () => api.openMultipleDialog());
}

async function loadFilesFromPaths(paths) {
  showLoading('Loading...');
  try {
    const results = await api.loadDroppedFiles(paths);
    processLoadedFiles(results);
  } catch (err) { toast(err.message, 'error'); }
  hideLoading();
}

function processLoadedFiles(results) {
  const ok = results.filter(r => r.status === 'ok');
  const errs = results.filter(r => r.status === 'error');
  if (errs.length > 0) toast(`${errs.length} file(s) failed`, 'error');
  if (ok.length > 0) {
    state.files = ok;
    state.activeFileId = ok[0].fileId;
    state.activeAnalysis = ok[0].analysis;
    state.lastPatchResult = null;
    renderFileList(); renderAll();
    $('#mainContent').style.display = 'block';
    toast(`Loaded ${ok.length} file(s)`, 'success');
  }
}

api.onFilesLoaded((files) => processLoadedFiles(files));

// ── File List ────────────────────────────────────────────────────────────────

function renderFileList() {
  const c = $('#fileList');
  if (state.files.length <= 1) { c.style.display = 'none'; return; }
  c.style.display = 'flex';
  c.innerHTML = state.files.map(f => {
    const s = f.analysis?.summary || {};
    return `<div class="file-list-item ${f.fileId === state.activeFileId ? 'selected' : ''}" data-fid="${f.fileId}">
      <span>${s.isDLL ? '📦' : '⚡'}</span>
      <div style="flex:1"><div class="file-name">${f.filename}</div>
      <div class="file-meta"><span>${s.format || '?'}</span><span>${f.analysis?.file?.sizeFormatted || ''}</span></div></div>
      <div class="file-flags">
        ${s.isLAA ? '<span class="status status-enabled">LAA</span>' : ''}
        ${s.isASLR ? '<span class="status status-enabled">ASLR</span>' : ''}
        ${s.isDEP ? '<span class="status status-enabled">DEP</span>' : ''}
        ${s.isCFG ? '<span class="status status-enabled">CFG</span>' : ''}
      </div></div>`;
  }).join('');
  c.querySelectorAll('.file-list-item').forEach(el => {
    el.addEventListener('click', async () => {
      const f = state.files.find(x => x.fileId === el.dataset.fid);
      if (!f) return;
      state.activeFileId = f.fileId; state.lastPatchResult = null;
      showLoading('Loading...');
      try { state.activeAnalysis = await api.getAnalysis(f.fileId); f.analysis = state.activeAnalysis; } catch (e) { toast(e.message, 'error'); }
      hideLoading(); renderFileList(); renderAll();
    });
  });
}

// ── Tabs ─────────────────────────────────────────────────────────────────────

function initTabs() { $$('.tab').forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab))); }
function switchTab(name) {
  $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  $$('.tab-content').forEach(tc => tc.classList.toggle('active', tc.id === `tab-${name}`));
}

api.onMenuAction((action) => {
  if (action === 'save') $('#btnSave')?.click();
  else if (action === 'save-as') $('#btnSaveAs')?.click();
  else if (action === 'apply') $('#btnApply')?.click();
  else if (action === 'reset') $('#btnReset')?.click();
  else if (action === 'show-license') { $('#licenseModal').classList.add('active'); renderLicenseModal(); }
  else if (action === 'deactivate-license') $('#btnDeactivate')?.click();
  else if (action.startsWith('tab-')) switchTab(action.slice(4));
});

api.onBatchDirectorySelected((dir) => { switchTab('batch'); $('#batchDir').value = dir; $('#btnBatchScan').click(); });

// ── Render ───────────────────────────────────────────────────────────────────

function renderAll() {
  const a = state.activeAnalysis; if (!a) return;
  renderOverview(a); renderFlags(a); renderSections(a); renderImports(a);
  renderExports(a); renderDataDirectories(a); renderHexDiff();
}

function renderOverview(a) {
  const s = a.summary, oh = a.optionalHeader;
  $('#summaryGrid').innerHTML = [
    { l: 'Format', v: s.format }, { l: 'Machine', v: s.machine }, { l: 'Subsystem', v: s.subsystem },
    { l: 'Type', v: s.isDLL ? 'DLL' : 'Executable' }, { l: 'Entry Point', v: s.entryPoint },
    { l: 'Image Base', v: s.imageBase }, { l: 'Size', v: a.file.sizeFormatted }, { l: 'Sections', v: s.sectionCount },
    { l: 'Imports', v: `${s.importCount} DLLs, ${s.totalImportedFunctions} funcs` },
    { l: 'Exports', v: s.exportCount }, { l: 'Linker', v: oh.LinkerVersion }, { l: 'Checksum', v: fmtHex(oh.CheckSum) },
    { l: '.NET', v: s.isDotNet ? 'Yes' : 'No' }, { l: 'Path', v: a.file.path || 'N/A' },
  ].map(i => `<div class="summary-item"><div class="label">${i.l}</div><div class="value">${i.v}</div></div>`).join('');

  $('#securityGrid').innerHTML = [
    { l: 'Large Address Aware', k: 'isLAA' }, { l: 'ASLR', k: 'isASLR' }, { l: 'DEP/NX', k: 'isDEP' },
    { l: 'CFG', k: 'isCFG' }, { l: 'High Entropy VA', k: 'isHighEntropyVA' },
  ].map(f => `<div class="summary-item"><div class="label">${f.l}</div><div class="value">
    <span class="status ${s[f.k] ? 'status-enabled' : 'status-disabled'}">${s[f.k] ? 'ENABLED' : 'DISABLED'}</span></div></div>`).join('');

  $('#hashGrid').innerHTML = [
    { l: 'MD5', v: a.file.md5 }, { l: 'SHA-1', v: a.file.sha1 }, { l: 'SHA-256', v: a.file.sha256 },
  ].map(h => `<div class="summary-item" style="grid-column:span 2"><div class="label">${h.l}</div><div class="value" style="font-size:0.78rem">${h.v}</div></div>`).join('');

  $('#coffCharsDisplay').innerHTML = a.coffHeader.CharacteristicsFlags.map(f =>
    `<div class="change-item"><span class="change-offset">${f.bitHex}</span>
    <span style="color:${f.enabled ? 'var(--green)' : 'var(--text-muted)'};font-weight:600">${f.enabled ? '●' : '○'}</span>
    <span style="color:var(--accent)">${f.name}</span><span class="change-desc">${f.description}</span></div>`).join('');
}

function renderFlags(a) {
  $('#coffFlags').innerHTML = a.coffHeader.CharacteristicsFlags.filter(f => f.name === 'LARGE_ADDRESS_AWARE').map(f =>
    `<div class="flag-item"><label class="toggle"><input type="checkbox" data-flag-name="laa" ${f.enabled ? 'checked' : ''}>
    <span class="slider"></span></label><div><div class="flag-name">${f.name}</div>
    <div class="flag-desc">${f.description}</div><div class="flag-bit">${f.bitHex}</div></div></div>`).join('');

  const dm = {
    'HIGH_ENTROPY_VA': 'highEntropyVA', 'DYNAMIC_BASE': 'aslr', 'FORCE_INTEGRITY': 'forceIntegrity',
    'NX_COMPAT': 'dep', 'NO_SEH': 'noSEH', 'GUARD_CF': 'cfg', 'APPCONTAINER': 'appContainer', 'TERMINAL_SERVER_AWARE': 'terminalServerAware'
  };
  $('#dllFlags').innerHTML = a.optionalHeader.DllCharacteristicsFlags.filter(f => dm[f.name]).map(f =>
    `<div class="flag-item"><label class="toggle"><input type="checkbox" data-flag-name="${dm[f.name]}" ${f.enabled ? 'checked' : ''}>
    <span class="slider"></span></label><div><div class="flag-name">${f.name}</div>
    <div class="flag-desc">${f.description}</div><div class="flag-bit">${f.bitHex}</div></div></div>`).join('');
}

function renderSections(a) {
  $('#sectionCount').textContent = `${a.sections.length} sections`;
  $('#sectionsBody').innerHTML = a.sections.map(s => {
    const pct = (s.Entropy / 8 * 100).toFixed(0);
    const ec = s.Entropy < 3 ? 'entropy-low' : s.Entropy < 6.5 ? 'entropy-medium' : 'entropy-high';
    const ph = s.Permissions.split('').map(c => c === 'R' ? '<span class="r">R</span>' : c === 'W' ? '<span class="w">W</span>' : c === 'X' ? '<span class="x">X</span>' : c).join('');
    return `<tr><td>${s.index}</td><td class="cell-name">${s.name || '—'}</td>
      <td class="cell-hex">${fmtHex(s.VirtualSize)}</td><td class="cell-rva">${fmtHex(s.VirtualAddress)}</td>
      <td class="cell-hex">${fmtHex(s.SizeOfRawData)}</td><td class="cell-hex">${fmtHex(s.PointerToRawData)}</td>
      <td class="cell-perms">${ph}</td>
      <td><div class="entropy-bar"><div class="entropy-bar-fill ${ec}" style="width:${pct}%"></div></div>${s.Entropy}</td>
      <td style="font-size:0.68rem;color:var(--text-muted);max-width:180px;word-break:break-word">${s.CharacteristicsFlags.slice(0, 4).join(', ')}</td></tr>`;
  }).join('');
}

function renderImports(a) {
  const imps = a.imports || [];
  const total = imps.reduce((s, i) => s + i.functionCount, 0);
  $('#importCount').textContent = `${imps.length} DLLs, ${total} functions`;
  if (!imps.length) { $('#importsContainer').innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:30px">No imports</p>'; return; }

  $('#importsContainer').innerHTML = imps.map((imp, i) =>
    `<div class="import-dll" data-idx="${i}"><div class="import-dll-header" data-toggle="${i}">
    <span class="arrow" id="arr-${i}">▶</span><span class="dll-name">${imp.dllName || '?'}</span>
    <span class="dll-count">${imp.functionCount}</span></div>
    <div class="import-functions" id="imp-${i}">${imp.functions.map(fn =>
      `<div class="import-func"><span class="func-hint">${fn.isOrdinal ? '' : (fn.hint ?? '')}</span>
      ${fn.isOrdinal ? `<span class="func-ordinal">Ord #${fn.ordinal}</span>` : `<span>${fn.name || '?'}</span>`}</div>`
    ).join('')}</div></div>`).join('');

  $$('[data-toggle]').forEach(el => {
    el.addEventListener('click', () => { $(`#imp-${el.dataset.toggle}`).classList.toggle('open'); $(`#arr-${el.dataset.toggle}`).classList.toggle('open'); });
  });
  $('#importSearch').oninput = (e) => {
    const q = e.target.value.toLowerCase();
    $$('.import-dll').forEach(el => {
      const imp = imps[parseInt(el.dataset.idx)];
      el.style.display = (!q || imp.dllName.toLowerCase().includes(q) || imp.functions.some(fn => fn.name && fn.name.toLowerCase().includes(q))) ? '' : 'none';
    });
  };
}

function renderExports(a) {
  const exp = a.exports;
  if (!exp?.functions?.length) { $('#exportCount').textContent = 'No exports'; $('#exportsContainer').innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:30px">No exports</p>'; return; }
  $('#exportCount').textContent = `${exp.dllName || ''} — ${exp.functions.length} functions`;
  const renderT = (fns) => `<div class="table-container"><table><thead><tr><th>Ordinal</th><th>Name</th><th>RVA</th><th>Forwarder</th></tr></thead><tbody>
    ${fns.map(fn => `<tr><td>${fn.ordinal}</td><td class="cell-name">${fn.name || '(ordinal)'}</td>
    <td class="cell-rva">${fmtHex(fn.rva)}</td><td style="color:var(--orange)">${fn.forwarder || '—'}</td></tr>`).join('')}</tbody></table></div>`;
  $('#exportsContainer').innerHTML = renderT(exp.functions);
  $('#exportSearch').oninput = (e) => {
    const q = e.target.value.toLowerCase();
    $('#exportsContainer').innerHTML = renderT(exp.functions.filter(fn => !q || (fn.name && fn.name.toLowerCase().includes(q)) || fn.ordinal.toString().includes(q)));
  };
}

function renderDataDirectories(a) {
  $('#directoriesBody').innerHTML = a.dataDirectories.map(d =>
    `<tr><td>${d.index}</td><td class="cell-name">${d.name}</td><td class="cell-rva">${d.rvaHex}</td>
    <td class="cell-hex">${d.sizeHex}</td><td><span class="status ${d.present ? 'status-enabled' : 'status-disabled'}">${d.present ? 'Present' : 'Empty'}</span></td></tr>`).join('');
}

function renderHexDiff() {
  const pr = state.lastPatchResult;
  if (!pr?.hexDiff) { $('#diffCount').textContent = 'No changes'; $('#changesContainer').innerHTML = '<p style="color:var(--text-muted)">Apply changes to see diff.</p>'; $('#hexDiffContainer').innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:30px">No changes yet.</p>'; return; }
  const d = pr.hexDiff;
  $('#diffCount').textContent = `${d.totalChangedBytes} byte(s) changed`;
  $('#changesContainer').innerHTML = d.changes.map(c => `<div class="change-item"><span class="change-offset">${c.offsetHex}</span>
    <span class="change-old">${c.oldHex}</span><span>→</span><span class="change-new">${c.newHex}</span>
    <span class="change-desc">${c.description}</span></div>`).join('');

  if (d.blocks?.length) {
    $('#hexDiffContainer').innerHTML = d.blocks.map(block => `<div class="diff-block">
      <div class="diff-block-header">Offset ${block.rows[0]?.offsetHex} — ${block.changedOffsets.length} byte(s)</div>
      ${block.rows.map(row => {
      if (!row.hasChanges) return `<div class="hex-row"><span class="hex-offset">${row.offsetHex}</span>
          <span class="hex-bytes">${row.oldHex.map(h => `<span class="hex-byte">${h}</span>`).join('')}</span>
          <span class="hex-separator">│</span><span class="hex-ascii">${row.oldAscii}</span></div>`;
      return `<div class="hex-row" style="background:var(--red-bg)"><span class="hex-label">OLD</span><span class="hex-offset">${row.offsetHex}</span>
          <span class="hex-bytes">${row.oldHex.map((h, i) => `<span class="hex-byte ${row.changed[i] ? 'changed-old' : ''}">${h}</span>`).join('')}</span>
          <span class="hex-separator">│</span><span class="hex-ascii">${row.oldAscii}</span></div>
          <div class="hex-row" style="background:var(--green-bg)"><span class="hex-label">NEW</span><span class="hex-offset">${row.offsetHex}</span>
          <span class="hex-bytes">${row.newHex.map((h, i) => `<span class="hex-byte ${row.changed[i] ? 'changed-new' : ''}">${h}</span>`).join('')}</span>
          <span class="hex-separator">│</span><span class="hex-ascii">${row.newAscii}</span></div>`;
    }).join('')}</div>`).join('');
  }
}

// ── Actions ──────────────────────────────────────────────────────────────────

function initActions() {
  $('#btnApply').addEventListener('click', async () => {
    if (!state.activeFileId) return;
    const flags = {}; $$('[data-flag-name]').forEach(i => { if (!i.closest('#batchFlags')) flags[i.dataset.flagName] = i.checked; });
    showLoading('Applying...');
    try {
      const r = await api.applyPatch(state.activeFileId, flags, true);
      state.activeAnalysis = r.analysis; state.lastPatchResult = r;
      const f = state.files.find(x => x.fileId === state.activeFileId); if (f) f.analysis = r.analysis;
      const changed = r.flagResults.filter(x => x.changed).length;
      if (changed > 0) { toast(`${changed} flag(s) changed`, 'success'); renderAll(); renderFileList(); switchTab('hexdiff'); }
      else toast('No changes needed', 'info');
    } catch (err) { toast(err.message, 'error'); }
    hideLoading();
  });

  $('#btnReset').addEventListener('click', async () => {
    if (!state.activeFileId) return; showLoading('Resetting...');
    try {
      state.activeAnalysis = await api.resetFile(state.activeFileId); state.lastPatchResult = null;
      const f = state.files.find(x => x.fileId === state.activeFileId); if (f) f.analysis = state.activeAnalysis;
      renderAll(); renderFileList(); toast('Reset', 'success');
    } catch (err) { toast(err.message, 'error'); } hideLoading();
  });

  $('#btnSave').addEventListener('click', async () => {
    if (!state.activeFileId) return; showLoading('Saving...');
    try { const r = await api.saveFile(state.activeFileId); toast(`Saved! Backup: ${r.backupPath}`, 'success'); }
    catch (err) { toast(err.message, 'error'); } hideLoading();
  });

  $('#btnSaveAs').addEventListener('click', async () => {
    if (!state.activeFileId) return;
    try { const r = await api.saveFileAs(state.activeFileId); if (r) toast(`Saved to ${r.savedPath}`, 'success'); }
    catch (err) { toast(err.message, 'error'); }
  });

  $('#btnReveal').addEventListener('click', () => {
    const p = state.activeAnalysis?.file?.path; if (p) api.revealInExplorer(p);
  });

  $('#btnBatchBrowse').addEventListener('click', async () => {
    const dir = await api.openBatchDirectoryDialog(); if (dir) $('#batchDir').value = dir;
  });

  $('#btnBatchScan').addEventListener('click', async () => {
    const dir = $('#batchDir').value.trim(); if (!dir) return toast('Enter directory', 'error');
    showLoading('Scanning...');
    try { const r = await api.batchScan(dir, $('#batchRecursive').checked); renderBatchResults(r); toast(`Found ${r.totalFiles} PE files`, 'success'); }
    catch (err) { toast(err.message, 'error'); } hideLoading();
  });

  $('#btnBSelectAll').addEventListener('click', () => $$('.b-chk').forEach(c => c.checked = true));
  $('#btnBSelectNone').addEventListener('click', () => $$('.b-chk').forEach(c => c.checked = false));

  $('#btnBatchPatch').addEventListener('click', async () => {
    const sel = []; $$('.b-chk:checked').forEach(c => sel.push(c.dataset.path));
    if (!sel.length) return toast('Select files', 'error');
    const flags = {}; $$('#batchFlags [data-flag-name]').forEach(i => { flags[i.dataset.flagName] = i.checked; });
    showLoading(`Patching ${sel.length} files...`);
    try {
      const r = await api.batchPatch(sel, flags, { createBackup: true, recalcChecksum: true });
      renderBatchPatchResults(r); toast(`Done: ${r.filter(x => x.status === 'patched').length} patched`, 'success');
    } catch (err) { toast(err.message, 'error'); } hideLoading();
  });
}

function renderBatchResults(r) {
  const s = r.summary;
  $('#batchResults').innerHTML = `<div class="summary-grid" style="margin-bottom:12px">
    ${[['Total', r.totalFiles], ['OK', s.ok], ['Errors', s.errors], ['LAA', s.withLAA], ['No LAA', s.withoutLAA],
    ['ASLR', s.withASLR], ['DEP', s.withDEP], ['CFG', s.withCFG], ['32-bit', s.pe32], ['64-bit', s.pe32plus]
    ].map(([l, v]) => `<div class="summary-item"><div class="label">${l}</div><div class="value">${v}</div></div>`).join('')}</div>`;

  $('#batchPatchCard').style.display = 'block';
  $('#batchFlags').innerHTML = [{ n: 'laa', l: 'LARGE_ADDRESS_AWARE', d: '4GB' }, { n: 'aslr', l: 'ASLR', d: 'Randomization' },
  { n: 'dep', l: 'DEP', d: 'NX' }, { n: 'cfg', l: 'CFG', d: 'Control Flow' }
  ].map(f => `<div class="flag-item"><label class="toggle"><input type="checkbox" data-flag-name="${f.n}" ${f.n === 'laa' ? 'checked' : ''}>
    <span class="slider"></span></label><div><div class="flag-name">${f.l}</div><div class="flag-desc">${f.d}</div></div></div>`).join('');

  const ok = r.results.filter(f => f.status === 'ok');
  $('#batchFileList').innerHTML = ok.map(f => {
    const s = f.analysis?.summary || {};
    return `<div class="batch-file-item"><label><input type="checkbox" class="b-chk" data-path="${f.path}" ${!s.isLAA ? 'checked' : ''}><span>${f.name}</span></label>
    <span style="font-size:0.72rem;color:var(--text-muted)">${s.format || '?'}</span>
    <div style="display:flex;gap:4px">${s.isLAA ? '<span class="status status-enabled">LAA</span>' : '<span class="status status-disabled">LAA</span>'}
    ${s.isASLR ? '<span class="status status-enabled">ASLR</span>' : ''}</div></div>`;
  }).join('');
}

function renderBatchPatchResults(results) {
  $('#batchPatchResults').innerHTML = `<div style="margin-top:12px"><h4 style="margin-bottom:6px">Results</h4>
    ${results.map(r => `<div class="change-item"><span style="font-family:var(--font-mono);color:var(--accent);font-size:0.8rem">${r.name}</span>
    <span class="status ${r.status === 'patched' ? 'status-enabled' : r.status === 'skipped' ? 'status-warning' : 'status-disabled'}">${r.status}</span>
    ${r.backupPath ? `<span style="color:var(--text-muted);font-size:0.72rem">${r.backupPath}</span>` : ''}
    ${r.error ? `<span style="color:var(--red);font-size:0.72rem">${r.error}</span>` : ''}</div>`).join('')}</div>`;
}

// ── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  initDropZone();
  initTabs();
  initActions();
  initLicenseUI();
  await initLicense();
});
