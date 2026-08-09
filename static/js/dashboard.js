/**
 * dashboard.js — NetScan Frontend
 * Scan launching, real-time polling, host/port rendering, Chart.js, history.
 */

'use strict';

// ── State ────────────────────────────────────────────────────────────────────
let activeScanId   = null;
let pollTimer      = null;
let currentHosts   = [];
let portChart      = null;
let serviceChart   = null;
let sortState      = { col: 'ip', dir: 'asc' };

// ── DOM refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initFooterClock();
  initCharts();
  loadStats();
  bindEvents();

  // Auto-load most recent scan hosts if any
  const firstLoad = $('btn-load-scan') ? document.querySelector('.btn-load-scan') : null;
  if (firstLoad) {
    const sid = parseInt(firstLoad.dataset.scanId);
    if (sid) loadScanHosts(sid);
  }
});

// ── Theme ─────────────────────────────────────────────────────────────────────
function initTheme() {
  const saved = localStorage.getItem('netscan-theme') || 'dark';
  applyTheme(saved);
}
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('netscan-theme', theme);
  $('icon-moon').style.display = theme === 'dark'  ? 'block' : 'none';
  $('icon-sun').style.display  = theme === 'light' ? 'block' : 'none';
}

// ── Footer clock ──────────────────────────────────────────────────────────────
function initFooterClock() {
  const el = $('footer-time');
  if (!el) return;
  const tick = () => { el.textContent = new Date().toLocaleTimeString(); };
  tick(); setInterval(tick, 1000);
}

// ── Events ────────────────────────────────────────────────────────────────────
function bindEvents() {
  $('btn-theme-toggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme');
    applyTheme(cur === 'dark' ? 'light' : 'dark');
  });

  $('btn-start-scan').addEventListener('click', startScan);
  $('input-subnet').addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

  $('btn-demo').addEventListener('click', loadDemoData);
  $('btn-refresh-history').addEventListener('click', refreshHistory);
  $('btn-close-panel').addEventListener('click', closePortPanel);
  $('port-panel-overlay').addEventListener('click', closePortPanel);
  $('btn-lookup-cve').addEventListener('click', lookupCVEs);

  $('host-search').addEventListener('input', renderHostTable);
  $('risk-filter').addEventListener('change', renderHostTable);

  // Sortable headers
  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (sortState.col === col) sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
      else { sortState.col = col; sortState.dir = 'asc'; }
      renderHostTable();
    });
  });

  // History: load / delete (event delegation)
  $('history-tbody').addEventListener('click', e => {
    const loadBtn = e.target.closest('.btn-load-scan');
    const delBtn  = e.target.closest('.btn-delete-scan');
    if (loadBtn) loadScanHosts(parseInt(loadBtn.dataset.scanId), true);
    if (delBtn)  deleteScan(parseInt(delBtn.dataset.scanId));
  });

  // Export buttons
  $('btn-export-json').addEventListener('click', () => {
    if (activeScanId) window.location = `/api/scan/${activeScanId}/export/json`;
  });
  $('btn-export-csv').addEventListener('click', () => {
    if (activeScanId) window.location = `/api/scan/${activeScanId}/export/csv`;
  });
}

// ── Scan Start ────────────────────────────────────────────────────────────────
async function startScan() {
  const subnet   = $('input-subnet').value.trim();
  const scanType = $('select-scan-type').value;

  if (!subnet) { showAlert('Enter a target subnet e.g. 192.168.1.0/24', 'error'); return; }

  const btn = $('btn-start-scan');
  btn.disabled = true;
  $('btn-scan-text').textContent = 'Starting…';

  try {
    const res  = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subnet, scan_type: scanType }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to start scan');

    activeScanId = data.scan_id;
    $('progress-container').style.display = 'block';
    $('export-group').style.display = 'flex';
    showAlert(`Scan #${activeScanId} started on ${subnet}`, 'info');
    startPolling(activeScanId);

  } catch (err) {
    showAlert(err.message, 'error');
    btn.disabled = false;
    $('btn-scan-text').textContent = 'Start Scan';
  }
}

// ── Polling ───────────────────────────────────────────────────────────────────
function startPolling(scanId) {
  clearInterval(pollTimer);
  pollTimer = setInterval(() => pollScan(scanId), 2000);
}

async function pollScan(scanId) {
  try {
    const res  = await fetch(`/api/scan/${scanId}`);
    const scan = await res.json();
    updateProgress(scan);

    if (scan.status === 'done' || scan.status === 'error') {
      clearInterval(pollTimer);
      const btn = $('btn-start-scan');
      btn.disabled = false;
      $('btn-scan-text').textContent = 'Start Scan';

      if (scan.status === 'done') {
        showAlert(`✓ Scan complete — ${scan.hosts_up} hosts, ${scan.total_ports} ports`, 'success');
        loadScanHosts(scanId);
        loadStats();
        refreshHistory();
      } else {
        showAlert(`✗ Scan failed: ${scan.error_msg}`, 'error');
      }
    }
  } catch (e) { /* network hiccup, keep polling */ }
}

function updateProgress(scan) {
  const pct  = scan.progress || 0;
  $('progress-bar').style.width = pct + '%';
  $('progress-pct').textContent = pct + '%';

  const steps = {
    step_masscan: pct > 5,
    step_nmap:    pct > 30,
    step_parse:   pct > 75,
    step_store:   pct >= 95,
  };
  for (const [id, active] of Object.entries(steps)) {
    const el = $(id.replace('_', '-'));
    if (!el) continue;
    el.classList.toggle('active', active && scan.status === 'running');
    el.classList.toggle('done', pct === 100 && scan.status === 'done');
  }

  const labels = {
    pending: 'Initializing…',
    running: pct < 30 ? 'masscan: fast port discovery…' : pct < 75 ? 'nmap: service & OS detection…' : 'Saving results…',
    done:    'Complete!',
    error:   'Error occurred',
  };
  $('progress-label').textContent = labels[scan.status] || '';
}

// ── Load Hosts ────────────────────────────────────────────────────────────────
async function loadScanHosts(scanId, showExport = false) {
  activeScanId = scanId;
  if (showExport) $('export-group').style.display = 'flex';

  const tbody = $('host-tbody');
  tbody.innerHTML = '<tr><td colspan="8"><div class="loading-dots"><span></span><span></span><span></span></div></td></tr>';

  try {
    const res   = await fetch(`/api/scan/${scanId}/hosts`);
    const hosts = await res.json();
    currentHosts = hosts;
    renderHostTable();
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state"><p>Failed to load hosts</p></div></td></tr>`;
  }
}

// ── Render Host Table ─────────────────────────────────────────────────────────
function renderHostTable() {
  const query    = ($('host-search').value || '').toLowerCase();
  const riskFilt = $('risk-filter').value;

  let hosts = currentHosts.filter(h => {
    if (riskFilt && h.risk_level !== riskFilt) return false;
    if (!query) return true;
    return (h.ip_address + (h.hostname || '') + (h.os_name || '')).toLowerCase().includes(query);
  });

  // Sort
  hosts.sort((a, b) => {
    let va = a[sortState.col] ?? '', vb = b[sortState.col] ?? '';
    if (sortState.col === 'ip') {
      va = ipToNum(a.ip_address); vb = ipToNum(b.ip_address);
    }
    if (sortState.col === 'open_ports') { va = a.open_ports; vb = b.open_ports; }
    if (sortState.col === 'risk_level') {
      const o = { high: 2, medium: 1, low: 0 };
      va = o[a.risk_level] ?? 0; vb = o[b.risk_level] ?? 0;
    }
    const cmp = va < vb ? -1 : va > vb ? 1 : 0;
    return sortState.dir === 'asc' ? cmp : -cmp;
  });

  const tbody = $('host-tbody');
  if (!hosts.length) {
    tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state"><p>No hosts match the filter</p></div></td></tr>';
    return;
  }

  tbody.innerHTML = hosts.map(h => {
    const riskClass = `risk-${h.risk_level}`;
    const portChips = (h.ports || []).slice(0, 6).map(p =>
      `<span class="port-chip chip-${p.risk_level || 'low'}" data-host-id="${h.id}" data-port="${p.port_number}">${p.port_number}</span>`
    ).join('');
    const moreChips = (h.ports || []).length > 6 ? `<span class="port-chip">+${h.ports.length - 6}</span>` : '';
    const services  = [...new Set((h.ports || []).filter(p => p.service).map(p => p.service))].slice(0, 3).join(', ');

    return `<tr>
      <td class="mono" style="color:var(--cyan);font-weight:600">${h.ip_address}</td>
      <td class="text-muted text-small">${h.hostname || '<span style="opacity:.4">—</span>'}</td>
      <td><span class="status-badge status-${h.status}"><span class="status-dot-sm"></span>${h.status}</span></td>
      <td class="text-small">${h.os_name ? `<span title="${h.os_name} (${h.os_accuracy}%)">${truncate(h.os_name, 24)}</span>` : '<span style="opacity:.4">—</span>'}</td>
      <td>${portChips}${moreChips}</td>
      <td class="text-small text-muted">${services || '—'}</td>
      <td><span class="risk-badge ${riskClass}">${h.risk_level}</span></td>
      <td>
        <button class="btn btn-ghost btn-xs btn-view-ports" data-host-id="${h.id}">Ports</button>
      </td>
    </tr>`;
  }).join('');

  // Bind port buttons
  tbody.querySelectorAll('.btn-view-ports').forEach(btn => {
    btn.addEventListener('click', () => openPortPanel(parseInt(btn.dataset.hostId)));
  });
  tbody.querySelectorAll('.port-chip[data-host-id]').forEach(chip => {
    chip.addEventListener('click', () => openPortPanel(parseInt(chip.dataset.hostId)));
  });
}

// ── Port Panel ────────────────────────────────────────────────────────────────
function openPortPanel(hostId) {
  const host = currentHosts.find(h => h.id === hostId);
  if (!host) return;

  $('panel-host-ip').textContent = host.ip_address;
  $('panel-host-os').textContent = host.os_name
    ? `${host.os_name} (${host.os_accuracy}% confidence)` : 'OS unknown';

  // Badges
  const badges = $('panel-badges');
  badges.innerHTML = [
    `<span class="risk-badge risk-${host.risk_level}">${host.risk_level} risk · score ${host.risk_score}</span>`,
    host.vendor ? `<span class="badge-type">${host.vendor}</span>` : '',
    host.mac_address ? `<span class="badge-type mono" style="font-size:.65rem">${host.mac_address}</span>` : '',
  ].join('');

  // Port table
  const ports = host.ports || [];
  $('port-detail-tbody').innerHTML = ports.length
    ? ports.map(p => `<tr>
        <td class="mono" style="color:var(--cyan)">${p.port_number}</td>
        <td class="mono">${p.protocol}</td>
        <td><span class="status-badge status-done"><span class="status-dot-sm"></span>${p.state}</span></td>
        <td>${p.service || '—'}</td>
        <td class="text-small text-muted">${[p.product, p.version].filter(Boolean).join(' ') || '—'}</td>
        <td><span class="risk-badge risk-${p.risk_level || 'low'}">${p.risk_level || 'low'}</span></td>
      </tr>`).join('')
    : '<tr><td colspan="6" style="text-align:center;color:var(--text3);padding:20px">No open ports</td></tr>';

  $('cve-section').style.display = 'none';
  $('port-panel').classList.add('open');
  $('port-panel').style.display = 'flex';
  $('port-panel-overlay').style.display = 'block';
  document.body.style.overflow = 'hidden';

  // Store host for CVE lookup
  $('btn-lookup-cve').dataset.hostId = hostId;
}

function closePortPanel() {
  $('port-panel').classList.remove('open');
  $('port-panel-overlay').style.display = 'none';
  setTimeout(() => { $('port-panel').style.display = 'none'; }, 300);
  document.body.style.overflow = '';
}

// ── CVE Lookup ────────────────────────────────────────────────────────────────
async function lookupCVEs() {
  const hostId = parseInt($('btn-lookup-cve').dataset.hostId);
  const host   = currentHosts.find(h => h.id === hostId);
  if (!host) return;

  const cveSection = $('cve-section');
  const cveList    = $('cve-list');
  cveSection.style.display = 'block';
  cveList.innerHTML = '<div class="loading-dots"><span></span><span></span><span></span></div>';

  // Gather unique services
  const services = [...new Set((host.ports || [])
    .filter(p => p.service && p.product)
    .map(p => ({ service: p.service, version: p.version }))
  )].slice(0, 3);

  if (!services.length) {
    cveList.innerHTML = '<p style="color:var(--text3);font-size:.78rem">No named services to look up.</p>';
    return;
  }

  const allCves = [];
  for (const { service, version } of services) {
    const params = new URLSearchParams({ service });
    if (version) params.append('version', version);
    try {
      const res  = await fetch(`/api/cve?${params}`);
      const data = await res.json();
      allCves.push(...(data.cves || []));
    } catch (e) { /* skip */ }
  }

  if (!allCves.length) {
    cveList.innerHTML = '<p style="color:var(--text3);font-size:.78rem">No CVEs found for these services.</p>';
    return;
  }

  cveList.innerHTML = allCves.slice(0, 8).map(c => `
    <div class="cve-item">
      <div class="cve-id"><a href="${c.url}" target="_blank" rel="noopener" style="color:inherit">${c.id}</a></div>
      <div class="cve-desc">${c.description || 'No description available.'}</div>
      <div class="cve-meta">
        <span class="cve-sev cve-sev-${(c.severity||'').toLowerCase()}">${c.severity || 'N/A'}</span>
        ${c.score ? `<span style="color:var(--text3)">Score: ${c.score}</span>` : ''}
      </div>
    </div>`).join('');
}

// ── Stats + Charts ─────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res   = await fetch('/api/stats');
    const stats = await res.json();

    // Stat cards
    animateCount($('stat-hosts-val'), stats.total_hosts);
    animateCount($('stat-ports-val'), stats.total_ports);
    animateCount($('stat-vulns-val'), stats.high_risk);
    animateCount($('stat-scans-val'), stats.total_scans);

    updateCharts(stats);
  } catch (e) { /* non-fatal */ }
}

function initCharts() {
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#8b97b0', font: { family: "'Inter', sans-serif", size: 11 } } } },
  };

  const portCtx = $('chart-ports').getContext('2d');
  portChart = new Chart(portCtx, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Occurrences', data: [], backgroundColor: 'rgba(0,212,255,.25)', borderColor: '#00d4ff', borderWidth: 1.5, borderRadius: 4 }] },
    options: {
      ...chartDefaults,
      plugins: { ...chartDefaults.plugins, legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b97b0', font: { family: "'JetBrains Mono', monospace", size: 10 } }, grid: { color: 'rgba(255,255,255,.04)' } },
        y: { ticks: { color: '#8b97b0', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,.04)' }, beginAtZero: true },
      },
    },
  });

  const svcCtx = $('chart-services').getContext('2d');
  const colors = ['#00d4ff','#a78bfa','#34d399','#f87171','#fbbf24','#60a5fa','#fb923c','#e879f9'];
  serviceChart = new Chart(svcCtx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: colors.map(c => c + '55'), borderColor: colors, borderWidth: 2, hoverBorderWidth: 3 }] },
    options: {
      ...chartDefaults,
      cutout: '65%',
      plugins: { ...chartDefaults.plugins, legend: { position: 'right', labels: { color: '#8b97b0', padding: 12, font: { size: 11 } } } },
    },
  });
}

function updateCharts(stats) {
  if (stats.port_frequency && portChart) {
    portChart.data.labels   = stats.port_frequency.map(p => `:${p.port}`);
    portChart.data.datasets[0].data = stats.port_frequency.map(p => p.count);
    portChart.update();
  }
  if (stats.service_distribution && serviceChart) {
    serviceChart.data.labels = stats.service_distribution.map(s => s.service);
    serviceChart.data.datasets[0].data = stats.service_distribution.map(s => s.count);
    serviceChart.update();
  }
}

// ── History ───────────────────────────────────────────────────────────────────
async function refreshHistory() {
  try {
    const res   = await fetch('/api/scans?limit=20');
    const scans = await res.json();
    renderHistory(scans);
  } catch (e) { /* non-fatal */ }
}

function renderHistory(scans) {
  const tbody = $('history-tbody');
  if (!scans.length) {
    tbody.innerHTML = '<tr><td colspan="10"><div class="empty-state-sm">No scans yet</div></td></tr>';
    return;
  }
  tbody.innerHTML = scans.map(s => {
    const started = s.started_at ? new Date(s.started_at).toLocaleString('en-US', { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' }) : '—';
    const dur     = s.duration ? `${s.duration}s` : '—';
    const risk    = s.high_risk > 0 ? `<span class="risk-badge risk-high">${s.high_risk} high</span>`
                  : s.medium_risk > 0 ? `<span class="risk-badge risk-medium">${s.medium_risk} med</span>`
                  : `<span class="risk-badge risk-low">low</span>`;
    return `<tr class="history-row" id="history-row-${s.id}">
      <td class="mono">#${s.id}</td>
      <td class="mono">${s.subnet}</td>
      <td><span class="badge-type">${s.scan_type}</span></td>
      <td><span class="status-badge status-${s.status}"><span class="status-dot-sm"></span>${s.status}</span></td>
      <td>${s.hosts_up}</td>
      <td>${s.total_ports}</td>
      <td>${risk}</td>
      <td class="mono text-muted">${dur}</td>
      <td class="mono text-muted text-small">${started}</td>
      <td style="display:flex;gap:4px">
        <button class="btn btn-ghost btn-xs btn-load-scan" data-scan-id="${s.id}">Load</button>
        <button class="btn btn-ghost btn-xs btn-delete-scan" data-scan-id="${s.id}">✕</button>
      </td>
    </tr>`;
  }).join('');
}

async function deleteScan(scanId) {
  const row = $(`history-row-${scanId}`);
  if (row) row.classList.add('deleting');
  try {
    await fetch(`/api/scan/${scanId}`, { method: 'DELETE' });
    if (activeScanId === scanId) {
      currentHosts = [];
      renderHostTable();
      activeScanId = null;
    }
    refreshHistory();
    loadStats();
  } catch (e) {
    if (row) row.classList.remove('deleting');
  }
}

// ── Demo ──────────────────────────────────────────────────────────────────────
async function loadDemoData() {
  const btn = $('btn-demo');
  btn.disabled = true;
  btn.textContent = 'Loading…';
  try {
    const res  = await fetch('/api/demo', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    showAlert(`✓ Demo data loaded (${data.hosts} hosts)`, 'success');
    activeScanId = data.scan_id;
    $('export-group').style.display = 'flex';
    await loadScanHosts(data.scan_id);
    await loadStats();
    await refreshHistory();
  } catch (e) {
    showAlert('Failed to load demo: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Load Demo Data';
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function showAlert(msg, type = 'info') {
  const el = $('scan-alert');
  el.className = `scan-alert alert-${type}`;
  el.textContent = msg;
  el.style.display = 'block';
  clearTimeout(el._timer);
  el._timer = setTimeout(() => { el.style.display = 'none'; }, 6000);
}

function animateCount(el, target) {
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  const dur   = 600;
  const t0    = performance.now();
  const tick  = (now) => {
    const p = Math.min((now - t0) / dur, 1);
    el.textContent = Math.round(start + (target - start) * easeOut(p));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}
function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

function ipToNum(ip) {
  return (ip || '').split('.').reduce((acc, oct) => acc * 256 + parseInt(oct || 0), 0);
}
function truncate(str, n) {
  return str && str.length > n ? str.slice(0, n) + '…' : str;
}
