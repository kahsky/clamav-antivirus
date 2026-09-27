/* ═══════════════════════════════════════════════════════════════════════════
   CLAMAV ANTIVIRUS — Frontend Logic
   Communication avec le backend Python via webkit.messageHandlers
   Traductions : ui/i18n.js (window.I18N), clé → texte, {param} interpolé
   ═══════════════════════════════════════════════════════════════════════════ */

// ─── State ──────────────────────────────────────────────────────────────────
let currentTab = 'dashboard';
let isUpdating = false;
let isInstalling = false;
let lastStatus = null;
let logScope = 'system';
let lang = 'fr';
let systemStatus = null;
let alerts = [];

const RING_CIRC = 2 * Math.PI * 52;   // circonférence de l'anneau (r = 52)

const scan = {
    running: false,
    source: null,          // 'daemon' | 'local'
    path: null,
    phase: 'idle',         // idle | prepare | counting | scanning | done
    scanned: 0, total: 0, found: 0,
    infected: 0, denied: 0, errors: 0,
    startedAt: null,       // epoch (secondes)
    file: '',
    threats: [],
    lines: [],             // {kind, text}
    samples: [],           // {t, n} pour la vitesse / ETA
    ticker: null,
    result: null,          // {status, message, summary}
    auto: false,
    usb: null,
    needsPassword: false,
};

// ─── Toast Container ────────────────────────────────────────────────────────
const toastContainer = document.createElement('div');
toastContainer.className = 'toast-container';
document.body.appendChild(toastContainer);

const $ = (id) => document.getElementById(id);


// ─── i18n ───────────────────────────────────────────────────────────────────

function t(key, params) {
    const dict = (window.I18N && (window.I18N[lang] || window.I18N.en)) || {};
    let text = dict[key];
    if (text === undefined && window.I18N) {
        text = (window.I18N.en || {})[key] ?? (window.I18N.fr || {})[key];
    }
    if (text === undefined) return key;
    if (params) {
        text = text.replace(/\{(\w+)\}/g, (m, k) => (params[k] !== undefined ? params[k] : m));
    }
    return text;
}

function setLanguage(code) {
    if (window.I18N && !window.I18N[code]) code = 'en';
    lang = code;
    document.documentElement.lang = code;
    document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    document.querySelectorAll('[data-i18n-title]').forEach(el => { el.title = t(el.dataset.i18nTitle); });
    const sel = $('langSelect');
    if (sel && sel.value !== code) sel.value = code;
    // Re-rendre les zones dynamiques avec la nouvelle langue
    if (lastStatus) updateDashboardStatus(lastStatus);
    renderScanHero();
    if (scan.result) renderScanResults(scan.result);
    renderSystemStatus();
    renderAlerts();
    const btnUpdate = $('btnUpdate');
    if (btnUpdate) btnUpdate.textContent = isUpdating ? t('update.btn_running') : t('update.btn');
    const btnInstall = $('btnInstall');
    if (btnInstall) btnInstall.textContent = isInstalling ? t('install.btn_running') : t('install.btn');
    $('logTitle').textContent = logScope === 'system' ? t('logs.title_system') : t('logs.title_user');
}

function changeLanguage(code) {
    sendToBackend({ action: 'set_language', lang: code });
    setLanguage(code);   // effet immédiat, même sans backend
}

function locale() {
    return { fr: 'fr-CH', en: 'en-GB', de: 'de-CH', it: 'it-CH' }[lang] || 'en-GB';
}


// ─── Backend Communication ──────────────────────────────────────────────────

function sendToBackend(data) {
    try {
        window.webkit.messageHandlers.backend.postMessage(JSON.stringify(data));
    } catch (e) {
        simulateBackend(data);   // mode développement (HTML ouvert dans un navigateur)
    }
}

function onBackendMessage(msg) {
    const { event, data } = msg;
    switch (event) {
        case 'statusUpdate':    updateDashboardStatus(data); break;
        case 'dbInfo':          renderDbInfo(data.files); break;
        case 'operationResult': handleOperationResult(data); break;
        case 'scanStarted':     onScanStarted(data); break;
        case 'scanProgress':    onScanProgress(data); break;
        case 'scanLine':        onScanLine(data); break;
        case 'scanDone':        onScanDone(data); break;
        case 'jobQueued':       onJobQueued(data); break;
        case 'updateStarted':   onUpdateStarted(data); break;
        case 'updateLine':      onUpdateLine(data); break;
        case 'logContent':      renderLogs(data); break;
        case 'quarantineList':  renderQuarantine(data.files); break;
        case 'folderPicked':    onFolderPicked(data); break;
        case 'systemStatus':    onSystemStatus(data); break;
        case 'alertEvent':      onAlertEvent(data); break;
        case 'alertsList':      alerts = data.alerts || []; renderAlerts(data.available !== false); break;
        case 'error':           showToast(data.message, 'error'); break;
    }
}

/** Appelé par le tray icon (Python) */
function updateTrayStatus(color, message) {
    updateStatusUI(color, message);
}

/** Appelé par le tray icon et par les cartes du tableau de bord */
function triggerUpdate() {
    switchTab('update');
    startUpdate();
}


// ─── Tab Navigation ─────────────────────────────────────────────────────────

function switchTab(tabId) {
    currentTab = tabId;
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === `tab-${tabId}`);
    });
    syncTopbar();

    if (tabId === 'dashboard') {
        sendToBackend({ action: 'check_status' });
        sendToBackend({ action: 'get_db_info' });
    } else if (tabId === 'update') {
        sendToBackend({ action: 'get_db_info' });
    } else if (tabId === 'logs') {
        loadLogs();
    } else if (tabId === 'quarantine') {
        loadQuarantine();
    } else if (tabId === 'system') {
        sendToBackend({ action: 'get_system_status', refresh: false });
        sendToBackend({ action: 'get_alerts' });
    }
}


// ─── Dashboard ──────────────────────────────────────────────────────────────

function updateDashboardStatus(data) {
    lastStatus = data;
    if (data.lang && data.lang !== lang) setLanguage(data.lang);
    updateStatusUI(data.color, data.message);
    toggleInstallTab(!data.fully_installed);

    $('statusDbAge').textContent = data.last_update ? formatRelative(data.last_update) : t('update.unknown');
    $('statusLastScan').textContent = data.last_scan ? formatRelative(data.last_scan.date) : t('dash.protection.none');

    // Service système
    const d = data.daemon || {};
    const pill = $('servicePill');
    pill.classList.toggle('online', !!d.available);
    pill.querySelector('.service-text').textContent = d.available ? t('sidebar.service_active') : t('sidebar.service_inactive');

    const badge = $('daemonBadge');
    badge.textContent = d.available ? t('common.active') : t('common.inactive');
    badge.className = 'badge ' + (d.available ? 'badge-green' : 'badge-red');
    $('protDaemon').textContent = d.available
        ? t('dash.protection.service_on', { version: d.version || '?' })
        : t('dash.protection.service_off');
    $('protMonitor').textContent = d.available
        ? `${d.monitor_active ? t('dash.protection.monitor_on') : t('dash.protection.monitor_off')} · ${d.usb_active ? t('dash.protection.usb_on') : t('dash.protection.usb_off')}`
        : '';

    // Planification
    const s = data.schedule || {};
    if (s.next_update) {
        $('protNextUpdate').textContent = t('dash.protection.next', { date: formatDateTime(s.next_update), rel: formatRelative(s.next_update) });
    } else {
        $('protNextUpdate').textContent = s.timer_active ? '' : t('dash.protection.timer_off');
    }
    $('updLast').textContent = data.last_update ? `${formatDateTime(data.last_update)} — ${formatRelative(data.last_update)}` : t('update.unknown');
    $('updNext').textContent = s.next_update ? formatDateTime(s.next_update) : t('update.not_scheduled');

    // Dernier scan
    if (data.last_scan) {
        const ls = data.last_scan;
        const res = ls.status === 'infected' || ls.infected > 0
            ? t('history.infected', { count: ls.infected }) : (ls.status === 'error' ? t('history.error') : t('history.clean'));
        $('protLastScan').textContent = `${scanPathLabel(ls.path, ls.usb)} — ${res}`;
        $('protLastScanSub').textContent = `${formatDateTime(ls.date)}${ls.files ? ` · ${t('history.files', { n: formatNumber(ls.files) })}` : ''}${ls.duration ? ` · ${formatDuration(ls.duration)}` : ''}${ls.auto ? ` · ${t('history.auto')}` : ''}`;
    } else {
        $('protLastScan').textContent = t('dash.protection.none');
        $('protLastScanSub').textContent = '';
    }

    $('fullScanHint').textContent = d.available ? t('dash.action.full_scan_hint_on') : t('dash.action.full_scan_hint_off');
    $('targetsHint').textContent = d.available ? t('scan.targets.hint_on') : t('scan.targets.hint_off');
    updateSourceBadge();

    // État du système (résumé)
    if (data.system_status && !systemStatus) systemStatus = Object.assign({ summary: true }, data.system_status);
    else if (data.system_status && systemStatus && systemStatus.summary) systemStatus = Object.assign({ summary: true }, data.system_status);
    renderSystemSummary();
    if (Array.isArray(data.alerts) && data.alerts.length && !alerts.length) { alerts = data.alerts; renderAlerts(); }

    toggleInitialScanPrompt(data.never_scanned && data.fully_installed && !d.first_scan_pending && !scan.running);

    // Scan interrompu : proposer la reprise
    const resumeEl = $('dashResumeScan');
    const r = data.resumable;
    if (r && r.path && !scan.running) {
        $('resumeScanPath').textContent = r.path;
        $('resumeScanDetail').textContent = r.total
            ? t('dash.resume.detail', { scanned: formatNumber(r.scanned || 0), total: formatNumber(r.total) })
            : t('dash.resume.possible');
        resumeEl.hidden = false;
        resumeEl.dataset.path = r.path;
    } else {
        resumeEl.hidden = true;
    }

    renderHistory(data.history || []);
}

function scanPathLabel(path, usb) {
    if (usb && (usb.label || usb.model)) return `USB ${usb.label || usb.model}`;
    return path === '/' ? t('scan.full_system') : (path || '?');
}

function renderHistory(list) {
    const el = $('historyList');
    $('historyCount').textContent = list.length ? t('dash.history.last', { n: list.length }) : '';
    if (!list.length) {
        el.innerHTML = `<p class="text-muted">${t('dash.history.none')}</p>`;
        return;
    }
    el.innerHTML = list.slice(0, 6).map(h => {
        const st = h.status === 'infected' || h.infected > 0 ? 'infected' : (h.status === 'error' ? 'error' : 'clean');
        const label = st === 'infected' ? t('history.infected', { count: h.infected }) : (st === 'error' ? t('history.error') : t('history.clean'));
        return `
        <div class="history-item">
            <span class="history-status history-${st}"></span>
            <div class="history-main">
                <span class="history-path" title="${escapeHtml(h.path || '')}">${escapeHtml(scanPathLabel(h.path, h.usb))}</span>
                <span class="history-meta">${formatDateTime(h.date)} · ${t('history.files', { n: formatNumber(h.files || 0) })} · ${formatDuration(h.duration || 0)}${h.source === 'daemon' ? ` · ${t('history.service')}` : ''}${h.auto ? ` · ${t('history.auto')}` : ''}${h.usb ? ' · USB' : ''}</span>
            </div>
            <span class="history-result history-${st}">${label}</span>
        </div>`;
    }).join('');
}

function toggleInstallTab(show) {
    const navBtn = document.querySelector('.nav-btn[data-tab="install"]');
    const tabPanel = $('tab-install');
    if (navBtn) navBtn.style.display = show ? '' : 'none';
    if (tabPanel && !show && tabPanel.classList.contains('active')) switchTab('dashboard');
}

function toggleInitialScanPrompt(show) {
    $('cardInitialScan').hidden = !show;
}

function updateStatusUI(color, message) {
    const card = $('cardStatus');
    card.className = `card card-status status-${color}`;
    const colors = {
        green: { main: '#22c55e', dark: '#059669' },
        blue:  { main: '#3b82f6', dark: '#2563eb' },
        red:   { main: '#ef4444', dark: '#dc2626' }
    };
    const c = colors[color] || colors.green;
    document.documentElement.style.setProperty('--status-color', c.main);
    document.documentElement.style.setProperty('--status-color-dark', c.dark);
    $('statusTitle').textContent = t(`status.title.${color}`) !== `status.title.${color}` ? t(`status.title.${color}`) : t('status.checking');
    $('statusMessage').textContent = message;
    const pill = $('statusPill');
    pill.className = `status-pill status-${color}`;
    pill.querySelector('.status-text').textContent = message;
}

function renderDbInfo(files) {
    ['dbInfoContent', 'dbDetailsList'].forEach(id => {
        const container = $(id);
        if (!container) return;
        if (!files || files.length === 0) {
            container.innerHTML = `<p class="text-muted">${t('dash.db.none')}</p>`;
            return;
        }
        container.innerHTML = files.map(f => `
            <div class="db-file">
                <span class="db-file-name">${escapeHtml(f.name)}</span>
                <span class="db-file-meta">${escapeHtml(f.date)} — ${formatSize(f.size)}</span>
            </div>`).join('');
    });
}


// ─── État du système ────────────────────────────────────────────────────────

function onSystemStatus(data) {
    if (data.available === false) {
        systemStatus = null;
        $('systemChecked').textContent = t('system.unavailable');
        renderSystemStatus();
        return;
    }
    if (data.refreshing) {
        $('systemChecked').textContent = t('system.refreshing');
        $('btnSystemRefresh').disabled = true;
    } else {
        $('btnSystemRefresh').disabled = false;
    }
    if (data.status) {
        systemStatus = data.status;
        renderSystemStatus();
        renderSystemSummary();
    }
}

function refreshSystemStatus() {
    $('btnSystemRefresh').disabled = true;
    $('systemChecked').textContent = t('system.refreshing');
    sendToBackend({ action: 'get_system_status', refresh: true, force: true });
}

function systemState(st) {
    if (!st || !st.ok) return 'unknown';
    if (st.security > 0 || (st.cve_count || 0) > 0) return 'security';
    if (st.reboot_required) return 'reboot';
    if (st.upgradable > 0) return 'updates';
    return 'ok';
}

function renderSystemSummary() {
    const st = systemStatus;
    const state = systemState(st);
    const badge = $('systemBadge');
    const count = st ? (st.security || 0) : 0;
    if (count > 0) { badge.textContent = count; badge.style.display = ''; } else badge.style.display = 'none';
    const labels = {
        unknown: t('dash.system.unknown'),
        ok: t('dash.system.uptodate'),
        updates: t('dash.system.updates', { n: st ? st.upgradable : 0 }),
        security: t('dash.system.security', { n: st ? st.security : 0, cves: st ? (st.cve_count || 0) : 0 }),
        reboot: t('dash.system.reboot'),
    };
    $('statusSystem').textContent = labels[state];
    $('dashSystemHint').textContent = labels[state];
    const icon = $('dashSystemIcon');
    icon.className = 'card-icon ' + ({ ok: 'accent-green', updates: 'accent-blue', security: 'accent-red', reboot: 'accent-amber', unknown: 'accent-blue' }[state]);
}

function renderSystemStatus() {
    const st = systemStatus;
    const state = systemState(st);
    const banner = $('systemBanner');
    banner.dataset.state = state;
    const titles = {
        unknown: [t('system.unknown_title'), t('system.unknown_body')],
        ok: [t('system.uptodate_title'), t('system.uptodate_body')],
        updates: [t('system.updates_title', { n: st ? st.upgradable : 0 }), t('system.updates_body')],
        security: [t('system.pending_title', { n: st ? st.security : 0 }), t('system.pending_body', { cves: st ? (st.cve_count || 0) : 0 })],
        reboot: [t('system.reboot_title'), t('system.reboot_body', { pkgs: st && st.reboot_pkgs ? st.reboot_pkgs.join(', ') : '' })],
    };
    $('systemBannerTitle').textContent = titles[state][0];
    $('systemBannerBody').textContent = titles[state][1];

    if (!st) {
        ['sysOs', 'sysKernel', 'sysUpgradable', 'sysSecurity', 'sysCves', 'sysReboot'].forEach(id => { $(id).textContent = '—'; });
        $('cveList').innerHTML = `<p class="text-muted">${t('system.cve_none')}</p>`;
        $('cveCount').textContent = '';
        $('cardPackages').hidden = true;
        return;
    }
    $('systemChecked').textContent = st.checked_at
        ? t('system.checked', { date: formatDateTime(st.checked_at), rel: formatRelative(st.checked_at) }) + (st.lists_updated ? ` · ${t('system.lists', { rel: formatRelative(st.lists_updated) })}` : '')
        : t('system.never');
    $('sysOs').textContent = st.os || '—';
    $('sysKernel').textContent = st.kernel || '—';
    $('sysUpgradable').textContent = formatNumber(st.upgradable || 0);
    $('sysSecurity').textContent = formatNumber(st.security || 0);
    $('sysCves').textContent = formatNumber(st.cve_count || 0);
    $('sysReboot').textContent = st.reboot_required ? t('system.reboot_yes') : t('system.reboot_no');
    $('sysSecurity').parentElement.classList.toggle('has-threats', (st.security || 0) > 0);
    $('sysCves').parentElement.classList.toggle('has-threats', (st.cve_count || 0) > 0);
    $('sysReboot').parentElement.classList.toggle('has-warning', !!st.reboot_required);

    const cves = st.cves || [];
    $('cveCount').textContent = cves.length ? `${cves.length} CVE` : '';
    if (!cves.length) {
        $('cveList').innerHTML = `<p class="text-muted">${st.summary ? t('system.cve_loading') : t('system.cve_none')}</p>`;
    } else {
        $('cveList').innerHTML = cves.map(c => `
            <div class="cve-item">
                <div class="cve-head">
                    <a class="cve-id" href="#" onclick="sendToBackend({action:'open_url', url:'${escapeJs(c.url)}'}); return false;">${escapeHtml(c.id)}</a>
                    <span class="scope-badge scope-system">${escapeHtml(c.package)}</span>
                    <span class="cve-versions">${escapeHtml(c.installed || '?')} → ${escapeHtml(c.candidate || '?')}</span>
                </div>
                <div class="cve-title">${escapeHtml(c.title || t('system.cve_pkg', { pkg: c.package }))}</div>
            </div>`).join('');
    }

    const pkgs = (st.packages || []);
    $('cardPackages').hidden = !pkgs.length;
    if (pkgs.length) {
        $('packageList').innerHTML = pkgs.slice(0, 60).map(p => `
            <div class="package-item ${p.security ? 'security' : ''}">
                <span class="package-name">${escapeHtml(p.name)}</span>
                <span class="package-versions">${escapeHtml(p.installed || '?')} → ${escapeHtml(p.candidate || '?')}</span>
                ${p.security ? `<span class="scope-badge scope-danger">${t('system.pkg_security')}</span>` : `<span class="scope-badge scope-user">${escapeHtml(p.archive || '')}</span>`}
            </div>`).join('') + (pkgs.length > 60 ? `<p class="text-muted">+${pkgs.length - 60}</p>` : '');
    }
}

function onAlertEvent(alert) {
    alerts.unshift(alert);
    if (alerts.length > 30) alerts.length = 30;
    renderAlerts();
}

function renderAlerts(available = true) {
    const el = $('alertsList');
    $('alertsHint').textContent = available ? '' : t('system.alerts.unavailable');
    if (!alerts.length) {
        el.innerHTML = `<p class="text-muted">${t('system.alerts.none')}</p>`;
        return;
    }
    el.innerHTML = alerts.map(a => {
        const reasons = (a.reasons || []).map(r => t(`alert.reason.${r}`)).join(', ');
        const infected = [...(a.infected_exe || []), ...(a.infected_files || [])];
        return `
        <div class="alert-item alert-${a.severity}">
            <div class="alert-head">
                <span class="badge ${a.severity === 'danger' ? 'badge-red' : 'badge-blue'}">${a.severity === 'danger' ? t('system.alert.danger') : t('system.alert.info')}</span>
                <span class="alert-program">${escapeHtml(a.comm || '?')}</span>
                <span class="alert-meta">${formatDateTime(a.time)} · pid ${a.pid}${a.user ? ` · ${escapeHtml(a.user)}` : ''}</span>
            </div>
            <div class="alert-body">${t('system.alert.files', { count: formatNumber(a.count || 0), seconds: a.window || 15, dir: escapeHtml(a.top_dir || '/') })}${a.trusted ? '' : ` · ${t('system.alert.untrusted')}`}</div>
            ${a.exe ? `<div class="alert-exe">${escapeHtml(a.exe)}${a.cmdline ? ` — ${escapeHtml(a.cmdline)}` : ''}</div>` : ''}
            ${reasons ? `<div class="alert-reasons">${escapeHtml(reasons)}</div>` : ''}
            ${infected.length ? `<div class="alert-infected">${infected.map(escapeHtml).join('<br>')}</div>` : ''}
            ${(a.sample || []).length ? `<details class="alert-sample"><summary>${t('system.alert.sample', { n: (a.sample || []).length })}</summary>${(a.sample || []).map(p => `<div>${escapeHtml(p)}</div>`).join('')}</details>` : ''}
            <div class="alert-actions"><button class="btn btn-secondary btn-sm" onclick="startScan('${escapeJs(a.top_dir || '/')}')">${t('popup.btn.scan_folder')}</button></div>
        </div>`;
    }).join('');
}


// ─── Scan : démarrage / annulation ──────────────────────────────────────────

function startFullSystemScan() {
    if (scan.running) { showToast(t('toast.scan_running'), 'info'); switchTab('scan'); return; }
    toggleInitialScanPrompt(false);
    switchTab('scan');
    prepareScanUI('/');
    const d = (lastStatus && lastStatus.daemon) || {};
    if (!d.available) setHeroNote(t('scan.note.service_off'));
    sendToBackend({ action: 'scan', path: '/' });
}

function startScan(path) {
    if (scan.running) { showToast(t('toast.scan_running'), 'info'); return; }
    path = (path || '').trim();
    if (!path) { showToast(t('toast.enter_path'), 'error'); return; }
    switchTab('scan');
    prepareScanUI(path);
    document.querySelectorAll('.target-btn').forEach(btn => btn.classList.toggle('scanning', btn.dataset.path === path));
    sendToBackend({ action: 'scan', path });
}

function resumeScan() {
    if (scan.running) return;
    const path = $('dashResumeScan').dataset.path;
    if (!path) return;
    $('dashResumeScan').hidden = true;
    switchTab('scan');
    prepareScanUI(path);
    sendToBackend({ action: 'scan', path, resume: true });
}

function cancelScan() {
    if (!scan.running) return;
    setHeroNote(t('scan.note.cancelling'));
    $('btnCancelScan').disabled = true;
    sendToBackend({ action: 'cancel_scan' });
}

function pickFolder(purpose, extra) {
    sendToBackend({ action: 'pick_folder', purpose, extra: extra || null,
                    start: purpose === 'scan' ? ($('customPath').value || null) : null });
}

function onFolderPicked({ path, purpose, extra }) {
    if (!path) return;
    if (purpose === 'scan') {
        $('customPath').value = path;
        startScan(path);
    } else if (purpose === 'restore' && extra) {
        sendToBackend({ action: 'restore_quarantine', path: extra.path, scope: extra.scope, dest: path });
    }
}

/** Réinitialise l'interface de scan avant le lancement (état "préparation"). */
function prepareScanUI(path) {
    Object.assign(scan, {
        running: true, source: null, path, phase: 'prepare',
        scanned: 0, total: 0, found: 0, infected: 0, denied: 0, errors: 0,
        startedAt: Date.now() / 1000, file: '', threats: [], lines: [], samples: [],
        result: null, auto: false, usb: null, needsPassword: false,
    });
    $('scanResults').hidden = true;
    $('scanOutput').innerHTML = '';
    $('btnCancelScan').disabled = false;
    setHeroNote('');
    startTicker();
    renderScanHero();
}


// ─── Scan : événements du backend ───────────────────────────────────────────

function onScanStarted(data) {
    if (!scan.running) prepareScanUI(data.path);
    scan.source = data.source;
    scan.path = data.path || scan.path;
    scan.auto = !!data.auto;
    scan.usb = data.usb || null;
    scan.needsPassword = !!data.needs_password;
    if (data.started_at) scan.startedAt = data.started_at;
    if (data.job) applyProgress(data.job);
    if (scan.needsPassword) setHeroNote(t('scan.note.auth'));
    else if (scan.usb) setHeroNote(t('scan.note.usb', { name: scan.usb.label || scan.usb.model || scan.usb.devnode || 'USB' }));
    else if (scan.auto) setHeroNote(t('scan.note.auto'));
    else setHeroNote('');
    toggleInitialScanPrompt(false);
    $('dashResumeScan').hidden = true;
    document.querySelectorAll('.target-btn').forEach(btn => btn.classList.toggle('scanning', btn.dataset.path === scan.path));
    renderScanHero();
}

function applyProgress(p) {
    if (p.phase) scan.phase = p.phase === 'queued' ? 'prepare' : p.phase;
    scan.scanned = p.scanned || 0;
    scan.total = p.total || 0;
    scan.found = p.found || 0;
    scan.infected = p.infected || 0;
    scan.denied = p.denied || 0;
    scan.errors = p.errors || 0;
    scan.file = p.file || '';
    if (p.usb) scan.usb = p.usb;
    if (p.started_at) scan.startedAt = p.started_at;
    if (Array.isArray(p.threats) && p.threats.length > scan.threats.length) scan.threats = p.threats.slice();
    if (scan.phase === 'scanning') {
        const now = Date.now() / 1000;
        scan.samples.push({ t: now, n: scan.scanned });
        while (scan.samples.length > 2 && now - scan.samples[0].t > 30) scan.samples.shift();
    }
}

function onScanProgress(data) {
    if (!scan.running) { prepareScanUI(data.path); scan.source = data.source; }
    applyProgress(data);
    renderScanHero();
}

function onScanLine({ kind, text }) {
    if (!scan.running) return;
    if (kind === 'found') {
        const m = text.match(/^(.*): (.*) FOUND$/);
        if (m && !scan.threats.some(x => x.path === m[1])) scan.threats.push({ path: m[1], signature: m[2] });
        scan.infected = Math.max(scan.infected, scan.threats.length);
    }
    scan.lines.push({ kind, text });
    if (scan.lines.length > 2000) scan.lines.shift();
    appendConsoleLine(kind, text);
    if (kind === 'found') renderScanHero();
}

function onScanDone(data) {
    stopTicker();
    scan.running = false;
    scan.phase = 'done';
    scan.result = data;
    const summary = data.summary || {};
    if (summary.files) scan.total = summary.files;
    if (summary.infected != null) scan.infected = summary.infected;
    if (Array.isArray(summary.threats) && summary.threats.length) scan.threats = summary.threats;
    if (data.status === 'clean' || data.status === 'infected') scan.scanned = scan.total;
    scan.file = '';
    document.querySelectorAll('.target-btn').forEach(btn => btn.classList.remove('scanning'));

    renderScanHero();
    renderScanResults(data);
    syncTopbar();

    const toastType = data.status === 'infected' ? 'error' : (data.status === 'clean' ? 'success' : 'info');
    showToast(data.message, toastType);

    sendToBackend({ action: 'check_status' });
    if (data.status === 'infected') sendToBackend({ action: 'get_quarantine' });
}

function onJobQueued(job) {
    if (job.kind === 'scan') showToast(t('toast.queued', { path: job.path }), 'info');
}


// ─── Scan : rendu ───────────────────────────────────────────────────────────

function scanPercent() {
    if (scan.phase === 'done' && scan.result && (scan.result.status === 'clean' || scan.result.status === 'infected')) return 100;
    if (scan.total > 0) return Math.min(100, scan.scanned / scan.total * 100);
    return 0;
}

function scanRate() {
    const s = scan.samples;
    if (s.length < 2) return null;
    const dt = s[s.length - 1].t - s[0].t;
    const dn = s[s.length - 1].n - s[0].n;
    return dt > 1 ? dn / dt : null;
}

function scanTargetLabel() {
    return scanPathLabel(scan.path, scan.usb);
}

function renderScanHero() {
    const hero = $('scanHero');
    const pct = scanPercent();
    const state = scan.running ? 'running' : (scan.result ? scan.result.status : 'idle');
    hero.dataset.state = state;
    hero.dataset.phase = scan.phase;

    $('scanRingFill').style.strokeDashoffset = RING_CIRC * (1 - pct / 100);
    $('scanRingPct').textContent = scan.running && scan.phase !== 'scanning' && scan.total === 0 ? '…' : `${Math.floor(pct)} %`;
    $('scanRingSub').textContent = scan.running
        ? (scan.phase === 'counting' ? t('scan.ring.counting_files', { n: formatNumber(scan.found) }) : (scan.phase === 'prepare' ? t('scan.ring.starting') : t('scan.ring.analysis')))
        : (scan.result ? t('scan.ring.done') : '');

    let title, sub;
    if (scan.running) {
        title = scan.phase === 'counting' ? t('scan.counting') : scan.phase === 'prepare' ? t('scan.preparing') : t('scan.running');
        sub = scan.phase === 'scanning'
            ? t('scan.sub.scanning', { path: scanTargetLabel(), scanned: formatNumber(scan.scanned), total: formatNumber(scan.total) })
            : (scan.phase === 'counting' ? t('scan.sub.counting', { path: scanTargetLabel(), found: formatNumber(scan.found) }) : scanTargetLabel());
    } else if (scan.result) {
        const r = scan.result;
        title = r.status === 'clean' ? t('scan.result.done_clean_title')
              : r.status === 'infected' ? t('scan.result.done_infected_title', { count: scan.infected })
              : r.status === 'cancelled' ? t('scan.result.done_cancelled_title')
              : t('scan.result.done_error_title');
        sub = r.message || '';
    } else {
        title = t('scan.ready');
        sub = t('scan.ready_sub');
    }
    $('scanHeroTitle').textContent = title;
    $('scanHeroSub').textContent = sub;

    const order = ['prepare', 'counting', 'scanning', 'done'];
    const idx = order.indexOf(scan.phase);
    document.querySelectorAll('#scanPhases li').forEach(li => {
        const i = order.indexOf(li.dataset.phase);
        li.classList.toggle('done', scan.phase !== 'idle' && i < idx);
        li.classList.toggle('active', scan.phase !== 'idle' && i === idx && (scan.running || scan.phase === 'done'));
    });

    $('statScanned').textContent = formatNumber(scan.scanned);
    $('statTotal').textContent = scan.total ? formatNumber(scan.total) : (scan.phase === 'counting' ? formatNumber(scan.found) : '—');
    $('statThreats').textContent = formatNumber(scan.infected);
    $('statThreats').parentElement.classList.toggle('has-threats', scan.infected > 0);
    updateTimeStats();

    $('scanCurrentPath').textContent = scan.file ? rtlPath(scan.file) : (scan.running ? '…' : '—');
    $('scanCurrent').classList.toggle('active', scan.running && !!scan.file);

    $('btnFullScan').hidden = scan.running;
    $('btnCancelScan').hidden = !scan.running;
    $('scanConsoleDot').style.visibility = scan.running ? 'visible' : 'hidden';
    $('navScanLive').hidden = !scan.running;
    updateSourceBadge();
    syncTopbar();
    syncDashboardLive();
}

function updateTimeStats() {
    const elapsed = scan.startedAt ? Math.max(0, Date.now() / 1000 - scan.startedAt) : 0;
    if (scan.result && scan.result.summary && scan.result.summary.duration) {
        $('statElapsed').textContent = formatDuration(scan.result.summary.duration);
    } else {
        $('statElapsed').textContent = scan.startedAt ? formatDuration(elapsed) : '0 s';
    }
    const rate = scan.running && scan.phase === 'scanning' ? scanRate() : null;
    $('statSpeed').textContent = rate != null ? formatNumber(Math.round(rate)) : '—';
    if (rate && rate > 0 && scan.total > scan.scanned) {
        const eta = (scan.total - scan.scanned) / rate;
        $('statEta').textContent = eta < 5 ? t('scan.eta.soon') : `≈ ${formatDuration(eta)}`;
    } else if (scan.running && scan.phase === 'scanning' && scan.total > 0) {
        $('statEta').textContent = t('scan.eta.estimating');
    } else {
        $('statEta').textContent = '—';
    }
}

function updateSourceBadge() {
    const badge = $('scanSourceBadge');
    const d = (lastStatus && lastStatus.daemon) || {};
    if (scan.running || scan.result) {
        if (scan.usb) { badge.textContent = t('scan.badge.usb'); badge.className = 'badge badge-blue'; }
        else if (scan.source === 'daemon') { badge.textContent = t('scan.badge.service'); badge.className = 'badge badge-green'; }
        else if (scan.needsPassword) { badge.textContent = t('scan.badge.admin'); badge.className = 'badge badge-amber'; }
        else if (scan.source === 'local') { badge.textContent = t('scan.badge.user'); badge.className = 'badge badge-blue'; }
        else { badge.textContent = t('scan.badge.starting'); badge.className = 'badge'; }
    } else {
        badge.textContent = d.available ? t('scan.badge.ready') : t('scan.badge.off');
        badge.className = 'badge ' + (d.available ? 'badge-green' : 'badge-red');
    }
}

function setHeroNote(text) {
    $('scanHeroNote').textContent = text || '';
}

function startTicker() {
    stopTicker();
    scan.ticker = setInterval(() => { if (scan.running) { updateTimeStats(); syncTopbar(); } }, 1000);
}

function stopTicker() {
    if (scan.ticker) { clearInterval(scan.ticker); scan.ticker = null; }
}

function renderScanResults(data) {
    const box = $('scanResults');
    const summary = data.summary || {};
    const st = data.status;
    box.hidden = false;
    box.dataset.state = st;
    $('scanResultsTitle').textContent =
        st === 'clean' ? t('scan.result.clean') :
        st === 'infected' ? t('scan.result.infected', { count: scan.infected }) :
        st === 'cancelled' ? t('scan.result.cancelled') :
        t('scan.result.error');
    $('btnSeeQuarantine').hidden = st !== 'infected';

    const by = data.source === 'daemon' ? t('scan.result.by_service') : (scan.needsPassword ? t('scan.result.by_admin') : t('scan.result.by_user'));
    const tiles = [
        [t('scan.result.files'), formatNumber(st === 'cancelled' ? scan.scanned : (summary.files ?? scan.total))],
        [t('scan.result.threats'), formatNumber(summary.infected ?? scan.infected)],
        [t('scan.result.duration'), formatDuration(summary.duration || 0)],
        [t('scan.result.denied'), formatNumber(summary.denied ?? scan.denied)],
        [t('scan.result.errors'), formatNumber(summary.errors ?? scan.errors)],
        [t('scan.result.by'), by],
    ];
    $('scanResultsGrid').innerHTML = tiles.map(([l, v]) =>
        `<div class="result-tile"><span class="result-value">${escapeHtml(String(v))}</span><span class="result-label">${escapeHtml(l)}</span></div>`).join('');

    const threats = (summary.threats && summary.threats.length) ? summary.threats : scan.threats;
    $('threatList').innerHTML = threats.length ? `
        <h5>${t('scan.result.threat_list')}</h5>
        ${threats.map(x => `
            <div class="threat-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <div class="threat-info">
                    <span class="threat-path" title="${escapeHtml(x.path)}">${escapeHtml(x.path)}</span>
                    <span class="threat-sig">${escapeHtml(x.signature || '')}</span>
                </div>
            </div>`).join('')}` : '';
}

function appendConsoleLine(kind, text) {
    if ($('chkOnlyThreats').checked && !['found', 'error', 'summary'].includes(kind)) return;
    const output = $('scanOutput');
    const div = document.createElement('div');
    div.className = `line-${kind}`;
    div.textContent = text;
    output.appendChild(div);
    while (output.childElementCount > 1500) output.removeChild(output.firstChild);
    output.scrollTop = output.scrollHeight;
}

function renderScanConsole() {
    const output = $('scanOutput');
    output.innerHTML = '';
    scan.lines.forEach(l => appendConsoleLine(l.kind, l.text));
}

function toggleScanDetails(show) {
    const box = $('scanConsole');
    box.hidden = show === undefined ? !box.hidden : !show;
    if (!box.hidden) { renderScanConsole(); box.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
}

function syncTopbar() {
    const bar = $('scanTopbar');
    const show = scan.running && currentTab !== 'scan';
    bar.hidden = !show;
    if (!show) return;
    const pct = scanPercent();
    $('scanTopbarFill').style.width = `${pct}%`;
    $('scanTopbarFill').classList.toggle('indeterminate', scan.phase !== 'scanning');
    $('scanTopbarTitle').textContent = scan.phase === 'counting' ? t('scan.phase.counting') : (scan.phase === 'prepare' ? t('scan.phase.prepare') : t('topbar.scanning', { path: scanTargetLabel() }));
    $('scanTopbarCount').textContent = scan.phase === 'scanning'
        ? `${Math.floor(pct)} % — ${formatNumber(scan.scanned)} / ${formatNumber(scan.total)}`
        : (scan.phase === 'counting' ? t('history.files', { n: formatNumber(scan.found) }) : '');
    $('scanTopbarEta').textContent = $('statEta').textContent !== '—' ? t('topbar.remaining', { eta: $('statEta').textContent }) : '';
    $('scanTopbarFile').textContent = rtlPath(scan.file);
}

function syncDashboardLive() {
    const card = $('dashScanLive');
    card.hidden = !scan.running;
    if (!scan.running) return;
    const pct = scanPercent();
    $('dashScanTitle').textContent = scan.phase === 'counting' ? t('dash.live.counting') : t('topbar.scanning', { path: scanTargetLabel() });
    $('dashScanCount').textContent = scan.phase === 'scanning' ? `${Math.floor(pct)} % — ${formatNumber(scan.scanned)} / ${formatNumber(scan.total)}` : t('history.files', { n: formatNumber(scan.found) });
    $('dashProgressFill').style.width = `${pct}%`;
    $('dashCurrentFile').textContent = rtlPath(scan.file);
}


// ─── Update ─────────────────────────────────────────────────────────────────

function startUpdate() {
    if (isUpdating) { showToast(t('toast.update_running'), 'info'); return; }
    isUpdating = true;
    const btn = $('btnUpdate');
    btn.disabled = true;
    btn.textContent = t('update.btn_running');
    $('updateConsole').hidden = false;
    $('updateOutput').innerHTML = '';
    $('updateConsoleTitle').textContent = t('update.console.running');
    $('updateNote').textContent = '';
    appendLine($('updateOutput'), t('update.request_line'), 'info');
    sendToBackend({ action: 'update' });
}

function onUpdateStarted(data) {
    if (!isUpdating) {
        isUpdating = true;
        $('btnUpdate').disabled = true;
        $('btnUpdate').textContent = t('update.btn_running');
        $('updateConsole').hidden = false;
        $('updateOutput').innerHTML = '';
        $('updateConsoleTitle').textContent = t('update.console.running');
        if (data.auto) appendLine($('updateOutput'), t('update.auto_line'), 'info');
    }
    $('updateNote').textContent = data.source === 'daemon'
        ? (data.queued ? t('update.note.queued') : t('update.note.daemon'))
        : t('update.note.local');
}

function onUpdateLine({ text }) {
    if (!text) return;
    let kind = '';
    if (/error|failed|échec/i.test(text)) kind = 'error';
    else if (/up-to-date|up to date|updated/i.test(text)) kind = 'ok';
    appendLine($('updateOutput'), text, kind);
}


// ─── Install ────────────────────────────────────────────────────────────────

function installClamAV() {
    if (isInstalling) return;
    isInstalling = true;
    const btn = $('btnInstall');
    btn.disabled = true;
    btn.textContent = t('install.btn_running');
    $('installConsole').hidden = false;
    $('installOutput').innerHTML = '';
    sendToBackend({ action: 'install' });
}


// ─── Logs ───────────────────────────────────────────────────────────────────

function setLogScope(scope) {
    logScope = scope;
    document.querySelectorAll('#logScope .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.scope === scope));
    loadLogs();
}

function loadLogs() {
    sendToBackend({ action: 'get_log', scope: logScope });
}

function clearLogs() {
    if (confirm(t('logs.confirm_clear'))) {
        sendToBackend({ action: 'clear_log', scope: logScope });
        showToast(t('logs.cleared'), 'success');
    }
}

function renderLogs({ lines, scope, available }) {
    const output = $('logOutput');
    $('logTitle').textContent = scope === 'system' ? t('logs.title_system') : t('logs.title_user');
    if (scope === 'system' && available === false) {
        output.innerHTML = `<p class="text-muted center">${t('logs.unavailable')}</p>`;
        return;
    }
    if (!lines || lines.length === 0) {
        output.innerHTML = `<p class="text-muted center">${t('logs.none')}</p>`;
        return;
    }
    output.innerHTML = lines.map(line => {
        let cls = '';
        if (line.includes('FOUND')) cls = 'line-found';
        else if (line.includes('Infected files: 0') || line.includes('0 infected') || line.includes('up to date')) cls = 'line-ok';
        else if (line.includes('▶') || line.includes('■')) cls = 'line-info';
        else if (/error|failed|Access denied|⚠/i.test(line)) cls = 'line-error';
        return `<div class="${cls}">${escapeHtml(line.trim())}</div>`;
    }).join('');
    output.scrollTop = output.scrollHeight;
}


// ─── Quarantine ─────────────────────────────────────────────────────────────

function loadQuarantine() {
    sendToBackend({ action: 'get_quarantine' });
}

function renderQuarantine(files) {
    const container = $('quarantineList');
    const badge = $('quarantineBadge');
    const btnEmpty = $('btnEmptyQuarantine');

    if (badge) {
        if (files && files.length > 0) { badge.textContent = files.length; badge.style.display = ''; }
        else badge.style.display = 'none';
    }
    if (!container) return;

    if (!files || files.length === 0) {
        container.innerHTML = `
            <div class="quarantine-empty">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <polyline points="9,12 12,15 15,9"/>
                </svg>
                <p>${t('quarantine.none')}</p>
                <small class="text-muted">${t('quarantine.none_hint')}</small>
            </div>`;
        if (btnEmpty) btnEmpty.style.display = 'none';
        return;
    }
    if (btnEmpty) btnEmpty.style.display = '';

    container.innerHTML = files.map(f => `
        <div class="quarantine-item">
            <div class="quarantine-item-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
            </div>
            <div class="quarantine-item-info">
                <div class="quarantine-item-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}
                    <span class="scope-badge scope-${f.scope === 'system' ? 'system' : 'user'}">${f.scope === 'system' ? t('quarantine.scope.system') : t('quarantine.scope.user')}</span>
                </div>
                <div class="quarantine-item-meta">${escapeHtml(f.date)} — ${formatSize(String(f.size))}</div>
            </div>
            <div class="quarantine-item-actions">
                <button class="btn btn-secondary" onclick="restoreQuarantineFile('${escapeJs(f.path)}', '${escapeJs(f.scope || 'user')}')">${t('quarantine.restore')}</button>
                <button class="btn btn-danger" onclick="deleteQuarantineFile('${escapeJs(f.path)}', '${escapeJs(f.name)}', '${escapeJs(f.scope || 'user')}')">${t('quarantine.delete')}</button>
            </div>
        </div>`).join('');
}

function deleteQuarantineFile(filepath, name, scope) {
    if (confirm(t('quarantine.confirm_delete', { name }))) {
        sendToBackend({ action: 'delete_quarantine', path: filepath, scope });
    }
}

function restoreQuarantineFile(filepath, scope) {
    pickFolder('restore', { path: filepath, scope });
}

function emptyQuarantine() {
    if (confirm(t('quarantine.confirm_empty'))) {
        sendToBackend({ action: 'empty_quarantine' });
    }
}


// ─── Operation Results (update / install / quarantaine) ─────────────────────

function handleOperationResult(data) {
    const { status, message, op } = data;

    if (status === 'progress') {
        if (isInstalling) appendLine($('installOutput'), message);
        return;
    }
    if (status === 'info') { showToast(message, 'info'); return; }

    if (op === 'update' || (isUpdating && op !== 'install' && op !== 'quarantine')) {
        isUpdating = false;
        const btn = $('btnUpdate');
        btn.disabled = false;
        btn.textContent = t('update.btn');
        $('updateConsoleTitle').textContent = status === 'success' ? t('update.console.done') : t('update.console.failed');
        appendLine($('updateOutput'), (status === 'success' ? '✅ ' : '⚠ ') + message, status === 'success' ? 'ok' : 'error');
        showToast(message, status === 'success' ? 'success' : 'error');
        sendToBackend({ action: 'check_status' });
        sendToBackend({ action: 'get_db_info' });
        return;
    }
    if (op === 'install' || isInstalling) {
        isInstalling = false;
        const btn = $('btnInstall');
        btn.disabled = false;
        btn.textContent = t('install.btn');
        showToast(message, status === 'success' ? 'success' : 'error');
        sendToBackend({ action: 'check_status' });
        return;
    }
    if (status === 'error' && scan.running && !scan.source) {
        // Le scan n'a pas pu démarrer
        stopTicker();
        scan.running = false;
        scan.phase = 'idle';
        scan.result = null;
        renderScanHero();
        document.querySelectorAll('.target-btn').forEach(btn => btn.classList.remove('scanning'));
    }
    showToast(message, status === 'success' ? 'success' : 'error');
}


// ─── Utilities ──────────────────────────────────────────────────────────────

function appendLine(container, text, type = '') {
    if (!container) return;
    const div = document.createElement('div');
    if (type) div.className = `line-${type}`;
    div.textContent = text;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str == null ? '' : String(str);
    return d.innerHTML;
}

function escapeJs(str) {
    return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
}

/** Chemin affiché avec ellipse à gauche (direction: rtl) sans déplacer les barres obliques. */
function rtlPath(path) {
    return path ? `\u200E${path}\u200E` : '';
}

function formatSize(bytes) {
    const b = parseInt(bytes, 10);
    if (isNaN(b)) return bytes;
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(1) + ' GB';
}

function formatNumber(n) {
    return Number(n || 0).toLocaleString(locale());
}

function formatDuration(seconds) {
    seconds = Math.max(0, Math.round(seconds || 0));
    const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60), s = seconds % 60;
    if (h) return `${h} ${t('dur.h')} ${String(m).padStart(2, '0')} ${t('dur.min')}`;
    if (m) return `${m} ${t('dur.min')} ${String(s).padStart(2, '0')} ${t('dur.s')}`;
    return `${s} ${t('dur.s')}`;
}

function formatDateTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString(locale(), { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatRelative(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    const diff = (Date.now() - d.getTime()) / 1000;
    const abs = Math.abs(diff);
    let txt;
    if (abs < 60) txt = t('rel.less_minute');
    else if (abs < 3600) txt = t('rel.minutes', { n: Math.round(abs / 60) });
    else if (abs < 86400) txt = t('rel.hours', { n: Math.round(abs / 3600) });
    else txt = t('rel.days', { n: Math.round(abs / 86400) });
    return diff < 0 ? t('rel.in', { t: txt }) : t('rel.ago', { t: txt });
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toastContainer.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}


// ─── Dev/Simulation Mode ────────────────────────────────────────────────────
// Quand on ouvre le HTML directement dans un navigateur (sans le backend Python)

function simulateBackend(data) {
    const reply = (event, payload, delay = 150) => setTimeout(() => onBackendMessage({ event, data: payload }), delay);
    switch (data.action) {
        case 'check_status':
            reply('statusUpdate', {
                lang, color: 'green', message: 'Protected — signatures up to date (2 h)', installed: true, fully_installed: true,
                last_update: new Date(Date.now() - 2 * 3600e3).toISOString(),
                last_scan: { date: new Date(Date.now() - 86400e3).toISOString(), path: '/', files: 1234567, infected: 0, duration: 5400, status: 'clean', source: 'daemon', auto: true },
                never_scanned: false, resumable: null,
                history: [{ date: new Date(Date.now() - 86400e3).toISOString(), path: '/', files: 1234567, infected: 0, duration: 5400, status: 'clean', source: 'daemon', auto: true },
                          { date: new Date(Date.now() - 3 * 86400e3).toISOString(), path: '/home', files: 236886, infected: 1, duration: 6756, status: 'infected', source: 'local' }],
                daemon: { available: true, version: '1.5.0', first_scan_pending: false, queue: [], monitor_active: true, usb_active: true },
                schedule: { next_update: new Date(new Date().setHours(31, 0, 0, 0)).toISOString(), timer_active: true },
                system_status: { ok: true, upgradable: 3, security: 2, cve_count: 5, reboot_required: false, checked_at: new Date().toISOString() },
            });
            break;
        case 'get_db_info':
            reply('dbInfo', { files: [
                { name: 'bytecode.cvd', size: '281702', date: '2026-03-21 07:58' },
                { name: 'daily.cld', size: '87045632', date: '2026-09-27 21:40' },
                { name: 'main.cvd', size: '89072577', date: '2026-03-21 07:58' }] });
            break;
        case 'get_quarantine':
            reply('quarantineList', { files: [{ name: 'eicar.com', path: '/var/lib/clamav-antivirus/quarantine/eicar.com', size: 68, date: '2026-09-27 22:40', scope: 'system' }] });
            break;
        case 'get_log':
            reply('logContent', { scope: data.scope, available: true, lines: ['[2026-09-27T22:40:16] ▶ scan /home', '[2026-09-27T22:40:35] /home/user/eicar.com: Eicar-Test-Signature FOUND', '[2026-09-27T22:40:35] ■ done: 1 infected / 3 files'] });
            break;
        case 'get_system_status':
            reply('systemStatus', { available: true, refreshing: false, status: {
                checked_at: new Date().toISOString(), ok: true, os: 'Linux Mint 22.3', kernel: '6.8.0-139-generic', reboot_required: true, reboot_pkgs: ['linux-image-6.8.0-140-generic'],
                lists_updated: new Date(Date.now() - 7200e3).toISOString(), upgradable: 3, security: 2, cve_count: 2,
                packages: [{ name: 'openssl', installed: '3.0.13-0ubuntu3.13', candidate: '3.0.13-0ubuntu3.15', security: true, archive: 'noble-security' }, { name: 'libgd3', installed: '2.3.3-9ubuntu5', candidate: '2.3.3-13', security: false, archive: 'noble' }],
                cves: [{ id: 'CVE-2026-63072', package: 'openssl', installed: '3.0.13-0ubuntu3.13', candidate: '3.0.13-0ubuntu3.15', title: 'Heap Buffer Overflow in CMS Key Unwrapping', url: 'https://ubuntu.com/security/CVE-2026-63072' },
                       { id: 'CVE-2026-54874', package: 'openssl', installed: '3.0.13-0ubuntu3.13', candidate: '3.0.13-0ubuntu3.15', title: 'Excessive Memory Use Buffering DTLS Records', url: 'https://ubuntu.com/security/CVE-2026-54874' }] } });
            break;
        case 'get_alerts':
            reply('alertsList', { available: true, alerts: [{ time: new Date().toISOString(), severity: 'danger', reasons: ['untrusted_home_burst'], pid: 4242, comm: 'cryptolocker', exe: '/home/user/Downloads/cryptolocker', cmdline: './cryptolocker', user: 'user', trusted: false, count: 120, home_count: 120, window: 15, sample: ['/home/user/Documents/a.docx.locked', '/home/user/Documents/b.xlsx.locked'], top_dir: '/home/user/Documents', infected_exe: [], infected_files: [] },
                                                            { time: new Date(Date.now() - 600e3).toISOString(), severity: 'info', reasons: [], pid: 1234, comm: 'apt', exe: '/usr/bin/apt', cmdline: 'apt upgrade', user: 'root', trusted: true, count: 340, home_count: 0, window: 15, sample: ['/usr/lib/x86_64-linux-gnu/libssl.so.3'], top_dir: '/usr/lib/x86_64-linux-gnu', infected_exe: [], infected_files: [] }] });
            break;
        case 'scan': {
            const total = 48213, start = Date.now() / 1000;
            reply('scanStarted', { source: 'daemon', path: data.path, started_at: start, auto: false });
            let found = 0;
            const count = setInterval(() => {
                found = Math.min(total, found + 2400);
                onBackendMessage({ event: 'scanProgress', data: { kind: 'scan', phase: 'counting', found, scanned: 0, total: 0, source: 'daemon', path: data.path, started_at: start } });
                if (found >= total) {
                    clearInterval(count);
                    let n = 0;
                    const tick = setInterval(() => {
                        n = Math.min(total, n + 190 + Math.floor(Math.random() * 90));
                        onBackendMessage({ event: 'scanProgress', data: { kind: 'scan', phase: 'scanning', scanned: n, total, file: `/home/user/Documents/projet/src/module_${n}.py`, infected: n > 20000 ? 1 : 0, denied: 12, source: 'daemon', path: data.path, started_at: start } });
                        if (n > 20000 && !window.__simFound) { window.__simFound = true; onBackendMessage({ event: 'scanLine', data: { kind: 'found', text: '/home/user/Downloads/eicar.com: Eicar-Test-Signature FOUND' } }); }
                        if (n >= total) {
                            clearInterval(tick); window.__simFound = false;
                            onBackendMessage({ event: 'scanDone', data: { status: 'infected', source: 'daemon', message: '1 threat(s) detected — files moved to quarantine', summary: { files: total, infected: 1, denied: 12, errors: 0, duration: Date.now() / 1000 - start, threats: [{ path: '/home/user/Downloads/eicar.com', signature: 'Eicar-Test-Signature' }] } } });
                        }
                    }, 250);
                }
            }, 250);
            break;
        }
        case 'cancel_scan':
            reply('scanDone', { status: 'cancelled', source: 'daemon', message: 'Scan interrupted — can be resumed', summary: {} });
            break;
        case 'update':
            reply('updateStarted', { source: 'daemon' });
            reply('updateLine', { text: '→ freshclam' }, 400);
            reply('updateLine', { text: 'daily.cld database is up-to-date' }, 1200);
            reply('operationResult', { status: 'success', message: 'Virus database is up to date', op: 'update' }, 1800);
            break;
    }
}


// ─── Credits Modal ──────────────────────────────────────────────────────────

function openCredits() {
    $('creditsModal').classList.add('open');
}

function closeCredits(event) {
    if (!event || event.target === event.currentTarget) $('creditsModal').classList.remove('open');
}

function switchCreditsTab(tabId, btn) {
    document.querySelectorAll('.modal-tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.credits-panel').forEach(p => p.classList.remove('active'));
    if (btn) btn.classList.add('active');
    const panel = $(`credits-${tabId}`);
    if (panel) panel.classList.add('active');
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeCredits();
});


// ─── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(location.search);
    const nav = (params.get('lang') || navigator.language || 'en').slice(0, 2).toLowerCase();
    setLanguage(window.I18N && window.I18N[nav] ? nav : 'en');
    renderScanHero();
    if (location.hash && $(`tab-${location.hash.slice(1)}`)) switchTab(location.hash.slice(1));
    sendToBackend({ action: 'check_status' });
    sendToBackend({ action: 'get_db_info' });
    sendToBackend({ action: 'get_quarantine' });
    setInterval(() => { if (currentTab === 'dashboard' && !scan.running) sendToBackend({ action: 'check_status' }); }, 60000);
});
