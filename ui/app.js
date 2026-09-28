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
let viewMode = 'simple';
let securityStatus = null;
let settingsData = null;
let overall = null;
let secData = { vulns: null, checklist: null, integrity: null, persistence: null, connections: null, app_update: null };
let vulnFilter = 'unfixed';
let vulnPrio = 'high';   // priorité minimale affichée : 'high' (critique + haute), 'medium', 'all'
const VULN_PRIO_RANK = { critical: 0, high: 1, medium: 2, low: 3, negligible: 4, untriaged: 5 };
function setVulnPrio(p) { vulnPrio = p; renderVulns(); }
let legalAccepted = true;

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
    ['langSelect', 'langSelectSimple', 'setLanguage'].forEach(id => { const sel = $(id); if (sel && sel.value !== code) sel.value = code; });
    // Re-rendre les zones dynamiques avec la nouvelle langue
    if (lastStatus) updateDashboardStatus(lastStatus);
    renderScanHero();
    if (scan.result) renderScanResults(scan.result);
    renderSystemStatus();
    renderAlerts();
    renderSecurity();
    renderSimpleView();
    renderAdmin();
    if (secData.checklist) renderChecklist();
    if (secData.vulns) renderVulns();
    if (secData.integrity) renderIntegrity();
    if (secData.persistence) renderPersistence();
    if (secData.connections) renderConnections();
    renderAppUpdate();
    if ($('tab-awareness') && $('tab-awareness').classList.contains('active')) renderAwareness('awarenessList');
    if ($('simpleAwareness') && !$('simpleAwareness').hidden) renderAwareness('awarenessListSimple');
    renderLegal();
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
        case 'securityStatus':  onSecurityStatus(data); break;
        case 'settingsData':    onSettingsData(data); break;
        case 'trustedList':     onTrustedList(data); break;
        case 'backupStatus':    onBackupStatus(data); break;
        case 'backupProgress':  onBackupProgress(data); break;
        case 'backupDone':      onBackupDone(data); break;
        case 'backupTimeshift': if (backupData) { backupData.timeshift = data; renderBackupTab(); renderBackupWizard(); } if (lastStatus && lastStatus.backup) { lastStatus.backup.timeshift = data; renderSimpleView(); } break;
        case 'securityData':    onSecurityData(data); break;
        case 'overall':         overall = data; renderSimpleView(); renderAdmin(); break;
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
    if (tabId === 'backup') loadBackup();

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
    } else if (tabId === 'firewall') {
        sendToBackend({ action: 'get_security', refresh: true });
    } else if (tabId === 'settings') {
        loadSettings();
    } else if (tabId === 'security') {
        ['checklist', 'vulns', 'integrity', 'app_update'].forEach(k => loadSecurityData(k));
    }
    if (tabId === 'system') { loadSecurityData('connections'); loadSecurityData('persistence'); }
    if (tabId === 'awareness') renderAwareness('awarenessList');
}


// ─── Bonnes pratiques (sensibilisation) ─────────────────────────────────────

function lessons() {
    const all = window.AWARENESS || {};
    return all[lang] || all.en || all.fr || [];
}

function renderAwareness(containerId, openId) {
    const el = $(containerId);
    if (!el) return;
    el.innerHTML = lessons().map((l, i) => `
        <details class="lesson ${readLessons.has(l.id) ? 'read' : ''}" id="${containerId}-${escapeHtml(l.id)}" data-id="${escapeHtml(l.id)}" ${openId === l.id ? 'open' : ''}>
            <summary>
                <span class="lesson-num">${i + 1}</span>
                <span class="lesson-head"><span class="lesson-title">${escapeHtml(l.title)}</span><span class="lesson-summary">${escapeHtml(l.summary)}</span></span>
                <span class="lesson-read" title="${t('awareness.mark_unread')}" onclick="markLessonUnread(event, '${escapeJs(l.id)}')">✓ ${t('awareness.read')}</span>
                <span class="lesson-more">${t('popup.btn.read_more')}</span>
            </summary>
            <div class="lesson-body">
                ${(l.details || []).map(p => `<p>${escapeHtml(p)}</p>`).join('')}
                ${(l.tips || []).length ? `<h5>${t('awareness.tips')}</h5><ul>${l.tips.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul>` : ''}
            </div>
        </details>`).join('');
    el.querySelectorAll('details.lesson').forEach(d => d.addEventListener('toggle', () => onLessonToggle(d)));
    if (openId) { const d = $(`${containerId}-${openId}`); if (d) onLessonToggle(d); }
}

// Une leçon est « lue » quand elle est restée ouverte au moins 5 secondes (« Lire plus »)
const LESSON_READ_DELAY_MS = 5000;
let readLessons = new Set();

function onLessonToggle(d) {
    clearTimeout(d._readTimer);
    if (!d.open) return;
    d._readTimer = setTimeout(() => { if (d.open && document.body.contains(d)) markLessonRead(d.dataset.id); }, LESSON_READ_DELAY_MS);
}

function markLessonRead(id) {
    if (!id || readLessons.has(id)) return;
    readLessons.add(id);
    updateLessonBadges();
    sendToBackend({ action: 'lesson_read', id });
}

function markLessonUnread(ev, id) {
    ev.preventDefault(); ev.stopPropagation();
    readLessons.delete(id);
    updateLessonBadges();
    sendToBackend({ action: 'lesson_unread', id });
}

function updateLessonBadges() {
    document.querySelectorAll('details.lesson').forEach(d => d.classList.toggle('read', readLessons.has(d.dataset.id)));
}

function showAwareness() {
    $('simpleAwareness').hidden = false;
    document.body.classList.add('awareness-open');
    renderAwareness('awarenessListSimple');
}

function hideAwareness() {
    $('simpleAwareness').hidden = true;
    document.body.classList.remove('awareness-open');
}

/** Appelé par le popup « Lire plus » (Python). */
function openLesson(id) {
    if (viewMode === 'simple') {
        showAwareness();
        renderAwareness('awarenessListSimple', id);
        const el = $(`awarenessListSimple-${id}`);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else {
        switchTab('awareness');
        renderAwareness('awarenessList', id);
        const el = $(`awarenessList-${id}`);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}


// ─── Avertissement juridique ────────────────────────────────────────────────

function legalHtml() {
    const paras = [];
    for (let i = 1; i <= 12; i++) {
        const k = `legal.p${i}`;
        const txt = t(k);
        if (txt !== k) paras.push(`<p>${escapeHtml(txt)}</p>`);
    }
    return paras.join('');
}

function renderLegal() {
    const html = legalHtml();
    if ($('legalText')) $('legalText').innerHTML = html;
    if ($('legalTextCredits')) $('legalTextCredits').innerHTML = html;
}

function openLegal() {
    renderLegal();
    $('legalClose').hidden = !legalAccepted;
    $('legalAccept').hidden = legalAccepted;
    $('legalModal').classList.add('open');
}

function closeLegal() {
    if (!legalAccepted) return;
    $('legalModal').classList.remove('open');
}

function acceptLegal() {
    legalAccepted = true;
    sendToBackend({ action: 'accept_disclaimer' });
    $('legalModal').classList.remove('open');
}


// ─── Centre de sécurité ─────────────────────────────────────────────────────

function loadSecurityData(type, refresh = false, run = false) {
    if (type === 'vulns' && refresh) { $('btnVulnsRefresh').disabled = true; $('vulnsChecked').textContent = t('system.refreshing'); }
    if (type === 'integrity' && run) { $('btnIntegrityRun').disabled = true; }
    sendToBackend({ action: 'get_security_data', type, refresh, run });
}

function onSecurityData(data) {
    const type = data.type;
    if (type === 'integrity_running') { integrityRunning = true; syncScanButtons(); $('btnIntegrityRun').disabled = true; $('integrityList').innerHTML = `<p class="text-muted">${t('security.integrity.running')}</p>`; return; }
    if (type === 'integrity') { integrityRunning = !!data.refreshing; syncScanButtons(); }
    if (type === 'suspended') { if (lastStatus) { lastStatus.suspended = data.data; renderSimpleView(); } return; }
    if (data.available === false) { renderSecurityUnavailable(type); return; }
    if (type === 'integrity' && data.after_scan && data.data && scan.running) setHeroNote((data.data.warnings || 0) ? t('scan.note.integrity_warn', { n: data.data.warnings }) : t('scan.note.integrity_ok'));
    secData[type] = data.data || null;
    if (type === 'vulns') { renderVulns(data.refreshing); }
    else if (type === 'checklist') renderChecklist();
    else if (type === 'integrity') renderIntegrity(data.refreshing);
    else if (type === 'persistence') renderPersistence();
    else if (type === 'connections') renderConnections();
    else if (type === 'app_update') renderAppUpdate();
    renderSecurityBadge();
}

function renderSecurityUnavailable(type) {
    const map = { vulns: 'vulnList', checklist: 'checklistList', integrity: 'integrityList', persistence: 'persistenceList', connections: 'connectionsList' };
    if (map[type]) $(map[type]).innerHTML = `<p class="text-muted">${t('system.unavailable')}</p>`;
    if (type === 'app_update') { $('appUpdateSummary').textContent = t('system.unavailable'); }
}

function renderSecurityBadge() {
    const v = secData.vulns || (lastStatus && lastStatus.vulns_summary);
    const counts = (v && v.counts) || {};
    const n = (counts.unfixed || 0) + (counts.pro_only || 0);
    const b = $('securityBadge');
    if (n > 0) { b.textContent = n > 99 ? '99+' : n; b.style.display = ''; } else b.style.display = 'none';
}

function renderChecklist() {
    const c = secData.checklist || null;
    const banner = $('scoreBanner');
    if (!c) { $('scoreValue').textContent = '—'; $('scoreGrade').textContent = ''; $('checklistList').innerHTML = `<p class="text-muted">${t('security.checklist.none_yet')}</p>`; return; }
    banner.dataset.grade = c.grade || '';
    $('scoreValue').textContent = c.score;
    $('scoreGrade').textContent = c.grade || '';
    $('scoreFill').style.strokeDashoffset = RING_CIRC * (1 - (c.score || 0) / 100);
    $('scoreChecked').textContent = c.checked_at ? t('system.checked', { date: formatDateTime(c.checked_at), rel: formatRelative(c.checked_at) }) : '';
    const items = c.items || [];
    const counts = { ok: 0, warn: 0, fail: 0 };
    items.forEach(i => { if (counts[i.status] !== undefined) counts[i.status]++; });
    $('checklistCounts').textContent = t('security.checklist.counts', { ok: counts.ok, warn: counts.warn, fail: counts.fail });
    const order = { fail: 0, warn: 1, unknown: 2, ok: 3, na: 4 };
    $('checklistList').innerHTML = items.slice().sort((a, b) => order[a.status] - order[b.status] || b.weight - a.weight).map(i => `
        <div class="check-item check-${i.status}">
            <span class="check-icon">${i.status === 'ok' ? '✓' : i.status === 'fail' ? '✕' : i.status === 'warn' ? '!' : '?'}</span>
            <div class="check-text">
                <span class="check-title">${t(`check.${i.key}.title`)}</span>
                <span class="check-detail">${t(`check.${i.key}.${i.status === 'ok' ? 'ok' : 'hint'}`)}${i.detail_key ? ` — ${escapeHtml(t(i.detail_key, i.detail_params || {}))}` : i.detail ? ` — ${escapeHtml(i.detail)}` : ''}</span>
            </div>
            ${i.status !== 'ok' && i.status !== 'na' ? `<button class="btn ${i.status === 'fail' ? 'btn-danger' : 'btn-secondary'} btn-sm check-fix-btn" onclick="fixCheck('${escapeJs(i.key)}')">${CHECK_FIX[i.key] ? t('security.fix') : t('security.fix.how')}</button>` : ''}
            <span class="check-weight">${i.weight}</span>
            ${t(`check.${i.key}.fix`) !== `check.${i.key}.fix` ? `<div class="check-fix" id="fix-${escapeHtml(i.key)}" hidden>${escapeHtml(t(`check.${i.key}.fix`))}</div>` : ''}
        </div>`).join('');
    const ports = c.ports || [];
    $('portsList').innerHTML = `<p class="text-muted ports-intro">${t('ports.intro')}</p>` + (ports.length ? ports.map(p => {
        const v = p.verdict || (p.exposed ? 'reachable' : 'local');
        const hintKey = p.service ? `ports.hint.${p.service}` : `ports.hint.proc.${p.process || ''}`;
        const hint = t(hintKey) !== hintKey ? t(hintKey) : t('ports.hint.generic', { proc: p.process || '?' });
        return `<div class="port-item verdict-${v}">
            <span class="rule-to">${p.port}/${escapeHtml(p.proto)}</span>
            <span class="port-proc">${escapeHtml(p.process || p.service || '')}</span>
            <span class="rule-from">${escapeHtml(p.addr)}</span>
            <span class="scope-badge ${v === 'reachable' ? 'scope-danger' : v === 'filtered' ? 'scope-phased' : 'scope-user'}">${t(`ports.verdict.${v}`)}</span>
            ${v === 'reachable' ? `<button class="btn btn-secondary btn-sm" onclick="firewallQuickDeny(${Number(p.port)}, '${escapeJs(p.proto)}')">${t('ports.block')}</button>` : ''}
            <span class="port-hint">${escapeHtml(hint)}</span>
        </div>`;
    }).join('') : `<p class="text-muted">${t('security.ports.none')}</p>`);
}

function setVulnFilter(f) {
    vulnFilter = f;
    document.querySelectorAll('#vulnFilter .seg-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === f));
    renderVulns();
}

function renderVulns(refreshing = false) {
    const v = secData.vulns;
    $('btnVulnsRefresh').disabled = !!refreshing;
    if (!v || !v.checked_at) { $('vulnsChecked').textContent = refreshing ? t('system.refreshing') : ''; $('vulnList').innerHTML = `<p class="text-muted">${refreshing ? t('system.refreshing') : t('security.vulns.none_yet')}</p>`; $('vulnSummary').innerHTML = ''; return; }
    $('vulnsChecked').textContent = (refreshing ? t('system.refreshing') + ' · ' : '') + t('system.checked', { date: formatDateTime(v.checked_at), rel: formatRelative(v.checked_at) }) + (v.ok === false ? ` · ${t('security.vulns.error', { error: v.error || '' })}` : '');
    const c = v.counts || {};
    const bp = v.by_priority || {};
    $('vulnSummary').innerHTML = [
        ['unfixed', c.unfixed || 0, 'danger'], ['pro_only', c.pro_only || 0, 'warn'], ['fix_available', c.fix_available || 0, 'info'],
    ].map(([k, n, cls]) => `<div class="stat ${n && cls === 'danger' ? 'has-threats' : n && cls === 'warn' ? 'has-warning' : ''}"><span class="stat-value">${formatNumber(n)}</span><span class="stat-label">${t(`security.vulns.${k === 'pro_only' ? 'pro' : k}`)}</span></div>`).join('')
        + ['critical', 'high', 'medium', 'low'].map(pr => `<div class="stat"><span class="stat-value">${formatNumber(bp[pr] || 0)}</span><span class="stat-label">${t(`priority.${pr}`)}</span></div>`).join('')
        + `<div class="stat"><span class="stat-value">${formatNumber(v.sources || 0)}</span><span class="stat-label">${t('security.vulns.sources')}</span></div>`;
    const maxRank = vulnPrio === 'all' ? 99 : vulnPrio === 'medium' ? 2 : 1;
    const items = (v.items || []).filter(i => i.status === vulnFilter && (VULN_PRIO_RANK[i.priority] ?? 5) <= maxRank);
    const hidden = (v.items || []).filter(i => i.status === vulnFilter).length - items.length;
    if ($('vulnPrio')) $('vulnPrio').value = vulnPrio;
    if ($('vulnHidden')) $('vulnHidden').textContent = hidden > 0 ? t('security.vulns.hidden', { n: hidden }) : '';
    $('vulnList').innerHTML = items.length ? items.slice(0, 300).map(i => `
        <div class="cve-item vuln-${i.status} prio-${i.priority}">
            <div class="cve-head">
                <a class="cve-id" href="#" onclick="sendToBackend({action:'open_url', url:'${escapeJs(i.url)}'}); return false;">${escapeHtml(i.cve)}</a>
                <span class="scope-badge prio-badge prio-${i.priority}">${t(`priority.${i.priority}`) !== `priority.${i.priority}` ? t(`priority.${i.priority}`) : escapeHtml(i.priority)}</span>
                <span class="scope-badge scope-system">${escapeHtml(i.package)}</span>
                <span class="cve-versions">${escapeHtml(i.installed)}${i.fixed ? ` → ${escapeHtml(i.fixed)}` : ''}</span>
                ${i.cvss ? `<span class="cve-versions">${escapeHtml(i.cvss)}</span>` : ''}
            </div>
            <div class="cve-title">${escapeHtml(i.summary || '')}</div>
        </div>`).join('') + (items.length > 300 ? `<p class="text-muted">+${items.length - 300}</p>` : '') : `<p class="text-muted">${t('security.vulns.none_in_filter')}</p>`;
    const store = [...(v.flatpak || []).map(x => ({ ...x, kind: 'Flatpak' })), ...(v.snap || []).map(x => ({ ...x, kind: 'Snap' }))];
    $('storeUpdates').innerHTML = store.length ? `<h5 class="sub-title">${t('security.vulns.store_updates')}</h5>` + store.map(x => `<div class="package-item"><span class="package-name">${escapeHtml(x.name)}</span><span class="package-versions">${escapeHtml(x.id)} · ${escapeHtml(x.version)}</span><span class="scope-badge scope-user">${x.kind}</span></div>`).join('') : '';
}

function renderIntegrity(running = false) {
    const it = secData.integrity;
    $('btnIntegrityRun').disabled = !!running;
    if (!it || !it.checked_at) { $('integrityList').innerHTML = `<p class="text-muted">${running ? t('security.integrity.running') : t('security.integrity.none_yet')}</p>`; $('btnInstallTools').hidden = true; return; }
    const tools = it.tools || {};
    const missing = Object.keys(tools).filter(k => !tools[k].installed);
    $('btnInstallTools').hidden = !missing.length;
    let html = `<div class="text-muted">${t('system.checked', { date: formatDateTime(it.checked_at), rel: formatRelative(it.checked_at) })}</div>`;
    for (const [name, tl] of Object.entries(tools)) {
        const st = !tl.installed ? 'unknown' : (tl.warnings || []).length ? 'warn' : 'ok';
        html += `<div class="check-item check-${st}"><span class="check-icon">${st === 'ok' ? '✓' : st === 'warn' ? '!' : '?'}</span><div class="check-text"><span class="check-title">${escapeHtml(name)}</span><span class="check-detail">${!tl.installed ? t('security.integrity.not_installed') : (tl.warnings || []).length ? t('security.integrity.warnings', { n: tl.warnings.length }) : t('security.integrity.clean')}</span>${(tl.warnings || []).length ? `<details class="alert-sample"><summary>${t('popup.btn.details')}</summary>${tl.warnings.map(w => `<div>${escapeHtml(w)}</div>`).join('')}</details>` : ''}</div></div>`;
    }
    const app = it.app || {};
    const appSt = !app.available ? 'unknown' : (app.modified || []).length || (app.missing || []).length ? 'fail' : 'ok';
    html += `<div class="check-item check-${appSt}"><span class="check-icon">${appSt === 'ok' ? '✓' : appSt === 'fail' ? '✕' : '?'}</span><div class="check-text"><span class="check-title">${t('security.integrity.app')}</span><span class="check-detail">${!app.available ? t('security.integrity.app_no_manifest') : appSt === 'ok' ? t('security.integrity.app_ok', { n: app.count, signed: app.signed ? (app.verified ? t('security.integrity.signed_ok') : t('security.integrity.signed_bad')) : t('security.integrity.unsigned') }) : t('security.integrity.app_modified', { n: (app.modified || []).length + (app.missing || []).length })}</span>${(app.modified || []).concat(app.missing || []).length ? `<details class="alert-sample"><summary>${t('popup.btn.details')}</summary>${(app.modified || []).map(f => `<div>${escapeHtml(f)}</div>`).join('')}${(app.missing || []).map(f => `<div>${escapeHtml(f)} (${t('security.integrity.missing')})</div>`).join('')}</details>` : ''}</div></div>`;
    $('integrityList').innerHTML = html;
}

function renderAppUpdate() {
    const u = secData.app_update || (lastStatus && lastStatus.app_update) || null;
    const card = $('cardAppUpdate');
    const badge = $('appUpdateBadge');
    const current = (u && u.current) || (lastStatus && lastStatus.version) || '';
    if (!u || !u.checked_at) {
        card.dataset.state = 'unknown'; badge.textContent = t('simple.unknown'); badge.className = 'badge';
        $('appUpdateSummary').textContent = t('security.update.never', { current });
        $('btnInstallUpdate').hidden = true;
    } else if (u.error && !u.available) {
        card.dataset.state = 'error'; badge.textContent = t('security.update.error_badge'); badge.className = 'badge badge-amber';
        $('appUpdateSummary').textContent = t('security.update.error', { current, error: u.error.startsWith('download') ? t('security.update.unreachable') : u.error.startsWith('signature') ? t('security.update.bad_signature') : u.error });
        $('btnInstallUpdate').hidden = true;
    } else if (u.available) {
        card.dataset.state = 'available'; badge.textContent = u.version; badge.className = 'badge badge-blue';
        $('appUpdateSummary').textContent = t('security.update.available', { version: u.version, current, size: formatSize(u.size || 0), date: u.date ? formatDateTime(u.date) : '' }) + (u.verified ? ` · ${t('security.update.verified')}` : '');
        $('btnInstallUpdate').hidden = !(u.verified && u.downloaded);
    } else {
        card.dataset.state = 'ok'; badge.textContent = t('security.update.uptodate_badge'); badge.className = 'badge badge-green';
        $('appUpdateSummary').textContent = t('security.update.uptodate', { current, rel: formatRelative(u.checked_at) }) + (u.verified ? ` · ${t('security.update.verified')}` : '');
        $('btnInstallUpdate').hidden = true;
    }
    $('appUpdateRepo').textContent = t('security.update.repo_hint');
}

function renderConnections() {
    const c = secData.connections;
    const el = $('connectionsList');
    if (!c) { el.innerHTML = `<p class="text-muted">${t('system.unavailable')}</p>`; return; }
    $('connectionsChecked').textContent = c.checked_at ? t('system.connections.checked', { rel: formatRelative(c.checked_at), n: c.blocklist_size || 0 }) : '';
    const procs = c.processes || [];
    el.innerHTML = procs.length ? procs.map(p => `
        <div class="conn-item ${p.trusted === false ? 'untrusted' : ''}">
            <div class="conn-head">
                <span class="alert-program">${escapeHtml(p.comm)}</span>
                <span class="alert-meta">pid ${p.pid}${p.user ? ` · ${escapeHtml(p.user)}` : ''}</span>
                ${p.trusted === false ? `<span class="scope-badge scope-danger">${t('system.alert.untrusted')}</span>` : p.trusted ? `<span class="scope-badge scope-user">${t('system.connections.trusted')}</span>` : ''}
                <span class="alert-exe conn-exe">${escapeHtml(p.exe || '')}${p.exe_replaced ? ` · ${t('system.exe_replaced')}` : ''}</span>
                ${p.trusted === false && p.exe ? `<button class="btn btn-secondary btn-sm" onclick="trustProgram('${escapeJs(p.exe)}','${escapeJs(p.comm || '')}')">${t('popup.btn.its_me')}</button>` : ''}
            </div>
            <div class="conn-remotes">${Object.values(p.remotes || {}).map(r => `<span class="conn-remote ${r.flagged ? 'flagged' : ''}" title="${escapeHtml(r.org || '')}">${r.country ? `<span class="conn-flag">${escapeHtml(r.country)}</span>` : ''}${escapeHtml(r.ip)}:${(r.ports || []).join(',')}${r.org ? ` <em>${escapeHtml(r.org)}</em>` : ''}${r.flagged ? ` <strong>${t('system.connections.flagged')}</strong>` : ''}</span>`).join('')}</div>
        </div>`).join('') : `<p class="text-muted">${t('system.connections.none')}</p>`;
}

function renderPersistence() {
    const p = secData.persistence;
    if (!p) { $('persistenceList').innerHTML = `<p class="text-muted">${t('system.unavailable')}</p>`; $('extensionsList').innerHTML = ''; return; }
    $('persistenceChecked').textContent = p.checked_at ? t('system.checked', { date: formatDateTime(p.checked_at), rel: formatRelative(p.checked_at) }) : '';
    const items = (p.items || []).slice().sort((a, b) => (a.trusted === b.trusted) ? a.kind.localeCompare(b.kind) : (a.trusted ? 1 : -1));
    $('persistenceList').innerHTML = items.length ? items.slice(0, 200).map(i => `
        <div class="package-item ${i.trusted ? '' : 'security'}">
            <span class="scope-badge scope-user">${t(`persist.${i.kind}`) !== `persist.${i.kind}` ? t(`persist.${i.kind}`) : escapeHtml(i.kind)}</span>
            <span class="package-name">${escapeHtml(i.name)}</span>
            <span class="package-versions" title="${escapeHtml(i.path)}">${escapeHtml(i.exec || i.path)}</span>
            ${i.user ? `<span class="alert-meta">${escapeHtml(i.user)}</span>` : ''}
            ${i.approved ? `<span class="scope-badge scope-user" title="${escapeHtml(i.key || '')}">${t('system.persistence.approved')}</span> <button class="btn btn-secondary btn-sm" onclick="acknowledgePersistence('${escapeJs(i.key || '')}', true)">${t('settings.trusted.remove')}</button>` : i.trusted ? `<span class="scope-badge scope-user">${escapeHtml(i.owner || t('system.connections.trusted'))}</span>` : `<span class="scope-badge scope-danger">${t('system.persistence.unknown')}</span> <button class="btn btn-secondary btn-sm" onclick="acknowledgePersistence('${escapeJs(i.key || '')}')">${t('popup.btn.its_me')}</button>`}
        </div>`).join('') : `<p class="text-muted">${t('system.persistence.none')}</p>`;
    const exts = p.extensions || [];
    $('extensionsList').innerHTML = exts.length ? exts.map(e => `
        <div class="package-item ${e.from_store ? '' : 'security'}">
            <span class="scope-badge scope-user">${escapeHtml(e.browser)}</span>
            <span class="package-name">${escapeHtml(e.name)}</span>
            <span class="package-versions">${escapeHtml(e.id)} · ${escapeHtml(e.version)}${e.enabled === false ? ` · ${t('system.extensions.disabled')}` : ''}</span>
            <span class="alert-meta">${escapeHtml(e.user)}</span>
            ${e.approved ? `<span class="scope-badge scope-user">${t('system.persistence.approved')}</span> <button class="btn btn-secondary btn-sm" onclick="acknowledgePersistence('${escapeJs(e.key || '')}', true)">${t('settings.trusted.remove')}</button>` : e.from_store ? `<span class="scope-badge scope-user">${t('system.extensions.store')}</span>` : `<span class="scope-badge scope-danger">${t('system.extensions.outside_store')}</span> <button class="btn btn-secondary btn-sm" onclick="acknowledgePersistence('${escapeJs(e.key || '')}')">${t('popup.btn.its_me')}</button>`}
        </div>`).join('') : `<p class="text-muted">${t('system.extensions.none')}</p>`;
}


// ─── Session administrateur ─────────────────────────────────────────────────

function renderAdmin() {
    const pill = $('adminPill');
    if (!pill) return;
    const d = (lastStatus && lastStatus.daemon) || {};
    pill.hidden = !d.available;
    if (!d.available) return;
    const unlocked = !!(lastStatus && lastStatus.unlocked);
    const family = !!(lastStatus && lastStatus.family_mode);
    $('adminText').textContent = unlocked ? t('admin.unlocked') : (family ? t('admin.locked_family') : t('admin.locked'));
    pill.classList.toggle('unlocked', unlocked);
    $('btnAdminToggle').textContent = unlocked ? t('admin.lock') : t('admin.unlock');
}

function toggleAdmin() {
    if (lastStatus && lastStatus.unlocked) sendToBackend({ action: 'lock' });
    else sendToBackend({ action: 'unlock' });
}


// ─── Vue simple / avancée ───────────────────────────────────────────────────

function setViewMode(mode, persist = true) {
    viewMode = mode === 'advanced' ? 'advanced' : 'simple';
    document.body.classList.toggle('mode-simple', viewMode === 'simple');
    if (viewMode === 'simple') renderSimpleView();
    if (persist) sendToBackend({ action: 'set_view_mode', mode: viewMode });
}

function simpleOverall() {
    const d = (lastStatus && lastStatus.daemon) || {};
    const sec = securityStatus || (lastStatus && lastStatus.security) || null;
    const sys = systemStatus || (lastStatus && lastStatus.system_status) || null;
    const rows = [];
    let worst = 'ok';
    const bump = (st) => { if (st === 'danger') worst = 'danger'; else if (st === 'warn' && worst !== 'danger') worst = 'warn'; };

    // Antivirus / signatures
    const color = lastStatus ? lastStatus.color : 'green';
    const avState = !lastStatus ? 'neutral' : color === 'green' ? 'ok' : color === 'blue' ? 'warn' : 'danger';
    bump(avState);
    rows.push({ state: avState, label: t('simple.row.antivirus'),
        value: !lastStatus ? t('sidebar.loading') : (lastStatus.installed === false ? t('status.not_installed') : (color === 'green' ? t('simple.av.ok', { rel: formatRelative(lastStatus.last_update) }) : lastStatus.message)),
        action: color === 'green' ? null : { label: t('dash.action.update'), fn: 'triggerUpdate()' } });

    // Surveillance (service)
    const svc = d.available ? 'ok' : 'warn';
    bump(svc);
    rows.push({ state: svc, label: t('simple.row.service'),
        value: d.available ? (d.monitor_active ? t('simple.service.ok') : t('simple.service.partial')) : t('simple.service.off') });

    // Pare-feu
    let fwState = 'neutral', fwValue = t('simple.unknown'), fwAction = null;
    if (sec && sec.ufw) {
        if (!sec.ufw.installed) { fwState = 'warn'; fwValue = t('firewall.not_installed'); }
        else if (sec.ufw.active) { fwState = 'ok'; fwValue = t('simple.fw.ok') + (sec.ufw.profile ? ` · ${t(`firewall.profile.${sec.ufw.profile}`)}` : ''); }
        else { fwState = 'warn'; fwValue = t('simple.fw.off'); fwAction = { label: t('simple.enable'), fn: 'firewallToggle(true)' }; }
    }
    bump(fwState === 'neutral' ? 'ok' : fwState);
    rows.push({ state: fwState, label: t('simple.row.firewall'), value: fwValue, action: fwAction });

    // SSH
    let sshState = 'ok', sshValue = t('simple.ssh.off');
    if (sec && sec.ssh) {
        if (sec.ssh.active) { sshState = 'warn'; sshValue = t('simple.ssh.on', { port: sec.ssh.port }); }
        else if (!sec.ssh.installed) { sshValue = t('simple.ssh.not_installed'); }
    }
    bump(sshState);
    rows.push({ state: sshState, label: t('simple.row.ssh'), value: sshValue,
        action: sshState === 'warn' ? { label: t('simple.disable'), fn: 'sshToggle(false)' } : null });

    // Mises à jour système
    const sysState = systemState(sys);
    const sysRowState = sysState === 'security' ? 'danger' : (sysState === 'reboot' || sysState === 'updates') ? 'warn' : sysState === 'ok' ? 'ok' : 'neutral';
    bump(sysRowState === 'neutral' ? 'ok' : sysRowState);
    const sysLabels = { unknown: t('dash.system.unknown'), ok: systemOkLabel(sys), updates: t('dash.system.updates', { n: sys ? sys.upgradable : 0 }), security: t('dash.system.security', { n: sys ? sys.security : 0, cves: sys ? (sys.cve_count || 0) : 0 }), reboot: t('dash.system.reboot') };
    const vs = (lastStatus && lastStatus.vulns_summary) || null;
    const openVulns = vs && vs.counts ? (vs.counts.unfixed || 0) + (vs.counts.pro_only || 0) : 0;
    let sysValue = sysLabels[sysState];
    if (sysState === 'ok' && openVulns) sysValue = t('simple.vulns_open', { n: openVulns });
    rows.push({ state: sysRowState === 'ok' && openVulns ? 'warn' : sysRowState, label: t('simple.row.system'), value: sysValue,
        action: (sysState === 'security' || sysState === 'updates') ? { label: t('simple.update_system'), fn: "sendToBackend({action:'system_upgrade'})" } : (openVulns ? { label: t('popup.btn.details'), fn: "setViewMode('advanced'); switchTab('security')" } : null) });

    // Menaces / quarantaine
    const danger = alerts.find(a => a.severity === 'danger');
    const lastScan = lastStatus && lastStatus.last_scan;
    let thrState = 'ok', thrValue = t('simple.threats.none');
    const suspended = (lastStatus && lastStatus.suspended) || [];
    if (suspended.length) { thrState = 'danger'; thrValue = t('simple.threats.suspended', { program: suspended[0].comm || '?' }); }
    else if (danger) { thrState = 'danger'; thrValue = t('simple.threats.danger', { program: danger.comm || '?' }); }
    else if (lastScan && lastScan.infected > 0) { thrState = 'warn'; thrValue = t('simple.threats.quarantined', { n: lastScan.infected }); }
    bump(thrState);
    rows.push({ state: thrState, label: t('simple.row.threats'), value: thrValue,
        action: thrState !== 'ok' ? { label: t('popup.btn.details'), fn: danger ? "setViewMode('advanced'); switchTab('system')" : "setViewMode('advanced'); switchTab('quarantine')" } : null });

    // Sauvegardes (disponibilité)
    const bk = backupRowInfo();
    bump(bk.state === 'neutral' ? 'ok' : bk.state);
    rows.push({ state: bk.state, label: t('simple.row.backup'), value: bk.value, action: bk.action });

    return { worst, rows };
}

function renderSimpleView() {
    const view = $('simpleView');
    if (!view) return;
    let { worst, rows } = simpleOverall();
    if (overall && overall.color) {
        const map = { green: 'ok', yellow: 'warn', blue: 'warn', red: 'danger' };
        const rank = { ok: 0, warn: 1, danger: 2 };
        const o = map[overall.color] || 'ok';
        worst = (rank[o] || 0) >= (rank[worst] || 0) ? o : worst;   // le pire des deux : service + vue (sauvegardes)
    }
    view.dataset.state = worst;
    $('simpleTitle').textContent = t(`simple.title.${worst}`);
    $('simpleSub').textContent = t(`simple.sub.${worst}`);
    $('simpleRows').innerHTML = rows.map(r => `
        <li class="simple-row" data-state="${r.state}">
            <span class="simple-row-icon">${r.state === 'ok' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="5,12 10,17 19,7"/></svg>' : r.state === 'neutral' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="12" y1="5" x2="12" y2="14"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>'}</span>
            <span class="simple-row-text"><span class="simple-row-label">${escapeHtml(r.label)}</span><span class="simple-row-value" title="${escapeHtml(r.value)}">${escapeHtml(r.value)}</span></span>
            ${r.action ? `<button class="btn ${r.state === 'danger' ? 'btn-danger' : 'btn-secondary'} btn-sm" onclick="${r.action.fn}">${escapeHtml(r.action.label)}</button>` : ''}
        </li>`).join('');
    const ls = lastStatus && lastStatus.last_scan;
    $('simpleLastScan').textContent = ls ? t('simple.last_scan', { rel: formatRelative(ls.date) }) : t('simple.never_scanned');
    $('simpleScanBtn').disabled = scan.running;
    syncSimpleScan();
}

function syncSimpleScan() {
    const box = $('simpleScan');
    if (!box) return;
    box.hidden = !scan.running;
    if (!scan.running) return;
    const pct = scanPercent();
    $('simpleScanTitle').textContent = scan.phase === 'counting' ? t('dash.live.counting') : scan.phase === 'integrity' ? t('scan.integrity_running') : t('topbar.scanning', { path: scanTargetLabel() });
    $('simpleScanCount').textContent = scan.phase === 'scanning' ? `${Math.floor(pct)} % · ${$('statEta').textContent}` : t('history.files', { n: formatNumber(scan.found) });
    $('simpleScanFill').style.width = `${pct}%`;
}


// ─── Pare-feu & SSH ─────────────────────────────────────────────────────────

function onSecurityStatus(data) {
    if (data.available === false) { securityStatus = null; renderSecurity(false); renderFirewallProfile(null); return; }
    securityStatus = data.security || null;
    renderSecurity(true);
    renderFirewallProfile(securityStatus ? securityStatus.ufw : null);
    renderSimpleView();
}

// ─── Profil réseau du pare-feu : Maison / Public / Entreprise ───────────────

function setFirewallProfile(profile) {
    sendToBackend({ action: 'security_action', cmd: 'firewall_profile', profile });
    showToast(t('firewall.profile.applying', { profile: t(`firewall.profile.${profile}`) }), 'info');
}

function renderFirewallProfile(ufw) {
    const cur = (ufw && ufw.profile) || '';
    document.querySelectorAll('.profile-btn').forEach(b => { b.classList.toggle('active', b.dataset.profile === cur); b.disabled = !ufw || !ufw.installed; });
    if ($('fwProfileCurrent')) $('fwProfileCurrent').textContent = cur ? t('firewall.profile.current', { profile: t(`firewall.profile.${cur}`) }) : t('firewall.profile.none');
    const profiles = (ufw && ufw.profiles) || {};
    ['home', 'public', 'enterprise'].forEach(p => {
        const el = $(`fwProfilePreview_${p}`);
        if (!el) return;
        const info = profiles[p];
        if (!info) { el.textContent = ''; return; }
        const svc = (info.services || []).map(x => t(`firewall.profile.svc.${x}`) !== `firewall.profile.svc.${x}` ? t(`firewall.profile.svc.${x}`) : x);
        el.textContent = svc.length ? t('firewall.profile.preview', { services: svc.join(', '), nets: (info.nets || []).filter(n => !n.includes(':')).join(', ') }) : t('firewall.profile.preview_none');
    });
    const warn = $('fwProfileWarning');
    if (!warn) return;
    const open = ufw && ufw.active ? (ufw.rules || []).filter(r => /ALLOW/i.test(r.action || '') && !/OUT/i.test(r.action || '') && /anywhere/i.test(r.from || '') && !/cav-profile/.test(r.comment || '')) : [];
    warn.hidden = !(cur === 'public' && open.length);
    if (!warn.hidden) warn.textContent = t('firewall.profile.warning', { n: open.length, rules: open.map(r => r.to).join(', ') });
}

function sshPortValue() {
    return securityStatus && securityStatus.ssh ? securityStatus.ssh.port : 22;
}

function renderSecurity(available = true) {
    const sec = securityStatus;
    const card = $('cardFirewall');
    if (!card) return;
    const ufw = sec ? sec.ufw : null;
    const ssh = sec ? sec.ssh : null;

    const fwBadge = $('fwBadge');
    if (!available || !ufw) {
        card.dataset.state = 'unknown';
        fwBadge.textContent = t('simple.unknown'); fwBadge.className = 'badge';
        $('fwSummary').textContent = available ? t('firewall.unknown') : t('system.unavailable');
    } else if (!ufw.installed) {
        card.dataset.state = 'off';
        fwBadge.textContent = t('firewall.not_installed'); fwBadge.className = 'badge badge-amber';
        $('fwSummary').textContent = t('firewall.not_installed_hint');
    } else {
        card.dataset.state = ufw.active ? 'on' : 'off';
        fwBadge.textContent = ufw.active ? t('common.active') : t('common.inactive');
        fwBadge.className = 'badge ' + (ufw.active ? 'badge-green' : 'badge-red');
        $('fwSummary').textContent = ufw.active
            ? t('firewall.summary_on', { incoming: t(`firewall.policy.${ufw.default_incoming || 'deny'}`), outgoing: t(`firewall.policy.${ufw.default_outgoing || 'allow'}`), n: (ufw.rules || []).length })
            : t('firewall.summary_off');
        if (ufw.error === 'root_required') $('fwSummary').textContent += ` — ${t('firewall.root_required')}`;
        if (ufw.default_incoming) $('fwDefaultIn').value = ufw.default_incoming;
        if (ufw.default_outgoing) $('fwDefaultOut').value = ufw.default_outgoing;
    }
    $('btnFwEnable').hidden = !!(ufw && ufw.active);
    $('btnFwDisable').hidden = !(ufw && ufw.active);
    $('fwAllowSshLabel').hidden = !!(ufw && ufw.active) || !(ssh && ssh.installed);
    $('firewallBadge').style.display = (ufw && ufw.installed && !ufw.active) || (ssh && ssh.active && !(ufw && ufw.active)) ? '' : 'none';

    const cardSsh = $('cardSsh');
    const sshBadge = $('sshBadge');
    if (!ssh) {
        cardSsh.dataset.state = 'unknown'; sshBadge.textContent = t('simple.unknown'); sshBadge.className = 'badge';
        $('sshSummary').textContent = '';
    } else if (!ssh.installed) {
        cardSsh.dataset.state = 'off'; sshBadge.textContent = t('firewall.ssh.not_installed'); sshBadge.className = 'badge badge-green';
        $('sshSummary').textContent = t('firewall.ssh.not_installed_hint');
    } else {
        cardSsh.dataset.state = ssh.active ? 'on' : 'off';
        sshBadge.textContent = ssh.active ? t('common.active') : t('common.inactive');
        sshBadge.className = 'badge ' + (ssh.active ? 'badge-amber' : 'badge-green');
        $('sshSummary').textContent = ssh.active
            ? t('firewall.ssh.summary_on', { port: ssh.port, fw: ssh.allowed_by_firewall ? t('firewall.ssh.allowed') : t('firewall.ssh.blocked') })
            : t('firewall.ssh.summary_off');
    }
    $('btnSshEnable').hidden = !ssh || !ssh.installed || ssh.active;
    $('btnSshDisable').hidden = !ssh || !ssh.active;
    $('btnSshAllow').hidden = !ssh || !ssh.active || ssh.allowed_by_firewall || !(ufw && ufw.active);

    const rules = (ufw && ufw.rules) || [];
    const list = $('ruleList');
    if (!ufw || !ufw.installed) list.innerHTML = '';
    else if (ufw.error === 'root_required') list.innerHTML = `<p class="text-muted">${t('firewall.root_required')}</p>`;
    else if (!rules.length) list.innerHTML = `<p class="text-muted">${t('firewall.rules.none')}</p>`;
    else list.innerHTML = rules.map(r => {
        const act = (r.action || '').split(' ')[0].toLowerCase();
        return `<div class="rule-item">
            <span class="rule-to">${escapeHtml(r.to)}${r.v6 ? ' <span class="scope-badge scope-user">v6</span>' : ''}</span>
            <span class="rule-action ${act}">${escapeHtml(r.action)}</span>
            <span class="rule-from">${escapeHtml(r.from)}</span>
            ${r.comment ? `<span class="rule-comment">${escapeHtml(r.comment)}</span>` : ''}
            <button class="btn btn-danger btn-sm" onclick="firewallDeleteRule(${r.number})">${t('quarantine.delete')}</button>
        </div>`;
    }).join('');
}

function firewallToggle(enabled) {
    if (!enabled && !confirm(t('firewall.confirm_disable'))) return;
    sendToBackend({ action: 'security_action', cmd: 'firewall_set', enabled, allow_ssh: !!($('fwAllowSsh') && $('fwAllowSsh').checked) });
}

function firewallDefaults() {
    sendToBackend({ action: 'security_action', cmd: 'firewall_defaults', incoming: $('fwDefaultIn').value, outgoing: $('fwDefaultOut').value });
}

function firewallAddRule(port, proto, action, comment) {
    if (!port) { showToast(t('firewall.rules.need_port'), 'error'); return; }
    sendToBackend({ action: 'security_action', cmd: 'firewall_rule_add', port, proto, action, comment: comment || '' });
}

function firewallAddRuleFromForm() {
    firewallAddRule($('ruleAddPort').value.trim(), $('ruleAddProto').value, $('ruleAddAction').value, $('ruleAddComment').value.trim());
    $('ruleAddPort').value = ''; $('ruleAddComment').value = '';
}

function firewallDeleteRule(number) {
    if (confirm(t('firewall.rules.confirm_delete', { n: number }))) {
        sendToBackend({ action: 'security_action', cmd: 'firewall_rule_delete', number });
    }
}

function sshToggle(enabled) {
    if (enabled && !confirm(t('firewall.ssh.confirm_enable'))) return;
    sendToBackend({ action: 'security_action', cmd: 'ssh_set', enabled });
}


// ─── Paramètres ─────────────────────────────────────────────────────────────

function loadSettings() {
    sendToBackend({ action: 'get_settings' });
    sendToBackend({ action: 'get_trusted' });
}

// ─── « C'est moi » : programmes et entrées approuvés (plus d'alerte) ─────────

let trustedData = { programs: [], acknowledged: [] };

function trustProgram(exe, comm) { sendToBackend({ action: 'trust_program', exe, comm }); }
function untrustProgram(exe) { sendToBackend({ action: 'untrust_program', exe }); }
function acknowledgePersistence(key, remove = false) { sendToBackend({ action: 'acknowledge_persistence', key, remove }); }

function onTrustedList(data) {
    trustedData = { programs: (data && data.programs) || [], acknowledged: (data && data.acknowledged) || [] };
    renderTrusted();
}

function renderTrusted() {
    const el = $('trustedList');
    if (!el) return;
    const progs = trustedData.programs, ack = trustedData.acknowledged;
    if (!progs.length && !ack.length) { el.innerHTML = `<p class="text-muted">${t('settings.trusted.none')}</p>`; return; }
    el.innerHTML = [
        ...progs.map(p => `<div class="package-item">
            <span class="scope-badge scope-user">${t('settings.trusted.program')}</span>
            <span class="package-name">${escapeHtml(p.comm || '')}</span>
            <span class="package-versions" title="${escapeHtml(p.exe)}">${escapeHtml(p.exe)}</span>
            <span class="alert-meta">${escapeHtml(p.by || '')}${p.added ? ` · ${formatDateTime(p.added)}` : ''}</span>
            <button class="btn btn-secondary btn-sm" onclick="untrustProgram('${escapeJs(p.exe)}')">${t('settings.trusted.remove')}</button>
        </div>`),
        ...ack.map(k => `<div class="package-item">
            <span class="scope-badge scope-user">${t('settings.trusted.persistence')}</span>
            <span class="package-versions" title="${escapeHtml(k)}">${escapeHtml(k)}</span>
            <button class="btn btn-secondary btn-sm" onclick="acknowledgePersistence('${escapeJs(k)}', true)">${t('settings.trusted.remove')}</button>
        </div>`),
    ].join('');
}

function onSettingsData(data) {
    settingsData = data;
    const sys = data.system || {};
    const user = data.user || {};
    $('setLanguage').value = user.language || lang;
    $('setViewMode').value = user.view_mode || viewMode;
    const p = user.popups || {};
    $('setPopupInfo').checked = p.info !== false;
    $('setPopupUpload').checked = p.upload !== false;
    $('setPopupScan').checked = p.scan !== false;
    $('setPopupUpdate').checked = p.update !== false;
    $('setPopupSecurity').checked = p.security !== false;
    if ($('setPopupTip')) $('setPopupTip').checked = p.tip !== false;
    $('setUploadMonitor').checked = sys.upload_monitor !== false;
    $('setUploadGb').value = sys.upload_alert_gb ?? 5;
    $('setUploadHours').value = sys.upload_window_hours ?? 1;
    $('setBurstMonitor').checked = sys.burst_monitor !== false;
    $('setBurstInfo').value = sys.burst_info_threshold ?? 50;
    $('setBurstDanger').value = sys.burst_danger_threshold ?? 25;
    $('setBurstWindow').value = sys.burst_window_sec ?? 15;
    $('setUsbAuto').checked = sys.usb_auto_scan !== false;
    $('setUsbMax').value = sys.usb_auto_scan_max_gib ?? 128;
    $('setUpdateTime').value = `${String(sys.update_hour ?? 7).padStart(2, '0')}:${String(sys.update_minute ?? 0).padStart(2, '0')}`;
    $('setFamilyMode').checked = !!sys.family_mode;
    $('setAutoResponse').checked = sys.auto_response !== false;
    $('setConnectionMonitor').checked = sys.connection_monitor !== false;
    $('setGeoip').checked = sys.geoip_lookup !== false;
    if ($('setGeoipKey')) $('setGeoipKey').value = sys.geoip_api_key || '';
    if ($('geoipStats')) {
        const g = data.stats && data.stats.geoip;
        $('geoipStats').textContent = g ? t('settings.geoip.stats', { n: g.requests_24h || 0, cached: g.cached || 0, provider: t(g.provider === 'pro' ? 'settings.geoip.pro' : 'settings.geoip.free') }) + (g.last_error ? ` · ${t('settings.geoip.error', { error: g.last_error })}` : '') : '';
    }
    $('setIntegrityWeekly').checked = sys.integrity_weekly !== false;
    if ($('setBackupCheck')) $('setBackupCheck').checked = sys.backup_check !== false;
    $('setIntegrityDay').value = String(sys.integrity_day ?? 6);
    $('setIntegrityHour').value = sys.integrity_hour ?? 13;
    $('setAppUpdateCheck').checked = sys.app_update_check !== false;
    $('setAppUpdateAuto').checked = !!sys.app_update_auto;
    $('setWeekly').checked = !!sys.weekly_scan;
    $('setWeeklyDay').value = String(sys.weekly_scan_day ?? 6);
    $('setWeeklyHour').value = sys.weekly_scan_hour ?? 12;
    const gb = lastStatus && lastStatus.upload_gb;
    $('setUploadCurrent').textContent = gb != null ? t('settings.upload.current', { gb: Number(gb).toFixed(2), hours: sys.upload_window_hours ?? 1 }) : '';
    $('settingsNote').textContent = data.available === false ? t('settings.daemon_off') : '';
    document.querySelectorAll('#tab-settings input, #tab-settings select').forEach(el => {
        if (el.id.startsWith('setPopup') || el.id === 'setLanguage' || el.id === 'setViewMode') return;
        el.disabled = data.available === false;
    });
}

function saveSettings() {
    const [h, m] = ($('setUpdateTime').value || '07:00').split(':').map(x => parseInt(x, 10));
    const system = {
        upload_monitor: $('setUploadMonitor').checked,
        upload_alert_gb: parseFloat($('setUploadGb').value) || 5,
        upload_window_hours: parseInt($('setUploadHours').value, 10) || 1,
        burst_monitor: $('setBurstMonitor').checked,
        burst_info_threshold: parseInt($('setBurstInfo').value, 10) || 50,
        burst_danger_threshold: parseInt($('setBurstDanger').value, 10) || 25,
        burst_window_sec: parseInt($('setBurstWindow').value, 10) || 15,
        usb_auto_scan: $('setUsbAuto').checked,
        usb_auto_scan_max_gib: parseInt($('setUsbMax').value, 10) || 128,
        update_hour: isNaN(h) ? 7 : h, update_minute: isNaN(m) ? 0 : m,
        weekly_scan: $('setWeekly').checked,
        family_mode: $('setFamilyMode').checked,
        auto_response: $('setAutoResponse').checked,
        connection_monitor: $('setConnectionMonitor').checked,
        geoip_lookup: $('setGeoip').checked,
        geoip_api_key: $('setGeoipKey') ? $('setGeoipKey').value.trim() : '',
        integrity_weekly: $('setIntegrityWeekly').checked,
        backup_check: $('setBackupCheck') ? $('setBackupCheck').checked : true,
        integrity_day: parseInt($('setIntegrityDay').value, 10),
        integrity_hour: parseInt($('setIntegrityHour').value, 10) || 0,
        app_update_check: $('setAppUpdateCheck').checked,
        app_update_auto: $('setAppUpdateAuto').checked,
        weekly_scan_day: parseInt($('setWeeklyDay').value, 10),
        weekly_scan_hour: parseInt($('setWeeklyHour').value, 10) || 0,
    };
    const user = {
        language: $('setLanguage').value,
        view_mode: $('setViewMode').value,
        popups: { info: $('setPopupInfo').checked, upload: $('setPopupUpload').checked, scan: $('setPopupScan').checked,
                  update: $('setPopupUpdate').checked, security: $('setPopupSecurity').checked,
                  tip: $('setPopupTip') ? $('setPopupTip').checked : true },
    };
    sendToBackend({ action: 'set_settings', system, user });
}


// ─── Dashboard ──────────────────────────────────────────────────────────────

function updateDashboardStatus(data) {
    lastStatus = data;
    if (data.lang && data.lang !== lang) setLanguage(data.lang);
    if (data.view_mode && data.view_mode !== viewMode) setViewMode(data.view_mode, false);
    if (data.security) securityStatus = data.security;
    if (data.overall) overall = data.overall;
    if (Array.isArray(data.read_lessons)) { readLessons = new Set(data.read_lessons); updateLessonBadges(); }
    if (data.app_update && !secData.app_update) secData.app_update = data.app_update;
    if (data.disclaimer_accepted === false && legalAccepted) { legalAccepted = false; openLegal(); }
    else if (data.disclaimer_accepted === true) legalAccepted = true;
    renderAdmin();
    renderSecurityBadge();
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

    // Pare-feu / SSH (résumé)
    const sec = securityStatus;
    const netIcon = $('protNetIcon');
    if (sec && sec.ufw) {
        const fwOk = sec.ufw.active;
        const sshOn = sec.ssh && sec.ssh.active;
        $('protNetwork').textContent = `${fwOk ? t('simple.fw.ok') : (sec.ufw.installed ? t('simple.fw.off') : t('firewall.not_installed'))} · ${sshOn ? t('simple.ssh.on', { port: sec.ssh.port }) : t('simple.ssh.off')}`;
        $('protNetworkSub').textContent = fwOk && sec.ufw.default_incoming ? t('firewall.summary_on', { incoming: t(`firewall.policy.${sec.ufw.default_incoming}`), outgoing: t(`firewall.policy.${sec.ufw.default_outgoing || 'allow'}`), n: (sec.ufw.rules || []).length }) : '';
        netIcon.className = 'protection-icon ' + (fwOk && !sshOn ? 'accent-green' : fwOk ? 'accent-amber' : 'accent-red');
    } else {
        $('protNetwork').textContent = t('simple.unknown');
        $('protNetworkSub').textContent = '';
        netIcon.className = 'protection-icon accent-blue';
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
    renderSecurity(true);
    renderSimpleView();
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

/** « Système à jour », avec les paquets décalés (phasing) ou retenus par apt : on attend notre tour, tout reste vert. */
function systemOkLabel(st) {
    const parts = [];
    if (st && st.phased) parts.push(t('dash.system.phased_note', { n: st.phased }));
    if (st && st.held) parts.push(t('dash.system.held_note', { n: st.held }));
    return t('dash.system.uptodate') + (parts.length ? ' · ' + parts.join(' · ') : '');
}

function renderSystemSummary() {
    const st = systemStatus;
    const state = systemState(st);
    const badge = $('systemBadge');
    const count = st ? (st.security || 0) : 0;
    if (count > 0) { badge.textContent = count; badge.style.display = ''; } else badge.style.display = 'none';
    const labels = {
        unknown: t('dash.system.unknown'),
        ok: systemOkLabel(st),
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
        $('packageList').innerHTML = '';
        $('packageCounts').textContent = '';
        $('btnInstallPhased').hidden = true;
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
    const cat = (p) => p.category || (p.security ? 'security' : 'recommended');
    const nSec = pkgs.filter(p => cat(p) === 'security').length, nRec = pkgs.filter(p => cat(p) === 'recommended').length, nPh = pkgs.filter(p => cat(p) === 'phased').length, nHeld = pkgs.filter(p => cat(p) === 'held').length;
    $('packageCounts').textContent = pkgs.length ? t('system.packages.counts', { security: nSec, recommended: nRec, phased: nPh }) + (nHeld ? ' · ' + t('system.packages.held_count', { n: nHeld }) : '') : '';
    $('btnInstallPhased').hidden = !nPh;
    if (!pkgs.length) {
        $('packageList').innerHTML = `<div class="check-item check-ok"><span class="check-icon">✓</span><div class="check-text"><span class="check-title">${t('system.packages.all_ok')}</span><span class="check-detail">${t('system.packages.all_ok_hint')}</span></div></div>`;
    } else {
        const badge = { security: ['scope-danger', t('system.pkg.security')], recommended: ['scope-system', t('system.pkg.recommended')], phased: ['scope-phased', t('system.pkg.phased')], held: ['scope-held', t('system.pkg.held')] };
        $('packageList').innerHTML = pkgs.slice(0, 80).map(p => {
            const c = cat(p); const [cls, label] = badge[c] || badge.recommended;
            return `
            <div class="package-item ${c}">
                <span class="scope-badge ${cls}">${label}${c === 'phased' && p.phase != null ? ` ${escapeHtml(String(p.phase))}%` : ''}</span>
                <span class="package-name">${escapeHtml(p.name)}</span>
                <span class="package-versions">${escapeHtml(p.installed || '?')} → ${escapeHtml(p.candidate || '?')}</span>
                <span class="scope-badge scope-user">${escapeHtml(p.archive || '')}</span>
            </div>`;
        }).join('') + (pkgs.length > 80 ? `<p class="text-muted">+${pkgs.length - 80}</p>` : '');
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
        if (a.kind === 'connection') {
            return `
        <div class="alert-item ${a.severity === 'danger' ? 'alert-danger' : 'alert-info'}">
            <div class="alert-head">
                <span class="badge ${a.severity === 'danger' ? 'badge-red' : 'badge-amber'}">${a.flagged ? t('system.alert.blocklisted') : t('system.alert.connection')}</span>
                <span class="alert-program">${escapeHtml(a.comm || '?')}</span>
                <span class="alert-meta">${formatDateTime(a.time)} · pid ${a.pid}${a.user ? ` · ${escapeHtml(a.user)}` : ''}</span>
            </div>
            <div class="alert-body">${t('popup.connection.body', { program: escapeHtml(a.comm || '?'), ip: escapeHtml(a.ip || ''), port: escapeHtml(String(a.port || '')), where: escapeHtml([a.country, a.org].filter(Boolean).join(' · ') || '?') })}</div>
            ${a.exe ? `<div class="alert-exe">${escapeHtml(a.exe)}${a.exe_replaced ? ` · ${t('system.exe_replaced')}` : ''}</div>` : ''}
            <div class="alert-actions">${a.flagged || !a.exe ? '' : `<button class="btn btn-secondary btn-sm" onclick="trustProgram('${escapeJs(a.exe)}','${escapeJs(a.comm || '')}')">${t('popup.btn.its_me')}</button> `}${a.suspended ? `<button class="btn btn-danger btn-sm" onclick="sendToBackend({action:'process_action', pid:${a.pid}, action:'kill'})">${t('popup.btn.kill')}</button> <button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'process_action', pid:${a.pid}, action:'continue'})">${t('popup.btn.resume')}</button>` : ''}</div>
        </div>`;
        }
        if (a.kind === 'persistence' || a.kind === 'integrity' || a.kind === 'update') {
            const titles = { persistence: t('popup.persistence.title'), integrity: t('popup.integrity.title'), update: t('popup.appupdate.title', { version: a.title || '' }) };
            return `
        <div class="alert-item ${a.severity === 'warn' ? 'alert-warn' : 'alert-info'}">
            <div class="alert-head">
                <span class="badge ${a.severity === 'warn' ? 'badge-amber' : 'badge-blue'}">${t(`system.alert.${a.kind}`)}</span>
                <span class="alert-program">${escapeHtml(titles[a.kind])}</span>
                <span class="alert-meta">${formatDateTime(a.time)}</span>
            </div>
            <div class="alert-body">${escapeHtml(a.kind === 'update' ? '' : a.title || '')}${a.detail ? ` — ${escapeHtml(a.detail)}` : ''}</div>
        </div>`;
        }
        if (a.kind === 'upload') {
            const procs = (a.processes || []).map(p => `${escapeHtml(p.name)} (${p.connections})`).join(', ');
            return `
        <div class="alert-item alert-info">
            <div class="alert-head">
                <span class="badge badge-blue">${t('system.alert.upload')}</span>
                <span class="alert-program">${t('popup.upload.title')}</span>
                <span class="alert-meta">${formatDateTime(a.time)}</span>
            </div>
            <div class="alert-body">${t('popup.upload.body', { gb: a.gb, hours: a.window_hours, threshold: a.threshold_gb })}</div>
            ${procs ? `<div class="alert-exe">${t('popup.upload.processes', { list: procs })}</div>` : ''}
            <div class="alert-actions"><button class="btn btn-secondary btn-sm" onclick="switchTab('settings')">${t('popup.btn.settings')}</button></div>
        </div>`;
        }
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
            ${a.exe ? `<div class="alert-exe">${escapeHtml(a.exe)}${a.cmdline ? ` — ${escapeHtml(a.cmdline)}` : ''}${a.exe_replaced ? ` · ${t('system.exe_replaced')}` : ''}</div>` : ''}
            ${reasons ? `<div class="alert-reasons">${escapeHtml(reasons)}</div>` : ''}
            ${infected.length ? `<div class="alert-infected">${infected.map(escapeHtml).join('<br>')}</div>` : ''}
            ${(a.sample || []).length ? `<details class="alert-sample"><summary>${t('system.alert.sample', { n: (a.sample || []).length })}</summary>${(a.sample || []).map(p => `<div>${escapeHtml(p)}</div>`).join('')}</details>` : ''}
            <div class="alert-actions"><button class="btn btn-secondary btn-sm" onclick="startScan('${escapeJs(a.top_dir || '/')}')">${t('popup.btn.scan_folder')}</button>${a.exe ? ` <button class="btn btn-secondary btn-sm" onclick="trustProgram('${escapeJs(a.exe)}','${escapeJs(a.comm || '')}')">${t('popup.btn.its_me')}</button>` : ''}${a.suspended ? ` <button class="btn btn-danger btn-sm" onclick="sendToBackend({action:'process_action', pid:${a.pid}, action:'kill'})">${t('popup.btn.kill')}</button> <button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'process_action', pid:${a.pid}, action:'continue'})">${t('popup.btn.resume')}</button>` : ''}</div>
        </div>`;
    }).join('');
}


// ─── Scan : démarrage / annulation ──────────────────────────────────────────

function startFullSystemScan(withIntegrity = false) {
    scan.integrity = !!withIntegrity;
    if (scan.running) { showToast(t('toast.scan_running'), 'info'); if (viewMode === 'advanced') switchTab('scan'); return; }
    toggleInitialScanPrompt(false);
    if (viewMode === 'advanced') switchTab('scan');
    prepareScanUI('/');
    const d = (lastStatus && lastStatus.daemon) || {};
    if (!d.available) setHeroNote(t('scan.note.service_off'));
    sendToBackend({ action: 'scan', path: '/', integrity: !!withIntegrity });
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
    if (data && data.integrity != null) scan.integrity = !!data.integrity;
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
    if (data && data.integrity != null) scan.integrity = !!data.integrity;
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
    const sum = data.summary || {};
    const notes = [];
    if (data.integrity && data.integrity_warnings != null) notes.push(data.integrity_warnings ? t('scan.note.integrity_warn', { n: data.integrity_warnings }) : t('scan.note.integrity_ok'));
    if (sum.skipped) notes.push(t('scan.note.skipped', { n: formatNumber(sum.skipped) }));
    if (notes.length) setHeroNote(notes.join(' · '));

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
        ? (scan.phase === 'counting' ? t('scan.ring.counting_files', { n: formatNumber(scan.found) }) : scan.phase === 'integrity' ? t('scan.ring.integrity') : (scan.phase === 'prepare' ? t('scan.ring.starting') : t('scan.ring.analysis')))
        : (scan.result ? t('scan.ring.done') : '');

    let title, sub;
    if (scan.running) {
        title = scan.phase === 'counting' ? t('scan.counting') : scan.phase === 'integrity' ? t('scan.integrity_running') : scan.phase === 'prepare' ? t('scan.preparing') : t('scan.running');
        sub = scan.phase === 'scanning'
            ? t('scan.sub.scanning', { path: scanTargetLabel(), scanned: formatNumber(scan.scanned), total: formatNumber(scan.total) })
            : scan.phase === 'integrity' ? t('scan.sub.integrity')
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

    const order = ['prepare', 'integrity', 'counting', 'scanning', 'done'];
    const idx = order.indexOf(scan.phase);
    document.querySelectorAll('#scanPhases li').forEach(li => {
        if (li.dataset.phase === 'integrity') li.hidden = !scan.integrity;
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

    syncScanButtons();
    $('scanConsoleDot').style.visibility = scan.running ? 'visible' : 'hidden';
    $('navScanLive').hidden = !scan.running;
    updateSourceBadge();
    syncTopbar();
    syncDashboardLive();
    syncSimpleScan();
    const sb = $('simpleScanBtn');
    if (sb) sb.disabled = scan.running;
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
    scan.ticker = setInterval(() => { if (scan.running) { updateTimeStats(); syncTopbar(); syncSimpleScan(); } }, 1000);
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
    $('scanTopbarTitle').textContent = scan.phase === 'counting' ? t('scan.phase.counting') : scan.phase === 'integrity' ? t('scan.phase.integrity') : (scan.phase === 'prepare' ? t('scan.phase.prepare') : t('topbar.scanning', { path: scanTargetLabel() }));
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
    $('dashScanTitle').textContent = scan.phase === 'counting' ? t('dash.live.counting') : scan.phase === 'integrity' ? t('scan.integrity_running') : t('topbar.scanning', { path: scanTargetLabel() });
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
    if (op === 'settings' || op === 'security') {
        showToast(message, status === 'success' ? 'success' : 'error');
        if (op === 'security') sendToBackend({ action: 'get_security', refresh: true });
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

const DEV_OK = new URLSearchParams(location.search).get('ok') === '1';   // ?ok=1 : simulation « tout est en ordre »
function simulateBackend(data) {
    const reply = (event, payload, delay = 150) => setTimeout(() => onBackendMessage({ event, data: payload }), delay);
    switch (data.action) {
        case 'check_status':
            reply('statusUpdate', {
                backup: { timeshift: { installed: true, configured: DEV_OK, schedule: DEV_OK ? ['daily'] : [], snapshots: DEV_OK ? 5 : null, last: DEV_OK ? new Date(Date.now() - 86400e3).toISOString() : null },
                          user: DEV_OK ? { state: 'ok', last: new Date(Date.now() - 2 * 86400e3).toISOString(), age_days: 2, dest_label: 'SANDISK 32G', destinations: 1 } : { state: 'none', last: null, destinations: 0 }, running: null },
                lang, color: 'green', message: 'Protected — signatures up to date (2 h)', installed: true, fully_installed: true,
                last_update: new Date(Date.now() - 2 * 3600e3).toISOString(),
                last_scan: { date: new Date(Date.now() - 86400e3).toISOString(), path: '/', files: 1234567, infected: 0, duration: 5400, status: 'clean', source: 'daemon', auto: true },
                never_scanned: false, resumable: null,
                history: [{ date: new Date(Date.now() - 86400e3).toISOString(), path: '/', files: 1234567, infected: 0, duration: 5400, status: 'clean', source: 'daemon', auto: true },
                          { date: new Date(Date.now() - 3 * 86400e3).toISOString(), path: '/home', files: 236886, infected: 1, duration: 6756, status: 'infected', source: 'local' }],
                daemon: { available: true, version: '1.8.0', first_scan_pending: false, queue: [], monitor_active: true, usb_active: true },
                schedule: { next_update: new Date(new Date().setHours(31, 0, 0, 0)).toISOString(), timer_active: true },
                system_status: DEV_OK ? { ok: true, upgradable: 0, security: 0, cve_count: 0, phased: 0, held: 1, reboot_required: false, checked_at: new Date().toISOString() }
                                      : { ok: true, upgradable: 3, security: 2, cve_count: 5, reboot_required: false, checked_at: new Date().toISOString() },
                security: { ufw: { installed: true, active: true, enabled: true, default_incoming: 'deny', default_outgoing: 'allow', rules: [{ number: 1, to: '22/tcp', action: 'ALLOW IN', from: 'Anywhere', v6: false }] }, ssh: { installed: true, active: false, enabled: false, port: 22, allowed_by_firewall: true } },
                view_mode: (new URLSearchParams(location.search).get('view')) || 'advanced', upload_gb: 0.42,
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
                packages: [{ name: 'openssl', installed: '3.0.13-0ubuntu3.13', candidate: '3.0.13-0ubuntu3.15', security: true, category: 'security', archive: 'noble-security' }, { name: 'libgd3', installed: '2.3.3-9ubuntu5', candidate: '2.3.3-13', security: false, category: 'held', archive: 'noble' }, { name: 'gnome-shell', installed: '46.0-0ubuntu1', candidate: '46.0-0ubuntu2', security: false, category: 'phased', phase: 20, archive: 'noble-updates' }], phased: 1, held: 1, recommended: 0,
                cves: [{ id: 'CVE-2026-63072', package: 'openssl', installed: '3.0.13-0ubuntu3.13', candidate: '3.0.13-0ubuntu3.15', title: 'Heap Buffer Overflow in CMS Key Unwrapping', url: 'https://ubuntu.com/security/CVE-2026-63072' },
                       { id: 'CVE-2026-54874', package: 'openssl', installed: '3.0.13-0ubuntu3.13', candidate: '3.0.13-0ubuntu3.15', title: 'Excessive Memory Use Buffering DTLS Records', url: 'https://ubuntu.com/security/CVE-2026-54874' }] } });
            break;
        case 'get_security':
            reply('securityStatus', { available: true, security: { checked_at: new Date().toISOString(),
                ufw: { installed: true, active: true, enabled: true, default_incoming: 'deny', default_outgoing: 'allow', error: '', profile: 'home',
                       profiles: { home: { services: ['cups', 'mdns'], nets: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fe80::/10'] }, public: { services: [], nets: [] }, enterprise: { services: ['cups'], nets: ['192.168.1.0/24', 'fe80::/10'] } }, rules: [
                    { number: 1, to: '22/tcp', action: 'ALLOW IN', from: 'Anywhere', v6: false, comment: 'SSH' },
                    { number: 2, to: '80,443/tcp', action: 'ALLOW IN', from: '192.168.1.0/24', v6: false, comment: '' },
                    { number: 3, to: '22/tcp', action: 'ALLOW IN', from: 'Anywhere', v6: true, comment: '' }] },
                ssh: { installed: true, active: true, enabled: true, port: 22, allowed_by_firewall: true } } });
            break;
        case 'get_trusted':
            reply('trustedList', { programs: [{ exe: '/home/user/bin/backup.sh', comm: 'backup.sh', by: 'user', added: new Date().toISOString() }],
                                   acknowledged: ['autostart:/home/user/.config/autostart/sync.desktop'] });
            break;
        case 'trust_program': case 'untrust_program': case 'acknowledge_persistence':
            reply('operationResult', { status: 'success', message: data.action === 'trust_program' ? t('msg.program_trusted', { program: data.comm || data.exe }) : data.action === 'untrust_program' ? t('msg.program_untrusted') : t('msg.persistence_acknowledged') });
            break;
        case 'system_upgrade':
            reply('operationResult', { status: 'info', message: t('msg.system_upgrading') });
            break;
        case 'backup_status':
            reply('backupStatus', { timeshift: { installed: true, configured: false, schedule: [], snapshots: null, last: null },
                drives: [{ devnode: '/dev/sdb1', label: 'SANDISK 32G', model: 'SanDisk Ultra', mountpoint: '/media/user/SANDISK', uuid: 'AB12-CD34', fstype: 'vfat', size: 32e9, free: 21e9, writable: true, transport: 'usb' }],
                destinations: [{ id: 'd1', type: 'local', label: 'SANDISK 32G', mountpoint: '/media/user/SANDISK', uuid: 'AB12-CD34', fstype: 'vfat', last: new Date(Date.now() - 3 * 86400e3).toISOString(), last_ok: true, available: true },
                               { id: 'd2', type: 'cloud', label: 'swissbackup (Infomaniak Swiss Backup (S3))', remote: 'swissbackup:mon-bucket', provider: 'infomaniak_s3', last: null, last_ok: null, available: true }],
                user: { state: 'ok', last: new Date(Date.now() - 3 * 86400e3).toISOString(), age_days: 3, dest_label: 'SANDISK 32G', destinations: 2, schedule: 'weekly', due: false, sources: 5 },
                sources: ['/home/user/Documents', '/home/user/Images', '/home/user/Vidéos', '/home/user/Musique', '/home/user/Bureau'], excludes: ['.cache', 'node_modules', '*.tmp'], retention: 8, schedule: 'weekly',
                history: [{ ok: true, date: new Date(Date.now() - 3 * 86400e3).toISOString(), dest_label: 'SANDISK 32G', type: 'local', files: 1234, bytes: 2.3e9, duration: 95, auto: false }], rclone: false, remotes: [], running: null, hostuser: 'pc-user', timeshift_installed: true });
            break;
        case 'backup_run': case 'backup_quick':
            reply('backupProgress', { dest_id: data.dest_id || 'd1', dest_label: 'SANDISK 32G', pct: 0, text: '' }, 100);
            reply('backupProgress', { dest_id: data.dest_id || 'd1', dest_label: 'SANDISK 32G', pct: 42, text: '1.2G 42% 35MB/s 0:00:20' }, 900);
            reply('backupDone', { ok: true, dest_label: 'SANDISK 32G', files: 1234, bytes: 2.3e9, duration: 95 }, 2500);
            break;
        case 'get_settings':
            reply('settingsData', { stats: { geoip: { requests_24h: 14, cached: 37, provider: 'free', last_error: '' } }, available: true, system: { upload_monitor: true, upload_alert_gb: 5, upload_window_hours: 1, burst_monitor: true, burst_info_threshold: 50, burst_danger_threshold: 25, burst_window_sec: 15, usb_auto_scan: true, usb_auto_scan_max_gib: 128, update_hour: 7, update_minute: 0, weekly_scan: false, weekly_scan_day: 6, weekly_scan_hour: 12 },
                                    user: { language: lang, view_mode: viewMode, popups: { info: true, upload: true, scan: true, update: true, security: true } } });
            break;
        case 'set_view_mode':
        case 'set_settings':
        case 'security_action':
            reply('operationResult', { status: 'success', message: 'OK', op: data.action === 'security_action' ? 'security' : 'settings' });
            break;
        case 'get_security_data': {
            const now = new Date().toISOString();
            const sim = {
                checklist: { checked_at: now, score: 78, grade: 'B', ports: [{ proto: 'tcp', addr: '0.0.0.0', port: 22, process: 'sshd', service: 'ssh', exposed: true }, { proto: 'tcp', addr: '127.0.0.1', port: 631, process: 'cupsd', service: 'cups', exposed: false }],
                    items: [{ key: 'firewall', status: 'ok', weight: 15, detail: 'deny/allow' }, { key: 'disk_encryption', status: 'warn', weight: 8, detail: '' }, { key: 'secure_boot', status: 'ok', weight: 5 }, { key: 'apparmor', status: 'ok', weight: 6 }, { key: 'auto_updates', status: 'warn', weight: 6 }, { key: 'security_updates', status: 'fail', weight: 12, detail: '2' }, { key: 'empty_passwords', status: 'ok', weight: 10 }, { key: 'nopasswd_sudo', status: 'ok', weight: 5 }, { key: 'open_ports', status: 'warn', weight: 8, detail: '22/tcp sshd' }, { key: 'signatures', status: 'ok', weight: 8, detail: '0 d' }, { key: 'realtime', status: 'ok', weight: 6 }, { key: 'open_vulns', status: 'warn', weight: 6, detail: '12 unfixed, 2 high/critical' }] },
                vulns: { checked_at: now, ok: true, sources: 1480, counts: { unfixed: 12, pro_only: 3, fix_available: 5 }, by_priority: { high: 2, medium: 9, low: 9 }, flatpak: [{ id: 'org.gimp.GIMP', version: '3.2.7', name: 'GIMP' }], snap: [],
                    items: [{ id: 'UBUNTU-CVE-2026-32741', cve: 'CVE-2026-32741', package: 'libheif', installed: '1.17.6-1ubuntu4', fixed: '', status: 'unfixed', priority: 'high', cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', summary: 'Heap buffer overflow when decoding crafted HEIF images', url: 'https://ubuntu.com/security/CVE-2026-32741' }, { id: 'x', cve: 'CVE-2026-54369', package: 'acl', installed: '2.3.2-1build1.1', fixed: '', status: 'unfixed', priority: 'medium', cvss: '', summary: 'Race condition in setfacl', url: '#' }, { id: 'y', cve: 'CVE-2026-63072', package: 'openssl', installed: '3.0.13-0ubuntu3.13', fixed: '3.0.13-0ubuntu3.15', status: 'fix_available', priority: 'medium', cvss: '', summary: 'Heap Buffer Overflow in CMS Key Unwrapping', url: '#' }, { id: 'z', cve: 'CVE-2025-1234', package: 'libxml2', installed: '2.9.14', fixed: '2.9.14+esm1', status: 'pro_only', priority: 'low', cvss: '', summary: 'Use-after-free in xmlXPath', url: '#' }] },
                integrity: { checked_at: now, warnings: 1, tools: { rkhunter: { installed: true, ran: true, warnings: ['Warning: The file properties have changed: /usr/bin/ss'] }, chkrootkit: { installed: false, warnings: [] }, debsums: { installed: true, ran: true, warnings: [] } }, app: { available: true, signed: true, verified: true, modified: [], missing: [], count: 27 } },
                persistence: { checked_at: now, counts: { items: 5, untrusted: 1, extensions: 2, ext_outside_store: 1 }, items: [{ kind: 'autostart', path: '/home/user/.config/autostart/Conky.desktop', name: 'Conky', exec: 'conky -d', user: 'user', trusted: false, owner: '' }, { kind: 'cron', path: '/etc/cron.daily/apt-compat', name: 'apt-compat', exec: '', trusted: true, owner: 'apt' }], extensions: [{ browser: 'chrome', user: 'user', id: 'abcd', name: 'uBlock Origin', version: '1.60', from_store: true, enabled: true }, { browser: 'chrome', user: 'user', id: 'efgh', name: 'Mystery Helper', version: '0.1', from_store: false, enabled: true }] },
                connections: { checked_at: now, blocklist_size: 1234, processes: [{ pid: 5099, comm: 'chrome', exe: '/opt/google/chrome/chrome', user: 'user', trusted: true, remotes: { '140.82.112.26': { ip: '140.82.112.26', ports: ['443'], flagged: false, country: 'US', org: 'GitHub' } } }, { pid: 777, comm: 'miner', exe: '/tmp/miner', user: 'user', trusted: false, remotes: { '185.220.101.1': { ip: '185.220.101.1', ports: ['4444'], flagged: true, country: 'DE', org: 'Hetzner' } } }] },
                app_update: { checked_at: now, current: '1.7.0', available: true, verified: true, downloaded: true, version: '1.8.0', size: 102400, date: now, error: '' },
            };
            reply('securityData', { type: data.type, data: sim[data.type], available: true });
            break;
        }
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
    renderLegal();
    if (params.get('legal') === '1') { legalAccepted = false; openLegal(); }
    if (params.get('learn') === '1') showAwareness();
    if (params.get('backup') === '1') setTimeout(openBackupWizard, 400);   // dev : assistant de sauvegarde
    if (params.get('autoscan') === '1') setTimeout(() => startFullSystemScan(true), 500);   // dev : scan en cours
    if (params.get('lesson')) setTimeout(() => openLesson(params.get('lesson')), 300);   // dev : ouvre une leçon
    if (location.hash && $(`tab-${location.hash.slice(1)}`)) { setViewMode('advanced', false); switchTab(location.hash.slice(1)); }
    sendToBackend({ action: 'check_status' });
    sendToBackend({ action: 'get_db_info' });
    sendToBackend({ action: 'get_quarantine' });
    setInterval(() => { if (currentTab === 'dashboard' && !scan.running) sendToBackend({ action: 'check_status' }); }, 60000);
});


// ─── Sauvegardes (disponibilité : le « A » du triptyque CIA) ────────────────

let backupData = null;        // dernier backupStatus (onglet avancé + assistant)
let backupRunning = null;     // {dest_id, dest_label, pct, text} pendant une sauvegarde

function loadBackup(refresh = false) { sendToBackend({ action: 'backup_status', refresh }); }

function onBackupStatus(data) {
    backupData = data || null;
    backupRunning = (data && data.running) || null;
    if (lastStatus) lastStatus.backup = { timeshift: data.timeshift, user: data.user, running: backupRunning };
    renderBackupTab();
    renderBackupWizard();
    renderSimpleView();
    updateBackupProgress();
}

function onBackupProgress(d) {
    backupRunning = d;
    if (lastStatus && lastStatus.backup) lastStatus.backup.running = d;
    updateBackupProgress();
    renderSimpleView();
}

function onBackupDone(d) {
    backupRunning = null;
    if (lastStatus && lastStatus.backup) lastStatus.backup.running = null;
    updateBackupProgress();
    loadBackup();
}

function fmtBytes(n) {
    n = Number(n || 0);
    const units = ['o', 'Kio', 'Mio', 'Gio', 'Tio'];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return `${i ? n.toFixed(1) : n} ${units[i]}`;
}

function tsSchedLabel(ts) {
    const names = { boot: t('day.boot') !== 'day.boot' ? t('day.boot') : 'boot', hourly: t('backup.schedule.hourly') !== 'backup.schedule.hourly' ? t('backup.schedule.hourly') : 'hourly', daily: t('backup.schedule.daily'), weekly: t('backup.schedule.weekly'), monthly: t('backup.schedule.monthly') };
    return (ts.schedule || []).map(k => names[k] || k).join(', ') || '—';
}

/** État Timeshift → {state:'ok'|'warn'|'danger'|'neutral', text}. */
function timeshiftInfo(ts) {
    if (!ts) return { state: 'neutral', text: t('backup.timeshift.unknown', { sched: '—' }) };
    if (!ts.installed) return { state: 'warn', text: t('backup.timeshift.not_installed') };
    if (!ts.configured || !(ts.schedule || []).length) return { state: 'warn', text: t('backup.timeshift.not_configured') };
    const sched = tsSchedLabel(ts);
    if (ts.snapshots == null) return { state: 'neutral', text: t('backup.timeshift.unknown', { sched }) };
    if (!ts.last) return { state: 'warn', text: t('backup.timeshift.no_snapshot', { sched }) };
    const age = (Date.now() - new Date(ts.last).getTime()) / 86400e3;
    if (age > 30) return { state: 'warn', text: t('backup.timeshift.old', { rel: formatRelative(ts.last) }) };
    return { state: 'ok', text: t('backup.timeshift.ok', { n: ts.snapshots, rel: formatRelative(ts.last), sched }) };
}

/** Ligne « Sauvegardes » de la vue simple. */
function backupRowInfo() {
    const b = (lastStatus && lastStatus.backup) || {};
    const u = b.user || { state: 'none' };
    const ts = timeshiftInfo(b.timeshift);
    const running = b.running || backupRunning;
    if (running) return { state: 'ok', value: t('simple.backup.running', { pct: Math.floor(running.pct || 0) }), action: null };
    let state = 'ok', value;
    if (u.state === 'ok') value = t('simple.backup.ok', { rel: formatRelative(u.last), dest: u.dest_label || '' });
    else if (u.state === 'old') { state = 'warn'; value = t('simple.backup.old', { n: Math.round(u.age_days || 0) }); }
    else if (u.state === 'missing') { state = 'warn'; value = t('simple.backup.missing'); }
    else { state = 'warn'; value = t('simple.backup.none'); }
    if (ts.state === 'warn' || ts.state === 'danger') { state = state === 'ok' ? 'warn' : state; value += ` · ${t('simple.backup.timeshift_off')}`; }
    else if (ts.state === 'ok') value += ` · ${t('simple.backup.timeshift_ok')}`;
    return { state, value, action: { label: t('simple.backup.btn'), fn: 'openBackupWizard()' } };
}

// ── Assistant (vue simple) ──
function openBackupWizard() {
    $('simpleBackup').hidden = false;
    document.body.classList.add('awareness-open');
    renderBackupWizard();
    loadBackup(true);
}

function hideBackupWizard() {
    $('simpleBackup').hidden = true;
    document.body.classList.remove('awareness-open');
}

function driveIcon() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="2" width="16" height="20" rx="2"/><circle cx="12" cy="17" r="2"/><path d="M8 6h8"/></svg>'; }
function cloudIcon() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.5 19H7a4 4 0 0 1-.6-7.95A6 6 0 0 1 18 9a4.5 4.5 0 0 1-.5 10z"/></svg>'; }

function renderBackupWizard() {
    const box = $('backupWizardBody');
    if (!box || $('simpleBackup').hidden) return;
    const d = backupData;
    if (!d) { box.innerHTML = `<p class="text-muted">${t('sidebar.loading')}</p>`; return; }
    const list = (d.sources || []).map(p => p.split('/').pop()).join(', ');
    $('backupWizardIntro').textContent = t('backup.wizard.intro', { list });
    const running = backupRunning;
    let html = '';
    if (running) {
        html += `<div class="card backup-progress-card"><h4>${escapeHtml(t('backup.progress.title', { dest: running.dest_label || '' }))}</h4>
            <div class="simple-scan-bar"><div class="simple-scan-fill" style="width:${Math.min(100, running.pct || 0)}%"></div></div>
            <div class="text-muted backup-progress-text">${Math.floor(running.pct || 0)} % · ${escapeHtml(running.text || '')}</div>
            <div class="log-actions-right"><button class="btn btn-danger btn-sm" onclick="sendToBackend({action:'backup_cancel'})">${t('backup.progress.cancel')}</button></div></div>`;
    }
    html += `<h4>${t('backup.wizard.drives')} <button class="btn btn-secondary btn-sm" onclick="loadBackup(true)">${t('system.refresh')}</button></h4>`;
    const drives = d.drives || [];
    if (!drives.length) html += `<div class="backup-empty">${t('backup.wizard.no_drive')}</div>`;
    drives.forEach((dr, i) => {
        const known = (d.destinations || []).find(x => x.type === 'local' && dr.uuid && x.uuid === dr.uuid);
        html += `<div class="backup-choice ${dr.writable ? '' : 'disabled'}">
            <div class="backup-choice-icon">${driveIcon()}</div>
            <div class="backup-choice-text"><span class="backup-choice-title">${escapeHtml(dr.label)}${dr.model && dr.model !== dr.label ? ` · ${escapeHtml(dr.model)}` : ''}</span>
                <span class="backup-choice-sub">${escapeHtml(dr.mountpoint)} · ${t('backup.wizard.free', { free: fmtBytes(dr.free), size: fmtBytes(dr.size) })}${dr.writable ? '' : ` · ${t('backup.wizard.readonly')}`}${known && known.last ? ` · ${t('backup.dest.last', { rel: formatRelative(known.last) })}` : ''}</span></div>
            <button class="btn btn-primary btn-sm" ${dr.writable && !running ? '' : 'disabled'} onclick="backupQuick(${i})">${t('backup.wizard.here')}</button></div>`;
    });
    const clouds = (d.destinations || []).filter(x => x.type !== 'local');
    if (clouds.length) {
        html += `<h4>${t('backup.wizard.clouds')}</h4>`;
        clouds.forEach(c => {
            html += `<div class="backup-choice ${c.available ? '' : 'disabled'}"><div class="backup-choice-icon">${cloudIcon()}</div>
                <div class="backup-choice-text"><span class="backup-choice-title">${escapeHtml(c.label)}</span><span class="backup-choice-sub">${escapeHtml(c.remote || c.mountpoint || '')} · ${c.last ? t('backup.dest.last', { rel: formatRelative(c.last) }) : t('backup.dest.never')}</span></div>
                <button class="btn btn-primary btn-sm" ${c.available && !running ? '' : 'disabled'} onclick="sendToBackend({action:'backup_run', dest_id:'${escapeJs(c.id)}'})">${t('backup.wizard.here')}</button></div>`;
        });
    }
    html += `<p class="text-muted"><a href="#" class="credits-link" onclick="hideBackupWizard(); setViewMode('advanced'); switchTab('backup'); return false;">${t('backup.wizard.advanced')}</a></p>`;
    const ts = timeshiftInfo(d.timeshift);
    html += `<h4>${t('backup.wizard.timeshift')}</h4><div class="backup-choice"><div class="backup-choice-icon"><span class="ts-dot ${ts.state}"></span></div>
        <div class="backup-choice-text"><span class="backup-choice-title">${escapeHtml(ts.text)}</span><span class="backup-choice-sub">${t('backup.wizard.timeshift_hint')}</span></div>
        ${d.timeshift_installed ? `<button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'backup_open_timeshift'})">${t('backup.open_timeshift')}</button>` : `<button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'install_package', name:'timeshift'})">${t('backup.install_timeshift')}</button>`}</div>`;
    box.innerHTML = html;
}

function backupQuick(i) {
    const dr = backupData && backupData.drives && backupData.drives[i];
    if (!dr) return;
    sendToBackend({ action: 'backup_quick', drive: dr });
}

// ── Onglet avancé ──
function renderBackupTab() {
    const d = backupData;
    if (!d || !$('backupTimeshift')) return;
    const ts = timeshiftInfo(d.timeshift);
    $('backupTimeshift').innerHTML = `<div class="ts-line"><span class="ts-dot ${ts.state}"></span><span>${escapeHtml(ts.text)}</span></div>` +
        (d.timeshift_installed ? '' : `<button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'install_package', name:'timeshift'})">${t('backup.install_timeshift')}</button>`);
    if (document.activeElement !== $('backupSources')) $('backupSources').value = (d.sources || []).join('\n');
    if (document.activeElement !== $('backupExcludes')) $('backupExcludes').value = (d.excludes || []).join('\n');
    $('backupRetention').value = d.retention || 8;
    $('backupSchedule').value = d.schedule || 'weekly';
    const dests = d.destinations || [];
    $('backupDestList').innerHTML = dests.length ? dests.map(x => `
        <div class="package-item ${x.available ? '' : 'held'}">
            <span class="scope-badge ${x.type === 'cloud' ? 'scope-phased' : 'scope-user'}">${x.type === 'cloud' ? 'cloud' : x.type === 'path' ? 'dossier' : 'USB'}</span>
            <span class="package-name">${escapeHtml(x.label)}</span>
            <span class="package-versions" title="${escapeHtml(x.remote || x.mountpoint || '')}">${escapeHtml(x.remote || x.mountpoint || '')}</span>
            <span class="alert-meta">${x.last ? t('backup.dest.last', { rel: formatRelative(x.last) }) : t('backup.dest.never')}${x.last_ok === false ? ` · ${t('backup.dest.failed')}` : ''} · ${x.available ? t('backup.dest.available') : t('backup.dest.unavailable')}</span>
            <button class="btn btn-primary btn-sm" ${x.available && !backupRunning ? '' : 'disabled'} onclick="sendToBackend({action:'backup_run', dest_id:'${escapeJs(x.id)}'})">${t('backup.dest.run')}</button>
            <button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'backup_test', dest_id:'${escapeJs(x.id)}'})">${t('backup.dest.test')}</button>
            ${x.type !== 'cloud' ? `<button class="btn btn-secondary btn-sm" ${x.available ? '' : 'disabled'} onclick="sendToBackend({action:'backup_open_folder', dest_id:'${escapeJs(x.id)}'})">${t('backup.dest.open')}</button>` : ''}
            <button class="btn btn-secondary btn-sm" onclick="sendToBackend({action:'backup_remove', dest_id:'${escapeJs(x.id)}'})">${t('backup.dest.remove')}</button>
        </div>`).join('') : `<p class="text-muted">${t('backup.dest.none')}</p>`;
    const sel = $('backupDriveSelect');
    const drives = d.drives || [];
    sel.innerHTML = drives.length ? drives.map((dr, i) => `<option value="${i}">${escapeHtml(dr.label)} · ${escapeHtml(dr.mountpoint)} · ${fmtBytes(dr.free)}</option>`).join('') : `<option value="">${t('backup.dest.no_drive')}</option>`;
    $('backupRcloneNote').hidden = !!d.rclone;
    cloudKindChanged();
    const hist = d.history || [];
    $('backupHistory').innerHTML = hist.length ? hist.map(h => `
        <div class="package-item ${h.ok ? '' : 'security'}">
            <span class="scope-badge ${h.ok ? 'scope-user' : 'scope-danger'}">${h.ok ? '✓' : (h.cancelled ? t('backup.history.cancelled') : '✕')}</span>
            <span class="package-name">${formatDateTime(h.date)}</span>
            <span class="package-versions">${escapeHtml(h.dest_label || '')}${h.auto ? ` · ${t('backup.history.auto')}` : ''}</span>
            <span class="alert-meta">${h.ok ? t('backup.history.line', { files: formatNumber(h.files || 0), size: fmtBytes(h.bytes), duration: formatDuration(h.duration) }) : escapeHtml(h.error || '')}</span>
        </div>`).join('') : `<p class="text-muted">${t('backup.history.none')}</p>`;
    $('backupRestoreLocal').textContent = t('backup.restore.local', { hostuser: d.hostuser || '<hôte>-<utilisateur>' });
    $('backupRestoreCloud').textContent = t('backup.restore.cloud', { hostuser: d.hostuser || '<hôte>-<utilisateur>' });
    updateBackupProgress();
}

function updateBackupProgress() {
    const card = $('backupProgressCard');
    if (card) {
        card.hidden = !backupRunning;
        if (backupRunning) {
            $('backupProgressTitle').textContent = t('backup.progress.title', { dest: backupRunning.dest_label || '' });
            $('backupProgressFill').style.width = `${Math.min(100, backupRunning.pct || 0)}%`;
            $('backupProgressText').textContent = `${Math.floor(backupRunning.pct || 0)} % · ${backupRunning.text || ''}`;
        }
    }
    if ($('simpleBackup') && !$('simpleBackup').hidden) renderBackupWizard();
}

const CLOUD_FIELDS = { s3: ['name', 'endpoint', 'access_key', 'secret_key', 'bucket'], infomaniak_s3: ['name', 'endpoint', 'access_key', 'secret_key', 'bucket'],
                       infomaniak_swift: ['name', 'auth', 'user', 'key', 'bucket'], kdrive: ['name', 'url', 'user', 'key'], existing: ['remote'] };

function cloudKindChanged() {
    const kind = $('cloudKind') ? $('cloudKind').value : 'infomaniak_s3';
    const fields = CLOUD_FIELDS[kind] || [];
    document.querySelectorAll('#backupCloudForm .cloud-f').forEach(el => { el.hidden = !fields.includes(el.dataset.f); });
    $('cloudHint').textContent = kind.startsWith('infomaniak') ? t('backup.cloud.hint_infomaniak') : kind === 'kdrive' ? t('backup.cloud.hint_kdrive') : '';
    if (kind === 'infomaniak_swift' && !$('cloudAuth').value) $('cloudAuth').value = 'https://swiss-backup03.infomaniak.com/identity/v3';
}

function backupAddDrive() {
    const i = parseInt($('backupDriveSelect').value, 10);
    const dr = backupData && backupData.drives && backupData.drives[i];
    if (!dr) { showToast(t('backup.dest.no_drive'), 'error'); return; }
    sendToBackend({ action: 'backup_add_local', drive: dr });
}

function backupAddPath() {
    const p = ($('backupPathInput').value || '').trim();
    if (!p) return;
    sendToBackend({ action: 'backup_add_local', path: p });
    $('backupPathInput').value = '';
}

function backupAddCloud() {
    const kind = $('cloudKind').value;
    const params = { endpoint: $('cloudEndpoint').value.trim(), access_key: $('cloudAccessKey').value.trim(), secret_key: $('cloudSecretKey').value,
                     bucket: $('cloudBucket').value.trim(), container: $('cloudBucket').value.trim(), auth: $('cloudAuth').value.trim(),
                     user: $('cloudUser').value.trim(), key: $('cloudKey').value, url: $('cloudUrl').value.trim(), pass: $('cloudKey').value };
    sendToBackend({ action: 'backup_add_cloud', kind, name: $('cloudName').value.trim(), params, remote: $('cloudRemote').value.trim() });
    $('cloudSecretKey').value = ''; $('cloudKey').value = '';
}

function backupSaveContent() {
    sendToBackend({ action: 'backup_set', sources: $('backupSources').value.split('\n'), excludes: $('backupExcludes').value.split('\n'),
                    retention: parseInt($('backupRetention').value, 10) || 8, schedule: $('backupSchedule').value });
}


/** Intégrité seule (rkhunter, chkrootkit, debsums, fichiers de l'application), sans analyse antivirus. */
function runIntegrityOnly() {
    if (scan.running || integrityRunning) { showToast(t('scan.integrity_running'), 'info'); return; }
    integrityRunning = true;
    syncScanButtons();
    loadSecurityData('integrity', false, true);
    showToast(t('scan.integrity_running'), 'info');
    setHeroNote(t('scan.integrity_running'));
}


// ─── « Régler » : chaque contrôle mène au bon endroit ───────────────────────

const CHECK_FIX = {
    firewall: () => switchTab('firewall'),
    ssh: () => switchTab('firewall'),
    security_updates: () => sendToBackend({ action: 'system_upgrade' }),
    reboot: null,
    auto_updates: () => sendToBackend({ action: 'open_update_manager' }),
    signatures: () => triggerUpdate(),
    recent_scan: () => startFullSystemScan(true),
    realtime: () => switchTab('settings'),
    weekly_scan: () => switchTab('settings'),
    auto_response: () => switchTab('settings'),
    open_ports: () => openPortsPanel(),
    exposed_services: () => openPortsPanel(),
    open_vulns: () => { setVulnPrio('high'); const el = $('vulnList'); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); },
    persistence: () => { switchTab('system'); setTimeout(() => { const el = $('persistenceList'); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 150); },
    ld_preload: () => loadSecurityData('integrity', false, true),
};

function fixCheck(key) {
    const fn = CHECK_FIX[key];
    if (fn) fn();
    const info = $(`fix-${key}`);
    if (info) info.hidden = !info.hidden;
}

function openPortsPanel() {
    switchTab('security');
    const d = $('portsDetails');
    if (!d) return;
    d.open = true;
    setTimeout(() => d.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
}

function firewallQuickDeny(port, proto) {
    sendToBackend({ action: 'security_action', cmd: 'firewall_rule_add', port: String(port), proto, action: 'deny', comment: 'ClamAV Antivirus GUI' });
    showToast(t('ports.blocking', { port: `${port}/${proto}` }), 'info');
}


// ─── Boutons de scan : désactivés pendant une analyse ou une vérification d'intégrité ──
let integrityRunning = false;

function syncScanButtons() {
    const busy = !!scan.running;
    const set = (id, disabled) => { const el = $(id); if (el) el.disabled = disabled; };
    set('btnFullAnalysis', busy || integrityRunning);
    set('btnFullScan', busy);
    set('btnIntegrityOnly', busy || integrityRunning);
    set('btnIntegrityRun', (busy && scan.integrity) || integrityRunning);
    set('simpleScanBtn', busy || integrityRunning);
    if ($('btnCancelScan')) $('btnCancelScan').hidden = !busy;
    document.querySelectorAll('.target-btn').forEach(b => { b.disabled = busy; });
}
