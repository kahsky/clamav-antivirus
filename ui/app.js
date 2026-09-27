/* ═══════════════════════════════════════════════════════════════════════════
   CLAMAV ANTIVIRUS — Frontend Logic
   Communication avec le backend Python via webkit.messageHandlers
   ═══════════════════════════════════════════════════════════════════════════ */

// ─── State ──────────────────────────────────────────────────────────────────
let currentTab = 'dashboard';
let isUpdating = false;
let isInstalling = false;
let lastStatus = null;
let logScope = 'system';

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
    needsPassword: false,
};

// ─── Toast Container ────────────────────────────────────────────────────────
const toastContainer = document.createElement('div');
toastContainer.className = 'toast-container';
document.body.appendChild(toastContainer);

const $ = (id) => document.getElementById(id);

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
    }
}


// ─── Dashboard ──────────────────────────────────────────────────────────────

function updateDashboardStatus(data) {
    lastStatus = data;
    updateStatusUI(data.color, data.message);
    toggleInstallTab(!data.fully_installed);

    // Signatures / dernier scan dans la carte de statut
    $('statusDbAge').textContent = data.last_update ? formatRelative(data.last_update) : 'inconnues';
    $('statusLastScan').textContent = data.last_scan ? formatRelative(data.last_scan.date) : 'jamais';

    // Service système
    const d = data.daemon || {};
    const pill = $('servicePill');
    pill.classList.toggle('online', !!d.available);
    pill.querySelector('.service-text').textContent = d.available ? 'Service système actif' : 'Service système inactif';

    const badge = $('daemonBadge');
    badge.textContent = d.available ? 'Actif' : 'Inactif';
    badge.className = 'badge ' + (d.available ? 'badge-green' : 'badge-red');
    $('protDaemon').textContent = d.available
        ? `Actif — scans et mises à jour sans mot de passe (v${d.version || '?'})`
        : 'Inactif — le mot de passe administrateur sera demandé';

    // Planification
    const s = data.schedule || {};
    $('protSchedule').textContent = s.rule || 'Tous les jours à 07:00 et 5 min après le démarrage';
    if (s.next_update) {
        $('protNextUpdate').textContent = `Prochaine : ${formatDateTime(s.next_update)} (${formatRelative(s.next_update)})`;
    } else {
        $('protNextUpdate').textContent = s.timer_active ? '' : 'Planificateur systemd non actif';
    }
    $('updLast').textContent = data.last_update ? `${formatDateTime(data.last_update)} — ${formatRelative(data.last_update)}` : 'inconnue';
    $('updNext').textContent = s.next_update ? formatDateTime(s.next_update) : 'non planifiée';

    // Dernier scan
    if (data.last_scan) {
        const ls = data.last_scan;
        const res = ls.status === 'infected' || ls.infected > 0
            ? `${ls.infected} menace(s)` : (ls.status === 'error' ? 'erreur' : 'aucune menace');
        $('protLastScan').textContent = `${ls.path || '?'} — ${res}`;
        $('protLastScanSub').textContent = `${formatDateTime(ls.date)}${ls.files ? ` · ${formatNumber(ls.files)} fichiers` : ''}${ls.duration ? ` · ${formatDuration(ls.duration)}` : ''}${ls.auto ? ' · automatique' : ''}`;
    } else {
        $('protLastScan').textContent = 'Aucune analyse effectuée';
        $('protLastScanSub').textContent = '';
    }

    // Indices sur la nécessité d'un mot de passe
    $('fullScanHint').textContent = d.available
        ? 'Sans mot de passe via le service système'
        : 'Mot de passe administrateur requis (service inactif)';
    $('targetsHint').textContent = d.available
        ? 'Analysés par le service système, sans mot de passe'
        : 'Analysés avec vos droits utilisateur';
    updateSourceBadge();

    // Première utilisation (sauf si le service va lancer le scan initial lui-même)
    toggleInitialScanPrompt(data.never_scanned && data.fully_installed && !d.first_scan_pending && !scan.running);

    // Scan interrompu : proposer la reprise
    const resumeEl = $('dashResumeScan');
    const r = data.resumable;
    if (r && r.path && !scan.running) {
        $('resumeScanPath').textContent = r.path;
        $('resumeScanDetail').textContent = r.total
            ? `${formatNumber(r.scanned || 0)} / ${formatNumber(r.total)} fichiers analysés`
            : 'reprise possible';
        resumeEl.hidden = false;
        resumeEl.dataset.path = r.path;
    } else {
        resumeEl.hidden = true;
    }

    renderHistory(data.history || []);
}

function renderHistory(list) {
    const el = $('historyList');
    $('historyCount').textContent = list.length ? `${list.length} dernière(s)` : '';
    if (!list.length) {
        el.innerHTML = '<p class="text-muted">Aucune analyse enregistrée</p>';
        return;
    }
    el.innerHTML = list.slice(0, 6).map(h => {
        const st = h.status === 'infected' || h.infected > 0 ? 'infected' : (h.status === 'error' ? 'error' : 'clean');
        const label = st === 'infected' ? `${h.infected} menace(s)` : (st === 'error' ? 'Erreur' : 'Sain');
        return `
        <div class="history-item">
            <span class="history-status history-${st}"></span>
            <div class="history-main">
                <span class="history-path" title="${escapeHtml(h.path || '')}">${escapeHtml(h.path || '?')}</span>
                <span class="history-meta">${formatDateTime(h.date)} · ${formatNumber(h.files || 0)} fichiers · ${formatDuration(h.duration || 0)}${h.source === 'daemon' ? ' · service' : ''}${h.auto ? ' · auto' : ''}</span>
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
    const titles = { green: 'Système protégé', blue: 'Mise à jour recommandée', red: 'Protection expirée' };
    $('statusTitle').textContent = titles[color] || 'Vérification...';
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
            container.innerHTML = '<p class="text-muted">Aucune base de données trouvée. Installez ClamAV puis lancez une mise à jour.</p>';
            return;
        }
        container.innerHTML = files.map(f => `
            <div class="db-file">
                <span class="db-file-name">${escapeHtml(f.name)}</span>
                <span class="db-file-meta">${escapeHtml(f.date)} — ${formatSize(f.size)}</span>
            </div>`).join('');
    });
}


// ─── Scan : démarrage / annulation ──────────────────────────────────────────

function startFullSystemScan() {
    if (scan.running) { showToast('Une analyse est déjà en cours', 'info'); switchTab('scan'); return; }
    toggleInitialScanPrompt(false);
    switchTab('scan');
    prepareScanUI('/');
    const d = (lastStatus && lastStatus.daemon) || {};
    if (!d.available) {
        setHeroNote('Service système inactif : une fenêtre d\'authentification va s\'ouvrir…');
    }
    sendToBackend({ action: 'scan', path: '/' });
}

function startScan(path) {
    if (scan.running) { showToast('Une analyse est déjà en cours', 'info'); return; }
    path = (path || '').trim();
    if (!path) { showToast('Veuillez indiquer un chemin', 'error'); return; }
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
    setHeroNote('Annulation en cours…');
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
        result: null, auto: false, needsPassword: false,
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
    // Peut arriver sans action de l'utilisateur (scan initial automatique, scan lancé par le tray…)
    if (!scan.running) prepareScanUI(data.path);
    scan.source = data.source;
    scan.path = data.path || scan.path;
    scan.auto = !!data.auto;
    scan.needsPassword = !!data.needs_password;
    if (data.started_at) scan.startedAt = data.started_at;
    if (data.job) applyProgress(data.job);
    if (scan.needsPassword) setHeroNote('Authentification administrateur requise (service système inactif)');
    else if (scan.auto) setHeroNote('Analyse automatique lancée par le service système après l\'installation');
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
    if (p.started_at) scan.startedAt = p.started_at;
    if (Array.isArray(p.threats) && p.threats.length > scan.threats.length) scan.threats = p.threats.slice();
    if (scan.phase === 'scanning') {
        const t = Date.now() / 1000;
        scan.samples.push({ t, n: scan.scanned });
        while (scan.samples.length > 2 && t - scan.samples[0].t > 30) scan.samples.shift();
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
        if (m && !scan.threats.some(t => t.path === m[1])) scan.threats.push({ path: m[1], signature: m[2] });
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
    if (job.kind === 'scan') showToast(`Analyse de ${job.path} en attente de la fin de l'opération en cours`, 'info');
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

function renderScanHero() {
    const hero = $('scanHero');
    const pct = scanPercent();
    const state = scan.running ? 'running' : (scan.result ? scan.result.status : 'idle');
    hero.dataset.state = state;
    hero.dataset.phase = scan.phase;

    // Anneau
    $('scanRingFill').style.strokeDashoffset = RING_CIRC * (1 - pct / 100);
    $('scanRingPct').textContent = scan.running && scan.phase !== 'scanning' && scan.total === 0
        ? '…' : `${Math.floor(pct)} %`;
    $('scanRingSub').textContent = scan.running
        ? (scan.phase === 'counting' ? `${formatNumber(scan.found)} fichiers` : (scan.phase === 'prepare' ? 'démarrage' : 'analyse'))
        : (scan.result ? 'terminé' : '');

    // Titre / sous-titre
    let title, sub;
    if (scan.running) {
        title = scan.phase === 'counting' ? 'Inventaire des fichiers…'
              : scan.phase === 'prepare' ? 'Préparation de l\'analyse…'
              : `Analyse en cours`;
        sub = scan.phase === 'scanning'
            ? `${scan.path === '/' ? 'Système complet' : scan.path} — ${formatNumber(scan.scanned)} sur ${formatNumber(scan.total)} fichiers`
            : (scan.phase === 'counting' ? `${scan.path === '/' ? 'Système complet' : scan.path} — ${formatNumber(scan.found)} fichiers recensés` : (scan.path === '/' ? 'Système complet' : scan.path));
    } else if (scan.result) {
        const r = scan.result;
        title = r.status === 'clean' ? 'Aucune menace détectée'
              : r.status === 'infected' ? `${scan.infected} menace(s) détectée(s)`
              : r.status === 'cancelled' ? 'Analyse interrompue'
              : 'Analyse échouée';
        sub = r.message || '';
    } else {
        title = 'Prêt à analyser';
        sub = 'Lancez un scan complet ou choisissez un dossier ci-dessous.';
    }
    $('scanHeroTitle').textContent = title;
    $('scanHeroSub').textContent = sub;

    // Étapes
    const order = ['prepare', 'counting', 'scanning', 'done'];
    const idx = order.indexOf(scan.phase);
    document.querySelectorAll('#scanPhases li').forEach(li => {
        const i = order.indexOf(li.dataset.phase);
        li.classList.toggle('done', scan.phase !== 'idle' && i < idx);
        li.classList.toggle('active', scan.phase !== 'idle' && i === idx && (scan.running || scan.phase === 'done'));
    });

    // Statistiques
    $('statScanned').textContent = formatNumber(scan.scanned);
    $('statTotal').textContent = scan.total ? formatNumber(scan.total) : (scan.phase === 'counting' ? formatNumber(scan.found) : '—');
    $('statThreats').textContent = formatNumber(scan.infected);
    $('statThreats').parentElement.classList.toggle('has-threats', scan.infected > 0);
    updateTimeStats();

    // Fichier courant
    $('scanCurrentPath').textContent = scan.file ? rtlPath(scan.file) : (scan.running ? '…' : '—');
    $('scanCurrent').classList.toggle('active', scan.running && !!scan.file);

    // Boutons
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
        $('statEta').textContent = eta < 5 ? 'quelques secondes' : `≈ ${formatDuration(eta)}`;
    } else if (scan.running && scan.phase === 'scanning' && scan.total > 0) {
        $('statEta').textContent = 'estimation…';
    } else {
        $('statEta').textContent = '—';
    }
}

function updateSourceBadge() {
    const badge = $('scanSourceBadge');
    const d = (lastStatus && lastStatus.daemon) || {};
    if (scan.running || scan.result) {
        if (scan.source === 'daemon') { badge.textContent = 'Service système'; badge.className = 'badge badge-green'; }
        else if (scan.needsPassword) { badge.textContent = 'Administrateur (pkexec)'; badge.className = 'badge badge-amber'; }
        else if (scan.source === 'local') { badge.textContent = 'Droits utilisateur'; badge.className = 'badge badge-blue'; }
        else { badge.textContent = 'Démarrage…'; badge.className = 'badge'; }
    } else {
        badge.textContent = d.available ? 'Service système prêt' : 'Service inactif';
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
        st === 'clean' ? 'Résultat : système sain' :
        st === 'infected' ? `Résultat : ${scan.infected} menace(s) isolée(s) en quarantaine` :
        st === 'cancelled' ? 'Analyse interrompue — reprise possible depuis le tableau de bord' :
        'Analyse échouée';
    $('btnSeeQuarantine').hidden = st !== 'infected';

    const tiles = [
        ['Fichiers analysés', formatNumber(st === 'cancelled' ? scan.scanned : (summary.files ?? scan.total))],
        ['Menaces', formatNumber(summary.infected ?? scan.infected)],
        ['Durée', formatDuration(summary.duration || 0)],
        ['Accès refusés', formatNumber(summary.denied ?? scan.denied)],
        ['Erreurs', formatNumber(summary.errors ?? scan.errors)],
        ['Exécuté par', data.source === 'daemon' ? 'Service système' : (scan.needsPassword ? 'Administrateur' : 'Utilisateur')],
    ];
    $('scanResultsGrid').innerHTML = tiles.map(([l, v]) =>
        `<div class="result-tile"><span class="result-value">${escapeHtml(String(v))}</span><span class="result-label">${l}</span></div>`).join('');

    const threats = (summary.threats && summary.threats.length) ? summary.threats : scan.threats;
    $('threatList').innerHTML = threats.length ? `
        <h5>Fichiers infectés (déplacés en quarantaine)</h5>
        ${threats.map(t => `
            <div class="threat-item">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <div class="threat-info">
                    <span class="threat-path" title="${escapeHtml(t.path)}">${escapeHtml(t.path)}</span>
                    <span class="threat-sig">${escapeHtml(t.signature || '')}</span>
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
    $('scanTopbarTitle').textContent = scan.phase === 'counting' ? 'Inventaire' : (scan.phase === 'prepare' ? 'Préparation' : `Analyse de ${scan.path === '/' ? 'tout le système' : scan.path}`);
    $('scanTopbarCount').textContent = scan.phase === 'scanning'
        ? `${Math.floor(pct)} % — ${formatNumber(scan.scanned)} / ${formatNumber(scan.total)}`
        : (scan.phase === 'counting' ? `${formatNumber(scan.found)} fichiers` : '');
    $('scanTopbarEta').textContent = $('statEta').textContent !== '—' ? `reste ${$('statEta').textContent}` : '';
    $('scanTopbarFile').textContent = rtlPath(scan.file);
}

function syncDashboardLive() {
    const card = $('dashScanLive');
    card.hidden = !scan.running;
    if (!scan.running) return;
    const pct = scanPercent();
    $('dashScanTitle').textContent = scan.phase === 'counting' ? 'Inventaire des fichiers' : `Analyse de ${scan.path === '/' ? 'tout le système' : scan.path}`;
    $('dashScanCount').textContent = scan.phase === 'scanning' ? `${Math.floor(pct)} % — ${formatNumber(scan.scanned)} / ${formatNumber(scan.total)}` : `${formatNumber(scan.found)} fichiers`;
    $('dashProgressFill').style.width = `${pct}%`;
    $('dashCurrentFile').textContent = rtlPath(scan.file);
}


// ─── Update ─────────────────────────────────────────────────────────────────

function startUpdate() {
    if (isUpdating) { showToast('Mise à jour déjà en cours', 'info'); return; }
    isUpdating = true;
    const btn = $('btnUpdate');
    btn.disabled = true;
    btn.textContent = 'Mise à jour en cours...';
    $('updateConsole').hidden = false;
    $('updateOutput').innerHTML = '';
    $('updateConsoleTitle').textContent = 'Mise à jour en cours...';
    $('updateNote').textContent = '';
    appendLine($('updateOutput'), '▶ Demande de mise à jour…', 'info');
    sendToBackend({ action: 'update' });
}

function onUpdateStarted(data) {
    if (!isUpdating) {
        // Mise à jour lancée par le planificateur ou le service : l'afficher quand même
        isUpdating = true;
        $('btnUpdate').disabled = true;
        $('btnUpdate').textContent = 'Mise à jour en cours...';
        $('updateConsole').hidden = false;
        $('updateOutput').innerHTML = '';
        if (data.auto) appendLine($('updateOutput'), '▶ Mise à jour automatique lancée par le service système', 'info');
    }
    $('updateNote').textContent = data.source === 'daemon'
        ? (data.queued ? 'En file d\'attente derrière l\'opération en cours' : 'Exécutée par le service système, sans mot de passe')
        : 'Service inactif : mot de passe administrateur requis';
}

function onUpdateLine({ text }) {
    if (!text) return;
    let kind = '';
    if (/error|failed|échec/i.test(text)) kind = 'error';
    else if (/up-to-date|up to date|updated|à jour/i.test(text)) kind = 'ok';
    appendLine($('updateOutput'), text, kind);
}


// ─── Install ────────────────────────────────────────────────────────────────

function installClamAV() {
    if (isInstalling) return;
    isInstalling = true;
    const btn = $('btnInstall');
    btn.disabled = true;
    btn.textContent = 'Installation en cours...';
    $('installConsole').hidden = false;
    $('installOutput').innerHTML = '';
    appendLine($('installOutput'), '▶ Installation de ClamAV...', 'info');
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
    if (confirm('Voulez-vous vraiment vider ce journal ?')) {
        sendToBackend({ action: 'clear_log', scope: logScope });
        showToast('Journal vidé', 'success');
    }
}

function renderLogs({ lines, scope, available }) {
    const output = $('logOutput');
    $('logTitle').textContent = scope === 'system' ? 'Journal du service système' : 'Journal de mon compte';
    if (scope === 'system' && available === false) {
        output.innerHTML = '<p class="text-muted center">Service système indisponible</p>';
        return;
    }
    if (!lines || lines.length === 0) {
        output.innerHTML = '<p class="text-muted center">Aucun journal disponible</p>';
        return;
    }
    output.innerHTML = lines.map(line => {
        let cls = '';
        if (line.includes('FOUND')) cls = 'line-found';
        else if (line.includes('Infected files: 0') || line.includes('Aucune menace') || line.includes('à jour')) cls = 'line-ok';
        else if (line.includes('▶') || line.includes('■')) cls = 'line-info';
        else if (/error|échec|Access denied/i.test(line)) cls = 'line-error';
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
                <p>Aucun fichier en quarantaine</p>
                <small class="text-muted">Les fichiers infectés détectés lors des analyses apparaîtront ici</small>
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
                    <span class="scope-badge scope-${f.scope === 'system' ? 'system' : 'user'}">${f.scope === 'system' ? 'Système' : 'Mon compte'}</span>
                </div>
                <div class="quarantine-item-meta">${escapeHtml(f.date)} — ${formatSize(String(f.size))}</div>
            </div>
            <div class="quarantine-item-actions">
                <button class="btn btn-secondary" onclick="restoreQuarantineFile('${escapeJs(f.path)}', '${escapeJs(f.scope || 'user')}')">Restaurer…</button>
                <button class="btn btn-danger" onclick="deleteQuarantineFile('${escapeJs(f.path)}', '${escapeJs(f.name)}', '${escapeJs(f.scope || 'user')}')">Supprimer</button>
            </div>
        </div>`).join('');
}

function deleteQuarantineFile(filepath, name, scope) {
    if (confirm(`Supprimer définitivement « ${name} » ?`)) {
        sendToBackend({ action: 'delete_quarantine', path: filepath, scope });
    }
}

function restoreQuarantineFile(filepath, scope) {
    pickFolder('restore', { path: filepath, scope });
}

function emptyQuarantine() {
    if (confirm('Supprimer définitivement TOUS les fichiers en quarantaine ?')) {
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
        btn.textContent = 'Lancer la mise à jour';
        $('updateConsoleTitle').textContent = status === 'success' ? 'Mise à jour terminée' : 'Mise à jour échouée';
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
        btn.textContent = 'Installer maintenant';
        showToast(message, status === 'success' ? 'success' : 'error');
        sendToBackend({ action: 'check_status' });
        return;
    }
    // Quarantaine ou erreur générique (ex. scan refusé)
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

function formatSize(bytes) {
    const b = parseInt(bytes, 10);
    if (isNaN(b)) return bytes;
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
}

/** Chemin affiché avec ellipse à gauche (direction: rtl) sans déplacer les barres obliques. */
function rtlPath(path) {
    return path ? `\u200E${path}\u200E` : '';
}

function formatNumber(n) {
    return Number(n || 0).toLocaleString('fr-CH');
}

function formatDuration(seconds) {
    seconds = Math.max(0, Math.round(seconds || 0));
    const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60), s = seconds % 60;
    if (h) return `${h} h ${String(m).padStart(2, '0')} min`;
    if (m) return `${m} min ${String(s).padStart(2, '0')} s`;
    return `${s} s`;
}

function formatDateTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString('fr-CH', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatRelative(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    const diff = (Date.now() - d.getTime()) / 1000;
    const abs = Math.abs(diff);
    const future = diff < 0;
    let txt;
    if (abs < 60) txt = 'moins d\'une minute';
    else if (abs < 3600) txt = `${Math.round(abs / 60)} min`;
    else if (abs < 86400) txt = `${Math.round(abs / 3600)} h`;
    else txt = `${Math.round(abs / 86400)} j`;
    return future ? `dans ${txt}` : `il y a ${txt}`;
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
                color: 'green', message: 'Protégé — signatures à jour (2 h)', installed: true, fully_installed: true,
                last_update: new Date(Date.now() - 2 * 3600e3).toISOString(),
                last_scan: { date: new Date(Date.now() - 86400e3).toISOString(), path: '/', files: 1234567, infected: 0, duration: 5400, status: 'clean', source: 'daemon', auto: true },
                never_scanned: false, resumable: null,
                history: [{ date: new Date(Date.now() - 86400e3).toISOString(), path: '/', files: 1234567, infected: 0, duration: 5400, status: 'clean', source: 'daemon', auto: true },
                          { date: new Date(Date.now() - 3 * 86400e3).toISOString(), path: '/home', files: 236886, infected: 1, duration: 6756, status: 'infected', source: 'local' }],
                daemon: { available: true, version: '1.4.0', first_scan_pending: false, queue: [] },
                schedule: { next_update: new Date(new Date().setHours(31, 0, 0, 0)).toISOString(), timer_active: true, rule: 'Tous les jours à 07:00 et 5 minutes après le démarrage' },
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
            reply('logContent', { scope: data.scope, available: true, lines: ['[2026-09-27T22:40:16] ▶ Scan de /home', '[2026-09-27T22:40:35] /home/user/eicar.com: Eicar-Test-Signature FOUND', '[2026-09-27T22:40:35] ■ Scan terminé : 1 menace(s) détectée(s)'] });
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
                        if (n === 20000 + (n % 190)) { /* noop */ }
                        if (n > 20000 && !window.__simFound) { window.__simFound = true; onBackendMessage({ event: 'scanLine', data: { kind: 'found', text: '/home/user/Téléchargements/eicar.com: Eicar-Test-Signature FOUND' } }); }
                        if (n >= total) {
                            clearInterval(tick); window.__simFound = false;
                            onBackendMessage({ event: 'scanDone', data: { status: 'infected', source: 'daemon', message: '1 menace(s) détectée(s) — fichiers déplacés en quarantaine', summary: { files: total, infected: 1, denied: 12, errors: 0, duration: Date.now() / 1000 - start, threats: [{ path: '/home/user/Téléchargements/eicar.com', signature: 'Eicar-Test-Signature' }] } } });
                        }
                    }, 250);
                }
            }, 250);
            break;
        }
        case 'cancel_scan':
            reply('scanDone', { status: 'cancelled', source: 'daemon', message: 'Scan interrompu — reprise possible', summary: {} });
            break;
        case 'update':
            reply('updateStarted', { source: 'daemon' });
            reply('updateLine', { text: '→ Téléchargement des signatures…' }, 400);
            reply('updateLine', { text: 'daily.cld database is up-to-date' }, 1200);
            reply('operationResult', { status: 'success', message: 'Base de données virale à jour', op: 'update' }, 1800);
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
    document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
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
    renderScanHero();
    sendToBackend({ action: 'check_status' });
    sendToBackend({ action: 'get_db_info' });
    sendToBackend({ action: 'get_quarantine' });
    // Rafraîchir le statut périodiquement (planification, service, signatures)
    setInterval(() => { if (currentTab === 'dashboard' && !scan.running) sendToBackend({ action: 'check_status' }); }, 60000);
});
