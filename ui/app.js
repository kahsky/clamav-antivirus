/* ═══════════════════════════════════════════════════════════════════════════
   CLAMAV ANTIVIRUS — Frontend Logic
   Communication avec le backend Python via webkit.messageHandlers
   ═══════════════════════════════════════════════════════════════════════════ */

// ─── State ──────────────────────────────────────────────────────────────────
let currentTab = 'dashboard';
let isScanning = false;
let isUpdating = false;
let isInstalling = false;

// ─── Toast Container ────────────────────────────────────────────────────────
const toastContainer = document.createElement('div');
toastContainer.className = 'toast-container';
document.body.appendChild(toastContainer);

// ─── Backend Communication ──────────────────────────────────────────────────

/**
 * Envoyer un message au backend Python
 */
function sendToBackend(data) {
    try {
        window.webkit.messageHandlers.backend.postMessage(JSON.stringify(data));
    } catch (e) {
        console.warn('Backend non disponible (mode dev?)', e);
        // Simulated responses for development without the Python backend
        simulateBackend(data);
    }
}

/**
 * Recevoir un message du backend (appelé par Python via run_javascript)
 */
function onBackendMessage(msg) {
    const { event, data } = msg;

    switch (event) {
        case 'statusUpdate':
            updateDashboardStatus(data);
            break;
        case 'dbInfo':
            renderDbInfo(data.files);
            break;
        case 'operationResult':
            handleOperationResult(data);
            break;
        case 'logContent':
            renderLogs(data.lines);
            break;
        case 'quarantineList':
            renderQuarantine(data.files);
            break;
        case 'error':
            showToast(data.message, 'error');
            break;
    }
}

/**
 * Appelé par le tray icon pour mettre à jour le statut
 */
function updateTrayStatus(color, message) {
    updateStatusUI(color, message);
}

/**
 * Appelé par le tray icon pour lancer une mise à jour
 */
function triggerUpdate() {
    switchTab('update');
    startUpdate();
}


// ─── Tab Navigation ─────────────────────────────────────────────────────────

function switchTab(tabId) {
    currentTab = tabId;

    // Update nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
    });

    // Update panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === `tab-${tabId}`);
    });

    // Load tab-specific data
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
    updateStatusUI(data.color, data.message, data.installed);
    toggleInstallTab(!data.fully_installed);
    toggleInitialScanPrompt(data.never_scanned && data.fully_installed);
}

function toggleInstallTab(show) {
    const navBtn = document.querySelector('.nav-btn[data-tab="install"]');
    const tabPanel = document.getElementById('tab-install');
    if (navBtn) navBtn.style.display = show ? '' : 'none';
    if (tabPanel && !show && tabPanel.classList.contains('active')) {
        switchTab('dashboard');
    }
}

function toggleInitialScanPrompt(show) {
    const card = document.getElementById('cardInitialScan');
    if (card) card.style.display = show ? '' : 'none';
}

function startFullSystemScan() {
    if (isScanning) {
        showToast('Un scan est déjà en cours', 'info');
        return;
    }

    // Switch to scan tab to see output
    switchTab('scan');

    isScanning = true;
    const consoleBox = document.getElementById('scanConsole');
    const output = document.getElementById('scanOutput');
    const btn = document.getElementById('btnFullScan');
    consoleBox.style.display = 'block';
    output.innerHTML = '';

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Scan en cours...';
    }

    // Scan all main directories sequentially via a single / scan
    appendLine(output, '▶ Scan complet du système lancé — /home /etc /var /opt /usr /tmp', 'info');
    appendLine(output, '  Cela peut prendre plusieurs minutes...', 'info');
    sendToBackend({ action: 'scan', path: '/' });
}

function updateStatusUI(color, message, installed) {
    const card = document.getElementById('cardStatus');
    const title = document.getElementById('statusTitle');
    const msg = document.getElementById('statusMessage');
    const pill = document.getElementById('statusPill');

    // Status card
    card.className = `card card-status status-${color}`;

    // Dynamic CSS variable for shield gradient
    const colors = {
        green: { main: '#22c55e', dark: '#059669' },
        blue:  { main: '#3b82f6', dark: '#2563eb' },
        red:   { main: '#ef4444', dark: '#dc2626' }
    };
    const c = colors[color] || colors.green;
    document.documentElement.style.setProperty('--status-color', c.main);
    document.documentElement.style.setProperty('--status-color-dark', c.dark);

    // Text
    const titles = {
        green: 'Système protégé',
        blue:  'Mise à jour recommandée',
        red:   'Protection expirée'
    };
    title.textContent = titles[color] || 'Vérification...';
    msg.textContent = message;

    // Sidebar pill
    pill.className = `status-pill status-${color}`;
    pill.querySelector('.status-text').textContent = message;
}

function renderDbInfo(files) {
    const targets = ['dbInfoContent', 'dbDetailsList'];
    targets.forEach(id => {
        const container = document.getElementById(id);
        if (!container) return;

        if (!files || files.length === 0) {
            container.innerHTML = '<p class="text-muted">Aucune base de données trouvée. Installez ClamAV puis lancez une mise à jour.</p>';
            return;
        }

        container.innerHTML = files.map(f => `
            <div class="db-file">
                <span class="db-file-name">${escapeHtml(f.name)}</span>
                <span class="db-file-meta">${escapeHtml(f.date)} — ${formatSize(f.size)}</span>
            </div>
        `).join('');
    });
}


// ─── Scan ───────────────────────────────────────────────────────────────────

function startScan(path) {
    if (isScanning) {
        showToast('Un scan est déjà en cours', 'info');
        return;
    }
    if (!path || path.trim() === '') {
        showToast('Veuillez spécifier un chemin', 'error');
        return;
    }

    isScanning = true;
    const consoleBox = document.getElementById('scanConsole');
    const output = document.getElementById('scanOutput');
    consoleBox.style.display = 'block';
    output.innerHTML = '';

    // Highlight scanning button
    document.querySelectorAll('.target-btn').forEach(btn => {
        btn.classList.toggle('scanning', btn.dataset.path === path);
    });

    appendLine(output, `▶ Scan de ${path} lancé...`, 'info');
    sendToBackend({ action: 'scan', path: path.trim() });
}


// ─── Update ─────────────────────────────────────────────────────────────────

function startUpdate() {
    if (isUpdating) return;
    isUpdating = true;

    const btn = document.getElementById('btnUpdate');
    btn.disabled = true;
    btn.textContent = 'Mise à jour en cours...';

    const consoleBox = document.getElementById('updateConsole');
    const output = document.getElementById('updateOutput');
    consoleBox.style.display = 'block';
    output.innerHTML = '';

    appendLine(output, '▶ Téléchargement des mises à jour...', 'info');
    sendToBackend({ action: 'update' });
}


// ─── Install ────────────────────────────────────────────────────────────────

function installClamAV() {
    if (isInstalling) return;
    isInstalling = true;

    const btn = document.getElementById('btnInstall');
    btn.disabled = true;
    btn.textContent = 'Installation en cours...';

    const consoleBox = document.getElementById('installConsole');
    const output = document.getElementById('installOutput');
    consoleBox.style.display = 'block';
    output.innerHTML = '';

    appendLine(output, '▶ Installation de ClamAV...', 'info');
    sendToBackend({ action: 'install' });
}


// ─── Logs ───────────────────────────────────────────────────────────────────

function loadLogs() {
    sendToBackend({ action: 'get_log' });
}

function clearLogs() {
    if (confirm('Voulez-vous vraiment vider les journaux ?')) {
        sendToBackend({ action: 'clear_log' });
        showToast('Journaux vidés', 'success');
    }
}

function renderLogs(lines) {
    const output = document.getElementById('logOutput');
    if (!lines || lines.length === 0) {
        output.innerHTML = '<p class="text-muted center">Aucun journal disponible</p>';
        return;
    }
    output.innerHTML = lines.map(line => {
        let cls = '';
        if (line.includes('FOUND')) cls = 'line-infected';
        else if (line.includes('OK') || line.includes('clean')) cls = 'line-ok';
        return `<div class="${cls}">${escapeHtml(line.trim())}</div>`;
    }).join('');
    output.scrollTop = output.scrollHeight;
}


// ─── Quarantine ─────────────────────────────────────────────────────────────

function loadQuarantine() {
    sendToBackend({ action: 'get_quarantine' });
}

function renderQuarantine(files) {
    const container = document.getElementById('quarantineList');
    const badge = document.getElementById('quarantineBadge');
    const btnEmpty = document.getElementById('btnEmptyQuarantine');

    // Update badge
    if (badge) {
        if (files && files.length > 0) {
            badge.textContent = files.length;
            badge.style.display = '';
        } else {
            badge.style.display = 'none';
        }
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
                <small class="text-muted">Les fichiers infectés détectés lors des scans apparaîtront ici</small>
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
                <div class="quarantine-item-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</div>
                <div class="quarantine-item-meta">${escapeHtml(f.date)} — ${formatSize(String(f.size))}</div>
            </div>
            <div class="quarantine-item-actions">
                <button class="btn btn-secondary" onclick="restoreQuarantineFile('${escapeJs(f.path)}')">Restaurer</button>
                <button class="btn btn-danger" onclick="deleteQuarantineFile('${escapeJs(f.path)}', '${escapeJs(f.name)}')">Supprimer</button>
            </div>
        </div>
    `).join('');
}

function deleteQuarantineFile(filepath, name) {
    if (confirm(`Supprimer définitivement « ${name} » ?`)) {
        sendToBackend({ action: 'delete_quarantine', path: filepath });
    }
}

function restoreQuarantineFile(filepath) {
    const dest = prompt('Restaurer vers quel répertoire ?', '/home');
    if (dest) {
        sendToBackend({ action: 'restore_quarantine', path: filepath, dest: dest });
    }
}

function emptyQuarantine() {
    if (confirm('Supprimer définitivement TOUS les fichiers en quarantaine ?')) {
        sendToBackend({ action: 'empty_quarantine' });
    }
}


// ─── Operation Results Handler ──────────────────────────────────────────────

function handleOperationResult(data) {
    const { status, message } = data;

    switch (status) {
        case 'progress':
            // Route to the appropriate console
            const activeConsoles = {
                scan: 'scanOutput',
                update: 'updateOutput',
                install: 'installOutput'
            };
            for (const [key, id] of Object.entries(activeConsoles)) {
                const el = document.getElementById(id);
                if (el && document.getElementById(`${key}Console`)?.style.display !== 'none') {
                    appendLine(el, message);
                }
            }
            // Fallback: write to all visible consoles
            if (isScanning) appendLine(document.getElementById('scanOutput'), message);
            if (isUpdating) appendLine(document.getElementById('updateOutput'), message);
            if (isInstalling) appendLine(document.getElementById('installOutput'), message);
            break;

        case 'success':
            showToast(message, 'success');
            resetOperationState();
            sendToBackend({ action: 'check_status' });
            sendToBackend({ action: 'get_db_info' });
            break;

        case 'clean':
            showToast(message, 'success');
            if (isScanning) {
                appendLine(document.getElementById('scanOutput'), `\n✅ ${message}`, 'ok');
            }
            resetOperationState();
            sendToBackend({ action: 'check_status' });
            sendToBackend({ action: 'get_quarantine' });
            break;

        case 'infected':
            showToast(message, 'error');
            if (isScanning) {
                appendLine(document.getElementById('scanOutput'), `\n🚨 ${message}`, 'infected');
            }
            resetOperationState();
            sendToBackend({ action: 'check_status' });
            sendToBackend({ action: 'get_quarantine' });
            break;

        case 'error':
            showToast(message, 'error');
            resetOperationState();
            break;
    }
}

function resetOperationState() {
    isScanning = false;
    isUpdating = false;
    isInstalling = false;

    document.querySelectorAll('.target-btn').forEach(btn => btn.classList.remove('scanning'));

    const btnUpdate = document.getElementById('btnUpdate');
    if (btnUpdate) { btnUpdate.disabled = false; btnUpdate.textContent = 'Lancer la mise à jour'; }

    const btnInstall = document.getElementById('btnInstall');
    if (btnInstall) { btnInstall.disabled = false; btnInstall.textContent = 'Installer maintenant'; }

    const btnFullScan = document.getElementById('btnFullScan');
    if (btnFullScan) {
        btnFullScan.disabled = false;
        btnFullScan.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9,12 12,15 15,9"/></svg> Scan complet du système';
    }
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
    d.textContent = str;
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
    setTimeout(() => {
        switch (data.action) {
            case 'check_status':
                onBackendMessage({
                    event: 'statusUpdate',
                    data: { color: 'blue', message: 'Mode développement — backend non connecté', installed: false }
                });
                break;
            case 'get_db_info':
                onBackendMessage({
                    event: 'dbInfo',
                    data: { files: [
                        { name: 'main.cvd', size: '167802880', date: 'Mar 20 2026' },
                        { name: 'daily.cvd', size: '524288', date: 'Mar 21 2026' },
                        { name: 'bytecode.cvd', size: '327680', date: 'Mar 15 2026' }
                    ]}
                });
                break;
            case 'get_log':
                onBackendMessage({
                    event: 'logContent',
                    data: { lines: [
                        '[2026-03-21T10:00:00] /home/user/file.txt: OK',
                        '[2026-03-21T10:00:01] /home/user/downloads/test.exe: Win.Trojan.Generic FOUND',
                        '[2026-03-21T10:00:02] ----------- SCAN SUMMARY -----------',
                    ]}
                });
                break;
        }
    }, 200);
}


// ─── Credits Modal ──────────────────────────────────────────────────────────

function openCredits() {
    document.getElementById('creditsModal').classList.add('open');
}

function closeCredits(event) {
    if (!event || event.target === event.currentTarget) {
        document.getElementById('creditsModal').classList.remove('open');
    }
}

function switchCreditsTab(tabId, btn) {
    document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.credits-panel').forEach(p => p.classList.remove('active'));
    if (btn) btn.classList.add('active');
    const panel = document.getElementById(`credits-${tabId}`);
    if (panel) panel.classList.add('active');
}

// Close on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeCredits();
});


// ─── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    sendToBackend({ action: 'check_status' });
    sendToBackend({ action: 'get_db_info' });
    sendToBackend({ action: 'get_quarantine' });
});
