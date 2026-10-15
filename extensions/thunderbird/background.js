/* ClamAV Antivirus GUI — Protection des courriels (Thunderbird).
   À l'affichage d'un message : les liens sont soumis au service système (script de contenu), les pièces jointes
   sont analysées par clamd (par l'hôte natif). Les courriels entrants sont aussi analysés en arrière-plan.
   Un lien dangereux n'ouvre pas le navigateur sans confirmation ; une pièce jointe infectée est signalée dans le
   message, par une notification et par le popup du service. */
'use strict';
const { api, call, hello, state, msg, reasonText } = UG;
const messenger = api;
const perTab = new Map();              // tabId → { links: [...], attachments: [...], messageId }
const scanned = new Map();             // messageId → résultats des pièces jointes (évite une seconde analyse)
const MAX_ATTACHMENT = 50 * 1024 * 1024;

function remember(tabId, key, value, messageId) {
    const cur = perTab.get(tabId) || {};
    cur[key] = value;
    if (messageId) cur.messageId = messageId;
    perTab.set(tabId, cur);
}

function updateBadge(tabId) {
    const cur = perTab.get(tabId) || {};
    const links = cur.links || [], atts = cur.attachments || [];
    const danger = links.filter(l => l.verdict === 'danger').length + atts.filter(a => a.infected).length;
    const warn = links.filter(l => l.verdict === 'warn').length;
    const text = danger ? String(danger) : warn ? String(warn) : (links.length || atts.length ? '✓' : '');
    try {
        messenger.messageDisplayAction.setBadgeText({ tabId, text });
        messenger.messageDisplayAction.setBadgeBackgroundColor({ tabId, color: danger ? '#dc2626' : warn ? '#d97706' : '#16a34a' });
        messenger.messageDisplayAction.setTitle({ tabId, title: msg('mail_name') + (danger ? ' — ' + msg('verdict_danger') : '') });
    } catch (e) { /* onglet fermé */ }
}

function b64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
}

async function scanMessageAttachments(message) {
    if (scanned.has(message.id)) return scanned.get(message.id);
    let atts = [];
    try { atts = await messenger.messages.listAttachments(message.id); } catch (e) { return []; }
    const results = [];
    for (const a of atts) {
        if (!a.partName || (a.size && a.size > MAX_ATTACHMENT)) { results.push({ name: a.name, size: a.size, skipped: true }); continue; }
        try {
            const file = await messenger.messages.getAttachmentFile(message.id, a.partName);
            const buf = await file.arrayBuffer();
            if (!buf.byteLength) { results.push({ name: a.name, size: 0, infected: false, empty: true }); continue; }
            const r = await call({ cmd: 'scan', name: a.name, data: b64(buf), sender: message.author, subject: message.subject, app: 'thunderbird' }, 240000);
            results.push({ name: a.name, size: buf.byteLength, infected: !!(r && r.infected), signature: (r && r.signature) || '', ok: !!(r && r.ok), error: (r && r.error) || '' });
        } catch (e) {
            results.push({ name: a.name, size: a.size, ok: false, error: String(e && e.message || e) });
        }
    }
    scanned.set(message.id, results);
    if (scanned.size > 500) scanned.delete(scanned.keys().next().value);
    return results;
}

function notifyInfected(message, results) {
    const bad = results.filter(r => r.infected);
    if (!bad.length) return;
    try {
        messenger.notifications.create('ug-mail-' + message.id, {
            type: 'basic', iconUrl: 'icons/48.png', title: msg('att_infected_title'),
            message: msg('att_infected', [bad.map(b => b.name).join(', '), bad[0].signature || '']) + '\n' + (message.subject || ''),
        });
    } catch (e) { /* notifications indisponibles */ }
}

messenger.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
    perTab.set(tab.id, { messageId: message.id, links: [], attachments: null });
    updateBadge(tab.id);
    if (!state.mailScan) return;
    const results = await scanMessageAttachments(message);
    remember(tab.id, 'attachments', results, message.id);
    updateBadge(tab.id);
    messenger.tabs.sendMessage(tab.id, { type: 'attachments', results }).catch(() => {});
    notifyInfected(message, results);
});

// Courriels entrants : pièces jointes analysées dès l'arrivée (notification + popup du service si infectées)
if (messenger.messages.onNewMailReceived) {
    messenger.messages.onNewMailReceived.addListener(async (folder, list) => {
        if (!state.mailScan) return;
        for (const message of (list && list.messages) || []) {
            try { notifyInfected(message, await scanMessageAttachments(message)); } catch (e) { /* message retiré */ }
        }
    });
}

messenger.runtime.onMessage.addListener((m, sender) => {
    const tabId = sender.tab && sender.tab.id;
    if (m.type === 'checkLinks') {
        return call({ cmd: 'check', urls: m.links, context: { sender: m.sender || '' }, app: 'thunderbird' }, 20000)
            .then(r => {
                const results = (r && r.results) || [];
                if (tabId !== undefined) { remember(tabId, 'links', results); updateBadge(tabId); }
                return { ok: !!(r && r.ok !== false), enabled: !r || r.enabled !== false, results, error: (r && r.error) || '' };
            })
            .catch(e => ({ ok: false, error: String(e && e.message || e), results: [] }));
    }
    if (m.type === 'open') {
        call({ cmd: 'report', url: m.url, verdict: m.verdict || 'danger', action: 'opened', app: 'thunderbird' }).catch(() => {});
        return messenger.windows.openDefaultBrowser(m.url).then(() => ({ ok: true }), e => ({ ok: false, error: String(e) }));
    }
    if (m.type === 'allowHost') {
        return call({ cmd: 'allow', host: m.host, app: 'thunderbird' }).then(() => ({ ok: true }), e => ({ ok: false, error: String(e) }));
    }
    if (m.type === 'getState') {
        return Promise.resolve({ tab: perTab.get(m.tabId !== undefined ? m.tabId : tabId) || {}, state });
    }
    if (m.type === 'blocked') {
        call({ cmd: 'report', url: m.url, verdict: 'danger', action: 'blocked', app: 'thunderbird' }).catch(() => {});
        return Promise.resolve({ ok: true });
    }
    return false;
});

messenger.tabs.onRemoved.addListener(tabId => perTab.delete(tabId));

messenger.messageDisplayScripts.register({ js: [{ file: 'content.js' }], css: [{ file: 'content.css' }] }).catch(() => {});
hello('thunderbird').catch(() => {});
