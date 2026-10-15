/* ClamAV Antivirus GUI — Contrôle des liens (Firefox, Chrome, Chromium, Edge, Brave).
   Avant chaque navigation principale, l'adresse est soumise au service système par l'hôte natif.
   Danger → page d'avertissement (« Retour », « Ouvrir quand même », « Toujours autoriser ce site »).
   Prudence → notification. Service injoignable → navigation laissée libre, badge « ? ». */
'use strict';
if (typeof importScripts === 'function') { importScripts('client.js'); }

const { api, call, hello, state, msg, reasonText } = UG;
const IS_GECKO = typeof browser !== 'undefined' && !!browser.runtime && !!browser.runtime.getBrowserInfo;
const action = api.action || api.browserAction;
const cache = new Map();           // url → { r, t }
const allowOnce = new Map();       // tabId → url autorisée une fois
const recentBack = new Map();      // tabId → { url, t } : « Retour » depuis la page d'avertissement
const stats = { checked: 0, blocked: 0, warned: 0 };
let appName = 'chrome';

function detectApp() {
    if (IS_GECKO) { appName = 'firefox'; return; }
    const ua = (typeof navigator !== 'undefined' && navigator.userAgent) || '';
    if (/Edg\//.test(ua)) appName = 'edge';
    else if (typeof navigator !== 'undefined' && navigator.brave) appName = 'brave';
    else if (/Chromium\//.test(ua)) appName = 'chromium';
    else appName = 'chrome';
}

function warningUrl(url, r) {
    return api.runtime.getURL('warning.html') + '?u=' + encodeURIComponent(url) + '&r=' + encodeURIComponent(JSON.stringify(r));
}

function isInternal(url) {
    return !/^https?:/i.test(url) || url.startsWith(api.runtime.getURL(''));
}

async function verdict(url) {
    const c = cache.get(url);
    if (c && Date.now() - c.t < 300000) return c.r;
    const resp = await call({ cmd: 'check', urls: [url], app: appName });
    if (resp && resp.ok === false) throw new Error(resp.error || 'daemon_unavailable');
    const r = resp && resp.results && resp.results[0] ? resp.results[0] : { verdict: 'safe', reasons: [] };
    if (cache.size > 2000) cache.clear();
    cache.set(url, { r, t: Date.now() });
    state.daemon = true;
    return r;
}

function setBadge(tabId, text, color) {
    if (!action) return;
    try {
        action.setBadgeText({ tabId, text: text || '' });
        if (color) action.setBadgeBackgroundColor({ tabId, color });
    } catch (e) { /* onglet fermé */ }
}

function notifyWarn(url, r) {
    try {
        const host = r.host || url;
        api.notifications.create('ug-' + Date.now(), {
            type: 'basic', iconUrl: 'icons/48.png', title: msg('notif_warn_title'),
            message: host + ' — ' + (r.reasons || []).slice(0, 3).map(reasonText).join(', '),
        });
    } catch (e) { /* notifications indisponibles */ }
}

async function handleNavigation(tabId, url) {
    if (isInternal(url)) return null;
    if (allowOnce.get(tabId) === url) { allowOnce.delete(tabId); return null; }
    const back = recentBack.get(tabId);
    if (back && back.url === url && Date.now() - back.t < 4000) {
        // « Retour » est retombé sur l'adresse bloquée (historique) : encore un pas en arrière
        recentBack.delete(tabId);
        if (api.tabs.goBack) { try { api.tabs.goBack(tabId); } catch (e) { /* rien */ } }
        return 'about:blank';
    }
    let r;
    try { r = await verdict(url); } catch (e) {
        state.daemon = false; state.lastError = String(e && e.message || e);
        setBadge(tabId, '?', '#64748b');
        return null;                                    // service injoignable : jamais de blocage aveugle
    }
    stats.checked++;
    if (!r || r.verdict === 'safe') { setBadge(tabId, '', null); return null; }
    if (r.verdict === 'danger') {
        stats.blocked++;
        setBadge(tabId, '!', '#dc2626');
        call({ cmd: 'report', url, verdict: 'danger', action: 'blocked', app: appName }).catch(() => {});
        return warningUrl(url, r);
    }
    stats.warned++;
    setBadge(tabId, '?', '#d97706');
    notifyWarn(url, r);
    return null;
}

if (IS_GECKO && api.webRequest && api.webRequest.onBeforeRequest) {
    // Firefox : requête bloquante (promesse) → redirigée avant tout chargement de la page
    api.webRequest.onBeforeRequest.addListener(
        d => handleNavigation(d.tabId, d.url).then(w => (w ? { redirectUrl: w } : {})).catch(() => ({})),
        { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] }, ['blocking']);
} else {
    // Chrome, Chromium, Edge, Brave (MV3) : vérification au début de la navigation, onglet redirigé si danger
    api.webNavigation.onBeforeNavigate.addListener(d => {
        if (d.frameId !== 0) return;
        handleNavigation(d.tabId, d.url).then(w => { if (w && w !== 'about:blank') api.tabs.update(d.tabId, { url: w }); }).catch(() => {});
    });
}

api.tabs.onRemoved.addListener(tabId => { allowOnce.delete(tabId); recentBack.delete(tabId); });

api.runtime.onMessage.addListener((m, sender, sendResponse) => {
    const tabId = (sender.tab && sender.tab.id) || m.tabId;
    if (m.type === 'allowOnce') {
        allowOnce.set(tabId, m.url);
        call({ cmd: 'report', url: m.url, verdict: 'danger', action: 'opened', app: appName }).catch(() => {});
        api.tabs.update(tabId, { url: m.url });
        sendResponse({ ok: true });
    } else if (m.type === 'allowHost') {
        call({ cmd: 'allow', host: m.host, app: appName }).then(() => { cache.clear(); sendResponse({ ok: true }); }, e => sendResponse({ ok: false, error: String(e) }));
        return true;
    } else if (m.type === 'back') {
        recentBack.set(tabId, { url: m.url, t: Date.now() });
        if (api.tabs.goBack) { api.tabs.goBack(tabId).catch(() => api.tabs.remove(tabId)); } else { api.tabs.remove(tabId); }
        sendResponse({ ok: true });
    } else if (m.type === 'state') {
        hello(appName).then(() => sendResponse({ state, stats, app: appName }));
        return true;
    } else if (m.type === 'check') {
        verdict(m.url).then(r => sendResponse({ ok: true, r }), e => sendResponse({ ok: false, error: String(e) }));
        return true;
    }
    return false;
});

detectApp();
hello(appName).catch(() => {});
if (api.runtime.onStartup) api.runtime.onStartup.addListener(() => hello(appName).catch(() => {}));
