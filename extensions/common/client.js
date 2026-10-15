/* ClamAV Antivirus GUI — client de l'hôte de messagerie native (partagé navigateurs / Thunderbird).
   Une connexion native persistante, une file de requêtes identifiées par `id`, reconnexion à la demande.
   L'extension ne décide rien : le service système répond sûr / prudence / danger avec ses raisons. */
'use strict';

const UG = (() => {
    const api = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;
    const NATIVE = 'clamav_antivirus';
    let port = null, seq = 0;
    const pending = new Map();
    const state = { daemon: null, enabled: true, mailScan: true, version: '', lastError: '' };

    function connect() {
        port = api.runtime.connectNative(NATIVE);
        port.onMessage.addListener(m => {
            const p = m && pending.get(m.id);
            if (p) { pending.delete(m.id); clearTimeout(p.timer); p.resolve(m); }
        });
        port.onDisconnect.addListener(() => {
            const err = (port && port.error && port.error.message) || (api.runtime.lastError && api.runtime.lastError.message) || 'native_disconnected';
            state.lastError = err;
            port = null;
            for (const p of pending.values()) { clearTimeout(p.timer); p.reject(new Error(err)); }
            pending.clear();
        });
    }

    function call(msg, timeoutMs = 12000) {
        return new Promise((resolve, reject) => {
            try { if (!port) connect(); } catch (e) { state.lastError = String(e); reject(e); return; }
            const id = ++seq;
            const timer = setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error('timeout')); } }, timeoutMs);
            pending.set(id, { resolve, reject, timer });
            try {
                port.postMessage(Object.assign({ id, version: api.runtime.getManifest().version }, msg));
            } catch (e) {
                pending.delete(id); clearTimeout(timer); port = null; reject(e);
            }
        });
    }

    async function hello(app) {
        try {
            const r = await call({ cmd: 'hello', app }, 8000);
            state.daemon = !!(r && r.daemon);
            state.enabled = !r || r.enabled !== false;
            state.mailScan = !r || r.mail_scan !== false;
            state.version = (r && r.version) || '';
            state.lastError = state.daemon ? '' : ((r && r.error) || 'daemon_unavailable');
        } catch (e) {
            state.daemon = false; state.lastError = String(e && e.message || e);
        }
        return state;
    }

    function msg(key, subs) {
        try { return api.i18n.getMessage(key, subs) || key; } catch (e) { return key; }
    }

    function reasonText(r) {
        const t = msg('reason_' + r);
        return t === 'reason_' + r ? r : t;
    }

    return { api, call, hello, state, msg, reasonText };
})();
