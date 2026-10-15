'use strict';
(() => {
    const api = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;
    const t = (k, s) => { try { return api.i18n.getMessage(k, s) || k; } catch (e) { return k; } };
    document.getElementById('name').textContent = t('ext_name');
    api.runtime.sendMessage({ type: 'state' }, resp => {
        const dot = document.getElementById('dot'), st = document.getElementById('stateText');
        const s = (resp && resp.state) || {}, stats = (resp && resp.stats) || {};
        if (s.daemon === false) { dot.className = 'dot bad'; st.textContent = t('offline'); }
        else if (s.enabled === false) { dot.className = 'dot off'; st.textContent = t('popup_off'); }
        else { dot.className = 'dot ok'; st.textContent = t('popup_ok'); }
        document.getElementById('stats').textContent = t('popup_checked', [String(stats.checked || 0), String(stats.blocked || 0), String(stats.warned || 0)]);
    });
})();
