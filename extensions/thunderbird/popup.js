'use strict';
(async () => {
    const api = (typeof messenger !== 'undefined') ? messenger : browser;
    const t = (k, s) => { try { return api.i18n.getMessage(k, s) || k; } catch (e) { return k; } };
    const reasonText = r => { const x = t('reason_' + r); return x === 'reason_' + r ? r : x; };
    document.getElementById('name').textContent = t('mail_name');
    document.getElementById('linksTitle').textContent = t('popup_links');
    document.getElementById('attsTitle').textContent = t('popup_attachments');
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    const resp = await api.runtime.sendMessage({ type: 'getState', tabId: tabs[0] ? tabs[0].id : undefined });
    const s = (resp && resp.state) || {}, tab = (resp && resp.tab) || {};
    const dot = document.getElementById('dot'), st = document.getElementById('stateText');
    if (s.daemon === false) { dot.className = 'dot bad'; st.textContent = t('offline'); }
    else if (s.enabled === false) { dot.className = 'dot off'; st.textContent = t('popup_off'); }
    else { dot.className = 'dot ok'; st.textContent = t('popup_ok'); }
    const links = document.getElementById('links');
    const flagged = (tab.links || []).filter(l => l.verdict !== 'safe');
    if (!(tab.links || []).length) links.innerHTML = `<li class="muted">${t('banner_nolinks')}</li>`;
    else if (!flagged.length) links.innerHTML = `<li class="muted">${t('banner_safe', [String(tab.links.length)])}</li>`;
    else flagged.forEach(l => { const li = document.createElement('li'); li.className = l.verdict; li.textContent = (l.host || l.url) + ' — ' + (l.reasons || []).slice(0, 3).map(reasonText).join(', '); links.appendChild(li); });
    const atts = document.getElementById('atts');
    const list = tab.attachments || [];
    if (!list.length) atts.innerHTML = `<li class="muted">${t('popup_no_attachments')}</li>`;
    else list.forEach(a => { const li = document.createElement('li'); li.className = a.infected ? 'danger' : ''; li.textContent = a.name + ' — ' + (a.infected ? a.signature : a.ok === false ? t('att_error') : a.skipped ? t('att_skipped') : t('att_ok')); atts.appendChild(li); });
})();
