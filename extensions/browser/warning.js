/* Page d'avertissement : adresse bloquée, raisons, retour / ouvrir quand même / toujours autoriser. */
'use strict';
(() => {
    const api = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;
    const $ = id => document.getElementById(id);
    const t = (k, s) => { try { return api.i18n.getMessage(k, s) || k; } catch (e) { return k; } };
    const params = new URLSearchParams(location.search);
    const url = params.get('u') || '';
    let r = {};
    try { r = JSON.parse(params.get('r') || '{}'); } catch (e) { r = {}; }
    const reasons = (r.reasons || []).filter(x => x !== 'brand_login' || true);
    const meta = r.meta || {};

    document.title = t('warn_title') + ' — ClamAV Antivirus GUI';
    $('title').textContent = t('warn_title');
    $('lead').textContent = t('warn_lead');
    $('host').textContent = r.host || '';
    $('url').textContent = url;
    $('whyTitle').textContent = t('warn_why');
    $('reasons').innerHTML = '';
    reasons.forEach(k => {
        const li = document.createElement('li');
        const label = t('reason_' + k);
        li.textContent = label === 'reason_' + k ? k : label;
        $('reasons').appendChild(li);
    });
    const parts = [];
    if (meta.list) parts.push(t('list_prefix') + ' ' + meta.list);
    if (meta.brand) parts.push(t('brand_prefix') + ' ' + meta.brand);
    if (meta.final_url) parts.push(t('final_prefix') + ' ' + meta.final_url);
    if (meta.shown_host) parts.push(t('shown_prefix') + ' ' + meta.shown_host);
    $('meta').textContent = parts.join(' · ');
    $('btnBack').textContent = t('btn_back');
    $('btnOpen').textContent = t('btn_open');
    $('btnAllow').textContent = t('btn_allow');
    $('foot').textContent = t('warn_foot');

    $('btnBack').addEventListener('click', () => {
        api.runtime.sendMessage({ type: 'back', url });
        setTimeout(() => { try { history.back(); } catch (e) { /* rien */ } }, 150);
    });
    $('btnOpen').addEventListener('click', () => api.runtime.sendMessage({ type: 'allowOnce', url }));
    $('btnAllow').addEventListener('click', () => {
        const host = r.host || '';
        api.runtime.sendMessage({ type: 'allowHost', host }, () => api.runtime.sendMessage({ type: 'allowOnce', url }));
    });
})();
