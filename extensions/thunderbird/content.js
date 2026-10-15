/* ClamAV Antivirus GUI — script injecté dans chaque message affiché (Thunderbird).
   Relève les liens, demande leur verdict au fond d'écran, marque les liens dangereux (clic intercepté → confirmation
   dans le message, jamais de dialogue natif) et affiche un bandeau : liens vérifiés, pièces jointes analysées. */
(() => {
    'use strict';
    if (window.__clamavUrlGuard) return;
    window.__clamavUrlGuard = true;
    const api = (typeof messenger !== 'undefined') ? messenger : browser;
    const t = (k, s) => { try { return api.i18n.getMessage(k, s) || k; } catch (e) { return k; } };
    const reasonText = r => { const x = t('reason_' + r); return x === 'reason_' + r ? r : x; };
    const verdicts = new Map();          // href → résultat
    let banner, linksLine, attsLine, confirmBox;

    function ensureBanner() {
        if (banner) return banner;
        banner = document.createElement('div');
        banner.id = 'clamav-urlguard-banner';
        banner.className = 'ug-banner ug-neutral';
        const logo = document.createElement('span'); logo.className = 'ug-logo'; logo.textContent = '🛡';
        const body = document.createElement('div'); body.className = 'ug-body';
        linksLine = document.createElement('div'); linksLine.className = 'ug-line';
        attsLine = document.createElement('div'); attsLine.className = 'ug-line ug-atts';
        body.appendChild(linksLine); body.appendChild(attsLine);
        banner.appendChild(logo); banner.appendChild(body);
        (document.body || document.documentElement).insertBefore(banner, (document.body || document.documentElement).firstChild);
        return banner;
    }

    function setLevel(level) {
        ensureBanner();
        const order = { neutral: 0, safe: 1, warn: 2, danger: 3 };
        const cur = (banner.className.match(/ug-(neutral|safe|warn|danger)/) || [])[1] || 'neutral';
        if (order[level] >= order[cur] || level === 'safe' && cur === 'neutral') banner.className = 'ug-banner ug-' + level;
    }

    function collectLinks() {
        const anchors = Array.from(document.querySelectorAll('a[href]'));
        const items = [];
        const seen = new Set();
        for (const a of anchors) {
            const href = a.href || '';
            if (!/^https?:/i.test(href) || seen.has(href)) continue;
            seen.add(href);
            items.push({ url: href, text: (a.textContent || '').trim().slice(0, 200) });
        }
        return { anchors, items };
    }

    function showConfirm(url, r) {
        if (confirmBox) confirmBox.remove();
        confirmBox = document.createElement('div');
        confirmBox.className = 'ug-confirm';
        const title = document.createElement('div'); title.className = 'ug-confirm-title'; title.textContent = t('confirm_title');
        const addr = document.createElement('div'); addr.className = 'ug-confirm-url'; addr.textContent = url;
        const why = document.createElement('ul');
        (r.reasons || []).forEach(k => { const li = document.createElement('li'); li.textContent = reasonText(k); why.appendChild(li); });
        const meta = document.createElement('div'); meta.className = 'ug-confirm-meta';
        const m = r.meta || {};
        meta.textContent = [m.list ? t('list_prefix') + ' ' + m.list : '', m.brand ? t('brand_prefix') + ' ' + m.brand : '', m.final_url ? t('final_prefix') + ' ' + m.final_url : '', m.shown_host ? t('shown_prefix') + ' ' + m.shown_host : ''].filter(Boolean).join(' · ');
        const actions = document.createElement('div'); actions.className = 'ug-confirm-actions';
        const cancel = document.createElement('button'); cancel.textContent = t('confirm_cancel'); cancel.className = 'ug-btn ug-btn-primary';
        const open = document.createElement('button'); open.textContent = t('confirm_open'); open.className = 'ug-btn';
        const allow = document.createElement('button'); allow.textContent = t('btn_allow'); allow.className = 'ug-btn ug-btn-subtle';
        cancel.addEventListener('click', () => confirmBox.remove());
        open.addEventListener('click', () => { api.runtime.sendMessage({ type: 'open', url, verdict: r.verdict }); confirmBox.remove(); });
        allow.addEventListener('click', () => { api.runtime.sendMessage({ type: 'allowHost', host: r.host || '' }).then(() => api.runtime.sendMessage({ type: 'open', url, verdict: r.verdict })); confirmBox.remove(); });
        actions.appendChild(cancel); actions.appendChild(open); actions.appendChild(allow);
        confirmBox.appendChild(title); confirmBox.appendChild(addr); confirmBox.appendChild(why);
        if (meta.textContent) confirmBox.appendChild(meta);
        confirmBox.appendChild(actions);
        ensureBanner().appendChild(confirmBox);
        confirmBox.scrollIntoView({ block: 'nearest' });
    }

    document.addEventListener('click', e => {
        const a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
        if (!a) return;
        const r = verdicts.get(a.href);
        if (r && r.verdict === 'danger') {
            e.preventDefault(); e.stopPropagation();
            api.runtime.sendMessage({ type: 'blocked', url: a.href }).catch(() => {});
            showConfirm(a.href, r);
        }
    }, true);

    function markLinks(anchors) {
        for (const a of anchors) {
            const r = verdicts.get(a.href);
            if (!r || r.verdict === 'safe') continue;
            a.classList.add(r.verdict === 'danger' ? 'ug-link-danger' : 'ug-link-warn');
            a.title = t(r.verdict === 'danger' ? 'link_danger_tip' : 'link_warn_tip', [(r.reasons || []).slice(0, 3).map(reasonText).join(', ')]);
        }
    }

    async function checkLinks() {
        const { anchors, items } = collectLinks();
        ensureBanner();
        if (!items.length) { linksLine.textContent = t('banner_nolinks'); setLevel('safe'); return; }
        linksLine.textContent = t('banner_checking', [String(items.length)]);
        let resp;
        try { resp = await api.runtime.sendMessage({ type: 'checkLinks', links: items }); } catch (e) { resp = { ok: false, error: String(e) }; }
        if (!resp || resp.ok === false) { linksLine.textContent = t('offline'); setLevel('neutral'); return; }
        if (resp.enabled === false) { linksLine.textContent = t('popup_off'); setLevel('neutral'); return; }
        (resp.results || []).forEach(r => verdicts.set(r.url, r));
        markLinks(anchors);
        const danger = (resp.results || []).filter(r => r.verdict === 'danger').length;
        const warn = (resp.results || []).filter(r => r.verdict === 'warn').length;
        if (danger) { linksLine.textContent = t('banner_danger', [String(danger), String(items.length)]); setLevel('danger'); }
        else if (warn) { linksLine.textContent = t('banner_warn', [String(warn), String(items.length)]); setLevel('warn'); }
        else { linksLine.textContent = t('banner_safe', [String(items.length)]); setLevel('safe'); }
    }

    function showAttachments(results) {
        ensureBanner();
        if (!results || !results.length) { attsLine.textContent = ''; return; }
        const infected = results.filter(r => r.infected);
        const failed = results.filter(r => r.ok === false && !r.skipped);
        if (infected.length) {
            attsLine.textContent = t('att_infected', [infected.map(r => r.name).join(', '), infected[0].signature || '']);
            setLevel('danger');
        } else if (failed.length === results.length) {
            attsLine.textContent = t('att_error');
        } else {
            attsLine.textContent = t('att_clean', [String(results.length - failed.length)]);
            setLevel('safe');
        }
    }

    api.runtime.onMessage.addListener(m => {
        if (m && m.type === 'attachments') showAttachments(m.results);
    });

    checkLinks();
})();
