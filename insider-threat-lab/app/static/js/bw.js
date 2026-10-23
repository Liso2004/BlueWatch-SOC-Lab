// Shared helpers for SecureBank and the BlueWatch console.
const esc = v => String(v ?? '—').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const pct = (v, d = 0) => (v * 100).toFixed(d) + '%';
const fmt = n => Number(n).toLocaleString('en-ZA');

async function api(url, opts = {}) {
    if (opts.json !== undefined) {
        opts = {...opts, method: opts.method || 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(opts.json)};
    }
    const r = await fetch(url, opts);
    let body = null;
    try { body = await r.json(); } catch (e) {}
    if (!r.ok) throw new Error((body && body.error) || `${r.status} ${r.statusText}`);
    return body;
}

let toastTimer;
function toast(msg, isError = false) {
    let t = document.getElementById('toast');
    if (!t) { t = document.createElement('div'); t.id = 'toast'; t.setAttribute('role', 'status'); document.body.appendChild(t); }
    t.textContent = msg;
    t.className = 'show' + (isError ? ' err' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.className = isError ? 'err' : '', 3200);
}

function timeAgo(iso) {
    const d = new Date(iso.replace(' ', 'T') + (iso.endsWith('Z') || iso.includes('+') ? '' : 'Z'));
    const s = Math.round((Date.now() - d) / 1000);
    if (isNaN(s)) return iso;
    if (s < 60) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' days ago';
}

// Hover/focus tooltip for any element with data-tip (chart marks, dots, bars).
(function () {
    const show = (el, x, y) => {
        const tip = document.getElementById('tip'); if (!tip) return;
        tip.textContent = el.dataset.tip; tip.classList.add('show');
        tip.style.left = Math.min(x + 12, innerWidth - tip.offsetWidth - 8) + 'px';
        tip.style.top = (y - tip.offsetHeight - 10) + 'px';
    };
    const hide = () => { const t = document.getElementById('tip'); if (t) t.classList.remove('show'); };
    document.addEventListener('mousemove', e => { const el = e.target.closest('[data-tip]'); el ? show(el, e.clientX, e.clientY) : hide(); });
    document.addEventListener('focusin', e => { const el = e.target.closest('[data-tip]'); if (el) { const r = el.getBoundingClientRect(); show(el, r.left, r.top); } });
    document.addEventListener('focusout', hide);
})();

// "⋯" buttons open the help text of their card.
document.addEventListener('click', e => {
    const b = e.target.closest('[data-help]'); if (!b) return;
    const panel = document.getElementById(b.dataset.help); if (!panel) return;
    const open = panel.classList.toggle('open'); b.setAttribute('aria-expanded', open);
});
function helpButton(id) {
    return `<button class="icon-btn" data-help="${id}" aria-expanded="false" aria-controls="${id}" title="How to use this">⋯</button>`;
}

// Horizontal bar list: rows = [{label, value, cls}]
function barList(rows, unit = '') {
    if (!rows.length) return '<p class="empty">Nothing recorded yet.</p>';
    const max = Math.max(...rows.map(r => r.value), 1);
    return '<div class="bars">' + rows.map(r => `
        <div class="bar-row"><span title="${esc(r.label)}">${esc(r.label)}</span>
        <div class="bar-track" role="img" aria-label="${esc(r.label)}: ${esc(r.value)}${unit}"><div class="bar-fill ${r.cls || ''}" style="width:${(r.value / max * 100).toFixed(1)}%"></div></div>
        <span class="num">${fmt(r.value)}</span></div>`).join('') + '</div>';
}
