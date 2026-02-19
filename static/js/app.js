/* ==========================================================================
   Red Team Lab — Client-Side JavaScript
   Replaces React state management with vanilla JS
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initConfig();
    initViewSwitching();
    initThreatLibrary();
});

/* ---------- Sidebar Toggle ---------- */

function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.getElementById('sidebarToggle');
    if (!sidebar || !toggle) return;

    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        toggle.textContent = sidebar.classList.contains('collapsed') ? '»' : '«';
        toggle.title = sidebar.classList.contains('collapsed') ? 'Expand' : 'Collapse';
    });
}

/* ---------- Config (C2 Host & Target IP) ---------- */

function initConfig() {
    const c2Input = document.getElementById('c2HostInput');
    const ipInput = document.getElementById('targetIpInput');
    const ipError = document.getElementById('ipError');
    const c2Dot = document.getElementById('c2Dot');

    if (!c2Input || !ipInput) return;

    // Load saved values
    const savedC2 = localStorage.getItem('c2_host') || '';
    const savedIp = localStorage.getItem('target_ip') || '127.0.0.1';
    c2Input.value = savedC2;
    ipInput.value = savedIp;
    updateC2Dot();

    // C2 Host
    c2Input.addEventListener('input', () => {
        localStorage.setItem('c2_host', c2Input.value);
        updateC2Dot();
    });

    // Target IP
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

    ipInput.addEventListener('input', () => {
        const val = ipInput.value;
        if (val === 'localhost' || ipRegex.test(val)) {
            ipInput.classList.remove('error');
            if (ipError) ipError.style.display = 'none';
            localStorage.setItem('target_ip', val);
        } else {
            ipInput.classList.add('error');
            if (ipError) ipError.style.display = 'block';
        }
    });

    function updateC2Dot() {
        if (!c2Dot) return;
        if (c2Input.value) {
            c2Dot.style.background = 'var(--primary)';
            c2Dot.style.boxShadow = '0 0 5px var(--primary)';
        } else {
            c2Dot.style.background = 'var(--danger)';
            c2Dot.style.boxShadow = 'none';
        }
    }
}

/* ---------- View Switching (Adversaries / Scenarios / Campaigns) ---------- */

function initViewSwitching() {
    const navItems = document.querySelectorAll('.sidebar-nav-item[data-view]');
    if (!navItems.length) return;

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const view = item.dataset.view;

            // Update nav active state
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            // Show/hide views
            document.querySelectorAll('.view-section').forEach(section => {
                section.style.display = 'none';
            });
            const target = document.getElementById('view-' + view);
            if (target) {
                target.style.display = 'block';
                target.style.animation = 'fadeIn 0.3s ease';
            }

            // Reset actor detail view when switching
            if (view === 'adversaries') {
                const grid = document.getElementById('actorGrid');
                const detail = document.getElementById('actorDetail');
                if (grid) grid.style.display = '';
                if (detail) detail.style.display = 'none';
            }
        });
    });
}

/* ---------- Threat Library (Actor Detail + TTP Execution) ---------- */

function initThreatLibrary() {
    const actorCards = document.querySelectorAll('.actor-card');
    const backBtn = document.getElementById('backToLibrary');

    if (!actorCards.length) return;

    // Click actor card → show detail
    actorCards.forEach(card => {
        card.addEventListener('click', () => {
            const actorId = card.dataset.actorId;
            showActorDetail(actorId);
        });
    });

    // Back button
    if (backBtn) {
        backBtn.addEventListener('click', () => {
            document.getElementById('actorGrid').style.display = '';
            document.getElementById('actorDetail').style.display = 'none';
        });
    }
}

// Track executed TTPs and their outputs
const executedTTPs = new Set();
const ttpOutputs = {};
const ttpInputValues = {};

function showActorDetail(actorId) {
    if (!window.THREAT_ACTORS) return;

    const actor = window.THREAT_ACTORS.find(a => a.id === actorId);
    if (!actor) return;

    document.getElementById('actorGrid').style.display = 'none';
    document.getElementById('actorDetail').style.display = 'block';
    document.getElementById('actorDetail').style.animation = 'fadeIn 0.3s ease';

    document.getElementById('detailActorName').textContent = actor.name;
    document.getElementById('detailActorAliases').textContent =
        actor.aliases.length ? 'ALIASES: ' + actor.aliases.join(', ') : '';
    document.getElementById('detailActorDesc').textContent = actor.description;

    const list = document.getElementById('detailTTPList');
    list.innerHTML = '';

    actor.ttps.forEach(ttp => {
        const isExecuted = executedTTPs.has(ttp.id);
        const div = document.createElement('div');
        div.className = 'ttp-item' + (isExecuted ? ' executed' : '');
        div.id = 'ttp-' + ttp.id;

        let inputHTML = '';
        if (ttp.inputParams && ttp.inputParams.length) {
            inputHTML = '<div style="margin-bottom:1rem; display:grid; gap:0.5rem">';
            ttp.inputParams.forEach(param => {
                const savedVal = (ttpInputValues[ttp.id] && ttpInputValues[ttp.id][param.name]) || '';
                inputHTML += `
                    <div>
                        <label class="mono text-dim" style="font-size:0.8rem; display:block; margin-bottom:0.25rem">
                            ${param.label} ${param.required ? '<span style="color:#ff3333">*</span>' : ''}
                        </label>
                        <input type="text" class="ttp-input-field" id="input-${ttp.id}-${param.name}"
                               placeholder="${param.placeholder}" value="${savedVal}"
                               data-ttp-id="${ttp.id}" data-param-name="${param.name}" data-param-type="${param.type}"
                               data-required="${param.required}">
                        <span class="input-error" id="err-${ttp.id}-${param.name}"
                              style="color:#ff3333; font-size:0.75rem; display:none">Invalid ${param.type} format</span>
                    </div>`;
            });
            inputHTML += '</div>';
        }

        let buttonsHTML = '<div style="display:flex; gap:0.5rem; flex-wrap:wrap">';
        if (ttp.scriptPath) {
            buttonsHTML += `<button class="btn btn-execute" id="exec-btn-${ttp.id}"
                             onclick="executeTTP('${actorId}', '${ttp.id}')">EXECUTE</button>`;
        }
        if (ttp.revertScriptPath && isExecuted) {
            buttonsHTML += `<button class="btn-revert" id="revert-btn-${ttp.id}"
                             onclick="revertTTP('${actorId}', '${ttp.id}')">REVERT</button>`;
        }
        if (!ttp.scriptPath) {
            buttonsHTML += '<span class="text-dim mono" style="font-size:0.8rem">PENDING IMPLEMENTATION</span>';
        }
        buttonsHTML += '</div>';

        let outputHTML = '';
        if (ttpOutputs[ttp.id]) {
            outputHTML = `<div class="ttp-output"><pre>${escapeHtml(ttpOutputs[ttp.id])}</pre></div>`;
        }

        div.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem">
                <span class="mono text-primary" style="font-weight:bold">${ttp.id}</span>
                <div style="display:flex; gap:0.5rem; align-items:center">
                    <span class="mono text-dim" style="font-size:0.8rem">${ttp.tactic.toUpperCase()}</span>
                    ${isExecuted ? '<span class="executed-badge">EXECUTED</span>' : ''}
                </div>
            </div>
            <h4 style="margin-bottom:0.5rem">${ttp.technique}</h4>
            <p class="text-dim" style="font-size:0.9rem; margin-bottom:1rem">${ttp.description}</p>
            <div class="ttp-code-block">${escapeHtml(ttp.commandSnippet)}</div>
            ${inputHTML}
            ${buttonsHTML}
            ${outputHTML}
        `;

        list.appendChild(div);
    });
}

/* ---------- Input Validation ---------- */

const validators = {
    ip: v => /^(\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every(n => parseInt(n) <= 255),
    hostname: v => /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})*$/.test(v),
    url: v => /^https?:\/\/.+/.test(v),
    domain: v => /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(v),
    subnet: v => /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v),
    text: () => true
};

function validateTTPInputs(ttpId) {
    const inputs = document.querySelectorAll(`input[data-ttp-id="${ttpId}"]`);
    let valid = true;

    inputs.forEach(input => {
        const name = input.dataset.paramName;
        const type = input.dataset.paramType;
        const required = input.dataset.required === 'true' || input.dataset.required === 'True';
        const value = input.value.trim();
        const errEl = document.getElementById(`err-${ttpId}-${name}`);

        // Save value
        if (!ttpInputValues[ttpId]) ttpInputValues[ttpId] = {};
        ttpInputValues[ttpId][name] = value;

        if (required && !value) {
            input.classList.add('error');
            if (errEl) { errEl.style.display = 'block'; errEl.textContent = 'Required field'; }
            valid = false;
        } else if (value && validators[type] && !validators[type](value)) {
            input.classList.add('error');
            if (errEl) { errEl.style.display = 'block'; }
            valid = false;
        } else {
            input.classList.remove('error');
            if (errEl) errEl.style.display = 'none';
        }
    });

    return valid;
}

/* ---------- TTP Execution ---------- */

async function executeTTP(actorId, ttpId) {
    const actor = window.THREAT_ACTORS.find(a => a.id === actorId);
    const ttp = actor ? actor.ttps.find(t => t.id === ttpId) : null;
    if (!ttp || !ttp.scriptPath) return;

    if (!validateTTPInputs(ttpId)) return;

    const btn = document.getElementById('exec-btn-' + ttpId);
    if (btn) { btn.disabled = true; btn.textContent = 'EXECUTING...'; }

    // Collect params
    const params = {};
    if (ttp.inputParams) {
        ttp.inputParams.forEach(p => {
            const val = (ttpInputValues[ttpId] && ttpInputValues[ttpId][p.name]) || '';
            if (val) params[p.name] = val;
        });
    }

    try {
        const res = await fetch('/api/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scriptPath: ttp.scriptPath, params })
        });
        const data = await res.json();
        ttpOutputs[ttpId] = data.output || data.error;
        executedTTPs.add(ttpId);
    } catch (e) {
        ttpOutputs[ttpId] = 'Failed to execute TTP.';
    }

    // Re-render detail
    if (btn) { btn.disabled = false; btn.textContent = 'EXECUTE'; }
    showActorDetail(actorId);
}

async function revertTTP(actorId, ttpId) {
    const actor = window.THREAT_ACTORS.find(a => a.id === actorId);
    const ttp = actor ? actor.ttps.find(t => t.id === ttpId) : null;
    if (!ttp || !ttp.revertScriptPath) return;

    const btn = document.getElementById('revert-btn-' + ttpId);
    if (btn) { btn.disabled = true; btn.textContent = 'REVERTING...'; }

    try {
        const res = await fetch('/api/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scriptPath: ttp.revertScriptPath, params: {} })
        });
        const data = await res.json();
        ttpOutputs[ttpId] = '[REVERT OUTPUT]\n' + (data.output || data.error);
        executedTTPs.delete(ttpId);
    } catch (e) {
        ttpOutputs[ttpId] = 'Failed to revert TTP.';
    }

    showActorDetail(actorId);
}

/* ---------- Helpers ---------- */

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
