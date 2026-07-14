/* ===================== KeePass Web Viewer v3.0 ===================== */
let currentUser = null;
let entries = [];
let groupsTree = null;
let currentGroupUuid = null;
let currentGroupName = 'Todas las entradas';
let socket = null;
let authToken = localStorage.getItem('authToken');

try {
    const saved = localStorage.getItem('currentUser');
    if (saved) currentUser = JSON.parse(saved);
} catch (e) { console.error('Error parsing saved user', e); }

// DOM refs
const loginScreen = document.getElementById('login-screen');
const masterScreen = document.getElementById('master-screen');
const mainScreen = document.getElementById('main-screen');
const entriesBody = document.getElementById('entries-body');
const entryModal = document.getElementById('entry-modal');
const adminModal = document.getElementById('admin-modal');
const confirmModal = document.getElementById('confirm-modal');

const IDLE_TIME = 15 * 60 * 1000;
let idleTimer = null;

/* ---------- Theme ---------- */
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    const icon = document.querySelector('#theme-btn i');
    if (icon) { icon.setAttribute('data-lucide', theme === 'dark' ? 'moon' : 'sun'); refreshIcons(); }
}
applyTheme(localStorage.getItem('theme') || 'dark');

/* ---------- Helpers ---------- */
function refreshIcons() { if (window.lucide) lucide.createIcons(); }

function toast(msg, type = 'info') {
    const c = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    const icon = type === 'success' ? 'check-circle' : type === 'error' ? 'alert-circle' : 'info';
    el.innerHTML = `<i data-lucide="${icon}"></i><span></span>`;
    el.querySelector('span').textContent = msg;
    c.appendChild(el);
    refreshIcons();
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 3500);
}

function confirmDialog(text) {
    return new Promise(resolve => {
        document.getElementById('confirm-text').textContent = text;
        confirmModal.classList.remove('hidden');
        const ok = document.getElementById('confirm-ok');
        const cancel = document.getElementById('confirm-cancel');
        const done = (val) => { confirmModal.classList.add('hidden'); ok.onclick = null; cancel.onclick = null; resolve(val); };
        ok.onclick = () => done(true);
        cancel.onclick = () => done(false);
    });
}

async function apiFetch(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401 && authToken) { logout(); throw new Error('Sesión expirada'); }
    return res;
}

function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
    authToken = null; currentUser = null;
    location.reload();
}

async function lockDatabase() {
    try { await apiFetch('/api/keepass/lock', { method: 'POST' }); } catch (e) {}
    showScreen('master');
    toast('Base de datos bloqueada', 'info');
}

/* ---------- Init ---------- */
document.addEventListener('DOMContentLoaded', async () => {
    if (authToken) {
        try {
            const res = await apiFetch('/api/keepass/open', { method: 'POST', body: JSON.stringify({ password: '' }) });
            if (res.ok) { showScreen('main'); refreshData(); } else { showScreen('master'); }
        } catch (e) { showScreen('master'); }
    } else {
        showScreen('login');
    }
    initSocket();
    setupEventListeners();
    resetIdleTimer();
    refreshIcons();
});

function resetIdleTimer() {
    if (idleTimer) clearTimeout(idleTimer);
    if (authToken) idleTimer = setTimeout(() => { lockDatabase(); }, IDLE_TIME);
}
['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(evt =>
    window.addEventListener(evt, resetIdleTimer, true));

function initSocket() {
    try {
        if (window.io && authToken) {
            socket = io({ auth: { token: authToken } });
            socket.on('entry_change', () => refreshData());
        }
    } catch (e) { console.warn('Socket init failed', e); }
}

/* ---------- Event listeners ---------- */
function setupEventListeners() {
    document.getElementById('theme-btn').onclick = () =>
        applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');

    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            const res = await fetch('/api/login', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: e.target.username.value, password: e.target.password.value })
            });
            if (res.ok) {
                const data = await res.json();
                currentUser = data.user; authToken = data.access_token;
                localStorage.setItem('authToken', authToken);
                localStorage.setItem('currentUser', JSON.stringify(currentUser));
                initSocket();
                const openRes = await apiFetch('/api/keepass/open', { method: 'POST', body: JSON.stringify({ password: '' }) });
                if (openRes.ok) { showScreen('main'); refreshData(); } else { showScreen('master'); }
            } else if (res.status === 429) {
                showError('login', 'Demasiados intentos. Espera unos minutos.');
            } else {
                showError('login', 'Credenciales inválidas');
            }
        } catch (err) { showError('login', 'Error de conexión'); }
    });

    document.getElementById('master-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            const res = await apiFetch('/api/keepass/open', { method: 'POST', body: JSON.stringify({ password: e.target['master-pass'].value }) });
            if (res.ok) { showScreen('main'); refreshData(); }
            else { const d = await res.json(); showError('master', d.detail || 'Error al abrir el archivo'); }
        } catch (err) { showError('master', 'Error de conexión'); }
    });

    document.getElementById('entry-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const uuid = document.getElementById('entry-uuid').value;
        const data = {
            title: document.getElementById('entry-title').value,
            username: document.getElementById('entry-username').value,
            password: document.getElementById('entry-password').value,
            url: document.getElementById('entry-url').value,
            notes: document.getElementById('entry-notes').value,
            group_uuid: document.getElementById('entry-group').value || null
        };
        const res = await apiFetch(uuid ? `/api/keepass/entries/${uuid}` : '/api/keepass/entries', {
            method: uuid ? 'PUT' : 'POST', body: JSON.stringify(data)
        });
        if (res.ok) { closeModals(); refreshData(); toast(uuid ? 'Entrada actualizada' : 'Entrada creada', 'success'); }
        else { toast('No se pudo guardar la entrada', 'error'); }
    });

    document.getElementById('config-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const config = Object.fromEntries(new FormData(e.target).entries());
        config.save_keepass_password = document.getElementById('conf-save-keepass-password').checked;
        const res = await apiFetch('/api/config', { method: 'POST', body: JSON.stringify(config) });
        if (res.ok) { closeModals(); toast('Configuración guardada', 'success'); }
        else { toast('Error al guardar la configuración', 'error'); }
    });

    const passInput = document.getElementById('entry-password');
    passInput.oninput = (e) => updatePasswordStrength(e.target.value);

    document.getElementById('gen-pass-btn').onclick = () => {
        const p = generatePassword();
        passInput.value = p; passInput.type = 'text'; updatePasswordStrength(p);
    };

    document.getElementById('add-entry-btn').onclick = () => openEntryModal();
    document.getElementById('config-btn').onclick = (e) => { e.preventDefault(); openAdminModal(); };
    document.getElementById('lock-btn').onclick = () => logout();
    document.getElementById('lock-db-btn').onclick = () => lockDatabase();
    document.getElementById('logout-btn').onclick = () => logout();

    document.getElementById('export-btn').onclick = async () => {
        try {
            const res = await apiFetch('/api/keepass/export');
            if (!res.ok) { toast('No autorizado para exportar', 'error'); return; }
            const blob = await res.blob();
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob); a.download = 'keepass_backup.kdbx'; a.click();
            URL.revokeObjectURL(a.href);
            toast('Backup descargado', 'success');
        } catch (e) { toast('Error al exportar', 'error'); }
    };

    document.querySelectorAll('.close-modal').forEach(b => b.onclick = closeModals);
    document.querySelectorAll('.modal').forEach(m => m.addEventListener('click', (e) => { if (e.target === m) closeModals(); }));

    document.getElementById('search-input').oninput = (e) => renderEntries(e.target.value);

    document.getElementById('toggle-entry-pass').onclick = () => {
        const i = passInput, icon = document.querySelector('#toggle-entry-pass i');
        i.type = i.type === 'password' ? 'text' : 'password';
        icon.setAttribute('data-lucide', i.type === 'password' ? 'eye' : 'eye-off');
        refreshIcons();
    };

    document.getElementById('reveal-entry-pass').onclick = async () => {
        const uuid = document.getElementById('entry-uuid').value;
        if (!uuid) return;
        const pwd = await fetchPassword(uuid);
        if (pwd !== null) { passInput.value = pwd; passInput.type = 'text'; updatePasswordStrength(pwd); }
    };

    document.getElementById('add-group-btn').onclick = async () => {
        const name = prompt(currentGroupUuid ? `Nuevo subgrupo dentro de "${currentGroupName}":` : 'Nombre del nuevo grupo:');
        if (name && name.trim()) {
            const res = await apiFetch('/api/keepass/groups', { method: 'POST', body: JSON.stringify({ name: name.trim(), parent_uuid: currentGroupUuid }) });
            if (res.ok) { refreshData(); toast('Grupo creado', 'success'); }
        }
    };

    document.getElementById('del-group-btn').onclick = async () => {
        if (!currentGroupUuid) return;
        if (await confirmDialog(`¿Eliminar el grupo "${currentGroupName}" y todo su contenido?`)) {
            const res = await apiFetch(`/api/keepass/groups/${currentGroupUuid}`, { method: 'DELETE' });
            if (res.ok) { currentGroupUuid = null; currentGroupName = 'Todas las entradas'; refreshData(); toast('Grupo eliminado', 'success'); }
            else { toast('No se pudo eliminar el grupo', 'error'); }
        }
    };

    document.getElementById('sidebar-toggle').onclick = () => document.getElementById('sidebar').classList.toggle('open');

    document.getElementById('test-ad-btn').onclick = testAdConnection;

    document.querySelectorAll('.tab-btn').forEach(btn => btn.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
    }));

    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModals(); });
}

/* ---------- Data ---------- */
async function refreshData() {
    const loading = document.getElementById('loading-state');
    loading.classList.remove('hidden');
    try {
        const [eRes, gRes] = await Promise.all([apiFetch('/api/keepass/entries'), apiFetch('/api/keepass/groups')]);
        if (eRes.ok) entries = await eRes.json();
        if (gRes.ok) groupsTree = await gRes.json();
        renderGroups();
        renderEntries(document.getElementById('search-input').value);
    } catch (e) { console.error('refreshData', e); }
    finally { loading.classList.add('hidden'); }
}

function renderGroups() {
    const container = document.getElementById('group-list');
    container.innerHTML = '';
    if (!groupsTree || !groupsTree.name) return;

    const build = (group) => {
        const row = document.createElement('div');
        row.className = 'tree-row';
        if (currentGroupUuid === group.uuid || (!currentGroupUuid && group.level === 0)) row.classList.add('active');
        row.style.paddingLeft = `${(group.level * 14) + 12}px`;
        const iconName = group.subgroups.length ? 'folder' : 'folder-open';
        row.innerHTML = `<i data-lucide="${iconName}" class="tree-icon"></i><span></span>`;
        row.querySelector('span').textContent = group.name;
        row.onclick = () => {
            currentGroupUuid = group.level === 0 ? null : group.uuid;
            currentGroupName = group.level === 0 ? 'Todas las entradas' : group.name;
            document.getElementById('current-group').textContent = currentGroupName;
            document.getElementById('del-group-btn').classList.toggle('hidden', !currentGroupUuid);
            document.getElementById('sidebar').classList.remove('open');
            renderGroups();
            renderEntries(document.getElementById('search-input').value);
        };
        container.appendChild(row);
        group.subgroups.forEach(build);
    };
    build(groupsTree);
    refreshIcons();
}

function renderEntries(filter = '') {
    const search = filter.toLowerCase();
    const filtered = entries.filter(e => {
        const matchesGroup = !currentGroupUuid || e.group_uuid === currentGroupUuid;
        return matchesGroup && (
            e.title.toLowerCase().includes(search) ||
            e.username.toLowerCase().includes(search) ||
            (e.url && e.url.toLowerCase().includes(search)) ||
            (e.notes && e.notes.toLowerCase().includes(search))
        );
    });

    entriesBody.innerHTML = '';
    document.getElementById('empty-state').classList.toggle('hidden', filtered.length > 0);
    document.getElementById('table-wrapper').classList.toggle('hidden', filtered.length === 0);

    filtered.forEach(entry => {
        const tr = document.createElement('tr');
        const tdTitle = document.createElement('td');
        tdTitle.setAttribute('data-label', 'Título');
        tdTitle.innerHTML = `<div class="cell-title"><i data-lucide="key" class="tree-icon"></i><span class="val-text"></span></div>`;
        tdTitle.querySelector('span').textContent = entry.title;

        const tdUser = document.createElement('td');
        tdUser.setAttribute('data-label', 'Usuario');
        tdUser.innerHTML = `<div class="cell-flex"><span class="val-text"></span><button class="copy-btn" title="Copiar usuario" aria-label="Copiar usuario"><i data-lucide="copy"></i></button></div>`;
        tdUser.querySelector('span').textContent = entry.username;
        tdUser.querySelector('.copy-btn').onclick = (ev) => { copyText(entry.username); flashIcon(ev.currentTarget); };

        const tdPass = document.createElement('td');
        tdPass.setAttribute('data-label', 'Contraseña');
        tdPass.innerHTML = `<div class="cell-flex"><span class="pass-text">••••••••</span>
            <button class="reveal-btn" title="Mostrar" aria-label="Mostrar contraseña"><i data-lucide="eye"></i></button>
            <button class="copy-btn" title="Copiar contraseña" aria-label="Copiar contraseña"><i data-lucide="copy"></i></button></div>`;
        const passSpan = tdPass.querySelector('.pass-text');
        let revealed = false, hideTimer = null;
        tdPass.querySelector('.reveal-btn').onclick = async (ev) => {
            const icon = ev.currentTarget.querySelector('i');
            if (revealed) { passSpan.textContent = '••••••••'; revealed = false; icon.setAttribute('data-lucide', 'eye'); refreshIcons(); clearTimeout(hideTimer); return; }
            const pwd = await fetchPassword(entry.uuid);
            if (pwd !== null) {
                passSpan.textContent = pwd; revealed = true; icon.setAttribute('data-lucide', 'eye-off'); refreshIcons();
                hideTimer = setTimeout(() => { passSpan.textContent = '••••••••'; revealed = false; icon.setAttribute('data-lucide', 'eye'); refreshIcons(); }, 15000);
            }
        };
        tdPass.querySelector('.copy-btn').onclick = async (ev) => {
            const pwd = await fetchPassword(entry.uuid);
            if (pwd !== null) { copyText(pwd); flashIcon(ev.currentTarget); }
        };

        const tdUrl = document.createElement('td');
        tdUrl.setAttribute('data-label', 'URL');
        if (entry.url) {
            const a = document.createElement('a');
            a.href = entry.url; a.target = '_blank'; a.rel = 'noopener noreferrer';
            a.className = 'url-link'; a.textContent = entry.url;
            tdUrl.appendChild(a);
        }

        const tdActions = document.createElement('td');
        tdActions.className = 'col-actions';
        tdActions.setAttribute('data-label', 'Acciones');
        tdActions.innerHTML = `<button class="icon-btn small" title="Editar" aria-label="Editar entrada"><i data-lucide="pencil"></i></button>`;
        tdActions.querySelector('button').onclick = () => openEntryModal(entry.uuid);

        tr.append(tdTitle, tdUser, tdPass, tdUrl, tdActions);
        entriesBody.appendChild(tr);
    });
    refreshIcons();
}

async function fetchPassword(uuid) {
    try {
        const res = await apiFetch(`/api/keepass/entries/${uuid}/password`);
        if (res.ok) return (await res.json()).password;
        toast('No se pudo obtener la contraseña', 'error');
    } catch (e) { toast('Error de conexión', 'error'); }
    return null;
}

function flashIcon(btn) {
    const icon = btn.querySelector('i');
    const orig = icon.getAttribute('data-lucide');
    icon.setAttribute('data-lucide', 'check'); refreshIcons();
    setTimeout(() => { icon.setAttribute('data-lucide', orig); refreshIcons(); }, 1500);
}

/* ---------- Utilities ---------- */
function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        toast('Copiado al portapapeles', 'success');
        setTimeout(() => navigator.clipboard.readText().then(c => { if (c === text) navigator.clipboard.writeText(''); }).catch(() => {}), 30000);
    }).catch(() => toast('No se pudo copiar', 'error'));
}

function generatePassword(length = 18) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=";
    const arr = new Uint32Array(length);
    crypto.getRandomValues(arr);
    return Array.from(arr, n => charset[n % charset.length]).join('');
}

function updatePasswordStrength(pass) {
    const bar = document.getElementById('strength-bar');
    const label = document.getElementById('strength-label');
    bar.className = 'strength-bar';
    if (!pass) { bar.style.width = '0'; label.textContent = ''; return; }
    let score = 0;
    if (pass.length >= 12) score++; if (pass.length >= 16) score++;
    if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) score++;
    if (/[0-9]/.test(pass)) score++;
    if (/[^A-Za-z0-9]/.test(pass)) score++;
    if (score <= 2) { bar.classList.add('weak'); bar.style.width = '30%'; label.textContent = 'Débil'; label.style.color = 'var(--error)'; }
    else if (score <= 3) { bar.classList.add('medium'); bar.style.width = '65%'; label.textContent = 'Media'; label.style.color = 'var(--warning)'; }
    else { bar.classList.add('strong'); bar.style.width = '100%'; label.textContent = 'Fuerte'; label.style.color = 'var(--success)'; }
}

/* ---------- Screens ---------- */
function showScreen(id) {
    [loginScreen, masterScreen, mainScreen].forEach(s => s.classList.add('hidden'));
    document.getElementById(`${id}-screen`).classList.remove('hidden');

    const header = document.getElementById('app-header');
    header.classList.toggle('hidden', id === 'login');

    const isAdmin = currentUser && (currentUser.role === 'admin' || currentUser.username === 'admin');
    document.getElementById('config-btn').classList.toggle('hidden', !(isAdmin && id !== 'login'));
    document.getElementById('lock-btn').classList.toggle('hidden', id === 'login');
    document.getElementById('lock-db-btn').classList.toggle('hidden', id !== 'main');

    const displayUser = document.getElementById('display-user');
    if (currentUser) displayUser.textContent = currentUser.username + (isAdmin ? ' · Admin' : '');
    resetIdleTimer();
    refreshIcons();
}

function showError(screen, msg) {
    const el = document.getElementById(`${screen}-error`);
    el.textContent = msg;
    setTimeout(() => { el.textContent = ''; }, 4000);
}

/* ---------- Entry modal ---------- */
function populateGroupSelect(selectedUuid) {
    const sel = document.getElementById('entry-group');
    sel.innerHTML = '';
    if (!groupsTree) return;
    const walk = (g) => {
        const opt = document.createElement('option');
        opt.value = g.uuid;
        opt.textContent = `${'— '.repeat(g.level)}${g.name}`;
        sel.appendChild(opt);
        g.subgroups.forEach(walk);
    };
    walk(groupsTree);
    if (selectedUuid) sel.value = selectedUuid;
    else if (currentGroupUuid) sel.value = currentGroupUuid;
}

function openEntryModal(uuid = null) {
    const form = document.getElementById('entry-form');
    form.reset();
    document.getElementById('entry-uuid').value = uuid || '';
    document.getElementById('strength-bar').style.width = '0';
    document.getElementById('strength-label').textContent = '';
    document.getElementById('entry-password').type = 'password';
    const delBtn = document.getElementById('delete-entry-btn');
    const revealBtn = document.getElementById('reveal-entry-pass');

    if (uuid) {
        const entry = entries.find(e => e.uuid === uuid);
        document.getElementById('entry-modal-title').textContent = 'Editar entrada';
        document.getElementById('entry-title').value = entry.title;
        document.getElementById('entry-username').value = entry.username;
        document.getElementById('entry-url').value = entry.url || '';
        document.getElementById('entry-notes').value = entry.notes || '';
        document.getElementById('entry-password').placeholder = '(sin cambios)';
        populateGroupSelect(entry.group_uuid);
        delBtn.classList.remove('hidden');
        revealBtn.classList.remove('hidden');
        delBtn.onclick = () => deleteEntry(uuid);
    } else {
        document.getElementById('entry-modal-title').textContent = 'Nueva entrada';
        document.getElementById('entry-password').placeholder = '';
        document.getElementById('entry-password').required = false;
        populateGroupSelect(null);
        delBtn.classList.add('hidden');
        revealBtn.classList.add('hidden');
    }
    entryModal.classList.remove('hidden');
    refreshIcons();
}

async function deleteEntry(uuid) {
    if (await confirmDialog('¿Eliminar esta entrada de forma permanente?')) {
        const res = await apiFetch(`/api/keepass/entries/${uuid}`, { method: 'DELETE' });
        if (res.ok) { closeModals(); refreshData(); toast('Entrada eliminada', 'success'); }
        else { toast('No se pudo eliminar', 'error'); }
    }
}

/* ---------- Admin modal ---------- */
async function openAdminModal() {
    const isAdmin = currentUser && (currentUser.role === 'admin' || currentUser.username === 'admin');
    if (!isAdmin) { toast('Solo el administrador puede acceder a la configuración', 'error'); return; }

    document.getElementById('config-form').reset();
    try {
        const res = await apiFetch('/api/config');
        if (res.ok) {
            const c = await res.json();
            document.getElementById('conf-file-path').value = c.keepass_file_path || '';
            document.getElementById('conf-ad-server').value = c.ad_server || '';
            document.getElementById('conf-ad-domain').value = c.ad_domain || '';
            document.getElementById('conf-ad-group').value = c.ad_group || '';
            document.getElementById('conf-azure-tenant').value = c.azure_tenant_id || '';
            document.getElementById('conf-azure-client').value = c.azure_client_id || '';
            document.getElementById('conf-azure-group').value = c.azure_group_id || '';
            document.getElementById('conf-admin-user').value = c.admin_user || '';
            document.getElementById('conf-save-keepass-password').checked = c.save_keepass_password === true || c.save_keepass_password === 'true';
            document.getElementById('conf-keepass-password').placeholder = c.keepass_password_set ? '•••••••• (guardada)' : '••••••••';
            document.getElementById('conf-azure-secret').placeholder = c.azure_client_secret_set ? '•••••••• (guardado)' : '••••••••';
        }
    } catch (e) { console.error(e); }

    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelector('.tab-btn[data-tab="tab-general"]').classList.add('active');
    document.getElementById('tab-general').classList.add('active');
    adminModal.classList.remove('hidden');
    refreshIcons();
}

async function testAdConnection() {
    const btn = document.getElementById('test-ad-btn');
    const result = document.getElementById('test-ad-result');
    const payload = {
        ad_server: document.getElementById('conf-ad-server').value,
        ad_domain: document.getElementById('conf-ad-domain').value,
        ad_group: document.getElementById('conf-ad-group').value,
        test_user: document.getElementById('test-ad-user').value,
        test_pass: document.getElementById('test-ad-pass').value
    };
    if (!payload.ad_server || !payload.ad_domain || !payload.test_user || !payload.test_pass) {
        toast('Rellena los campos de AD y de prueba', 'error'); return;
    }
    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader" class="spin"></i> Probando...';
    refreshIcons();
    result.classList.add('hidden');
    try {
        const res = await apiFetch('/api/config/test-ad', { method: 'POST', body: JSON.stringify(payload) });
        const data = await res.json();
        result.textContent = data.message;
        result.className = `test-result ${data.status === 'success' ? 'success' : 'error'}`;
        result.classList.remove('hidden');
    } catch (e) {
        result.textContent = 'Error de comunicación con el servidor.';
        result.className = 'test-result error';
        result.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="activity"></i> Comprobar conexión';
        refreshIcons();
    }
}

function closeModals() {
    entryModal.classList.add('hidden');
    adminModal.classList.add('hidden');
    confirmModal.classList.add('hidden');
}

/* ---------- Easter egg ---------- */
let titleClicks = 0;
document.addEventListener('click', (e) => {
    if (!e.target.closest('#app-title-main')) return;
    if (++titleClicks < 7) return;
    titleClicks = 0;
    const c = document.getElementById('easter-egg-container');
    c.classList.remove('hidden');
    c.innerHTML = '<div class="hacked-text">HACKED</div>';
    for (let i = 0; i < 40; i++) {
        const p = document.createElement('div');
        p.className = 'particle';
        const a = Math.random() * Math.PI * 2, d = 100 + Math.random() * 450;
        p.style.setProperty('--x', `${Math.cos(a) * d}px`);
        p.style.setProperty('--y', `${Math.sin(a) * d}px`);
        p.style.left = '50%'; p.style.top = '50%';
        c.appendChild(p);
    }
    setTimeout(() => { c.classList.add('hidden'); c.innerHTML = ''; }, 3000);
}, { passive: true });
