const API_URL = '';
let currentUser = null;
let entries = [];
let groups = [];
let currentGroup = 'Root';
let currentGroupUuid = null;
let socket = null;

// DOM Elements
const loginScreen = document.getElementById('login-screen');
const masterScreen = document.getElementById('master-screen');
const mainScreen = document.getElementById('main-screen');
const loginForm = document.getElementById('login-form');
const masterForm = document.getElementById('master-form');
const entryForm = document.getElementById('entry-form');
const configForm = document.getElementById('config-form');
const entriesBody = document.getElementById('entries-body');
const groupList = document.getElementById('group-list');
const entryModal = document.getElementById('entry-modal');
const adminModal = document.getElementById('admin-modal');

// Helper for authenticated fetches
async function apiFetch(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }

    try {
        const res = await fetch(url, { ...options, headers });
        
        if (res.status === 401) {
            console.warn('Session expired or unauthorized');
            logout();
            throw new Error('Sesión expirada');
        }
        
        return res;
    } catch (err) {
        console.error(`Fetch error on ${url}:`, err);
        throw err;
    }
}

function logout() {
    localStorage.removeItem('authToken');
    authToken = null;
    currentUser = null;
    location.reload();
}

// --- Initialization ---

document.addEventListener('DOMContentLoaded', () => {
    // Check if we have a token to skip login screen (optional, but good)
    if (authToken) {
        showScreen('master');
    }
    initSocket();
    setupEventListeners();
});

function initSocket() {
    try {
        if (typeof io !== 'undefined') {
            socket = io();
            socket.on('entry_change', (change) => {
                console.log('Remote change received:', change);
                refreshData();
            });
        }
    } catch (e) {
        console.warn('Socket.io could not be initialized:', e);
    }
}

function setupEventListeners() {
    // Login
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = e.target.username.value;
        const password = e.target.password.value;
        
        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            if (res.ok) {
                const data = await res.json();
                currentUser = data.user;
                authToken = data.access_token;
                localStorage.setItem('authToken', authToken);
                
                showScreen('master');
                document.getElementById('display-user').innerText = currentUser.username;
            } else {
                showError('login', 'Credenciales inválidas');
            }
        } catch (err) {
            showError('login', 'Error de conexión');
        }
    });

    // Master Password
    masterForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = e.target['master-pass'].value;
        
        try {
            const res = await apiFetch('/api/keepass/open', {
                method: 'POST',
                body: JSON.stringify({ password })
            });
            
            if (res.ok) {
                showScreen('main');
                refreshData();
            } else {
                const errorData = await res.json();
                showError('master', errorData.detail || 'Error al abrir el archivo');
            }
        } catch (err) {
            showError('master', 'Error de conexión');
        }
    });

    // Entry Form
    entryForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const uuid = document.getElementById('entry-uuid').value;
        const data = {
            title: document.getElementById('entry-title').value,
            username: document.getElementById('entry-username').value,
            password: document.getElementById('entry-password').value,
            url: document.getElementById('entry-url').value,
            notes: document.getElementById('entry-notes').value,
            group: currentGroup
        };

        const method = uuid ? 'PUT' : 'POST';
        const url = uuid ? `/api/keepass/entries/${uuid}` : '/api/keepass/entries';

        const res = await apiFetch(url, {
            method,
            body: JSON.stringify(data)
        });

        if (res.ok) {
            closeModals();
            refreshData();
        }
    });

    // Config Form
    configForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const config = Object.fromEntries(formData.entries());
        
        const res = await apiFetch('/api/config', {
            method: 'POST',
            body: JSON.stringify(config)
        });

        if (res.ok) {
            closeModals();
            alert('Configuración guardada.');
        }
    });

    // UI Buttons
    document.getElementById('add-entry-btn').onclick = () => openEntryModal();
    
    // Multiple config buttons
    ['config-btn', 'config-btn-login', 'config-btn-master'].forEach(id => {
        const btn = document.getElementById(id);
        if (btn) btn.onclick = () => openAdminModal();
    });
    document.getElementById('lock-btn').onclick = () => logout();
    document.getElementById('logout-btn').onclick = () => logout();
    document.querySelectorAll('.close-modal').forEach(btn => btn.onclick = closeModals);
    
    document.getElementById('search-input').oninput = (e) => {
        renderEntries(e.target.value);
    };

    document.getElementById('toggle-entry-pass').onclick = () => {
        const input = document.getElementById('entry-password');
        input.type = input.type === 'password' ? 'text' : 'password';
    };

    document.getElementById('add-group-btn').onclick = () => {
        const name = prompt('Nombre del nuevo grupo:');
        if (name) addGroup(name);
    };
}

async function addGroup(name) {
    const res = await apiFetch('/api/keepass/groups', {
        method: 'POST',
        body: JSON.stringify({ name })
    });
    if (res.ok) refreshData();
}

// --- Data Management ---

async function refreshData() {
    try {
        const [entriesRes, groupsRes] = await Promise.all([
            apiFetch('/api/keepass/entries'),
            apiFetch('/api/keepass/groups')
        ]);

        if (entriesRes.ok) entries = await entriesRes.json();
        if (groupsRes.ok) groups = await groupsRes.json();

        renderGroups();
        renderEntries();
    } catch (e) {
        console.error('Error refreshing data:', e);
    }
}

function renderGroups() {
    groupList.innerHTML = '<li class="group-item active" onclick="setGroup(\'Root\')">Todas las entradas</li>';
    groups.forEach(group => {
        const li = document.createElement('li');
        li.className = 'group-item';
        li.innerText = group.name;
        li.style.paddingLeft = `${(group.level * 15) + 16}px`;
        li.onclick = () => setGroup(group.name, li, group.uuid);
        groupList.appendChild(li);
    });
}

function setGroup(name, el, uuid = null) {
    currentGroup = name;
    currentGroupUuid = uuid;
    document.getElementById('current-group').innerText = name === 'Root' ? 'Todas las Entradas' : name;
    document.querySelectorAll('.group-item').forEach(item => item.classList.remove('active'));
    if (el) el.classList.add('active');
    renderEntries();
}

function renderEntries(filter = '') {
    const filtered = entries.filter(e => {
        const matchesGroup = !currentGroupUuid || e.group_uuid === currentGroupUuid || currentGroup === 'Root';
        const matchesSearch = e.title.toLowerCase().includes(filter.toLowerCase()) || 
                             e.username.toLowerCase().includes(filter.toLowerCase());
        return matchesGroup && matchesSearch;
    });

    entriesBody.innerHTML = '';
    filtered.forEach(entry => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${entry.title}</td>
            <td>${entry.username}</td>
            <td class="pass-cell">••••••••</td>
            <td>${entry.url}</td>
            <td>
                <button class="small-btn" onclick="openEntryModal('${entry.uuid}')">Editar</button>
            </td>
        `;
        entriesBody.appendChild(tr);
    });
}

// --- UI Helpers ---

function showScreen(id) {
    const screens = [loginScreen, masterScreen, mainScreen];
    screens.forEach(s => s.classList.add('hidden'));
    document.getElementById(`${id}-screen`).classList.remove('hidden');
    
    // Header logic
    const header = document.getElementById('app-header');
    const lockBtn = document.getElementById('lock-btn');
    
    if (id === 'login') {
        header.classList.add('hidden');
    } else {
        header.classList.remove('hidden');
    }
    
    if (id === 'main') {
        lockBtn.classList.remove('hidden');
    } else {
        lockBtn.classList.add('hidden');
    }
}

function showError(screen, msg) {
    const errEl = document.getElementById(`${screen}-error`);
    errEl.innerText = msg;
    setTimeout(() => errEl.innerText = '', 3000);
}

function openEntryModal(uuid = null) {
    const modalTitle = document.getElementById('entry-modal-title');
    const deleteBtn = document.getElementById('delete-entry-btn');
    entryForm.reset();
    document.getElementById('entry-uuid').value = uuid || '';

    if (uuid) {
        const entry = entries.find(e => e.uuid === uuid);
        modalTitle.innerText = 'Editar Entrada';
        document.getElementById('entry-title').value = entry.title;
        document.getElementById('entry-username').value = entry.username;
        document.getElementById('entry-password').value = entry.password;
        document.getElementById('entry-url').value = entry.url;
        document.getElementById('entry-notes').value = entry.notes;
        deleteBtn.classList.remove('hidden');
        deleteBtn.onclick = () => deleteEntry(uuid);
    } else {
        modalTitle.innerText = 'Nueva Entrada';
        deleteBtn.classList.add('hidden');
    }
    
    entryModal.classList.remove('hidden');
}

async function deleteEntry(uuid) {
    if (confirm('¿Estás seguro de eliminar esta entrada?')) {
        const res = await apiFetch(`/api/keepass/entries/${uuid}`, { method: 'DELETE' });
        if (res.ok) {
            closeModals();
            refreshData();
        }
    }
}

async function openAdminModal() {
    // If logged in, check if admin. If not logged in, allow for initial setup.
    if (currentUser && currentUser.role !== 'admin') {
        alert('Solo el administrador puede acceder a la configuración.');
        return;
    }
    
    try {
        const res = await apiFetch('/api/config');
        if (res.ok) {
            const config = await res.json();
            document.getElementById('conf-file-path').value = config.keepass_file_path || '';
            document.getElementById('conf-ad-server').value = config.ad_server || '';
            document.getElementById('conf-ad-domain').value = config.ad_domain || '';
            document.getElementById('conf-admin-user').value = config.admin_user || '';
            document.getElementById('conf-admin-pass').value = config.admin_pass || '';
        }
    } catch (e) {
        console.error('Error opening admin modal:', e);
    }
    
    adminModal.classList.remove('hidden');
}

function closeModals() {
    entryModal.classList.add('hidden');
    adminModal.classList.add('hidden');
}
