console.log('--- KeePassViewer Script Loading ---');
window.onerror = function(msg, url, line, col, error) {
   console.error("Global Error: " + msg + " at " + url + ":" + line);
   return false;
};

const API_URL = '';
let currentUser = null;
let entries = [];
let groups = [];
let currentGroup = 'Root';
let currentGroupUuid = null;
let socket = null;
let authToken = localStorage.getItem('authToken');
try {
    const savedUser = localStorage.getItem('currentUser');
    if (savedUser) currentUser = JSON.parse(savedUser);
} catch (e) {
    console.error('Error parsing saved user:', e);
}

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
            if (authToken) {
                logout();
            }
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
    localStorage.removeItem('currentUser');
    authToken = null;
    currentUser = null;
    location.reload();
}

// --- Initialization ---

let idleTimer = null;
const IDLE_TIME = 15 * 60 * 1000; // 15 minutes

document.addEventListener('DOMContentLoaded', async () => {
    if (authToken) {
        if (currentUser) {
            const displayUser = document.getElementById('display-user');
            if (displayUser) displayUser.innerText = currentUser.username;
        }
        
        // Intentar abrir el KeePass automáticamente
        try {
            const res = await apiFetch('/api/keepass/open', {
                method: 'POST',
                body: JSON.stringify({ password: '' })
            });
            if (res.ok) {
                showScreen('main');
                refreshData();
            } else {
                showScreen('master');
            }
        } catch (err) {
            showScreen('master');
        }
    } else {
        showScreen('login');
    }
    initSocket();
    setupEventListeners();
    resetIdleTimer();
    if (typeof lucide !== 'undefined') lucide.createIcons();
});

function resetIdleTimer() {
    if (idleTimer) clearTimeout(idleTimer);
    if (authToken) {
        idleTimer = setTimeout(() => {
            console.log('Inactividad detectada. Bloqueando...');
            logout();
        }, IDLE_TIME);
    }
}

// User interaction listeners to reset idle timer
['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(evt => {
    window.addEventListener(evt, resetIdleTimer, true);
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
    console.log('Setting up event listeners...');
    try {
        // Login
        if (loginForm) {
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
                        localStorage.setItem('currentUser', JSON.stringify(currentUser));
                        
                        document.getElementById('display-user').innerText = currentUser.username;
                        
                        // Intentar abrir el KeePass automáticamente
                        try {
                            const openRes = await apiFetch('/api/keepass/open', {
                                method: 'POST',
                                body: JSON.stringify({ password: '' })
                            });
                            if (openRes.ok) {
                                showScreen('main');
                                refreshData();
                            } else {
                                showScreen('master');
                            }
                        } catch (err) {
                            showScreen('master');
                        }
                    } else {
                        showError('login', 'Credenciales inválidas');
                    }
                } catch (err) {
                    showError('login', 'Error de conexión');
                }
            });
        }

        // Master Password
        if (masterForm) {
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
        }

        // Entry Form
        if (entryForm) {
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
        }

        // Config Form
        if (configForm) {
            configForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(e.target);
                const config = Object.fromEntries(formData.entries());
                
                // Explicitamente leer el valor de la checkbox para guardar contraseña
                const savePassCheckbox = document.getElementById('conf-save-keepass-password');
                if (savePassCheckbox) {
                    config.save_keepass_password = savePassCheckbox.checked;
                }
                
                const res = await apiFetch('/api/config', {
                    method: 'POST',
                    body: JSON.stringify(config)
                });

                if (res.ok) {
                    closeModals();
                    alert('✅ Configuración guardada correctamente.');
                } else {
                    try {
                        const errorData = await res.json();
                        alert('❌ Error al guardar: ' + (errorData.detail || 'Acceso denegado'));
                    } catch (e) {
                        alert('❌ Error al guardar: Sesión no autorizada. Por favor, inicia sesión como admin primero.');
                    }
                }
            });
        }



        // Password strength & Generator
        const passInput = document.getElementById('entry-password');
        if (passInput) {
            passInput.oninput = (e) => {
                updatePasswordStrength(e.target.value);
            };
        }

        const genBtn = document.getElementById('gen-pass-btn');
        if (genBtn) {
            genBtn.onclick = () => {
                const pass = generatePassword();
                document.getElementById('entry-password').value = pass;
                updatePasswordStrength(pass);
            };
        }

        // UI Buttons
        const addEntryBtn = document.getElementById('add-entry-btn');
        if (addEntryBtn) addEntryBtn.onclick = () => openEntryModal();
        
        // Config Buttons
        ['config-btn', 'config-btn-login', 'config-btn-master'].forEach(id => {
            const btn = document.getElementById(id);
            if (btn) {
                btn.onclick = (e) => {
                    e.preventDefault();
                    openAdminModal();
                };
            }
        });

        const lockBtn = document.getElementById('lock-btn');
        if (lockBtn) lockBtn.onclick = () => logout();

        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) logoutBtn.onclick = () => logout();

        const exportBtn = document.getElementById('export-btn');
        if (exportBtn) {
            exportBtn.onclick = () => {
                const token = localStorage.getItem('authToken');
                window.open(`/api/keepass/export?token=${token}`, '_blank');
            };
        }

        document.querySelectorAll('.close-modal').forEach(btn => btn.onclick = closeModals);
        
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.oninput = (e) => {
                renderEntries(e.target.value);
            };
        }

        const togglePassBtn = document.getElementById('toggle-entry-pass');
        if (togglePassBtn) {
            togglePassBtn.onclick = () => {
                const input = document.getElementById('entry-password');
                const icon = document.querySelector('#toggle-entry-pass i');
                if (input.type === 'password') {
                    input.type = 'text';
                    if (icon) icon.setAttribute('data-lucide', 'eye-off');
                } else {
                    input.type = 'password';
                    if (icon) icon.setAttribute('data-lucide', 'eye');
                }
                if (typeof lucide !== 'undefined') lucide.createIcons();
            };
        }

        const addGroupBtn = document.getElementById('add-group-btn');
        if (addGroupBtn) {
            addGroupBtn.onclick = () => {
                const name = prompt('Nombre del nuevo grupo:');
                if (name) addGroup(name);
            };
        }

        // AD Test Button
        const testAdBtn = document.getElementById('test-ad-btn');
        if (testAdBtn) {
            testAdBtn.onclick = async () => {
                const ad_server = document.getElementById('conf-ad-server').value;
                const ad_domain = document.getElementById('conf-ad-domain').value;
                const ad_group = document.getElementById('conf-ad-group').value;
                const test_user = document.getElementById('test-ad-user').value;
                const test_pass = document.getElementById('test-ad-pass').value;
                const resultDiv = document.getElementById('test-ad-result');

                if (!ad_server || !ad_domain || !test_user || !test_pass) {
                    alert('Por favor, rellena los campos de AD y los de prueba.');
                    return;
                }

                testAdBtn.disabled = true;
                testAdBtn.innerHTML = '<i data-lucide="loader" class="spin" style="width:16px; margin-right:8px; vertical-align:middle"></i> Probando...';
                lucide.createIcons();
                
                resultDiv.style.display = 'none';

                try {
                    const res = await apiFetch('/api/config/test-ad', {
                        method: 'POST',
                        body: JSON.stringify({ ad_server, ad_domain, ad_group, test_user, test_pass })
                    });
                    
                    const data = await res.json();
                    resultDiv.innerText = data.message;
                    resultDiv.style.display = 'block';
                    
                    if (data.status === 'success') {
                        resultDiv.style.background = 'rgba(34,197,94,0.2)';
                        resultDiv.style.color = '#4ade80';
                        resultDiv.style.border = '1px solid rgba(34,197,94,0.3)';
                    } else if (data.status === 'warning') {
                        resultDiv.style.background = 'rgba(234,179,8,0.2)';
                        resultDiv.style.color = '#fbbf24';
                        resultDiv.style.border = '1px solid rgba(234,179,8,0.3)';
                    } else {
                        resultDiv.style.background = 'rgba(239,68,68,0.2)';
                        resultDiv.style.color = '#f87171';
                        resultDiv.style.border = '1px solid rgba(239,68,68,0.3)';
                    }
                } catch (err) {
                    resultDiv.innerText = 'Error de comunicación con el servidor.';
                    resultDiv.style.display = 'block';
                    resultDiv.style.background = 'rgba(239,68,68,0.2)';
                    resultDiv.style.color = '#f87171';
                } finally {
                    testAdBtn.disabled = false;
                    testAdBtn.innerHTML = '<i data-lucide="activity" style="width:16px; margin-right:8px; vertical-align:middle"></i> Comprobar Conexión Local';
                    lucide.createIcons();
                }
            };
        }

        // Tab Switching Logic
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = btn.getAttribute('data-tab');
                console.log('Switching to tab:', targetId);
                
                // Update buttons
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Update panes
                document.querySelectorAll('.tab-pane').forEach(p => {
                    p.classList.remove('active');
                });
                
                const targetPane = document.getElementById(targetId);
                if (targetPane) {
                    targetPane.classList.add('active');
                } else {
                    console.error('Tab pane not found:', targetId);
                }
            });
        });
    } catch (err) {
        console.error('Error during setupEventListeners:', err);
    }
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
    const container = document.getElementById('group-list');
    container.innerHTML = '';
    
    if (!groups || !groups.name) return;

    function buildTree(group) {
        const div = document.createElement('div');
        div.className = 'tree-item';
        
        const row = document.createElement('div');
        row.className = 'tree-row';
        if (currentGroupUuid === group.uuid || (!currentGroupUuid && group.level === 0)) {
            row.classList.add('active');
        }
        
        row.style.paddingLeft = `${(group.level * 16) + 12}px`;
        
        const iconName = group.subgroups.length > 0 ? 'folder' : 'folder-keyhole';
        row.innerHTML = `
            <i data-lucide="${iconName}" class="tree-icon"></i>
            <span>${group.name}</span>
        `;
        
        row.onclick = () => {
            currentGroup = group.name;
            currentGroupUuid = group.uuid;
            document.getElementById('current-group').innerText = group.name;
            renderGroups();
            renderEntries();
        };
        
        div.appendChild(row);
        group.subgroups.forEach(sub => div.appendChild(buildTree(sub)));
        return div;
    }

    container.appendChild(buildTree(groups));
    lucide.createIcons();
}

function renderEntries(filter = '') {
    const filtered = entries.filter(e => {
        const matchesGroup = !currentGroupUuid || e.group_uuid === currentGroupUuid;
        const search = filter.toLowerCase();
        return matchesGroup && (
            e.title.toLowerCase().includes(search) || 
            e.username.toLowerCase().includes(search) ||
            (e.url && e.url.toLowerCase().includes(search)) ||
            (e.notes && e.notes.toLowerCase().includes(search))
        );
    });

    entriesBody.innerHTML = '';
    filtered.forEach(entry => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <div style="display:flex; align-items:center; gap:10px">
                    <i data-lucide="key" class="tree-icon"></i>
                    ${entry.title}
                </div>
            </td>
            <td>
                <span class="val-text">${entry.username}</span>
                <button class="copy-btn" data-copy="${btoa(unescape(encodeURIComponent(entry.username)))}" title="Copiar usuario">
                    <i data-lucide="copy" style="width:14px"></i>
                </button>
            </td>
            <td class="pass-cell">
                ••••••••
                <button class="copy-btn" data-copy="${btoa(unescape(encodeURIComponent(entry.password)))}" title="Copiar contraseña">
                    <i data-lucide="copy" style="width:14px"></i>
                </button>
            </td>
            <td><a href="${entry.url}" target="_blank" style="color:var(--primary);text-decoration:none">${entry.url || ''}</a></td>
            <td>
                <button class="icon-btn" onclick="openEntryModal('${entry.uuid}')">
                    <i data-lucide="edit-3"></i>
                </button>
            </td>
        `;
        
        // Attach copy events safely
        tr.querySelectorAll('.copy-btn').forEach(btn => {
            btn.onclick = (e) => {
                const encoded = btn.getAttribute('data-copy');
                const decoded = decodeURIComponent(escape(atob(encoded)));
                copyToClipboard(decoded);
                
                // Visual feedback
                const icon = btn.querySelector('i');
                const originalIcon = icon.getAttribute('data-lucide');
                icon.setAttribute('data-lucide', 'check');
                lucide.createIcons();
                setTimeout(() => {
                    icon.setAttribute('data-lucide', originalIcon);
                    lucide.createIcons();
                }, 2000);
            };
        });

        entriesBody.appendChild(tr);
    });
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

// --- Utilities ---

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        console.log('Copied to clipboard');
        // Clear clipboard after 30 seconds
        setTimeout(() => {
            navigator.clipboard.readText().then(current => {
                if (current === text) {
                    navigator.clipboard.writeText('');
                    console.log('Clipboard cleared');
                }
            });
        }, 30000);
    });
}

function generatePassword(length = 16) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
    let retVal = "";
    for (let i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    return retVal;
}

function updatePasswordStrength(pass) {
    const bar = document.getElementById('strength-bar');
    if (!bar) return;
    bar.className = 'strength-bar';
    let strength = 0;
    if (pass.length > 8) strength++;
    if (/[A-Z]/.test(pass)) strength++;
    if (/[0-9]/.test(pass)) strength++;
    if (/[^A-Za-z0-9]/.test(pass)) strength++;

    if (strength <= 1) {
        bar.classList.add('weak');
        bar.style.width = '25%';
    } else if (strength <= 3) {
        bar.classList.add('medium');
        bar.style.width = '60%';
    } else {
        bar.classList.add('strong');
        bar.style.width = '100%';
    }
}

// --- UI Helpers ---

function showScreen(id) {
    const screens = [loginScreen, masterScreen, mainScreen];
    screens.forEach(s => s.classList.add('hidden'));
    document.getElementById(`${id}-screen`).classList.remove('hidden');
    
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

    // Admin only config buttons - Aggressive visibility toggle
    const isAdmin = currentUser && (currentUser.role === 'admin' || currentUser.username === 'admin');
    
    document.querySelectorAll('[id^="config-btn"]').forEach(btn => {
        if (isAdmin && btn.id !== 'config-btn-login') {
            btn.classList.remove('hidden');
            btn.style.setProperty('display', 'flex', 'important');
        } else {
            btn.classList.add('hidden');
            btn.style.setProperty('display', 'none', 'important');
        }
    });

    const logoSpan = document.querySelector('.logo span');
    if (logoSpan) {
        logoSpan.style.setProperty('color', isAdmin ? '#fbbf24' : 'var(--primary)', 'important');
    }

    const displayUser = document.getElementById('display-user');
    if (displayUser && currentUser) {
        displayUser.innerText = currentUser.username + (isAdmin ? ' (Admin)' : '');
    }

    lucide.createIcons();
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
    document.getElementById('strength-bar').style.width = '0%';

    if (uuid) {
        const entry = entries.find(e => e.uuid === uuid);
        modalTitle.innerText = 'Editar Entrada';
        document.getElementById('entry-title').value = entry.title;
        document.getElementById('entry-username').value = entry.username;
        document.getElementById('entry-password').value = entry.password;
        document.getElementById('entry-url').value = entry.url;
        document.getElementById('entry-notes').value = entry.notes;
        updatePasswordStrength(entry.password);
        deleteBtn.classList.remove('hidden');
        deleteBtn.onclick = () => deleteEntry(uuid);
    } else {
        modalTitle.innerText = 'Nueva Entrada';
        deleteBtn.classList.add('hidden');
    }
    
    entryModal.style.display = 'flex';
    entryModal.classList.remove('hidden');
    if (typeof lucide !== 'undefined') lucide.createIcons();
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
    const isAdmin = currentUser && (currentUser.role === 'admin' || currentUser.username === 'admin');
    if (!isAdmin) {
        alert('Solo el administrador puede acceder a la configuración.');
        return;
    }
    
    const savePassCheckbox = document.getElementById('conf-save-keepass-password');
    const passInput = document.getElementById('conf-keepass-password');
    
    // Clear fields first
    document.getElementById('conf-file-path').value = '';
    document.getElementById('conf-ad-server').value = '';
    document.getElementById('conf-ad-domain').value = '';
    document.getElementById('conf-admin-user').value = '';
    document.getElementById('conf-admin-pass').value = '';
    if (savePassCheckbox) savePassCheckbox.checked = false;
    if (passInput) passInput.value = '';

    if (authToken) {
        try {
            const res = await apiFetch('/api/config');
            if (res.ok) {
                const config = await res.json();
                document.getElementById('conf-file-path').value = config.keepass_file_path || '';
                document.getElementById('conf-ad-server').value = config.ad_server || '';
                document.getElementById('conf-ad-domain').value = config.ad_domain || '';
                document.getElementById('conf-ad-group').value = config.ad_group || '';
                document.getElementById('conf-azure-tenant').value = config.azure_tenant_id || '';
                document.getElementById('conf-azure-client').value = config.azure_client_id || '';
                document.getElementById('conf-azure-secret').value = '';
                document.getElementById('conf-azure-group').value = config.azure_group_id || '';
                document.getElementById('conf-admin-user').value = config.admin_user || '';
                document.getElementById('conf-admin-pass').value = '';
                
                const isSaved = config.save_keepass_password === true || config.save_keepass_password === 'true';
                if (savePassCheckbox) savePassCheckbox.checked = isSaved;
                
                const hasPassword = !!config.keepass_password;
                if (passInput) {
                    passInput.value = '';
                    passInput.placeholder = hasPassword ? '•••••••• (Contraseña guardada)' : '••••••••';
                }
            }
        } catch (e) {
            console.error('Error fetching config:', e);
        }
    }
    
    console.log('Opening Admin Modal...');
    
    // Reset to first tab
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelector('.tab-btn[data-tab="tab-general"]').classList.add('active');
    document.getElementById('tab-general').classList.add('active');

    adminModal.style.display = 'flex';
    adminModal.classList.remove('hidden');
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

function closeModals() {
    entryModal.style.display = 'none';
    adminModal.style.display = 'none';
    entryModal.classList.add('hidden');
    adminModal.classList.add('hidden');
}

// --- Easter Egg Logic ---
let titleClicks = 0;
function triggerEasterEgg() {
    titleClicks++;
    console.log('Title clicks:', titleClicks);
    if (titleClicks >= 7) {
        titleClicks = 0;
        const container = document.getElementById('easter-egg-container');
        if (!container) return;
        
        container.classList.remove('hidden');
        container.innerHTML = '<div class="hacked-text">HACKED</div>';
        
        // Create particles
        for (let i = 0; i < 50; i++) {
            const p = document.createElement('div');
            p.className = 'particle';
            const angle = Math.random() * Math.PI * 2;
            const dist = 100 + Math.random() * 500;
            p.style.setProperty('--x', `${Math.cos(angle) * dist}px`);
            p.style.setProperty('--y', `${Math.sin(angle) * dist}px`);
            // Random start position near center
            p.style.left = '50%';
            p.style.top = '50%';
            container.appendChild(p);
        }
        
        // Hide after 3 seconds
        setTimeout(() => {
            container.classList.add('hidden');
            container.innerHTML = '';
        }, 3000);
    }
}

// Global click listener for the specific IDs
document.addEventListener('click', (e) => {
    const target = e.target.closest('#app-title, #app-title-main');
    if (target) {
        triggerEasterEgg();
    }
}, { passive: true });
