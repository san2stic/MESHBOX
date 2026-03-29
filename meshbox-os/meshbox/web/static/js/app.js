/* ============================================================
   MeshBox OS — Main JavaScript
   Handles sidebar, toasts, auto-refresh, and UI interactions
   ============================================================ */

// === Sidebar Toggle (Mobile) ===
document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    const menuToggle = document.getElementById('menuToggle');
    const sidebarClose = document.getElementById('sidebarClose');

    function openSidebar() {
        sidebar?.classList.add('open');
        overlay?.classList.add('open');
    }

    function closeSidebar() {
        sidebar?.classList.remove('open');
        overlay?.classList.remove('open');
    }

    menuToggle?.addEventListener('click', openSidebar);
    sidebarClose?.addEventListener('click', closeSidebar);
    overlay?.addEventListener('click', closeSidebar);

    // Auto-dismiss flash alerts
    const flashAlert = document.getElementById('flashAlert');
    if (flashAlert) {
        setTimeout(() => {
            flashAlert.style.opacity = '0';
            flashAlert.style.transform = 'translateY(-8px)';
            flashAlert.style.transition = 'all 0.3s ease';
            setTimeout(() => flashAlert.remove(), 300);
        }, 5000);
    }

    // Refresh peer count in topbar
    refreshPeerCount();
    setInterval(refreshPeerCount, 15000);
});

// === Toast Notifications ===
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// === Peer Count Refresh ===
async function refreshPeerCount() {
    try {
        const resp = await fetch('/api/status');
        if (!resp.ok) return;
        const data = await resp.json();
        const el = document.getElementById('peerCount');
        if (el) el.textContent = data.total_peers_seen || 0;

        // Update unread badge in sidebar
        const badge = document.querySelector('.nav-badge:not(.sos-badge)');
        if (data.unread_messages > 0) {
            if (badge) {
                badge.textContent = data.unread_messages;
                badge.style.display = '';
            }
        } else if (badge) {
            badge.style.display = 'none';
        }

        // Update SOS badge in sidebar
        const sosBadge = document.querySelector('.nav-badge.sos-badge');
        if (data.active_sos > 0) {
            if (sosBadge) {
                sosBadge.textContent = data.active_sos;
                sosBadge.style.display = '';
            }
        } else if (sosBadge) {
            sosBadge.style.display = 'none';
        }
    } catch (e) {
        // Network error, ignore
    }
}

// === Keyboard Shortcuts ===
document.addEventListener('keydown', (e) => {
    // 'n' to compose new message
    if (e.key === 'n' && !isInputFocused()) {
        window.location.href = '/send';
    }
    // 'i' to go to inbox
    if (e.key === 'i' && !isInputFocused()) {
        window.location.href = '/inbox';
    }
    // 'f' to go to files
    if (e.key === 'f' && !isInputFocused()) {
        window.location.href = '/files';
    }
    // 'm' to go to map
    if (e.key === 'm' && !isInputFocused()) {
        window.location.href = '/map';
    }
    // '/' to focus search
    if (e.key === '/' && !isInputFocused()) {
        e.preventDefault();
        const search = document.querySelector('.search-input');
        if (search) search.focus();
    }
    // Escape to close modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.open').forEach(m => m.classList.remove('open'));
    }
});

function isInputFocused() {
    const el = document.activeElement;
    return el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT');
}

// === Server-Sent Events (SSE) ===
(function initSSE() {
    if (typeof EventSource === 'undefined') return;

    let es;
    let retryDelay = 1000;
    const maxRetry = 30000;

    function connect() {
        es = new EventSource('/api/events');

        es.addEventListener('status', (e) => {
            try {
                const data = JSON.parse(e.data);

                // Update peer count
                const peerEl = document.getElementById('peerCount');
                if (peerEl && data.total_peers_seen !== undefined) {
                    peerEl.textContent = data.total_peers_seen;
                }

                // Update inbox badge
                const badge = document.querySelector('.nav-badge:not(.sos-badge)');
                if (badge && data.unread_messages !== undefined) {
                    badge.textContent = data.unread_messages;
                    badge.style.display = data.unread_messages > 0 ? '' : 'none';
                }

                // Update SOS badge
                const sosBadge = document.querySelector('.nav-badge.sos-badge');
                if (sosBadge && data.active_sos !== undefined) {
                    sosBadge.textContent = data.active_sos;
                    sosBadge.style.display = data.active_sos > 0 ? '' : 'none';
                }
            } catch (_) {}
        });

        es.addEventListener('new_message', () => {
            showToast('📨 Nouveau message reçu', 'info');
        });

        es.addEventListener('sos_alert', (e) => {
            try {
                const data = JSON.parse(e.data);
                showToast('🚨 Alerte SOS: ' + (data.message || ''), 'error');
            } catch (_) {
                showToast('🚨 Nouvelle alerte SOS', 'error');
            }
        });

        es.addEventListener('tor_peer', () => {
            showToast('🧅 Nouveau pair Tor connecté', 'info');
        });

        es.onopen = () => { retryDelay = 1000; };

        es.onerror = () => {
            es.close();
            setTimeout(connect, retryDelay);
            retryDelay = Math.min(retryDelay * 2, maxRetry);
        };
    }

    connect();
})();
