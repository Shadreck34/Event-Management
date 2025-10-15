// Enhanced auth.js with corrected UI permission controls
const API_BASE = 'http://localhost:5000';

const AuthService = {
    getToken() {
        return localStorage.getItem('accessToken');
    },

    async login(email, password) {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Login failed');
        }
        

        const data = await response.json();
        this.setAuthData(data);
        
        // Initialize UI permissions after login
        setTimeout(() => UIPermissions.applyPermissions(), 100);
        
        return data;
    },

    async register(email, password, name) {
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password, name })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Registration failed');
        }

        const data = await response.json();
        this.setAuthData(data);
        
        // Initialize UI permissions after registration
        setTimeout(() => UIPermissions.applyPermissions(), 100);
        
        return data;
    },

    setAuthData(data) {
        localStorage.setItem('accessToken', data.access_token);
        localStorage.setItem('refreshToken', data.refresh_token);
        localStorage.setItem('user', JSON.stringify(data.user));
    },

    clearAuthData() {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('user');
    },

    getCurrentUser() {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    },

    getAuthHeader() {
        const token = localStorage.getItem('accessToken');
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    },

    isAuthenticated() {
        const token = localStorage.getItem('accessToken');
        if (!token) return false;
        return true;
    },

    hasRole(requiredRole) {
        const user = this.getCurrentUser();
        if (!user) return false;
        
        const roleHierarchy = {
            'superadmin': 4,
            'admin': 3,
            'planner': 2,
            'viewer': 1
        };
        
        return roleHierarchy[user.role] >= roleHierarchy[requiredRole];
    },

    getUserRole() {
        const user = this.getCurrentUser();
        return user ? user.role : null;
    },

    logout() {
        this.clearAuthData();
        window.location.href = 'login.html';
    }
};

// Comprehensive UI Permissions Controller with corrected logic
class UIPermissions {
    static init() {
        // Apply permissions when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.applyPermissions());
        } else {
            this.applyPermissions();
        }

        // Set up mutation observer to handle dynamically added content
        this.setupMutationObserver();
        
        // Apply permissions on page navigation
        window.addEventListener('popstate', () => {
            setTimeout(() => this.applyPermissions(), 100);
        });
    }

    static setupMutationObserver() {
        const observer = new MutationObserver((mutations) => {
            let shouldReapply = false;
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        // Check if added node has permission-related attributes
                        if (node.hasAttribute('data-role-required') || 
                            node.hasAttribute('data-hide-for') || 
                            node.hasAttribute('data-show-for') ||
                            node.classList.contains('nav-item') ||
                            node.tagName === 'BUTTON') {
                            shouldReapply = true;
                        }
                    }
                });
            });
            
            if (shouldReapply) {
                setTimeout(() => this.applyPermissions(), 50);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    static applyPermissions() {
        const currentUser = AuthService.getCurrentUser();
        if (!currentUser) {
            this.redirectToLogin();
            return;
        }

        console.log(`Applying permissions for user: ${currentUser.name} (${currentUser.role})`);

        // Apply all permission checks
        this.enforcePageAccess();
        this.hideUnauthorizedElements();
        this.disableUnauthorizedActions();
        this.updateNavigation();
        this.updateUserDisplay();
        this.addViewerNotifications();
    }

    static redirectToLogin() {
        if (!window.location.pathname.includes('login.html') && 
            !window.location.pathname.includes('register.html')) {
            window.location.href = 'login.html';
        }
    }

    static enforcePageAccess() {
        const currentPage = window.location.pathname.split('/').pop() || 'index.html';
        const userRole = AuthService.getUserRole();
        
        const pagePermissions = {
            'start_planning.html': 'planner',
            'add_bulletin.html': 'planner',
            'edit_event.html': 'planner',
            'templates.html': 'planner',
            'admin.html': 'admin'
        };

        const requiredRole = pagePermissions[currentPage];
        if (requiredRole && !AuthService.hasRole(requiredRole)) {
            console.log(`Access denied to ${currentPage}. Required: ${requiredRole}, User: ${userRole}`);
            
            // Show access denied message
            document.body.innerHTML = `
                <div style="display: flex; justify-content: center; align-items: center; height: 100vh; flex-direction: column; background: #f8f9fa;">
                    <div style="text-align: center; padding: 40px; background: white; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                        <i class="fas fa-lock" style="font-size: 48px; color: #dc3545; margin-bottom: 20px;"></i>
                        <h2 style="color: #dc3545; margin-bottom: 10px;">Access Denied</h2>
                        <p style="color: #6c757d; margin-bottom: 20px;">You don't have permission to access this page.</p>
                        <p style="color: #6c757d; margin-bottom: 30px;">Required role: <strong>${requiredRole}</strong> | Your role: <strong>${userRole}</strong></p>
                        <button onclick="window.location.href='index.html'" style="background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                            Return to Dashboard
                        </button>
                    </div>
                </div>
            `;
            return;
        }
    }

    static hideUnauthorizedElements() {
        const userRole = AuthService.getUserRole();

        // First, reset any previously hidden elements to determine fresh visibility
        document.querySelectorAll('[data-hidden-by-permissions="true"]').forEach(element => {
            element.style.display = '';
            element.removeAttribute('data-hidden-by-permissions');
        });

        // Hide navigation items that require higher permissions
        this.hideNavigationItems();
        
        // Hide role-specific elements using data attributes
        document.querySelectorAll('[data-role-required]:not(.always-allowed)').forEach(element => {
            const requiredRole = element.getAttribute('data-role-required');
            if (!AuthService.hasRole(requiredRole)) {
                element.style.display = 'none';
                element.setAttribute('data-hidden-by-permissions', 'true');
            }
        });

        // Hide elements based on data-hide-for attribute
        document.querySelectorAll('[data-hide-for]').forEach(element => {
            const hiddenRoles = element.getAttribute('data-hide-for').split(',').map(r => r.trim());
            if (hiddenRoles.includes(userRole)) {
                element.style.display = 'none';
                element.setAttribute('data-hidden-by-permissions', 'true');
            }
        });

        // Show elements based on data-show-for attribute
        document.querySelectorAll('[data-show-for]').forEach(element => {
            const shownRoles = element.getAttribute('data-show-for').split(',').map(r => r.trim());
            if (!shownRoles.includes(userRole)) {
                element.style.display = 'none';
                element.setAttribute('data-hidden-by-permissions', 'true');
            }
        });

        // Handle specific role-based element visibility
        this.handleRoleBasedVisibility(userRole);
    }

    static handleRoleBasedVisibility(userRole) {
        // Only hide buttons that specifically require higher permissions
        // Don't hide all buttons indiscriminately
        
        if (userRole === 'viewer') {
            // Hide action buttons for viewers (but not view/read buttons)
            const actionButtons = document.querySelectorAll(`
                button[onclick*="create"]:not(.always-allowed),
                button[onclick*="add"]:not(.always-allowed),
                button[onclick*="edit"]:not(.always-allowed),
                button[onclick*="update"]:not(.always-allowed),
                button[onclick*="save"]:not(.always-allowed),
                .btn-success:not(.always-allowed):not(.view-only),
                .btn-primary:not(.always-allowed):not(.view-only)
            `);
            
            actionButtons.forEach(button => {
                button.style.display = 'none';
                button.setAttribute('data-hidden-by-permissions', 'true');
            });
        }

        // Hide delete buttons for non-admin users
        if (!AuthService.hasRole('admin')) {
            const deleteButtons = document.querySelectorAll(`
                button[onclick*="delete"]:not(.always-allowed),
                .btn-danger:not(.always-allowed),
                .delete-btn:not(.always-allowed)
            `);
            
            deleteButtons.forEach(button => {
                button.style.display = 'none';
                button.setAttribute('data-hidden-by-permissions', 'true');
            });
        }
    }

    static hideNavigationItems() {
        // Define navigation permissions
        const navPermissions = {
            'start_planning.html': 'planner',
            'templates.html': 'planner', 
            'admin.html': 'admin'
        };

        // Hide unauthorized navigation items
        Object.entries(navPermissions).forEach(([page, requiredRole]) => {
            if (!AuthService.hasRole(requiredRole)) {
                // Hide direct links
                const links = document.querySelectorAll(`a[href="${page}"], a[href*="${page}"]:not(.always-allowed)`);
                links.forEach(link => {
                    link.style.display = 'none';
                    // Hide parent nav-item as well
                    const navItem = link.closest('.nav-item');
                    if (navItem) {
                        navItem.style.display = 'none';
                        navItem.setAttribute('data-hidden-by-permissions', 'true');
                    }
                });
            }
        });
    }

    static disableUnauthorizedActions() {
        const userRole = AuthService.getUserRole();

        // Only disable form inputs for viewers, and only non-search inputs
        if (userRole === 'viewer') {
            const inputs = document.querySelectorAll(`
                input:not([type="search"]):not(.search-input):not(.always-enabled):not([readonly]),
                select:not(.always-enabled):not([disabled]),
                textarea:not(.always-enabled):not([readonly])
            `);

            inputs.forEach(element => {
                element.setAttribute('readonly', true);
                element.style.backgroundColor = '#f8f9fa';
                element.style.cursor = 'not-allowed';
                element.title = 'Read-only access - contact administrator for edit permissions';
            });
        }

        // Override click handlers for unauthorized actions
        this.overrideUnauthorizedHandlers();
    }

    static overrideUnauthorizedHandlers() {
        // Override buttons with permission checks
        document.querySelectorAll('button[onclick]:not(.always-allowed):not(.permission-checked)').forEach(button => {
            const onclick = button.getAttribute('onclick');
            
            // Determine required permission based on action
            let requiredRole = null;
            if (onclick.includes('create') || onclick.includes('add') || onclick.includes('edit') || onclick.includes('update') || onclick.includes('save')) {
                requiredRole = 'planner';
            } else if (onclick.includes('delete')) {
                requiredRole = 'admin';
            }

            // Mark as checked to avoid re-processing
            button.classList.add('permission-checked');

            if (requiredRole && !AuthService.hasRole(requiredRole)) {
                // Store original handler
                button.setAttribute('data-original-onclick', onclick);
                
                // Replace with permission check
                button.onclick = (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.showPermissionError(requiredRole);
                    return false;
                };
                
                button.style.opacity = '0.5';
                button.style.cursor = 'not-allowed';
                button.title = `Requires ${requiredRole} role`;
            }
        });
    }

    static showPermissionError(requiredRole) {
        const userRole = AuthService.getUserRole();
        alert(`Access Denied\n\nThis action requires "${requiredRole}" role.\nYour current role: "${userRole}"\n\nPlease contact an administrator for access.`);
    }

    static updateNavigation() {
        // Show navigation items that user has access to
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            const link = item.querySelector('a');
            if (link && !link.hasAttribute('data-hidden-by-permissions')) {
                item.style.display = '';
            }
        });
    }

    static updateUserDisplay() {
        const user = AuthService.getCurrentUser();
        if (!user) return;

        // Update user avatar
        const userAvatar = document.getElementById('userAvatar');
        if (userAvatar) {
            const initials = user.name ? 
                user.name.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2) :
                user.email.substring(0, 2).toUpperCase();
            userAvatar.textContent = initials;
            userAvatar.title = `${user.name || user.email} (${user.role})`;
        }

        // Add or update role badge
        this.addRoleBadge(user);
    }

    static addRoleBadge(user) {
        const userInfo = document.querySelector('.user-info');
        if (!userInfo) return;

        // Remove existing badge
        const existingBadge = userInfo.querySelector('.role-badge');
        if (existingBadge) {
            existingBadge.remove();
        }

        // Add new role badge
        const roleBadge = document.createElement('div');
        roleBadge.className = 'role-badge';
        roleBadge.textContent = user.role.toUpperCase();
        
        // Style the badge based on role
        const roleColors = {
            'viewer': '#6c757d',
            'planner': '#28a745', 
            'admin': '#fd7e14',
            'superadmin': '#dc3545'
        };
        
        roleBadge.style.cssText = `
            font-size: 10px;
            background: ${roleColors[user.role] || '#6c757d'};
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            margin: 2px 5px;
            text-align: center;
            font-weight: bold;
            display: inline-block;
        `;
        
        // Insert before logout button
        const logoutBtn = userInfo.querySelector('.logout-btn');
        if (logoutBtn) {
            userInfo.insertBefore(roleBadge, logoutBtn);
        } else {
            userInfo.appendChild(roleBadge);
        }
    }

    static addViewerNotifications() {
        const userRole = AuthService.getUserRole();
        if (userRole !== 'viewer') return;

        // Add viewer notification to pages
        const mainContent = document.querySelector('.main-content');
        if (mainContent && !mainContent.querySelector('.viewer-notice')) {
            const viewerNotice = document.createElement('div');
            viewerNotice.className = 'viewer-notice alert alert-info';
            viewerNotice.innerHTML = `
                <div style="display: flex; align-items: center; padding: 12px; background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; border-radius: 8px; margin: 20px 0;">
                    <i class="fas fa-eye" style="margin-right: 10px; font-size: 18px;"></i>
                    <div>
                        <strong>Read-Only Mode:</strong> You have viewer access only. 
                        Contact an administrator to request higher permissions.
                    </div>
                </div>
            `;
            
            // Insert after header
            const header = mainContent.querySelector('.header');
            if (header) {
                header.insertAdjacentElement('afterend', viewerNotice);
            } else {
                mainContent.insertBefore(viewerNotice, mainContent.firstChild);
            }
        }
    }

    // Public method to check permissions before executing actions
    static checkPermissionFor(action) {
        const permissions = {
            'create': 'planner',
            'edit': 'planner',
            'update': 'planner',
            'delete': 'admin',
            'manage_users': 'admin',
            'manage_templates': 'admin'
        };

        const requiredRole = permissions[action];
        if (requiredRole && !AuthService.hasRole(requiredRole)) {
            this.showPermissionError(requiredRole);
            return false;
        }
        return true;
    }

    // Method to reapply permissions (useful after dynamic content changes)
    static reapplyPermissions() {
        setTimeout(() => this.applyPermissions(), 100);
    }

    // Method to temporarily show all elements (for debugging)
    static showAllElements() {
        document.querySelectorAll('[data-hidden-by-permissions="true"]').forEach(element => {
            element.style.display = '';
            element.style.opacity = '0.5';
            element.title = 'Hidden by permissions';
        });
    }

    // Method to restore proper permissions after debugging
    static restorePermissions() {
        this.applyPermissions();
    }
}

// Enhanced auth interceptor
async function authFetch(url, options = {}) {
    const authHeader = AuthService.getAuthHeader();
    options.headers = {
        ...options.headers,
        ...authHeader
    };

    let response = await fetch(url, options);

    if (response.status === 401 && AuthService.isAuthenticated()) {
        AuthService.logout();
        throw new Error('Session expired');
    }

    if (response.status === 403) {
        throw new Error('Access denied - insufficient permissions');
    }

    return response;
}

// Enhanced Permissions class
class Permissions {
    static hasPermission(requiredRole) {
        return AuthService.hasRole(requiredRole);
    }
    
    static getCurrentRole() {
        return AuthService.getUserRole();
    }

    static canCreate() {
        return this.hasPermission('planner');
    }

    static canEdit() {
        return this.hasPermission('planner');
    }

    static canDelete() {
        return this.hasPermission('admin');
    }

    static canManageUsers() {
        return this.hasPermission('admin');
    }

    static isViewer() {
        return this.getCurrentRole() === 'viewer';
    }

    static isPlanner() {
        return this.hasPermission('planner');
    }

    static isAdmin() {
        return this.hasPermission('admin');
    }

    static isSuperAdmin() {
        return this.getCurrentRole() === 'superadmin';
    }
}

// Auto-initialize when script loads
(function() {
   document.addEventListener('DOMContentLoaded', () => {
  if (document.body) {
    UIPermissions.init();
  } else {
    // Fallback if body not ready
    setTimeout(() => UIPermissions.init(), 100);
  }
});
})();

// Global permission check function for inline handlers
function checkPermission(action) {
    return UIPermissions.checkPermissionFor(action);
}

// Protected wrapper functions
function protectedAction(action, callback, requiredRole = 'planner') {
    if (AuthService.hasRole(requiredRole)) {
        return callback();
    } else {
        UIPermissions.showPermissionError(requiredRole);
        return false;
    }
}

function protectedCreateEvent() {
    return protectedAction('create', () => {
        window.location.href = 'start_planning.html';
    });
}

function protectedEditEvent(eventId) {
    return protectedAction('edit', () => {
        window.location.href = `edit_event.html?event_id=${eventId}`;
    });
}

function protectedDeleteEvent(eventId) {
    return protectedAction('delete', () => {
        if (confirm('Are you sure you want to delete this event?')) {
            // Implement delete logic here
            return true;
        }
        return false;
    }, 'admin');
}