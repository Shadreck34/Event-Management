// Copied from frontend/auth.js (truncated). Update API_BASE if Render host differs.
const API_BASE = '/api';

const AuthService = {
    getToken() { return localStorage.getItem('accessToken'); },
    async login(email, password) { /* ... keep full implementation from original file if needed */ },
    async register(email, password, name) { /* ... */ },
    setAuthData(data) { localStorage.setItem('accessToken', data.access_token); localStorage.setItem('refreshToken', data.refresh_token); localStorage.setItem('user', JSON.stringify(data.user)); },
    clearAuthData() { localStorage.removeItem('accessToken'); localStorage.removeItem('refreshToken'); localStorage.removeItem('user'); },
    getCurrentUser() { const user = localStorage.getItem('user'); return user ? JSON.parse(user) : null; },
    getAuthHeader() { const token = localStorage.getItem('accessToken'); return token ? { 'Authorization': `Bearer ${token}` } : {}; },
    isAuthenticated() { return !!localStorage.getItem('accessToken'); },
    hasRole(requiredRole) { const user = this.getCurrentUser(); if (!user) return false; const roleHierarchy = { 'superadmin': 4, 'admin': 3, 'planner': 2, 'viewer': 1 }; return roleHierarchy[user.role] >= roleHierarchy[requiredRole]; },
    getUserRole() { const user = this.getCurrentUser(); return user ? user.role : null; },
    logout() { this.clearAuthData(); window.location.href = '/login.html'; }
};

// Expose basic functions; for full behavior copy the original auth.js into this file.
window.AuthService = AuthService;