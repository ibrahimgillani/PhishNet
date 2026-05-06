// ==================== APPLICATION CONFIGURATION ====================
// This file contains all configuration for the frontend application

// ==================== ENVIRONMENT CONFIGURATION ====================
// Auto-detect: use localhost for local development, Render URLs for production
// Single backend handles everything: auth, scanning, chatbot, analytics
const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.protocol === 'file:';

const API_BASE_URL = window.API_BASE_URL || (isLocal ? 'http://localhost:5000' : 'https://phishnet-txgk.onrender.com');

// Export configuration object
const config = {
  api: {
    baseURL: API_BASE_URL,
    authBaseURL: API_BASE_URL,
    mlBaseURL: API_BASE_URL,
    endpoints: {
      // Authentication
      auth: {
        login: '/api/v1/auth/login',
        register: '/api/v1/auth/signup',
        logout: '/api/v1/auth/logout',
        refreshToken: '/api/v1/auth/refresh-token',
        verify: '/api/v1/auth/verify'
      },
      // Users
      users: {
        profile: '/api/v1/users/profile',
        history: '/api/v1/urls/history',
        update: '/api/v1/users/profile',
        settings: '/api/v1/users/settings'
      },
      // Scanning (multi-source threat intel)
      scan: {
        url: '/api/v1/urls/scan',
        email: '/api/v1/emails/scan',
        domain: '/api/v1/urls/scan',
        batch: '/api/v1/urls/scan',
        modelInfo: '/health'
      },
      // Save scan results to history
      history: {
        saveUrl: '/api/v1/urls/check',
        saveEmail: '/api/v1/urls/check'
      },
      // Dashboard
      dashboard: {
        securityTips: '/api/dashboard/security-tips'
      },
      // Analytics
      analytics: {
        stats: '/api/v1/analytics/stats'
      },
      // Chatbot
      chatbot: {
        message: '/api/chatbot/message'
      },
      // Blog
      blog: {
        list: '/api/blog/posts',
        get: '/api/blog/posts/:id'
      },
      // Data Breach
      breach: {
        check: '/api/breach/check'
      }
    }
  }
};

// Helper function to build full API URLs
// All endpoints go to the single backend
function getApiUrl(endpoint) {
  return `${config.api.baseURL}${endpoint}`;
}

// Helper function to build full API URLs with query parameters
function getApiUrlWithParams(endpoint, params = {}) {
  const url = getApiUrl(endpoint);
  const queryString = new URLSearchParams(params).toString();
  return queryString ? `${url}?${queryString}` : url;
}

// Make config available globally for backward compatibility
window.API_CONFIG = config;
window.getApiUrl = getApiUrl;
window.getApiUrlWithParams = getApiUrlWithParams;
