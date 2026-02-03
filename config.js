// ==================== APPLICATION CONFIGURATION ====================
// This file contains all configuration for the frontend application

// ==================== ENVIRONMENT CONFIGURATION ====================
// Change this URL based on your environment:
// - Development: http://localhost:3000
// - Production: https://phishnet-backend-5eqv.onrender.com
const API_BASE_URL = window.API_BASE_URL || 'https://phishnet-backend-5eqv.onrender.com';

// For local development, uncomment the line below:
// const API_BASE_URL = window.API_BASE_URL || 'http://localhost:3000';

// Export configuration object
const config = {
  api: {
    baseURL: API_BASE_URL,
    endpoints: {
      // Authentication
      auth: {
        login: '/api/auth/login',
        register: '/api/auth/register',
        logout: '/api/auth/logout',
        refreshToken: '/api/auth/refresh',
        verify: '/api/auth/verify'
      },
      // Users
      users: {
        profile: '/api/users/profile',
        history: '/api/users/history',
        update: '/api/users/profile',
        settings: '/api/users/settings'
      },
      // Scanning
      scan: {
        url: '/api/scan-url',
        email: '/api/scan/email',
        domain: '/api/scan/domain'
      },
      // Dashboard
      dashboard: {
        securityTips: '/api/dashboard/security-tips'
      },
      // Analytics
      analytics: {
        stats: '/api/analytics/stats'
      },
      // Chatbot
      chatbot: {
        message: '/api/chatbot/message'
      },
      // Blog
      blog: {
        list: '/api/blog/posts',
        get: '/api/blog/posts/:id'
      }
    }
  }
};

// Helper function to build full API URLs
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
