// ==================== APPLICATION CONFIGURATION ====================
// This file contains all configuration for the frontend application

// ==================== ENVIRONMENT CONFIGURATION ====================
// Change this URL based on your environment:
// - Development: http://localhost:3000 (ML backend), http://localhost:5000 (Auth backend)
// - Production: https://phishnet-backend-5eqv.onrender.com

// ML Backend (scanning, threat intel) - Port 3000
const ML_API_BASE_URL = window.ML_API_BASE_URL || 'http://localhost:3000';

// Auth Backend (MongoDB, users, auth) - Port 5000
const AUTH_API_BASE_URL = window.AUTH_API_BASE_URL || 'http://localhost:5000';

// Legacy support - defaults to Auth backend for compatibility
const API_BASE_URL = window.API_BASE_URL || AUTH_API_BASE_URL;

// Export configuration object
const config = {
  api: {
    baseURL: API_BASE_URL,
    authBaseURL: AUTH_API_BASE_URL,
    mlBaseURL: ML_API_BASE_URL,
    endpoints: {
      // Authentication (uses Auth backend - port 5000)
      auth: {
        login: '/api/auth/login',
        register: '/api/auth/register',
        logout: '/api/auth/logout',
        refreshToken: '/api/auth/refresh',
        verify: '/api/auth/verify'
      },
      // Users (uses Auth backend - port 5000)
      users: {
        profile: '/api/users/profile',
        history: '/api/users/history',
        update: '/api/users/profile',
        settings: '/api/users/settings'
      },
      // Scanning - DistilBERT Phishing Detection (uses ML backend - port 3000)
      scan: {
        url: '/api/scan/scan-url',
        email: '/api/scan/email',
        domain: '/api/scan/domain',
        batch: '/api/scan/batch',
        modelInfo: '/api/scan/model-info'
      },
      // Save scan results to history (uses Auth backend - port 5000)
      history: {
        saveUrl: '/api/scan/url',
        saveEmail: '/api/scan/email'
      },
      // Dashboard
      dashboard: {
        securityTips: '/api/dashboard/security-tips'
      },
      // Analytics (uses Auth backend - port 5000)
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
// Auth endpoints use port 5000 (MongoDB backend), scan endpoints use port 3000 (ML backend)
function getApiUrl(endpoint) {
  // Auth and user endpoints go to Auth backend (port 5000)
  if (endpoint.startsWith('/api/auth') || 
      endpoint.startsWith('/api/users') || 
      endpoint.startsWith('/api/analytics')) {
    return `${config.api.authBaseURL}${endpoint}`;
  }
  // Scan endpoints go to ML backend (port 3000)
  if (endpoint.startsWith('/api/scan')) {
    return `${config.api.mlBaseURL}${endpoint}`;
  }
  // Default to base URL
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
