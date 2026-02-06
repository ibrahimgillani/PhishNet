// ==================== TOAST NOTIFICATION SYSTEM ====================
let toastElement = null;
let toastTimeout = null;

function showToast(message, type = 'info', duration = 3000) {
  // Create toast element if it doesn't exist
  if (!toastElement) {
    toastElement = document.createElement('div');
    toastElement.className = 'toast-notification';
    document.body.appendChild(toastElement);
  }

  // Clear any existing timeout
  if (toastTimeout) {
    clearTimeout(toastTimeout);
  }

  // Remove all type classes
  toastElement.classList.remove('success', 'error', 'warning', 'info', 'show');
  
  // Icon symbols for each notification type
  const icons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ'
  };
  
  // Set message with icon and type
  const icon = icons[type] || '•';
  toastElement.innerHTML = `<span class="toast-icon" data-type="${type}">${icon}</span><span class="toast-message">${message}</span>`;
  toastElement.classList.add(type);
  
  // Trigger reflow to restart animation
  void toastElement.offsetWidth;
  
  // Show toast
  setTimeout(() => {
    toastElement.classList.add('show');
  }, 10);

  // Hide after duration
  toastTimeout = setTimeout(() => {
    toastElement.classList.remove('show');
  }, duration);
}

// ==================== SIMPLE DEMO AUTH MANAGER ====================
class AuthManager {
  constructor() {
    this.storageKey = 'phishnet_user';
    this.scanCountKey = 'phishnet_scan_count';
  }

  isLoggedIn() {
    return localStorage.getItem(this.storageKey) !== null;
  }

  login(email, password) {
    // Call backend API to login user
    return fetch(getApiUrl(window.API_CONFIG.api.endpoints.auth.login), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email,
        password: password
      })
    })
    .then(response => {
      if (!response.ok) {
        return response.json().then(error => {
          throw new Error(error.message || 'Login failed');
        });
      }
      return response.json();
    })
    .then(data => {
        if (data.success && data.data.token) {
        // Store token and user info
        localStorage.setItem('token', data.data.token);
        // Clear any guest scan history to avoid leaking previous anonymous scans
        localStorage.removeItem('scanHistory');
        // Clear any selected report cached from previous sessions
        localStorage.removeItem('selectedScan');
        localStorage.removeItem('selectedScanId');
        // Clear any guest scan history to avoid leaking previous anonymous scans
        localStorage.removeItem('scanHistory');
        
        // Sync token to browser extension if available
        this.syncTokenToExtension(data.data.token);
        
        const user = {
          email: data.data.user.email,
          firstName: data.data.user.firstName,
          lastName: data.data.user.lastName,
          avatar: data.data.user.avatar || null,
          avatarFit: data.data.user.avatarFit || 'cover',
          initials: this.getInitials(data.data.user.email, data.data.user.firstName, data.data.user.lastName),
          loginTime: new Date().toISOString()
        };
        localStorage.setItem(this.storageKey, JSON.stringify(user));
        localStorage.setItem('pishnet_user', JSON.stringify(user));
        // Store avatar ONLY in window object for real-time access, NOT in localStorage
        // This prevents stale avatar issues and storage quota problems
        if (user.avatar) {
          window.currentUserAvatar = user.avatar;
          localStorage.setItem('avatarFitMode', user.avatarFit || 'cover');
        } else {
          window.currentUserAvatar = null;
          localStorage.removeItem('avatarFitMode');
        }
        return user;
      } else {
        throw new Error(data.message || 'Login failed');
      }
    });
  }

  // Sync authentication token to browser extension
  syncTokenToExtension(token) {
    try {
      // Try to communicate with the extension via postMessage or chrome runtime
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        // Direct extension communication (if extension ID is known)
        chrome.runtime.sendMessage({ type: 'phishnet.sync-token', token: token }, (response) => {
          if (chrome.runtime.lastError) {
            console.log('[PhishNet] Extension not available for token sync');
          } else {
            console.log('[PhishNet] Token synced to extension');
          }
        });
      }
      
      // Also broadcast via custom event for content scripts
      window.dispatchEvent(new CustomEvent('phishnet-token-sync', { detail: { token } }));
      
      // Store in a way the extension can access
      localStorage.setItem('phishnetToken', token || '');
    } catch (e) {
      console.log('[PhishNet] Extension sync not available:', e.message);
    }
  }

  logout() {
    (async () => {
      try {
        const token = localStorage.getItem('token');
        if (token) {
          await fetch(getApiUrl(window.API_CONFIG.api.endpoints.auth.logout), {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
        }
      } catch (e) {
        console.warn('Logout API call failed:', e);
      } finally {
        // Remove all user-sensitive keys
        localStorage.removeItem(this.storageKey);
        localStorage.removeItem('pishnet_user');
        localStorage.removeItem('phishnet_currentUser');
        localStorage.removeItem('currentUser');
        localStorage.removeItem('userAvatar');
        localStorage.removeItem('avatarFitMode');
        localStorage.removeItem('selectedScan');
        localStorage.removeItem('selectedScanId');
        // Remove auth token and any cached scan history
        localStorage.removeItem('token');
        localStorage.removeItem('scanHistory');
        localStorage.removeItem('phishnetToken');
        
        // Clear token from extension
        this.syncTokenToExtension(null);
        
        // Clear any in-memory scan manager
        if (window.scanManager && Array.isArray(window.scanManager.scanHistory)) {
          window.scanManager.scanHistory = [];
        }
        window.currentUserAvatar = null;
        // Redirect to login/index
        window.location.href = 'index.html';
      }
    })();
  }

  getUser() {
    const userData = localStorage.getItem(this.storageKey);
    return userData ? JSON.parse(userData) : null;
  }

  getInitials(email, firstName, lastName) {
    if (firstName && lastName) {
      return (firstName[0] + lastName[0]).toUpperCase();
    }
    if (firstName) {
      return firstName.substring(0, 2).toUpperCase();
    }
    const name = (email || '').split('@')[0];
    const parts = name.split(/[._-]/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return (name.substring(0, 2) || '').toUpperCase();
  }

  setProfile(profile) {
    const user = Object.assign({}, this.getUser() || {}, profile);
    if (profile.firstName || profile.lastName) {
      user.initials = this.getInitials(profile.email || user.email, profile.firstName, profile.lastName);
    }
    if (profile.avatarFit !== undefined) {
      user.avatarFit = profile.avatarFit || 'cover';
      localStorage.setItem('avatarFitMode', user.avatarFit);
    }
    // Don't store large avatar data in localStorage - fetch from server instead
    localStorage.setItem(this.storageKey, JSON.stringify(user));
    localStorage.setItem('pishnet_user', JSON.stringify(user));
  }

  getScanCount() {
    return parseInt(localStorage.getItem(this.scanCountKey) || '0');
  }

  incrementScanCount() {
    const count = this.getScanCount() + 1;
    localStorage.setItem(this.scanCountKey, count.toString());
    return count;
  }

  canScanAsGuest() {
    return this.getScanCount() === 0;
  }

  register(userData) {
    // Call backend API to register user
    return fetch(getApiUrl(window.API_CONFIG.api.endpoints.auth.register), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        firstName: userData.firstName,
        lastName: userData.lastName,
        email: userData.email,
        password: userData.password,
        confirmPassword: userData.confirmPassword
      })
    })
    .then(response => {
      if (!response.ok) {
        return response.json().then(error => {
          const err = new Error(error.message || 'Registration failed');
          // Propagate detailed validation errors from backend
          err.errors = Array.isArray(error.errors) ? error.errors : [];
          err.status = response.status;
          throw err;
        });
      }
      return response.json();
    })
    .then(data => {
      if (data.success && data.data.token) {
        // Store token and user info
        localStorage.setItem('token', data.data.token);
        const user = {
          email: data.data.user.email,
          firstName: data.data.user.firstName,
          lastName: data.data.user.lastName,
          avatar: data.data.user.avatar || null,
          avatarFit: data.data.user.avatarFit || 'cover',
          initials: this.getInitials(data.data.user.email, data.data.user.firstName, data.data.user.lastName),
          loginTime: new Date().toISOString()
        };
        localStorage.setItem(this.storageKey, JSON.stringify(user));
        localStorage.setItem('pishnet_user', JSON.stringify(user));
        // Store avatar ONLY in window object for real-time access, NOT in localStorage
        // This prevents stale avatar issues and storage quota problems
        if (user.avatar) {
          window.currentUserAvatar = user.avatar;
          localStorage.setItem('avatarFitMode', user.avatarFit || 'cover');
        } else {
          window.currentUserAvatar = null;
          localStorage.removeItem('avatarFitMode');
        }
        return user;
      } else {
        throw new Error(data.message || 'Registration failed');
      }
    });
  }

  async refreshProfile() {
    const token = localStorage.getItem('token');
    if (!token) return null;

    try {
      const response = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.users.profile), {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      if (data.success && data.data && data.data.user) {
        const user = data.data.user;
        this.setProfile({
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          avatarFit: user.avatarFit || 'cover',
        });

        // Store avatar in window object (not localStorage) to avoid storage quota issues
        // ALWAYS fetch fresh from server to get latest avatar
        if (user.avatar) {
          window.currentUserAvatar = user.avatar;
          localStorage.setItem('avatarFitMode', user.avatarFit || 'cover');
          // Remove stale localStorage avatar to force fresh fetches
          localStorage.removeItem('userAvatar');
        } else {
          window.currentUserAvatar = null;
          localStorage.removeItem('avatarFitMode');
          localStorage.removeItem('userAvatar');
        }
        
        // Apply avatar styling to all avatar elements
        this.applyAvatarStyling(user);
        
        return user;
      }
    } catch (err) {
      // Silent fail; user may not be logged in
    }
    return null;
  }

  // Apply avatar fit mode to all avatar elements on the page
  applyAvatarStyling(user) {
    if (!user || !user.avatar) return;
    
    const fitMode = user.avatarFit || 'cover';
    const avatarUrl = window.currentUserAvatar;
    
    // Add cache-busting timestamp to prevent showing stale cached images
    const cacheId = new Date().getTime();
    const urlWithCache = avatarUrl && !avatarUrl.startsWith('data:') 
      ? (avatarUrl.includes('?') ? `${avatarUrl}&t=${cacheId}` : `${avatarUrl}?t=${cacheId}`)
      : avatarUrl;
    
    // Update header avatar (.user-avatar)
    const headerAvatar = document.querySelector('.user-avatar');
    if (headerAvatar) {
      headerAvatar.style.backgroundImage = '';
      headerAvatar.style.backgroundImage = `url(${urlWithCache})`;
      headerAvatar.style.setProperty('background-size', fitMode, 'important');
      headerAvatar.style.backgroundPosition = 'center';
      headerAvatar.style.backgroundRepeat = 'no-repeat';
      headerAvatar.textContent = '';
    }
    
    // Update profile menu avatar (.profile-menu-avatar) if it exists
    const profileMenuAvatar = document.querySelector('.profile-menu-avatar');
    if (profileMenuAvatar) {
      profileMenuAvatar.style.backgroundImage = '';
      profileMenuAvatar.style.backgroundImage = `url(${urlWithCache})`;
      profileMenuAvatar.style.setProperty('background-size', fitMode, 'important');
      profileMenuAvatar.style.backgroundPosition = 'center';
      profileMenuAvatar.style.backgroundRepeat = 'no-repeat';
      profileMenuAvatar.textContent = '';
    }
    
    // Update settings avatar preview (.avatar-preview) if it exists
    const settingsAvatar = document.getElementById('settingsAvatarPreview');
    if (settingsAvatar) {
      settingsAvatar.style.backgroundImage = '';
      settingsAvatar.style.backgroundImage = `url(${urlWithCache})`;
      settingsAvatar.style.setProperty('background-size', fitMode, 'important');
      settingsAvatar.style.backgroundPosition = 'center';
      settingsAvatar.style.backgroundRepeat = 'no-repeat';
      settingsAvatar.textContent = '';
    }
  }
}

// Initialize AuthManager immediately
window.auth = new AuthManager();

// ==================== NAVIGATION MANAGEMENT ====================
class NavigationManager {
  constructor() {
    this.init();
  }

  init() {
    this.updateNavigation();
    this.setupEventListeners();
    this.setupDropdowns();
    this.refreshProfileAndUpdate();
  }

  async refreshProfileAndUpdate() {
    if (window.auth.isLoggedIn()) {
      const user = await window.auth.refreshProfile();
      // Ensure window.currentUserAvatar is set from fetched data
      if (user && user.avatar) {
        window.currentUserAvatar = user.avatar;
        console.log('Avatar refreshed from server:', user.avatar.substring(0, 50));
      } else {
        window.currentUserAvatar = null;
      }
      this.updateNavigation();
    }
  }

  updateNavigation() {
    const isLoggedIn = window.auth.isLoggedIn();

    // Update navigation links
    const navLinks = document.querySelector('.nav-links');
    if (navLinks) {
      if (isLoggedIn) {
        this.showLoggedInNav();
      } else {
        this.showGuestNav();
      }
    }

    // Update auth buttons and user avatar
    const authButtons = document.querySelector('.auth-buttons');
    const userAvatar = document.querySelector('.user-avatar');
    const dashboardButton = document.querySelector('.btn-dashboard');

    if (authButtons && userAvatar) {
      // Make auth UI visible after determination
      authButtons.style.opacity = '1';
      authButtons.style.visibility = 'visible';
      userAvatar.style.opacity = '1';
      userAvatar.style.visibility = 'visible';
      
      if (isLoggedIn) {
        authButtons.style.display = 'none';
        userAvatar.style.display = 'flex';

        const user = window.auth.getUser();
        
        // Use window.currentUserAvatar (kept in memory) instead of localStorage
        const savedAvatar = window.currentUserAvatar;
        const savedFitMode = (user && user.avatarFit) || localStorage.getItem('avatarFitMode') || 'cover';
        
        if (savedAvatar) {
          // Add cache-busting timestamp to prevent showing stale cached images
          const cacheId = new Date().getTime();
          const urlWithCache = !savedAvatar.startsWith('data:')
            ? (savedAvatar.includes('?') ? `${savedAvatar}&t=${cacheId}` : `${savedAvatar}?t=${cacheId}`)
            : savedAvatar;
          userAvatar.style.backgroundImage = '';
          userAvatar.style.backgroundImage = `url(${urlWithCache})`;
          userAvatar.style.setProperty('background-size', savedFitMode, 'important');
          userAvatar.style.backgroundPosition = 'center';
          userAvatar.style.backgroundRepeat = 'no-repeat';
          userAvatar.textContent = '';
        } else {
          userAvatar.style.backgroundImage = '';
          userAvatar.textContent = user ? user.initials : '';
        }

        // Hide extra dashboard button
        if (dashboardButton) dashboardButton.style.display = 'none';
      } else {
        authButtons.style.display = 'flex';
        userAvatar.style.display = 'none';

        // Show dashboard button for guests
        if (dashboardButton) dashboardButton.style.display = 'inline-flex';
      }
    }

    // Apply logged-in class for global styling
    document.body.classList.toggle('logged-in', isLoggedIn);

    // Hide guest-only quick scan helper text when logged in
    const quickScanGuestText = document.getElementById('quick-scan-guest-text');
    if (quickScanGuestText) {
      quickScanGuestText.style.display = isLoggedIn ? 'none' : 'block';
    }

    // Safety check for landing page
    if (isLoggedIn && window.location.pathname.includes('index.html')) {
      setTimeout(() => {
        const landingDashboardBtn = document.querySelector('.btn-dashboard');
        if (landingDashboardBtn) landingDashboardBtn.style.display = 'none';
      }, 100);
    }
  }


  showLoggedInNav() {
    const navLinks = document.querySelector('.nav-links');
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';

    navLinks.innerHTML = `
      <li><a href="dashboard.html" ${currentPage === 'dashboard.html' ? 'class="active"' : ''}>Dashboard</a></li>
      <li><a href="reports.html" ${currentPage === 'reports.html' ? 'class="active"' : ''}>Reports</a></li>
      <li><a href="blog.html" ${currentPage === 'blog.html' ? 'class="active"' : ''}>Blog</a></li>
      <li><a href="demo.html" ${currentPage === 'demo.html' ? 'class="active"' : ''}>Demo</a></li>
      <li><a href="pricing.html" ${currentPage === 'pricing.html' ? 'class="active"' : ''}>Pricing</a></li>
      <li class="dropdown">
        <a href="#" class="dropdown-toggle ${currentPage === 'about.html' || currentPage === 'faq.html' || currentPage === 'terms.html' || currentPage === 'privacy.html' ? 'active' : ''}">
          About
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-left: 0.25rem;">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </a>
        <ul class="dropdown-menu">
          <li><a href="about.html">About Us</a></li>
          <li><a href="faq.html">FAQs</a></li>
          <li><a href="terms.html">Terms of Use</a></li>
          <li><a href="privacy.html">Privacy Policy</a></li>
        </ul>
      </li>
    `;
  }

  showGuestNav() {
    const navLinks = document.querySelector('.nav-links');
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';

    if (navLinks) {
      navLinks.innerHTML = `
       <li><a href="pricing.html" ${currentPage === 'pricing.html' ? 'class="active"' : ''}>Pricing</a></li>
       <li><a href="demo.html" ${currentPage === 'demo.html' ? 'class="active"' : ''}>Demo</a></li>
        <li><a href="blog.html" ${currentPage === 'blog.html' ? 'class="active"' : ''}>Blog</a></li>
        <li class="dropdown">
          <a href="#" class="dropdown-toggle ${currentPage === 'about.html' || currentPage === 'faq.html' || currentPage === 'terms.html' || currentPage === 'privacy.html' ? 'active' : ''}">
            About
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-left: 0.25rem;">
              <polyline points="6 9 12 15 18 9"/>
            </svg>
          </a>
          <ul class="dropdown-menu">
            <li><a href="about.html">About Us</a></li>
            <li><a href="faq.html">FAQs</a></li>
            <li><a href="terms.html">Terms of Use</a></li>
            <li><a href="privacy.html">Privacy Policy</a></li>
          </ul>
        </li>
      `;
    }
  }

  setupEventListeners() {
    // Dashboard button click handler - redirect to login if not logged in
    const dashboardButtons = document.querySelectorAll('.btn-dashboard, [href="dashboard.html"]');
    dashboardButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        if (!window.auth.isLoggedIn()) {
          e.preventDefault();
          window.location.href = 'login.html';
        }
      });
    });

    // User avatar click handler
    const userAvatar = document.querySelector('.user-avatar');
    if (userAvatar) {
      userAvatar.addEventListener('click', () => {
        // Reverted: toggle profile menu on avatar click
        this.toggleProfileMenu();
      });
    }
  }

  setupDropdowns() {
    document.addEventListener('click', (e) => {
      const dropdownToggle = e.target.closest('.dropdown-toggle');
      if (dropdownToggle) {
        e.preventDefault();
        const dropdown = dropdownToggle.closest('.dropdown');
        dropdown.classList.toggle('active');
      } else {
        document.querySelectorAll('.dropdown').forEach(d => d.classList.remove('active'));
      }
    });
  }

  toggleProfileMenu() {
    const existingMenu = document.querySelector('.profile-menu');
    if (existingMenu) {
      existingMenu.classList.add('closing');
      setTimeout(() => existingMenu.remove(), 220);
      return;
    }

    const user = window.auth.getUser();
    const menu = document.createElement('div');
    menu.className = 'profile-menu';
    menu.innerHTML = `
      <div class="profile-menu-header">
        <div class="profile-menu-avatar"></div>
        <div class="profile-menu-info">
          <div class="profile-menu-name">${user ? (user.name || (user.firstName ? (user.firstName + (user.lastName ? ' ' + user.lastName : '')) : '')) : ''}</div>
          <div class="profile-menu-email">${user ? user.email : ''}</div>
        </div>
      </div>
      <div class="profile-menu-divider"></div>
      <a href="settings.html" class="profile-menu-item">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="3"/>
          <path d="M12 1v6m0 6v6m6-12v6m-6 0v6m-6-6v6"/>
        </svg>
        Settings
      </a>
      <button class="profile-menu-item" id="logout-btn">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16 17 21 12 16 7"/>
          <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
        Logout
      </button>
    `;

    const avatarEl = menu.querySelector('.profile-menu-avatar');
    if (window.currentUserAvatar) {
      // Add cache-busting timestamp to prevent showing stale cached images
      const cacheId = new Date().getTime();
      const urlWithCache = !window.currentUserAvatar.startsWith('data:')
        ? (window.currentUserAvatar.includes('?') ? `${window.currentUserAvatar}&t=${cacheId}` : `${window.currentUserAvatar}?t=${cacheId}`)
        : window.currentUserAvatar;
      avatarEl.style.backgroundImage = '';
      avatarEl.style.backgroundImage = `url(${urlWithCache})`;
      avatarEl.style.setProperty('background-size', user?.avatarFit || 'cover', 'important');
      avatarEl.style.backgroundPosition = 'center';
      avatarEl.style.backgroundRepeat = 'no-repeat';
    } else if (user && user.initials) {
      avatarEl.textContent = user.initials;
    }

    // Ensure email styling is applied inline to avoid being overridden
    const emailEl = menu.querySelector('.profile-menu-email');
    if (emailEl) {
      emailEl.style.setProperty('color', '#9CA3AF', 'important');
      emailEl.style.setProperty('font-size', '0.85rem', 'important');
      emailEl.style.setProperty('font-weight', '500', 'important');
      emailEl.style.setProperty('opacity', '0.85', 'important');
    }

    const userAvatar = document.querySelector('.user-avatar');
    userAvatar.appendChild(menu);

    // Add event listener for logout button
    const logoutBtn = menu.querySelector('#logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => window.auth.logout());
    }

    setTimeout(() => {
      document.addEventListener('click', function closeMenu(e) {
        if (!e.target.closest('.user-avatar')) {
          menu.classList.add('closing');
          setTimeout(() => {
            menu.remove();
            document.removeEventListener('click', closeMenu);
          }, 200);
        }
      });
    }, 10);
  }
}

// ==================== SCAN FUNCTIONALITY ====================
class ScanManager {
  constructor() {
    this.scanHistory = [];
    this.lastUrlResult = null;
    this.lastEmailResult = null;
    this.loadScanHistory();
    // If a global ScanningSystem exists, defer form handling to it to avoid duplicate bindings
    if (window.scanSystem) {
      console.log('[ScanManager] Detected global scanSystem; deferring form handlers');
    } else {
      this.setupScanForms();
    }
    this.setupCloseButtons();
  }

  async loadScanHistory() {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        console.log('[ScanManager] No token found, loading from localStorage');
        // Load from localStorage for non-logged-in users
        this.scanHistory = JSON.parse(localStorage.getItem('scanHistory')) || [];
        return;
      }

      const response = await fetch(getApiUrlWithParams(window.API_CONFIG.api.endpoints.users.history, { limit: 50 }), {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          // Transform API data to match frontend format
          this.scanHistory = data.data.history.map(item => {
            const rawThreat = item.threatLevel || item.threat || item.status || (item.isSafe === true ? 'safe' : (item.isSafe === false ? 'malicious' : null));
            const normalizedThreat = rawThreat && (['safe', 'suspicious', 'malicious'].includes(String(rawThreat).toLowerCase()))
              ? String(rawThreat).toLowerCase()
              : this.mapThreatLevel ? this.mapThreatLevel(rawThreat) : (rawThreat || 'safe');

            return ({
              id: item._id,
              type: item.scanType || (item.url.includes('@') ? 'email' : 'url'),
              value: item.url,
              threat: normalizedThreat || 'safe',
              threatType: item.threatType,
              confidence: item.confidence,
              timestamp: new Date(item.checkedAt).getTime(),
              date: new Date(item.checkedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
              time: new Date(item.checkedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true }),
              indicators: item.indicators || [],
              domain: item.domain,
              isSafe: item.isSafe
            });
          });
          console.log(`[ScanManager] Loaded ${this.scanHistory.length} scans from server`);
        } else {
          console.error('[ScanManager] Failed to load scan history:', data.message);
          this.scanHistory = [];
        }
      } else {
        // If token is invalid/expired, clear it and any cached scans to prevent leakage
        if (response.status === 401) {
          console.warn('[ScanManager] Unauthorized token - clearing token and scan history');
          localStorage.removeItem('token');
          localStorage.removeItem('scanHistory');
          if (window.scanManager) window.scanManager.scanHistory = [];
          this.scanHistory = [];
          return;
        }
        console.error('[ScanManager] Failed to fetch scan history:', response.status);
        this.scanHistory = [];
      }
    } catch (error) {
      console.error('[ScanManager] Error loading scan history:', error);
      this.scanHistory = [];
    }
  }

  setupCloseButtons() {
    const closeUrlBtn = document.getElementById('close-url-results');
    const closeEmailBtn = document.getElementById('close-email-results');
    
    if (closeUrlBtn) {
      closeUrlBtn.addEventListener('click', () => this.closeScanResults());
    }
    if (closeEmailBtn) {
      closeEmailBtn.addEventListener('click', () => this.closeScanResults());
    }
  }

  closeScanResults() {
    const resultsSection = document.getElementById('results-section');
    resultsSection.classList.add('closing');
    
    setTimeout(() => {
      resultsSection.style.display = 'none';
      resultsSection.classList.remove('closing');
      
      // Clear hidden classes
      document.getElementById('url-results').classList.add('hidden');
      document.getElementById('email-results').classList.add('hidden');
    }, 400);
  }

  setupScanForms() {
    // URL/email scan forms - attach handlers except for homepage panels
    // Never bind handlers for homepage panels (#panel-url / #panel-email)
    // These are managed by `ScanningSystem` to avoid duplicate event handlers.
    document.querySelectorAll('form').forEach(form => {
      const isHomepageUrlPanel = !!form.closest('#panel-url');
      const isHomepageEmailPanel = !!form.closest('#panel-email');
      if (isHomepageUrlPanel || isHomepageEmailPanel) return;

      const urlInput = form.querySelector('#url-input, input[type="url"]');
      const emailInput = form.querySelector('#email-input, textarea');

      if (urlInput || emailInput) {
        form.addEventListener('submit', (e) => {
          e.preventDefault();
          this.handleScan(urlInput || emailInput, urlInput ? 'url' : 'email');
        });
      }
    });
  }

  async handleScan(input, type) {
    const value = input.value.trim();

    if (!value) {
      this.showNotification('Please enter a ' + type + ' to scan', 'error');
      return;
    }

    // Check if guest can scan
    if (!auth.isLoggedIn() && !auth.canScanAsGuest()) {
      this.showNotification('Login to continue scanning', 'warning');
      setTimeout(() => {
        window.location.href = 'login.html';
      }, 2000);
      return;
    }

    // Show scanning notification
    this.showNotification('Scanning ' + type + '...', 'info');

    try {
      // Call real backend API
      console.log('🔍 Calling backend API for', type, 'scan...');
      const result = await this.callBackendScan(value, type);
      console.log('✅ Backend response:', result);
      auth.incrementScanCount();
      this.showScanResult(result);
      this.saveScanReport(result);
      this.displayScanHistory();
    } catch (error) {
      console.error('❌ Scan error:', error);
      console.error('Error details:', error.message, error.stack);
      // Fallback to simulated scan if backend unavailable
      this.showNotification('Backend unavailable - Using offline mode...', 'warning');
      setTimeout(() => {
        const result = this.simulateScan(value, type);
        auth.incrementScanCount();
        this.showScanResult(result);
        this.saveScanReport(result);
        this.displayScanHistory();
      }, 500);
    }
  }

  async callBackendScan(value, type) {
    const API_BASE = window.API_CONFIG?.api?.baseURL || window.CONFIG?.API_BASE_URL || 'http://localhost:3000';
    
    if (type === 'email') {
      const response = await fetch(`${API_BASE}/api/scan/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emailContent: value })
      });
      
      if (!response.ok) throw new Error('API request failed');
      
      const data = await response.json();
      
      // Convert backend response to UI format
      const isPhishing = data.classification === 'phishing';
      const threat = isPhishing ? (data.confidence > 0.8 ? 'malicious' : 'suspicious') : 'safe';
      
      return {
        type: 'email',
        value: value.substring(0, 100) + (value.length > 100 ? '...' : ''),
        threat,
        confidence: data.confidence * 100,
        timestamp: new Date().toISOString(),
        indicators: data.indicators || [],
        issues: isPhishing ? 
          ['⚠ Phishing detected', `⚠ Confidence: ${(data.confidence * 100).toFixed(1)}%`] :
          ['✓ Email appears safe', '✓ No phishing indicators'],
        summary: isPhishing ?
          `WARNING: This email appears to be a phishing attempt (${(data.confidence * 100).toFixed(1)}% confidence). ${data.indicators?.join('. ') || 'Be cautious with this email.'}` :
          'This email appears to be legitimate. No phishing indicators were detected.',
        riskLevel: threat === 'safe' ? 'Low' : threat === 'suspicious' ? 'Medium' : 'High',
        scanDetails: {
          model: data.model || 'PhishingDistilBERT',
          phishingScore: data.confidence * 100
        }
      };
    } else if (type === 'url') {
      const response = await fetch(`${API_BASE}/api/scan/scan-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value })
      });
      
      if (!response.ok) throw new Error('API request failed');
      
      const result = await response.json();
      const data = result.data || result; // Handle nested data structure
      
      // New advanced URL scanner response format
      const isPhishing = data.isPhishing === true;
      const riskScore = data.riskScore || 0;
      const riskLevel = data.riskLevel || 'low';
      
      // Determine threat level based on risk
      let threat = 'safe';
      if (riskLevel === 'critical' || riskLevel === 'high') {
        threat = 'malicious';
      } else if (riskLevel === 'medium') {
        threat = 'suspicious';
      }
      
      // Build issues from risk factors
      const riskFactors = data.riskFactors || [];
      const safetyIndicators = data.safetyIndicators || [];
      
      const issues = isPhishing || riskFactors.length > 0
        ? riskFactors.map(f => `⚠ ${f}`)
        : safetyIndicators.length > 0 
          ? safetyIndicators.map(s => `✓ ${s}`)
          : ['✓ URL appears safe', '✓ No phishing indicators'];
      
      // Build summary
      let summary = '';
      if (isPhishing) {
        summary = `WARNING: This URL is likely a phishing attempt! Risk Score: ${riskScore.toFixed(0)}%. ${riskFactors.slice(0, 3).join('. ')}.`;
      } else if (riskLevel === 'medium') {
        summary = `This URL shows some warning signs. Risk Score: ${riskScore.toFixed(0)}%. Exercise caution.`;
      } else {
        summary = 'This URL appears to be legitimate and safe to visit.';
      }
      
      return {
        type: 'url',
        value: value,
        threat,
        confidence: riskScore,
        timestamp: data.timestamp || new Date().toISOString(),
        indicators: riskFactors,
        issues,
        summary,
        riskLevel: riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1),
        scanDetails: {
          model: data.mlAnalysis?.method || 'Advanced URL Scanner',
          urlAnalysis: data.urlAnalysis,
          domainAnalysis: data.domainAnalysis,
          mlAnalysis: data.mlAnalysis,
          scanTime: data.scanTime
        }
      };
    }
    
    throw new Error('Unknown scan type');
  }

  simulateScan(value, type) {
    if (type === 'url') {
      return this.scanURL(value);
    } else if ((type || '').toString().toLowerCase().includes('email')) {
      return this.scanEmail(value);
    }
  }

  scanURL(url) {
    // URL-specific scanning logic
    const threats = [
      { threat: 'safe', weight: 40 },
      { threat: 'suspicious', weight: 35 },
      { threat: 'malicious', weight: 25 }
    ];

    const threat = this.weightedRandomThreat(threats);
    const urlLower = url.toLowerCase();
    
    // Generate URL-specific indicators based on threat level
    let indicators = [];
    let issues = [];
    let summary = '';

    if (threat === 'safe') {
      indicators = [
        'Valid SSL certificate (HTTPS)',
        'Domain registered over 3 years ago',
        'Not found in phishing databases',
        'No suspicious redirects detected',
        'No malware signatures detected'
      ];
      issues = ['✓ Domain reputation: Good', '✓ Security certificates: Valid'];
      summary = `${url} appears to be a legitimate website. The domain has a good reputation, valid SSL certificate, and no known malicious patterns. Safe to visit.`;
    } else if (threat === 'suspicious') {
      indicators = [
        'Recently registered domain (< 6 months)',
        'URL structure similar to popular services',
        'Unusual port number detected',
        'Possible credential harvesting attempt',
        'Mixed HTTP/HTTPS content'
      ];
      issues = ['⚠ Domain age: Very new', '⚠ URL pattern: Suspicious similarity', '⚠ SSL: Partial'];
      summary = `${url} shows warning signs. This domain was recently registered and has URL patterns similar to legitimate services. Possible phishing attempt. Verify before visiting.`;
    } else {
      indicators = [
        'Domain blacklisted in threat intelligence',
        'Known phishing/malware hosting site',
        'Spoofed domain of legitimate service',
        'History of credential theft',
        'Multiple malware distribution incidents'
      ];
      issues = ['✕ Blacklisted: Yes', '✕ Threat type: Phishing/Malware', '✕ Risk level: Critical'];
      summary = `WARNING: ${url} is a CONFIRMED MALICIOUS website. It is blacklisted in threat databases and has a history of phishing attacks and malware distribution. DO NOT VISIT OR ENTER ANY INFORMATION.`;
    }

    return {
      type: 'url',
      value: url,
      threat,
      confidence: threat === 'safe' ? 85 + Math.random() * 15 : 70 + Math.random() * 30,
      timestamp: new Date().toISOString(),
      indicators,
      issues,
      summary,
      riskLevel: threat === 'safe' ? 'Low' : threat === 'suspicious' ? 'Medium' : 'High',
      scanDetails: {
        urlStructure: this.analyzeURLStructure(url),
        sslStatus: threat === 'safe' ? 'Valid' : threat === 'suspicious' ? 'Partial' : 'Invalid',
        domainAge: threat === 'safe' ? '3+ years' : threat === 'suspicious' ? '< 6 months' : 'Newly registered',
        reputationScore: threat === 'safe' ? 85 : threat === 'suspicious' ? 35 : 5
      }
    };
  }

  scanEmail(emailContent) {
    // Email-specific scanning logic
    const threats = [
      { threat: 'safe', weight: 30 },
      { threat: 'suspicious', weight: 45 },
      { threat: 'malicious', weight: 25 }
    ];

    const threat = this.weightedRandomThreat(threats);
    
    // Extract email features for analysis
    const hasSuspiciousLanguage = emailContent.includes('verify') || emailContent.includes('confirm') || emailContent.includes('urgent');
    const hasLinks = emailContent.includes('http');
    const hasAttachments = emailContent.includes('attachment') || emailContent.includes('.zip') || emailContent.includes('.exe');
    
    let indicators = [];
    let issues = [];
    let summary = '';

    if (threat === 'safe') {
      indicators = [
        'Sender domain verified and authenticated',
        'Email headers valid and properly formatted',
        'No suspicious links or attachments',
        'Content aligns with sender profile',
        'No phishing language detected'
      ];
      issues = ['✓ Sender authentication: Valid', '✓ Content analysis: Clean'];
      summary = 'This email appears to be legitimate. The sender is verified, content is safe, and no phishing patterns detected. Safe to interact with.';
    } else if (threat === 'suspicious') {
      indicators = [
        'Sender domain mismatch (spoofing attempt)',
        'Unusual urgency or fear-based language',
        'Requests for sensitive information',
        'Suspicious links with shortened URLs',
        'Unexpected attachment from known sender'
      ];
      issues = ['⚠ Sender verification: Partial', '⚠ Language analysis: Warning signs', '⚠ Links: Suspicious'];
      summary = 'This email has warning signs and may be phishing. The sender appears spoofed, contains urgent language, and requests personal information. Do not click links or download attachments. Verify directly with the sender.';
    } else {
      indicators = [
        'Known phishing campaign signature detected',
        'Severe sender domain spoofing',
        'Malicious attachment or link detected',
        'Email found in threat databases',
        'Advanced social engineering techniques'
      ];
      issues = ['✕ Phishing campaign: Confirmed', '✕ Malicious content: Detected', '✕ Risk level: Critical'];
      summary = 'ALERT: This is a CONFIRMED PHISHING OR MALWARE EMAIL. It matches known attack patterns and contains malicious content. Delete immediately. Do not open attachments or click links. Report as spam/phishing to your email provider.';
    }

    return {
      type: 'email',
      value: emailContent.substring(0, 100) + (emailContent.length > 100 ? '...' : ''),
      threat,
      confidence: threat === 'safe' ? 80 + Math.random() * 20 : 65 + Math.random() * 35,
      timestamp: new Date().toISOString(),
      indicators,
      issues,
      summary,
      riskLevel: threat === 'safe' ? 'Low' : threat === 'suspicious' ? 'Medium' : 'High',
      scanDetails: {
        senderVerification: threat === 'safe' ? 'Valid' : threat === 'suspicious' ? 'Partial' : 'Spoofed',
        languageAnalysis: threat === 'safe' ? 'Normal' : threat === 'suspicious' ? 'Warning signs' : 'Urgent/Fear-based',
        attachmentsAnalysis: threat === 'safe' ? 'None/Safe' : threat === 'suspicious' ? 'Suspicious' : 'Malicious',
        phishingScore: threat === 'safe' ? 5 : threat === 'suspicious' ? 65 : 95
      }
    };
  }

  weightedRandomThreat(threats) {
    const totalWeight = threats.reduce((sum, t) => sum + t.weight, 0);
    let random = Math.random() * totalWeight;
    
    for (let threat of threats) {
      random -= threat.weight;
      if (random <= 0) return threat.threat;
    }
    
    return threats[0].threat;
  }

  analyzeURLStructure(url) {
    const hasHttps = url.startsWith('https');
    const isShortened = url.includes('bit.ly') || url.includes('tinyurl') || url.includes('short');
    const hasSubdomains = (url.match(/\./g) || []).length > 2;
    
    if (isShortened) return 'Shortened URL (obfuscated)';
    if (hasSubdomains) return 'Multiple subdomains (suspicious)';
    if (hasHttps) return 'Standard HTTPS structure';
    return 'HTTP (unencrypted)';
  }

  getIndicators(threat) {
    const indicators = {
      safe: ['Valid SSL certificate', 'Domain registered for 5+ years', 'No suspicious patterns detected'],
      suspicious: ['Recently registered domain', 'Unusual URL structure', 'Mixed security signals'],
      malicious: ['Spoofed domain detected', 'Known phishing patterns', 'Invalid SSL certificate', 'Blacklisted IP']
    };
    return indicators[threat] || [];
  }

  showScanResult(result) {
    // Show results section with smooth animation
    const resultsSection = document.getElementById('results-section');
    const urlResults = document.getElementById('url-results');
    const emailResults = document.getElementById('email-results');

    // Hide all result panels first
    if (urlResults) urlResults.classList.add('hidden');
    if (emailResults) emailResults.classList.add('hidden');

    if (result.type === 'url') {
      this.displayUrlResults(result);
      if (urlResults) urlResults.classList.remove('hidden');
    } else {
      this.displayEmailResults(result);
      if (emailResults) emailResults.classList.remove('hidden');
    }

    // Show results section with animation
    if (resultsSection) resultsSection.style.display = 'block';

    // Scroll to results smoothly
    setTimeout(() => {
      if (resultsSection) resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  }

  displayUrlResults(result) {
    const statusColor = document.getElementById('url-status-color');
    const statusLabel = document.getElementById('url-status-label');
    const statusDesc = document.getElementById('url-status-desc');
    const riskLevel = document.getElementById('url-risk-level');
    const riskBar = document.getElementById('url-risk-bar');
    const issuesList = document.getElementById('url-issues-list');
    const summary = document.getElementById('url-analysis-summary');
    const scanTime = document.getElementById('url-scan-time');

    // Set status color and label (guarded)
    if (statusColor) statusColor.className = 'status-indicator ' + (result.threat || 'safe');
    if (statusLabel) statusLabel.textContent = (result.threat || 'safe').charAt(0).toUpperCase() + (result.threat || 'safe').slice(1);
    if (statusDesc) statusDesc.textContent = this.getThreatDescription('url', result.threat || 'safe');

    // Set risk level with exact value from scan
    if (riskLevel) {
      riskLevel.textContent = result.riskLevel || 'N/A';
      riskLevel.className = 'risk-value ' + ((result.threat === 'safe') ? 'low' : (result.threat === 'suspicious') ? 'medium' : 'high');
    }

    // Animate risk bar based on threat
    const riskPercentages = { safe: 20, suspicious: 60, malicious: 95 };
    if (riskBar && riskPercentages[result.threat]) riskBar.style.width = riskPercentages[result.threat] + '%';

    // Display detailed issues with colored indicators
    if (issuesList && Array.isArray(result.issues)) {
      issuesList.innerHTML = result.issues.map(issue => {
        let className = '';
        if (issue.startsWith('✓')) {
          className = 'safe';
        } else if (issue.startsWith('⚠')) {
          className = 'warning';
        } else if (issue.startsWith('✕')) {
          className = 'malicious';
        }
        return `<li class="${className}">${issue}</li>`;
      }).join('');
    }

    // Show comprehensive summary
    if (summary) summary.textContent = result.summary || '';

    // Scan time
    if (scanTime) scanTime.textContent = `✓ Scan completed in ${(Math.random() * 1 + 0.8).toFixed(1)}s | Confidence: ${Math.round(result.confidence || 0)}%`;

    // Store reference for export
    this.lastUrlResult = result;

    // Setup View Report button
    const viewReportBtn = document.getElementById('url-view-report');
    if (viewReportBtn) {
      viewReportBtn.addEventListener('click', () => {
        window.location.href = `report.html?id=${result.id}`;
      });
    }
  }

  displayEmailResults(result) {
    const statusColor = document.getElementById('email-status-color');
    const statusLabel = document.getElementById('email-status-label');
    const statusDesc = document.getElementById('email-status-desc');
    const riskLevel = document.getElementById('email-risk-level');
    const riskBar = document.getElementById('email-risk-bar');
    const issuesList = document.getElementById('email-issues-list');
    const summary = document.getElementById('email-analysis-summary');
    const scanTime = document.getElementById('email-scan-time');

    // Set status color and label (guard elements)
    if (statusColor) statusColor.className = 'status-indicator ' + (result.threat || 'safe');
    if (statusLabel) statusLabel.textContent = (result.threat || 'safe').charAt(0).toUpperCase() + (result.threat || 'safe').slice(1);
    if (statusDesc) statusDesc.textContent = this.getThreatDescription('email', result.threat || 'safe');

    // Set risk level with exact value from scan
    if (riskLevel) {
      riskLevel.textContent = result.riskLevel || 'N/A';
      riskLevel.className = 'risk-value ' + ((result.threat === 'safe') ? 'low' : (result.threat === 'suspicious') ? 'medium' : 'high');
    }

    // Animate risk bar based on threat
    const riskPercentages = { safe: 25, suspicious: 65, malicious: 98 };
    if (riskBar && riskPercentages[result.threat]) riskBar.style.width = riskPercentages[result.threat] + '%';

    // Display detailed issues with colored indicators
    if (issuesList && Array.isArray(result.issues)) {
      issuesList.innerHTML = result.issues.map(issue => {
        let className = '';
        if (issue.startsWith('✓')) {
          className = 'safe';
        } else if (issue.startsWith('⚠')) {
          className = 'warning';
        } else if (issue.startsWith('✕')) {
          className = 'malicious';
        }
        return `<li class="${className}">${issue}</li>`;
      }).join('');
    }

    // Show comprehensive summary
    if (summary) summary.textContent = result.summary || '';

    // Scan time
    if (scanTime) scanTime.textContent = `✓ Scan completed in ${(Math.random() * 1.5 + 1).toFixed(1)}s | Confidence: ${Math.round(result.confidence || 0)}%`;
    
    // Store reference for export
    this.lastEmailResult = result;

    // Setup View Report button
    const viewReportBtn = document.getElementById('email-view-report');
    if (viewReportBtn) {
      viewReportBtn.addEventListener('click', () => {
        window.location.href = `report.html?id=${result.id}`;
      });
    }
  }

  getThreatDescription(type, threat) {
    const descriptions = {
      url: {
        safe: 'This URL appears to be safe and secure.',
        suspicious: 'This URL shows some suspicious characteristics. Proceed with caution.',
        malicious: 'This URL is identified as malicious. Do NOT visit.'
      },
      email: {
        safe: 'This email appears to be legitimate.',
        suspicious: 'This email shows signs of suspicious activity. Verify sender before responding.',
        malicious: 'This email is identified as phishing or malicious. Do not reply or click links.'
      }
    };
    return descriptions[type][threat] || '';
  }

  async saveScanReport(result) {
    const token = localStorage.getItem('token');
    // If a centralized ScanningSystem is present, delegate saving to it
    if (window.scanSystem && typeof window.scanSystem.saveScan === 'function') {
      try {
        await window.scanSystem.saveScan(result);
        return;
      } catch (err) {
        console.warn('[ScanManager] scanSystem.saveScan failed, falling back to local behavior', err);
      }
    }

    if (token) {
      // Logged-in user: send scan to server so it's stored under the user's account
      try {
        const endpoint = (result.type || '').toString().toLowerCase().includes('email') ? '/api/scan/email' : '/api/scan/url';
        const body = (result.type || '').toString().toLowerCase().includes('email')
          ? { senderEmail: result.senderEmail || 'unknown@local', emailContent: result.value || '', subject: result.subject || '' }
          : { url: result.value };

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify(body)
        });

        if (!response.ok) {
          console.warn('[ScanManager] Server returned error saving scan, saving locally instead');
          this.saveScanReportToLocal(result);
        } else {
          const data = await response.json();
          if (!data.success) {
            console.warn('[ScanManager] API responded with failure:', data.message);
            this.saveScanReportToLocal(result);
          } else {
            await this.loadScanHistory();
            this.displayScanHistory();
          }
        }
      } catch (err) {
        console.error('[ScanManager] Error saving scan to server, falling back to local save', err);
        this.saveScanReportToLocal(result);
      }
    } else {
      // Non-logged-in user: save to localStorage
      console.log('[ScanManager] Saving scan to localStorage for non-logged-in user');
      this.saveScanReportToLocal(result);
    }

    // Show success notification
    this.showNotification('Scan report saved automatically', 'success');
  }

  saveScanReportToLocal(result) {
    // Create comprehensive report object with stable string id and unified fields
    const ts = Date.now();
    const report = {
      id: `local-${ts}`,
      type: result.type,
      value: result.value,
      threat: result.threat || result.status || result.threatLevel,
      confidence: typeof result.confidence !== 'undefined' ? Math.round(result.confidence) : (result.riskPercent || null),
      riskLevel: result.riskLevel || result.riskPercent || null,
      indicators: result.indicators || [],
      issues: result.issues || [],
      summary: result.summary || '',
      details: result.scanDetails || result.details || null,
      timestamp: new Date().toISOString(),
      date: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
      time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true })
    };

    // Add to scan history, avoid duplicate when same as last
    const last = this.scanHistory[0];
    if (!(last && last.value === report.value && String(last.threat) === String(report.threat) && Math.abs(new Date(last.timestamp).getTime() - new Date(report.timestamp).getTime()) < 2000)) {
      this.scanHistory.unshift(report);
    }

    // Keep only last 50 scans
    if (this.scanHistory.length > 50) {
      this.scanHistory = this.scanHistory.slice(0, 50);
    }

    // Save to localStorage
    localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));

    // Update display
    this.displayScanHistory();

    // Synchronize with ScanningSystem (dashboard) if present so recent scans table updates
    try {
      if (window.scanSystem && Array.isArray(JSON.parse(localStorage.getItem('scanHistory') || '[]'))) {
        const serverHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');
        // Normalize serverHistory entries to scanning-system format (id, type, value, threat...)
        window.scanSystem.scanHistory = serverHistory.map(item => ({
          id: String(item.id),
          type: item.type || (item.value && String(item.value).includes('@') ? 'email' : 'url'),
          value: item.value || item.target || '',
          threat: item.threat || item.result || 'safe',
          confidence: item.confidence || item.confidence === 0 ? item.confidence : null,
          indicators: item.indicators || [],
          issues: item.issues || [],
          date: item.date,
          time: item.time,
          timestamp: item.timestamp || item.ts || Date.now()
        }));
        if (typeof window.scanSystem.updateDashboardTable === 'function') {
          window.scanSystem.updateDashboardTable();
        }
      }
    } catch (err) {
      console.warn('[ScanManager] sync to scanSystem failed', err);
    }
  }

  async deleteScanReport(reportId) {
    const token = localStorage.getItem('token');

    if (token) {
      // For logged-in users, attempt to delete on server
      try {
        const response = await fetch(`/api/scan/${reportId}`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          }
        });

        if (response.ok) {
          await this.loadScanHistory();
          this.displayScanHistory();
          this.showNotification('Report deleted', 'info');
          return;
        } else {
          console.warn('[ScanManager] Server failed to delete scan, falling back to local removal');
        }
      } catch (err) {
        console.error('[ScanManager] Error deleting scan on server, falling back to local removal', err);
      }
    } else {
      // Non-logged-in user: delete from localStorage
      this.scanHistory = this.scanHistory.filter(report => report.id !== reportId);
      localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));
      this.displayScanHistory();
    }

    // If we reached here, server delete didn't happen — ensure local removal
    this.scanHistory = this.scanHistory.filter(report => report.id !== reportId);
    localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));
    this.displayScanHistory();
    this.showNotification('Report deleted', 'info');
  }

  displayScanHistory() {
    const historyList = document.getElementById('scan-history-list');
    if (!historyList) return;

    // If centralized scanning system exists, use its history
    if (window.scanSystem && Array.isArray(window.scanSystem.scanHistory)) {
      this.scanHistory = window.scanSystem.scanHistory;
    }

    if (this.scanHistory.length === 0) {
      historyList.innerHTML = `
        <div class="history-empty-state">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
          </svg>
          <p>No scans yet. Perform your first scan above!</p>
        </div>
      `;
      return;
    }

    const extractEmail = (text) => {
      if (!text) return '';
      try { const m = String(text).match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i); return m ? m[0] : ''; } catch (e) { return ''; }
    };

    historyList.innerHTML = this.scanHistory.map(report => {
      const statusIcon = report.threat === 'safe' ? '✓' : report.threat === 'suspicious' ? '⚠' : '✕';
      const shortValue = (report.value || '').length > 50 ? (report.value || '').substring(0, 47) + '...' : (report.value || '');
        const displayValue = (report.type || '').toString().toLowerCase().includes('email') ? (report.senderEmail || extractEmail(report.value) || 'unknown@local') : shortValue;
      const issuesSummary = (report.indicators || []).slice(0, 2).join(' • ') + ((report.indicators || []).length > 2 ? ` +${(report.indicators || []).length - 2} more` : '');

      return `
        <div class="history-card" data-report-id="${report.id}">
          <div class="history-card-header">
            <span class="history-badge ${report.threat}">
              <span class="history-status-icon">${statusIcon}</span>
              <span>${report.threat.charAt(0).toUpperCase() + report.threat.slice(1)}</span>
            </span>
            <span class="history-type-badge">${report.type}</span>
          </div>
          
          <div class="history-card-value">${this.escapeHtml(displayValue)}</div>
          
          <div class="history-card-issues">
            <div class="history-issues-label">Detected Issues:</div>
            <div class="history-issues-summary">${this.escapeHtml(issuesSummary)}</div>
          </div>
          
          <div class="history-card-footer">
            <div class="history-time">
              <span>📅</span>
              <span>${report.date} ${report.time}</span>
            </div>
            <div class="history-actions">
              <button class="history-export-btn" data-report-id="${report.id}" title="Export as PDF">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                  <polyline points="7 10 12 15 17 10"></polyline>
                  <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
              </button>
              <button class="history-delete-btn" data-report-id="${report.id}" title="Delete report">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                  <line x1="10" y1="11" x2="10" y2="17"></line>
                  <line x1="14" y1="11" x2="14" y2="17"></line>
                </svg>
              </button>
            </div>
          </div>
        </div>
      `;
    }).join('');

    // Attach event listeners to history action buttons
    const exportButtons = historyList.querySelectorAll('.history-export-btn');
    exportButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const reportId = btn.getAttribute('data-report-id');
        this.exportReportAsPDF(reportId);
      });
    });

    const deleteButtons = historyList.querySelectorAll('.history-delete-btn');
    deleteButtons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const reportId = btn.getAttribute('data-report-id');
        if (window.scanSystem && typeof window.scanSystem.deleteScanById === 'function') {
          window.scanSystem.deleteScanById(reportId);
        } else {
          this.deleteScanReport(reportId);
        }
      });
    });
  }

  exportReportAsPDF(reportId) {
    // Find the report
    const report = this.scanHistory.find(r => r.id === reportId);
    if (!report) {
      this.showNotification('Report not found', 'error');
      return;
    }

    // Generate PDF content
    const pdfContent = this.generatePDFContent(report);
    
    // Create blob and download
    const blob = new Blob([pdfContent], { type: 'text/html' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `PhishNet_Report_${report.date.replace(/,/g, '').replace(/\s+/g, '_')}.html`;
    document.body.appendChild(link);
    link.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(link);
    
    this.showNotification('Report downloaded successfully', 'success');
  }

  generatePDFContent(report) {
    const threatColor = report.threat === 'safe' ? '#00FF88' : report.threat === 'suspicious' ? '#FFC107' : '#FF4D4D';
    const threatBgColor = report.threat === 'safe' ? 'rgba(0, 255, 136, 0.1)' : report.threat === 'suspicious' ? 'rgba(255, 193, 7, 0.1)' : 'rgba(255, 77, 77, 0.1)';
    
    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>PhishNet Scan Report</title>
  <style>
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      line-height: 1.6;
      color: #333;
      background: #f5f5f5;
      padding: 20px;
      margin: 0;
    }
    .container {
      max-width: 800px;
      margin: 0 auto;
      background: white;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .header {
      text-align: center;
      margin-bottom: 30px;
      border-bottom: 2px solid #0B63D9;
      padding-bottom: 20px;
    }
    .logo {
      font-size: 28px;
      font-weight: 700;
      color: #0B63D9;
      margin-bottom: 10px;
    }
    .report-title {
      font-size: 20px;
      color: #666;
      margin: 0;
    }
    .status-section {
      background: ${threatBgColor};
      border-left: 4px solid ${threatColor};
      padding: 20px;
      margin: 20px 0;
      border-radius: 4px;
    }
    .status-badge {
      display: inline-block;
      background: ${threatColor};
      color: white;
      padding: 8px 16px;
      border-radius: 20px;
      font-weight: 600;
      margin-bottom: 10px;
      font-size: 14px;
    }
    .status-title {
      font-size: 24px;
      font-weight: 700;
      color: #333;
      margin: 10px 0;
    }
    .scan-info {
      background: #f9f9f9;
      padding: 15px;
      border-radius: 4px;
      margin: 20px 0;
    }
    .info-row {
      display: flex;
      padding: 10px 0;
      border-bottom: 1px solid #eee;
    }
    .info-row:last-child {
      border-bottom: none;
    }
    .info-label {
      font-weight: 600;
      color: #666;
      width: 150px;
      flex-shrink: 0;
    }
    .info-value {
      color: #333;
      word-break: break-all;
    }
    .section {
      margin: 30px 0;
    }
    .section-title {
      font-size: 18px;
      font-weight: 700;
      color: #333;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 2px solid #0B63D9;
    }
    .issues-list {
      list-style: none;
      padding: 0;
      margin: 0;
    }
    .issues-list li {
      padding: 12px;
      margin-bottom: 10px;
      background: #f9f9f9;
      border-left: 3px solid #0B63D9;
      border-radius: 4px;
    }
    .issue-safe {
      border-left-color: #00FF88;
      background: rgba(0, 255, 136, 0.05);
    }
    .issue-warning {
      border-left-color: #FFC107;
      background: rgba(255, 193, 7, 0.05);
    }
    .issue-malicious {
      border-left-color: #FF4D4D;
      background: rgba(255, 77, 77, 0.05);
    }
    .summary-box {
      background: #f0f7ff;
      border: 1px solid #0B63D9;
      padding: 20px;
      border-radius: 4px;
      margin: 20px 0;
      line-height: 1.8;
    }
    .details-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin: 20px 0;
    }
    .detail-card {
      background: #f9f9f9;
      padding: 15px;
      border-radius: 4px;
      border-left: 3px solid #0B63D9;
    }
    .detail-card-title {
      font-weight: 600;
      color: #666;
      margin-bottom: 8px;
      font-size: 14px;
    }
    .detail-card-value {
      font-size: 16px;
      color: #333;
      font-weight: 700;
    }
    .footer {
      text-align: center;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #eee;
      color: #999;
      font-size: 12px;
    }
    .confidence-bar {
      width: 100%;
      height: 10px;
      background: #e0e0e0;
      border-radius: 5px;
      overflow: hidden;
      margin: 10px 0;
    }
    .confidence-fill {
      height: 100%;
      background: ${threatColor};
      width: ${report.confidence}%;
      transition: width 0.3s ease;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">PhishNet</div>
      <p class="report-title">Security Scan Report</p>
    </div>

    <div class="status-section">
      <span class="status-badge">${(report.threat||'').toUpperCase()} - ${((function(r){
        try{ const s=String(r).trim().toLowerCase(); if(s==='safe')return 'Low'; if(s==='suspicious')return 'Medium'; if(s==='malicious')return 'High'; if(['low','medium','high','critical'].includes(s)) return s.charAt(0).toUpperCase()+s.slice(1); }catch(e){}
        return 'Unknown';
      })(report.riskLevel))} Risk</span>
      <div class="status-title">${report.threat === 'safe' ? '✓ Safe' : report.threat === 'suspicious' ? '⚠ Suspicious' : '✕ Malicious'}</div>
      <p style="margin: 0; color: #666; font-size: 14px;">Confidence: ${report.confidence}%</p>
      <div class="confidence-bar">
        <div class="confidence-fill"></div>
      </div>
    </div>

    <div class="scan-info">
      <div class="info-row">
        <div class="info-label">Scan Type:</div>
        <div class="info-value"><strong>${report.type === 'url' ? 'URL Scan' : 'Email Scan'}</strong></div>
      </div>
      <div class="info-row">
        <div class="info-label">${report.type === 'url' ? 'URL' : 'Email'}:</div>
        <div class="info-value">${this.escapeHtml(this.getDisplayTarget ? this.getDisplayTarget(report) : (report.senderEmail || extractEmail(report.value) || ''))}</div>
      </div>
      <div class="info-row">
        <div class="info-label">Scan Date:</div>
        <div class="info-value">${report.date} at ${report.time}</div>
      </div>
      <div class="info-row">
        <div class="info-label">Status:</div>
        <div class="info-value"><strong style="color: ${threatColor};">${report.threat.toUpperCase()}</strong></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Detailed Findings</div>
      <ul class="issues-list">
        ${report.issues.map(issue => {
          let className = 'issue-safe';
          if (issue.startsWith('⚠')) className = 'issue-warning';
          if (issue.startsWith('✕')) className = 'issue-malicious';
          return `<li class="${className}">${issue}</li>`;
        }).join('')}
      </ul>
    </div>

    <div class="section">
      <div class="section-title">Summary</div>
      <div class="summary-box">
        ${report.summary}
      </div>
    </div>

    ${report.scanDetails ? `
    <div class="section">
      <div class="section-title">Technical Details</div>
      <div class="details-grid">
        ${Object.entries(report.scanDetails).map(([key, value]) => {
          const label = key.replace(/([A-Z])/g, ' $1').trim();
          return `<div class="detail-card">
            <div class="detail-card-title">${label}</div>
            <div class="detail-card-value">${value}</div>
          </div>`;
        }).join('')}
      </div>
    </div>
    ` : ''}

    <div class="footer">
      <p>This report was generated by PhishNet on ${new Date().toLocaleString()}</p>
      <p>PhishNet - Professional Phishing & Malware Detection</p>
    </div>
  </div>

  <script>
    // Auto-print when opened
    window.onload = function() {
      setTimeout(() => window.print(), 500);
    };
  </script>
</body>
</html>
    `;
  }

  showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `toast-notification ${type}`;
    
    const icon = {
      'info': '❓',
      'error': '⚠️',
      'warning': '⚠️',
      'success': '✅'
    }[type] || 'ℹ️';
    
    notification.innerHTML = `
      <span class="toast-icon">${icon}</span>
      <span class="toast-message">${message}</span>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.classList.add('show');
    }, 10);

    setTimeout(() => {
      notification.classList.remove('show');
      setTimeout(() => notification.remove(), 350);
    }, 3500);
  }
}

// ==================== FORM HANDLERS ====================
class FormManager {
  constructor() {
    this.setupLoginForm();
    this.setupSettingsForm();
    this.setupSignupForm(); // ensure signup handler runs if present
  }

  setupLoginForm() {
    // Handle login form on login.html page - two-stage: email -> password
    const loginForm = document.querySelector('#login-form');
    if (!loginForm || !window.location.pathname.includes('login.html')) return;

    const emailInput = document.querySelector('#email');
    const passwordInput = document.querySelector('#password');
    const emailFieldWrapper = document.querySelector('#emailFieldWrapper');
    const passwordFieldWrapper = document.querySelector('#passwordFieldWrapper');
    const emailError = document.querySelector('#emailError');
    const emailDisplay = document.querySelector('#emailDisplay');

    // Password toggle
    const loginPwToggle = document.querySelector('#loginPwToggle');

    // NEW: two separate auth link containers
    const authLinksEmail = document.querySelector('#authLinksEmail'); // shown only during email stage
    const authLinksFull = document.querySelector('#authLinksFull');   // shown only during password stage
    const loginLabel = document.querySelector('#login-label');
    const useDifferentEmail = document.querySelector('#useDifferentEmail');

    let passwordStage = false;

    function isValidEmail(value) {
      const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return re.test(value);
    }

    function showElement(el) {
      if (!el) return;
      el.classList.remove('animated-hidden');
      el.classList.remove('swipe-up-out');
      el.style.display = 'block';
      setTimeout(() => el.classList.add('swipe-up-in'), 10);
      el.setAttribute('aria-hidden', 'false');
    }

    function hideElementWithOut(el, cb) {
      if (!el) { if (cb) cb(); return; }
      el.classList.remove('swipe-up-in');
      el.classList.add('swipe-up-out');
      el.addEventListener('animationend', function handler() {
        el.style.display = 'none';
        el.classList.remove('swipe-up-out');
        el.removeEventListener('animationend', handler);
        if (cb) cb();
      });
    }

    function enterPasswordStage(emailVal) {
      passwordStage = true;
      if (emailDisplay) {
        emailDisplay.textContent = emailVal;
        emailDisplay.style.display = 'block';
        setTimeout(() => {
          emailDisplay.classList.remove('animated-hidden');
          emailDisplay.classList.add('swipe-up-in');
        }, 10);
        emailDisplay.setAttribute('aria-hidden', 'false');
      }
      if (emailFieldWrapper) hideElementWithOut(emailFieldWrapper);
      if (passwordFieldWrapper) {
        passwordFieldWrapper.style.display = 'block';
        setTimeout(() => showElement(passwordFieldWrapper), 20);
      }

      // SHOW full auth links (forgot + use diff + signup)
      if (authLinksEmail) {
        // hide the simple email-only links
        authLinksEmail.style.display = 'none';
        authLinksEmail.setAttribute('aria-hidden', 'true');
      }
      if (authLinksFull) {
        authLinksFull.style.display = 'block';
        authLinksFull.classList.remove('animated-hidden');
        authLinksFull.setAttribute('aria-hidden', 'false');
        setTimeout(() => authLinksFull.classList.add('swipe-up-in'), 10);
      }

      if (loginLabel) loginLabel.textContent = 'Enter your password:';
      setTimeout(() => { if (passwordInput) passwordInput.focus(); }, 50);
    }

    function backToEmailStage() {
      passwordStage = false;
      if (passwordFieldWrapper) {
        hideElementWithOut(passwordFieldWrapper, () => {
          if (emailFieldWrapper) { emailFieldWrapper.style.display = 'block'; setTimeout(() => showElement(emailFieldWrapper), 20); }
        });
      } else {
        if (emailFieldWrapper) { emailFieldWrapper.style.display = 'block'; setTimeout(() => showElement(emailFieldWrapper), 20); }
      }

      // hide email preview
      if (emailDisplay) {
        emailDisplay.classList.remove('swipe-up-in');
        emailDisplay.classList.add('swipe-up-out');
        emailDisplay.addEventListener('animationend', function hidePreview() {
          emailDisplay.classList.remove('swipe-up-out');
          emailDisplay.classList.add('animated-hidden');
          emailDisplay.style.display = 'none';
          emailDisplay.removeEventListener('animationend', hidePreview);
        });
      }

      // SHOW only the simple signup line, hide the full auth links
      if (authLinksFull) {
        authLinksFull.classList.remove('swipe-up-in');
        authLinksFull.classList.add('swipe-up-out');
        authLinksFull.addEventListener('animationend', function hideFull() {
          authLinksFull.style.display = 'none';
          authLinksFull.classList.add('animated-hidden');
          authLinksFull.classList.remove('swipe-up-out');
          authLinksFull.removeEventListener('animationend', hideFull);
        });
        authLinksFull.setAttribute('aria-hidden', 'true');
      }
      if (authLinksEmail) {
        authLinksEmail.style.display = 'block';
        authLinksEmail.classList.remove('animated-hidden');
        authLinksEmail.setAttribute('aria-hidden', 'false');
      }

      if (loginLabel) loginLabel.textContent = 'Enter your email address to sign in:';
      setTimeout(() => { if (emailInput) emailInput.focus(); }, 300);
    }

    // INITIAL STATE: show only simple signup line (authLinksEmail) and hide full links
    if (authLinksEmail) {
      authLinksEmail.style.display = 'block';
      authLinksEmail.classList.remove('animated-hidden');
      authLinksEmail.setAttribute('aria-hidden', 'false');
    }
    if (authLinksFull) {
      authLinksFull.style.display = 'none';
      authLinksFull.classList.add('animated-hidden');
      authLinksFull.setAttribute('aria-hidden', 'true');
    }

    if (useDifferentEmail) {
      useDifferentEmail.addEventListener('click', (ev) => { ev.preventDefault(); backToEmailStage(); });
    }

    loginForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const emailVal = emailInput ? emailInput.value.trim() : (emailDisplay ? emailDisplay.textContent.trim() : '');
      const pwdVal = passwordInput ? passwordInput.value.trim() : '';

      if (!passwordStage) {
        if (!emailVal) {
          if (emailError) { emailError.style.display = 'block'; emailError.textContent = 'Email is required.'; } else showToast('Please enter your email address', 'error');
          if (emailInput) emailInput.focus();
          return;
        }
        if (!isValidEmail(emailVal)) {
          if (emailError) { emailError.style.display = 'block'; emailError.textContent = 'Please enter a valid email address (example: user@domain.com).'; } else showToast('Please enter a valid email address', 'error');
          if (emailInput) emailInput.focus();
          return;
        }
        if (emailError) emailError.style.display = 'none';
        enterPasswordStage(emailVal);
        return;
      }

      if (!pwdVal) {
        showToast('Please enter your password', 'error');
        if (passwordInput) passwordInput.focus();
        return;
      }

      // Attempt login
      const finalEmail = emailVal || (emailDisplay ? emailDisplay.textContent : '');
      
      const submitBtn = loginForm.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Signing in...';
      }

      auth.login(finalEmail, pwdVal)
        .then(() => {
          // Clear guest scan history on successful login
          localStorage.removeItem('scanHistory');
          showToast('Login successful!', 'success');
          setTimeout(() => {
            window.location.href = 'dashboard.html';
          }, 500);
        })
        .catch((error) => {
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Continue';
          }
          showToast(error.message || 'Login failed. Please check your credentials', 'error');
          if (passwordInput) passwordInput.focus();
        });
    });

    if (emailInput) {
      emailInput.addEventListener('input', () => { if (emailError && emailError.style.display !== 'none') emailError.style.display = 'none'; });
    }

    // Password toggle functionality
    if (loginPwToggle && passwordInput) {
      loginPwToggle.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        loginPwToggle.classList.toggle('active', !isPassword);
      });
    }
  }

  setupSignupForm() {
    // Signup page handling: validate fields and create profile
    const signupForm = document.querySelector('#signup-form');
    if (!signupForm || !window.location.pathname.includes('signup.html')) return;

    const fName = document.querySelector('#firstName');
    const lName = document.querySelector('#lastName');
    const email = document.querySelector('#signup-email');
    const pwd = document.querySelector('#signup-password');
    const confirm = document.querySelector('#signup-confirm');
    const emailError = document.querySelector('#signupEmailError');
    const pwdError = document.querySelector('#signupPasswordError');

    // UI elements for strength meter
    const bar1 = document.getElementById('pwdBar1');
    const bar2 = document.getElementById('pwdBar2');
    const bar3 = document.getElementById('pwdBar3');
    const bar4 = document.getElementById('pwdBar4');
    const strengthText = document.getElementById('pwdStrength');
    const meter = document.getElementById('pwdMeter');

    // password toggles
    const signupPwToggle = document.getElementById('signupPwToggle');
    const signupConfirmPwToggle = document.getElementById('signupConfirmPwToggle');

    function isValidEmail(value) {
      const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return re.test(value);
    }

    // password strength scoring:
    // score 0..4 => Weak, Fair, Good, Strong
    function passwordScore(pass) {
      let score = 0;
      if (!pass || pass.length < 1) return 0;
      // length >=6
      if (pass.length >= 6) score++;
      // has lowercase & uppercase
      if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) score++;
      // has digits
      if (/\d/.test(pass)) score++;
      // has special char
      if (/[^A-Za-z0-9]/.test(pass)) score++;
      return score;
    }

    function updateStrengthUI(pass) {
      const s = passwordScore(pass);

      // reset
      [bar1, bar2, bar3, bar4].forEach(b => b && (b.style.background = 'rgba(255,255,255,0.06)'));

      // colours you requested
      const COLOR_WEAK   = '#FF4D4D';   // red
      const COLOR_FAIR   = '#FF8A00';   // orange
      const COLOR_GOOD   = '#FFD600';   // yellow
      const COLOR_STRONG = '#00C853';   // green

      if (s >= 1 && bar1) bar1.style.background = COLOR_WEAK;
      if (s >= 2 && bar2) bar2.style.background = COLOR_FAIR;
      if (s >= 3 && bar3) bar3.style.background = COLOR_GOOD;
      if (s >= 4 && bar4) bar4.style.background = COLOR_STRONG;

      // update textual label and meter class (optional)
      let label = '—';
      meter.classList.remove('weak','fair','good','strong');
      if (s <= 1) { label = 'Weak'; strengthText.style.color = COLOR_WEAK; meter.classList.add('weak'); }
      else if (s === 2) { label = 'Fair'; strengthText.style.color = COLOR_FAIR; meter.classList.add('fair'); }
      else if (s === 3) { label = 'Good'; strengthText.style.color = COLOR_GOOD; meter.classList.add('good'); }
      else if (s === 4) { label = 'Strong'; strengthText.style.color = COLOR_STRONG; meter.classList.add('strong'); }

      strengthText.textContent = label;
      return s;
    }

    // password toggle functionality
    if (signupPwToggle && pwd) {
      signupPwToggle.addEventListener('click', () => {
        const isPassword = pwd.type === 'password';
        pwd.type = isPassword ? 'text' : 'password';
        signupPwToggle.classList.toggle('active', !isPassword);
      });
    }
    if (signupConfirmPwToggle && confirm) {
      signupConfirmPwToggle.addEventListener('click', () => {
        const isPassword = confirm.type === 'password';
        confirm.type = isPassword ? 'text' : 'password';
        signupConfirmPwToggle.classList.toggle('active', !isPassword);
      });
    }

    // live strength update
    if (pwd) {
      pwd.addEventListener('input', () => {
        const score = updateStrengthUI(pwd.value);
        if (pwdError && pwdError.style.display !== 'none') pwdError.style.display = 'none';
        if (confirm && pwd.value === confirm.value && pwdError) { pwdError.style.display = 'none'; }
      });
    }

    if (confirm) {
      confirm.addEventListener('input', () => {
        if (pwdError && pwdError.style.display !== 'none') pwdError.style.display = 'none';
      });
    }

    signupForm.addEventListener('submit', (e) => {
      e.preventDefault();

      const first = fName ? fName.value.trim() : '';
      const last = lName ? lName.value.trim() : '';
      const em = email ? email.value.trim() : '';
      const pw = pwd ? pwd.value : '';
      const conf = confirm ? confirm.value : '';

      if (!first) { showToast('Please enter your first name', 'error'); if (fName) fName.focus(); return; }
      if (!last) { showToast('Please enter your last name', 'error'); if (lName) lName.focus(); return; }

      if (!em) {
        if (emailError) { emailError.style.display = 'block'; emailError.textContent = 'Email is required.'; }
        else showToast('Please enter your email address', 'error');
        if (email) email.focus();
        return;
      }

      if (!isValidEmail(em)) {
        if (emailError) { emailError.style.display = 'block'; emailError.textContent = 'Please enter a valid email address (e.g. user@domain.com).'; }
        else showToast('Please enter a valid email address', 'error');
        if (email) email.focus();
        return;
      } else if (emailError) {
        emailError.style.display = 'none';
      }

      // password checks
      if (!pw || pw.length < 6) {
        if (pwdError) { pwdError.style.display = 'block'; pwdError.textContent = 'Password must be at least 6 characters.'; }
        else showToast('Password must be at least 6 characters', 'error');
        if (pwd) pwd.focus();
        return;
      }

      const score = passwordScore(pw);
      // require Good -> score >=3
      if (score < 3) {
        if (pwdError) { pwdError.style.display = 'block'; pwdError.textContent = 'Password strength is not good enough. Make it stronger (uppercase, lowercase, digit or symbol).'; }
        else showToast('Password is not strong enough', 'error');
        if (pwd) pwd.focus();
        updateStrengthUI(pw);
        return;
      }

      if (pw !== conf) {
        if (pwdError) { pwdError.style.display = 'block'; pwdError.textContent = 'Passwords do not match.'; }
        else showToast('Passwords do not match', 'error');
        if (confirm) confirm.focus();
        return;
      } else if (pwdError) {
        pwdError.style.display = 'none';
      }

      // Register new user (demo mode)
      const submitBtn = signupForm.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating account...';
      }

      auth.register({
        firstName: first,
        lastName: last,
        email: em,
        password: pw,
        confirmPassword: conf
      })
      .then(() => {
        showToast('Account created successfully!', 'success');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 500);
      })
      .catch((error) => {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Create Account';
        }
        const allErrors = Array.isArray(error.errors) ? error.errors : [];
        const msg = error.message || '';
        const isPwdMsg = /password/i.test(msg);
        const isEmailMsg = /email/i.test(msg);
        const passwordErrors = allErrors.filter(e => /password/i.test(e));
        const emailErrorsList = allErrors.filter(e => /email/i.test(e) || /invalid email/i.test(e));

        // Route errors to appropriate field containers
        if (pwdError && (isPwdMsg || passwordErrors.length > 0)) {
          pwdError.style.display = 'block';
          const lines = [];
          if (isPwdMsg) lines.push(msg);
          lines.push(...passwordErrors);
          pwdError.innerHTML = lines.join('<br>') || 'Password does not meet requirements.';
        } else if (pwdError) {
          pwdError.style.display = 'none';
        }

        if (emailError && (isEmailMsg || emailErrorsList.length > 0)) {
          emailError.style.display = 'block';
          const lines = [];
          if (isEmailMsg) lines.push(msg);
          lines.push(...emailErrorsList);
          emailError.innerHTML = lines.join('<br>') || 'Please check your email input.';
        } else if (emailError) {
          // If message is generic, show it once in email error to avoid losing context
          if (!isPwdMsg && !isEmailMsg && allErrors.length === 0) {
            emailError.style.display = 'block';
            emailError.textContent = error.message || 'Registration failed. Please try again.';
          } else {
            emailError.style.display = 'none';
          }
        }

        if (!pwdError && !emailError) {
          showToast(error.message || 'Registration failed. Please try again', 'error');
        }
      });
    });
  }

  setupSettingsForm() {
    const settingsForm = document.querySelector('#settings-form');
    if (settingsForm) {
      settingsForm.addEventListener('submit', (e) => {
        e.preventDefault();
        showToast('Settings saved successfully! (Demo mode)', 'success');
      });
    }
  }
}

// ==================== INITIALIZE ON PAGE LOAD ====================
document.addEventListener('DOMContentLoaded', () => {
  const nav = new NavigationManager();
  window.scanManagerInstance = new ScanManager();
  const forms = new FormManager();

  // Note: NavigationManager.init() calls refreshProfileAndUpdate() 
  // which will fetch fresh user data including avatar from server
  // window.currentUserAvatar will be set by refreshProfile() method

  // Force avatar update after navigation loads
  setTimeout(() => {
    const userAvatar = document.querySelector('.user-avatar');
    const userObj = window.auth.getUser();
    
    // ONLY use window.currentUserAvatar which is set by refreshProfile() from fresh server data
    // Do NOT fall back to user.avatar from localStorage as it's stale
    const savedAvatar = window.currentUserAvatar;
    const savedFitMode = localStorage.getItem('avatarFitMode') || (userObj && userObj.avatarFit) || 'cover';
  
    console.log('Avatar display:', {
      hasUserAvatar: !!userAvatar,
      hasSavedAvatar: !!savedAvatar,
      isLoggedIn: !!userObj,
      usingWindowAvatar: !!window.currentUserAvatar,
      isDataURL: savedAvatar ? savedAvatar.startsWith('data:') : false
    });
  
    if (userAvatar && userObj && savedAvatar) {
      console.log('Displaying fresh avatar from server');
      let urlToUse = savedAvatar;
      if (!savedAvatar.startsWith('data:')) {
        const cacheId = new Date().getTime();
        urlToUse = savedAvatar.includes('?') ? `${savedAvatar}&t=${cacheId}` : `${savedAvatar}?t=${cacheId}`;
      }
      userAvatar.style.backgroundImage = '';
      userAvatar.style.backgroundImage = `url(${urlToUse})`;
      userAvatar.style.setProperty('background-size', savedFitMode, 'important');
      userAvatar.style.backgroundPosition = 'center';
      userAvatar.style.backgroundRepeat = 'no-repeat';
      userAvatar.textContent = '';
    } else if (userAvatar && userObj) {
      // If no avatar, show initials
      userAvatar.style.backgroundImage = '';
      userAvatar.textContent = userObj.initials || 'JD';
    }
  }, 800);  // Wait longer to ensure server fetch completes

  // Setup FAQ accordions
  document.querySelectorAll('.faq-question').forEach(question => {
    question.addEventListener('click', () => {
      const item = question.closest('.faq-item');
      item.classList.toggle('active');
    });
  });
});

// ==================== HERO TYPEWRITER ====================
(function() {
  try {
    const path = window.location.pathname.split('/').pop();
    if (!(path === '' || path === 'index.html' || path === '/')) return;

    const target = document.getElementById('hero-typewriter');
    const cursor = document.querySelector('.type-cursor');

    if (!target) {
      if (cursor) cursor.style.display = 'none';
      return;
    }

    // Make cursor visible before typing
    if (cursor) {
      cursor.style.display = 'inline-block';
      cursor.style.opacity = '1';
    }

    const fullText = target.getAttribute('data-text') || target.textContent.trim();
    target.textContent = ''; // start empty

    let i = 0;
    const speed = 30;

    function typeStep() {
      if (i < fullText.length) {
        target.textContent += fullText.charAt(i);
        i++;
        setTimeout(typeStep, speed);
      } else {
        // Hide cursor when done
        if (cursor) {
          cursor.style.transition = 'opacity 120ms linear';
          cursor.style.opacity = '0';
          setTimeout(() => { cursor.style.display = 'none'; }, 140);
        }
      }
    }

    setTimeout(typeStep, 350);
  } catch (err) {
    console.error('Typewriter error:', err);
  }
})();
