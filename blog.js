/**
 * PhishNet Blog System - Frontend JavaScript
 * Handles RSS feed fetching, categorization, filtering, and display
 * With intelligent caching and background preloading
 */

class BlogSystem {
  constructor() {
    const baseUrl = (window.API_CONFIG && window.API_CONFIG.api.baseURL) || 'http://localhost:3000';
    this.apiBase = `${baseUrl}/api/blogs`;
    this.currentCategory = 'all';
    this.allBlogs = [];
    this.filteredBlogs = [];
    this.categoryCounts = {};
    this.autoRefreshInterval = 5 * 60 * 1000; // 5 minutes
    this.categoryCache = {}; // In-memory cache for category data
    this.cacheExpiry = 30 * 60 * 1000; // 30 minutes cache validity
    this.lastCacheTime = {};
    this.preloadQueue = [];
    this.isPreloading = false;
    
    // Cache keys
    this.CACHE_KEYS = {
      blogs: 'phishnet_blogs_cache',
      categories: 'phishnet_categories_cache',
      cacheTime: 'phishnet_cache_time'
    };
    
    this.init();
  }

  /**
   * Initialize the blog system
   */
  async init() {
    console.log('🔄 Initializing PhishNet Blog System...');
    
    // Try to load from cache first for instant display
    const cachedBlogs = this.getFromCache(this.CACHE_KEYS.blogs);
    const cachedCounts = this.getFromCache(this.CACHE_KEYS.categories);
    
    if (cachedBlogs && cachedCounts) {
      console.log('📦 Loading from cache (instant)');
      this.allBlogs = cachedBlogs;
      this.filteredBlogs = [...this.allBlogs];
      this.categoryCounts = cachedCounts;
      this.renderBlogs();
      this.updateCategoryDisplay();
      this.updateActiveCategory('all');
      console.log('✓ Blogs loaded from cache');
      
      // Refresh cache in background
      this.refreshCacheInBackground();
    } else {
      // Fresh load - fetch from server
      console.log('🌐 Fetching fresh data from server');
      await Promise.all([
        this.loadBlogs(),
        this.loadCategoryCounts()
      ]);
      this.updateActiveCategory('all');
    }

    // Setup event listeners
    this.setupEventListeners();

    // Setup auto-refresh
    this.setupAutoRefresh();

    // Start background preloading of all categories
    this.startBackgroundPreloading();

    console.log('✓ Blog system initialized');
  }

  /**
   * Cache management - Save to cache
   */
  saveToCache(key, data) {
    try {
      const cacheData = {
        data: data,
        timestamp: Date.now()
      };
      localStorage.setItem(key, JSON.stringify(cacheData));
      this.lastCacheTime[key] = Date.now();
    } catch (error) {
      console.warn('⚠️ Cache save failed:', error);
    }
  }

  /**
   * Cache management - Get from cache
   */
  getFromCache(key) {
    try {
      const cached = localStorage.getItem(key);
      if (!cached) return null;
      
      const { data, timestamp } = JSON.parse(cached);
      
      // Check if cache is still valid
      if (Date.now() - timestamp > this.cacheExpiry) {
        localStorage.removeItem(key);
        return null;
      }
      
      return data;
    } catch (error) {
      console.warn('⚠️ Cache retrieval failed:', error);
      return null;
    }
  }

  /**
   * Refresh cache in background without blocking UI
   */
  async refreshCacheInBackground() {
    console.log('🔄 Refreshing cache in background...');
    setTimeout(async () => {
      try {
        await Promise.all([
          this.loadBlogs(),
          this.loadCategoryCounts()
        ]);
        console.log('✓ Cache refresh complete');
      } catch (error) {
        console.warn('⚠️ Background cache refresh failed:', error);
      }
    }, 1000);
  }

  /**
   * Start background preloading of all categories
   */
  async startBackgroundPreloading() {
    if (this.isPreloading) return;
    this.isPreloading = true;
    
    const categories = [
      'Security Tips',
      'Threat Analysis',
      'Case Studies',
      'Email Security',
      'Enterprise',
      'Phishing'
    ];

    console.log('🚀 Starting background preload of all categories...');
    
    // Use requestIdleCallback for better performance, fallback to setTimeout
    const schedulePreload = (callback) => {
      if ('requestIdleCallback' in window) {
        requestIdleCallback(callback, { timeout: 5000 });
      } else {
        setTimeout(callback, 2000);
      }
    };

    // Preload each category in background
    schedulePreload(async () => {
      for (let category of categories) {
        if (!this.categoryCache[category]) {
          try {
            const response = await fetch(`${this.apiBase}/category/${encodeURIComponent(category)}?limit=50`);
            if (response.ok) {
              const result = await response.json();
              if (result.success) {
                this.categoryCache[category] = {
                  data: result.data,
                  timestamp: Date.now()
                };
                console.log(`✓ Preloaded ${category}`);
              }
            }
          } catch (error) {
            console.warn(`⚠️ Failed to preload ${category}:`, error);
          }
          
          // Small delay between requests to avoid overwhelming server
          await new Promise(resolve => setTimeout(resolve, 300));
        }
      }
      console.log('✓ Background preloading complete');
      this.isPreloading = false;
    });
  }

  /**
   * Show loading popup
   */
  showLoading() {
    const popup = document.getElementById('blog-loading-popup');
    if (popup) {
      popup.classList.add('show');
    }
  }

  /**
   * Hide loading popup (with optional delay)
   */
  hideLoading(delay = 0) {
    const popup = document.getElementById('blog-loading-popup');
    if (popup) {
      if (delay > 0) {
        setTimeout(() => popup.classList.remove('show'), delay);
      } else {
        popup.classList.remove('show');
      }
    }
  }

  /**
   * Load all blogs from backend (with caching)
   */
  async loadBlogs() {
    try {
      const response = await fetch(`${this.apiBase}?limit=50`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const result = await response.json();
      if (result.success) {
        this.allBlogs = result.data;
        this.filteredBlogs = [...this.allBlogs];
        
        // Cache the blogs
        this.saveToCache(this.CACHE_KEYS.blogs, this.allBlogs);
        
        this.renderBlogs();
        console.log(`✓ Loaded ${result.count} blogs`);
      }
    } catch (error) {
      console.error('✗ Error loading blogs:', error);
      this.showFallbackContent();
    }
  }

  /**
   * Load category counts (with caching)
   */
  async loadCategoryCounts() {
    try {
      const response = await fetch(`${this.apiBase}/counts/categories`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const result = await response.json();
      if (result.success) {
        this.categoryCounts = result.data;
        
        // Cache the category counts
        this.saveToCache(this.CACHE_KEYS.categories, this.categoryCounts);
        
        this.updateCategoryDisplay();
        console.log('✓ Category counts updated');
      }
    } catch (error) {
      console.error('✗ Error loading category counts:', error);
    }
  }

  /**
   * Filter blogs by category (with instant display from cache)
   */
  async filterByCategory(category) {
    this.currentCategory = category;
    
    try {
      if (category === 'all') {
        // Instant display - all blogs already loaded
        this.filteredBlogs = [...this.allBlogs];
        this.renderBlogs();
        console.log(`✓ Displaying all blogs`);
      } else {
        // Check cache first for instant display
        let cachedCategory = this.categoryCache[category];
        
        if (cachedCategory && (Date.now() - cachedCategory.timestamp < this.cacheExpiry)) {
          // Use cached data - show instantly, no loading popup needed
          this.filteredBlogs = cachedCategory.data;
          this.renderBlogs();
          console.log(`✓ Displayed ${this.filteredBlogs.length} blogs for category: ${category} (from cache)`);
          
          // Refresh cache in background if older than 5 minutes
          if (Date.now() - cachedCategory.timestamp > 5 * 60 * 1000) {
            this.refreshCategoryInBackground(category);
          }
        } else {
          // Cache miss - show loading popup and fetch
          this.showLoading();
          
          const response = await fetch(`${this.apiBase}/category/${encodeURIComponent(category)}?limit=50`);
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          
          const result = await response.json();
          if (result.success) {
            this.filteredBlogs = result.data;
            
            // Cache the result
            this.categoryCache[category] = {
              data: this.filteredBlogs,
              timestamp: Date.now()
            };
            
            this.renderBlogs();
            console.log(`✓ Filtered ${result.count} blogs for category: ${category}`);
          }
          
          // Hide loading popup quickly
          this.hideLoading(150);
        }
      }
    } catch (error) {
      console.error('✗ Error filtering blogs:', error);
      this.filteredBlogs = [];
      this.renderBlogs();
      this.hideLoading();
    }
  }

  /**
   * Refresh a specific category in background
   */
  async refreshCategoryInBackground(category) {
    console.log(`🔄 Refreshing category cache: ${category}`);
    try {
      const response = await fetch(`${this.apiBase}/category/${encodeURIComponent(category)}?limit=50`);
      if (response.ok) {
        const result = await response.json();
        if (result.success) {
          this.categoryCache[category] = {
            data: result.data,
            timestamp: Date.now()
          };
          console.log(`✓ Refreshed cache for ${category}`);
        }
      }
    } catch (error) {
      console.warn(`⚠️ Failed to refresh cache for ${category}:`, error);
    }
  }

  /**
   * Search blogs
   */
  async searchBlogs(query) {
    if (!query.trim()) {
      this.filteredBlogs = [...this.allBlogs];
      this.renderBlogs();
      return;
    }

    try {
      const response = await fetch(`${this.apiBase}/search?q=${encodeURIComponent(query)}&limit=50`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const result = await response.json();
      if (result.success) {
        this.filteredBlogs = result.data;
        console.log(`✓ Found ${result.count} blogs matching "${query}"`);
      }
    } catch (error) {
      console.error('✗ Error searching blogs:', error);
      this.filteredBlogs = [];
    }
    
    this.renderBlogs();
  }

  /**
   * Render blog cards in main content area
   */
  renderBlogs() {
    const blogContainer = document.getElementById('blog-posts-container');
    if (!blogContainer) return;

    // Clear existing content
    blogContainer.innerHTML = '';

    if (this.filteredBlogs.length === 0) {
      blogContainer.innerHTML = '<div class="card" style="text-align: center; padding: 2rem;"><p style="color: var(--text-muted);">No blogs found. Check back soon for more content!</p></div>';
      return;
    }

    // Render featured blog (first one)
    const featuredBlog = this.filteredBlogs[0];
    const featuredCard = this.createBlogCard(featuredBlog, true);
    blogContainer.appendChild(featuredCard);

    // Render remaining blogs (6-7 total blogs)
    const additionalCount = Math.min(6, this.filteredBlogs.length - 1);
    for (let i = 1; i <= additionalCount; i++) {
      const card = this.createBlogCard(this.filteredBlogs[i], false);
      blogContainer.appendChild(card);
    }
  }

  /**
   * Create a blog card element
   */
  createBlogCard(blog, isFeatured = false) {
    const card = document.createElement('div');
    card.className = 'card';
    card.style.marginBottom = '2rem';

    // Build card HTML without images
    let cardHTML = '';
    
    if (isFeatured) {
      cardHTML = `
        <span class="badge badge-malicious" style="margin-bottom: 1rem;">Featured</span>
      `;
    }

    cardHTML += `
      <h${isFeatured ? '2' : '3'} style="margin-bottom: 0.75rem;">
        <a href="${blog.link}" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: none;" title="Open ${blog.sourceUrl}">
          ${this.escapeHtml(blog.title)}
        </a>
      </h${isFeatured ? '2' : '3'}>
      
      <div class="blog-meta">
        <div class="blog-meta-item">
          <svg class="blog-meta-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
            <line x1="16" y1="2" x2="16" y2="6"/>
            <line x1="8" y1="2" x2="8" y2="6"/>
            <line x1="3" y1="10" x2="21" y2="10"/>
          </svg>
          <span>${blog.pubDateFormatted}</span>
        </div>
        <div class="blog-meta-item">
          <svg class="blog-meta-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
          </svg>
          <span>${this.escapeHtml(blog.author)}</span>
        </div>
        <div class="blog-meta-item">
          <svg class="blog-meta-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
          </svg>
          <span>${blog.readTime}</span>
        </div>
      </div>

      <p style="color: var(--text-muted); line-height: 1.7; margin-top: 1rem;">
        ${this.escapeHtml(blog.summary)}
      </p>

      <div class="blog-tags" style="margin-top: 1rem;">
        ${blog.tags.map(tag => `<span class="tag">${this.escapeHtml(tag)}</span>`).join('')}
      </div>

      <a href="${blog.link}" target="_blank" rel="noopener noreferrer" class="btn btn-primary btn-sm" style="margin-top: 1rem; display: inline-block;">Read More →</a>
    `;

    card.innerHTML = cardHTML;
    return card;
  }

  /**
   * Update category display with counts
   */
  updateCategoryDisplay() {
    const categoryList = document.getElementById('category-list');
    if (!categoryList) return;

    categoryList.innerHTML = '';

    const categories = [
      'Security Tips',
      'Threat Analysis',
      'Case Studies',
      'Email Security',
      'Enterprise',
      'Phishing'
    ];

    // Create "All Categories" option
    const allLi = document.createElement('li');
    allLi.style.marginBottom = '0.75rem';

    const allLink = document.createElement('a');
    allLink.href = '#';
    allLink.dataset.category = 'all';
    
    const allCategoryName = document.createElement('span');
    allCategoryName.textContent = 'All Categories';
    
    const allBadge = document.createElement('span');
    allBadge.className = 'badge badge-safe';
    allBadge.textContent = Object.values(this.categoryCounts).reduce((sum, count) => sum + count, 0);

    allLink.appendChild(allCategoryName);
    allLink.appendChild(allBadge);

    allLink.addEventListener('click', (e) => {
      e.preventDefault();
      this.filterByCategory('all');
      this.updateActiveCategory('all');
    });

    allLi.appendChild(allLink);
    categoryList.appendChild(allLi);

    // Create separator
    const separator = document.createElement('li');
    separator.style.height = '1px';
    separator.style.background = 'var(--border-color)';
    separator.style.margin = '0.75rem 0';
    categoryList.appendChild(separator);

    categories.forEach(category => {
      const count = this.categoryCounts[category] || 0;
      const li = document.createElement('li');
      li.style.marginBottom = '0.75rem';

      const link = document.createElement('a');
      link.href = '#';
      link.dataset.category = category;
      
      const categoryName = document.createElement('span');
      categoryName.textContent = category;
      
      const badge = document.createElement('span');
      badge.className = 'badge badge-safe';
      badge.textContent = count;

      link.appendChild(categoryName);
      link.appendChild(badge);

      link.addEventListener('click', (e) => {
        e.preventDefault();
        this.filterByCategory(category);
        this.updateActiveCategory(category);
      });

      li.appendChild(link);
      categoryList.appendChild(li);
    });
  }

  /**
   * Update active category visual indicator
   */
  updateActiveCategory(category) {
    const categoryLinks = document.querySelectorAll('#category-list a');
    categoryLinks.forEach(link => {
      // Remove active class from all links
      link.classList.remove('active');
      
      // Add active class to the selected category
      if (link.dataset.category === category) {
        link.classList.add('active');
      }
    });
  }

  /**
   * Render recent posts in sidebar
   */
  renderRecentPosts() {
    const recentPostsList = document.getElementById('recent-posts-list');
    if (!recentPostsList) return;

    recentPostsList.innerHTML = '';

    const recentPosts = this.allBlogs.slice(0, 4);
    
    recentPosts.forEach((post, index) => {
      const li = document.createElement('li');
      li.style.padding = '0.75rem';
      li.style.marginBottom = '0.5rem';
      li.style.borderRadius = 'var(--radius-sm)';
      li.style.transition = 'all var(--transition-speed)';
      li.style.cursor = 'pointer';
      if (index !== recentPosts.length - 1) {
        li.style.borderBottom = '1px solid var(--border-color)';
      }

      li.innerHTML = `
        <a href="${post.link}" target="_blank" rel="noopener noreferrer" class="recent-post-link" style="color: white; font-size: 0.875rem; line-height: 1.4; text-decoration: none; display: block;" title="Open ${post.sourceUrl}">
          ${this.escapeHtml(post.title)}
        </a>
        <p style="font-size: 0.75rem; color: var(--text-muted); margin: 0.5rem 0 0;">
          ${post.pubDateFormatted}
        </p>
      `;

      // Add hover effect event listeners
      li.addEventListener('mouseenter', () => {
        li.style.background = 'rgba(255, 255, 255, 0.05)';
        li.style.transform = 'translateX(4px)';
      });
      
      li.addEventListener('mouseleave', () => {
        li.style.background = 'transparent';
        li.style.transform = 'translateX(0)';
      });

      recentPostsList.appendChild(li);
    });
  }

  /**
   * Setup event listeners
   */
  setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('blog-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchBlogs(e.target.value);
      });
    }

    // Load recent posts
    this.renderRecentPosts();

    // Add event listener for category filtering (if needed for additional setup)
    const categoryLinks = document.querySelectorAll('#category-list a');
    categoryLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
      });
    });
  }

  /**
   * Setup auto-refresh
   */
  setupAutoRefresh() {
    setInterval(async () => {
      console.log('🔄 Auto-refreshing blogs...');
      await this.loadBlogs();
      await this.loadCategoryCounts();
      console.log('✓ Blogs auto-refreshed');
    }, this.autoRefreshInterval);
  }

  /**
   * Escape HTML special characters
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Show fallback content if API fails
   */
  showFallbackContent() {
    const blogContainer = document.getElementById('blog-posts-container');
    if (blogContainer) {
      blogContainer.innerHTML = '<div class="card" style="padding: 2rem; text-align: center;"><p style="color: var(--text-muted);">Unable to load blogs at this time. Please refresh the page.</p></div>';
    }
  }
}

// Initialize blog system when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.blogSystem = new BlogSystem();
  });
} else {
  window.blogSystem = new BlogSystem();
}
