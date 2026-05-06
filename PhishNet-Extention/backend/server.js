require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const connectDB = require('./config/database');
const { errorHandler } = require('./middleware/errorHandler');

// Initialize Express app
const app = express();

// Connect to MongoDB (don't wait here, let it connect in background)
connectDB().catch(err => {
  console.error('Failed to connect to database:', err.message);
  process.exit(1);
});

// Middleware
app.use(helmet()); // Security headers
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    const allowedOrigins = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
    // Allow any localhost/127.0.0.1 port in development
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
      return callback(null, true);
    }
    // Allow chrome extensions
    if (origin.startsWith('chrome-extension://')) {
      return callback(null, true);
    }
    // Allow file:// (origin is 'null' string)
    if (origin === 'null') {
      return callback(null, true);
    }
    // Check explicit allowed list
    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Request logging middleware (simplified)
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url}`);
  next();
});

// API Routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const urlRoutes = require('./routes/scan');
const analyticsRoutes = require('./routes/analytics');
const emailScanRoutes = require('./routes/emailScan');
const chatbotRoutes = require('./routes/chatbot');
const breachRoutes = require('./routes/breach');

app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/users', userRoutes);
app.use('/api/v1/urls', urlRoutes);
app.use('/api/v1/analytics', analyticsRoutes);
app.use('/api/v1/emails', emailScanRoutes);
app.use('/api/chatbot', chatbotRoutes);
app.use('/api/breach', breachRoutes);

// Dashboard Security Tips route
app.get('/api/dashboard/security-tips', (req, res) => {
  res.json({
    success: true,
    data: [
      {
        id: 1,
        title: 'Verify Sender Identity',
        description: 'Always check the sender\'s email address carefully. Phishers often use addresses that look similar to legitimate ones.',
        icon: 'shield',
        category: 'email'
      },
      {
        id: 2,
        title: 'Check URLs Before Clicking',
        description: 'Hover over links to see the actual URL before clicking. Look for misspellings or unusual domains.',
        icon: 'link',
        category: 'url'
      },
      {
        id: 3,
        title: 'Enable Two-Factor Authentication',
        description: 'Add an extra layer of security to your accounts with 2FA. Even if passwords are compromised, 2FA protects you.',
        icon: 'lock',
        category: 'account'
      },
      {
        id: 4,
        title: 'Keep Software Updated',
        description: 'Regularly update your browser, operating system, and security software to patch known vulnerabilities.',
        icon: 'refresh',
        category: 'general'
      },
      {
        id: 5,
        title: 'Be Wary of Urgency',
        description: 'Phishing emails often create a false sense of urgency. Take time to verify before acting on urgent requests.',
        icon: 'alert',
        category: 'email'
      },
      {
        id: 6,
        title: 'Use PhishNet Extension',
        description: 'Install the PhishNet Chrome extension for real-time protection while browsing the web.',
        icon: 'extension',
        category: 'tool'
      }
    ]
  });
});

// Blog Posts route
app.get('/api/blog/posts', (req, res) => {
  res.json({
    success: true,
    data: [
      {
        id: 1,
        title: 'The Rise of AI-Powered Phishing Attacks in 2026',
        excerpt: 'How attackers are using artificial intelligence to craft more convincing phishing emails and how to protect yourself.',
        author: 'PhishNet Security Team',
        date: '2026-04-28',
        category: 'Threat Intelligence',
        readTime: '5 min',
        image: null
      },
      {
        id: 2,
        title: 'Understanding URL Typosquatting: A Deep Dive',
        excerpt: 'Learn how cybercriminals register domains that look like popular websites to steal your credentials.',
        author: 'PhishNet Security Team',
        date: '2026-04-20',
        category: 'Education',
        readTime: '7 min',
        image: null
      },
      {
        id: 3,
        title: 'How PhishNet Uses Machine Learning to Detect Phishing',
        excerpt: 'Behind the scenes: our DistilBERT model and 9-source threat intelligence pipeline explained.',
        author: 'PhishNet Engineering',
        date: '2026-04-15',
        category: 'Technology',
        readTime: '8 min',
        image: null
      },
      {
        id: 4,
        title: '5 Signs an Email Is a Phishing Attempt',
        excerpt: 'Quick checklist to identify phishing emails before they can do damage to your accounts.',
        author: 'PhishNet Security Team',
        date: '2026-04-10',
        category: 'Tips & Tricks',
        readTime: '4 min',
        image: null
      },
      {
        id: 5,
        title: 'Business Email Compromise: The Billion Dollar Threat',
        excerpt: 'BEC attacks cost businesses billions annually. Learn how to recognize and prevent them.',
        author: 'PhishNet Security Team',
        date: '2026-04-05',
        category: 'Threat Intelligence',
        readTime: '6 min',
        image: null
      },
      {
        id: 6,
        title: 'Setting Up PhishNet Chrome Extension: Complete Guide',
        excerpt: 'Step-by-step guide to installing and configuring PhishNet browser extension for maximum protection.',
        author: 'PhishNet Support',
        date: '2026-03-30',
        category: 'Guides',
        readTime: '3 min',
        image: null
      }
    ]
  });
});

app.get('/api/blog/posts/:id', (req, res) => {
  res.json({
    success: true,
    data: {
      id: req.params.id,
      title: 'Blog Post',
      content: 'Full blog content would be loaded from database.',
      author: 'PhishNet Security Team',
      date: '2026-04-28'
    }
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'PhishNet Extension Backend is running',
    timestamp: new Date().toISOString()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'PhishNet Extension Backend API',
    version: 'v1',
    endpoints: {
      auth: '/api/v1/auth',
      users: '/api/v1/users',
      urls: '/api/v1/urls',
      emails: '/api/v1/emails',
      analytics: '/api/v1/analytics',
      health: '/health'
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

// Global error handler
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 PhishNet Extension Backend server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Rejection:', err.message);
  console.error('Stack:', err.stack);
  // Don't exit, just log it
});
