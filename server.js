/**
 * PhishNet Backend Server
 * Express.js server with PhishingDistilBERT integration
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import phishingDetector from './models/phishing-detector.js';
import scanRoutes from './routes/scan.js';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ==================== MIDDLEWARE ====================

// Security Headers - allow cross-origin requests to auth backend
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https:"],
      styleSrc: ["'self'", "'unsafe-inline'", "https:"],
      fontSrc: ["'self'", "https:", "data:"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'", "http://localhost:*", "http://127.0.0.1:*", "https:"],
    }
  }
}));

// CORS Configuration - Allow all origins for browser extension compatibility
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    // Also allow chrome-extension:// and moz-extension:// for browser extensions
    if (!origin || 
        origin.startsWith('chrome-extension://') || 
        origin.startsWith('moz-extension://') ||
        origin.startsWith('http://localhost') ||
        origin.startsWith('http://127.0.0.1')) {
      callback(null, true);
    } else {
      // Check against explicit whitelist
      const whitelist = (process.env.CORS_ORIGIN || 'http://localhost:5000').split(',');
      if (whitelist.includes(origin) || whitelist.includes('*')) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Rate limiting — only applied to API routes, not static files
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', limiter);

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ==================== ROUTES ====================

// Serve static website files (signup.html, dashboard.html, etc.)
app.use(express.static(__dirname, {
  extensions: ['html'],
  index: 'index.html'
}));

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    modelLoaded: phishingDetector.isLoaded,
    environment: NODE_ENV
  });
});

// API routes
app.use('/api/scan', scanRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'PhishNet Backend API',
    version: '1.0.0',
    description: 'Advanced Phishing Detection System with DistilBERT',
    status: phishingDetector.isLoaded ? 'ready' : 'initializing',
    endpoints: {
      health: 'GET /health',
      scanUrl: 'POST /api/scan/scan-url',
      scanEmail: 'POST /api/scan/email',
      scanDomain: 'POST /api/scan/domain',
      batchScan: 'POST /api/scan/batch',
      modelInfo: 'GET /api/scan/model-info'
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    path: req.path
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error',
    ...(NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ==================== SERVER INITIALIZATION ====================

async function startServer() {
  try {
    console.log('\n🚀 Starting PhishNet Backend Server...');
    console.log(`📍 Environment: ${NODE_ENV}`);
    console.log(`🔌 Port: ${PORT}\n`);

    // Initialize the phishing detection model
    const modelPath = process.env.LOCAL_MODEL_PATH;
    await phishingDetector.initialize(modelPath);

    // Start listening
    app.listen(PORT, () => {
      console.log(`\n✅ PhishNet Server is running on http://localhost:${PORT}`);
      console.log(`📚 API Documentation: http://localhost:${PORT}`);
      console.log(`❤️  Health Check: http://localhost:${PORT}/health\n`);
    });
  } catch (error) {
    console.error('\n❌ Failed to start server:', error.message);
    console.error('Please ensure:');
    console.error('  1. All dependencies are installed: npm install');
    console.error('  2. .env file is configured correctly');
    console.error('  3. Internet connection available for model download\n');
    process.exit(1);
  }
}

// Start server
startServer();

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('\n⛔ SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\n⛔ SIGINT signal received: closing HTTP server');
  process.exit(0);
});

export default app;
