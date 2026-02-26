const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { verifyAccessToken } = require('../utils/jwt');
const URLCheckHistory = require('../models/URLCheckHistory');
const {
  validateUrl,
  validateUrlStatus,
  handleValidationErrors
} = require('../utils/validators');
const {
  checkUrl,
  getUrlHistory,
  getUnsafeUrls,
  checkUrlHistory,
  updateUrlStatus,
  deleteUrlRecord
} = require('../controllers/urlController');

// PUBLIC ENDPOINT for extension background scanner (no auth required)
// If an auth token is present, the scan result is also persisted to MongoDB
// Checks: Google Safe Browsing, VirusTotal, URLhaus, AbuseIPDB, Shodan (all in parallel)
// @route   POST /api/v1/urls/scan
// @desc    Multi-source threat intelligence URL scan
// @access  Public
router.post('/scan', async (req, res, next) => {
  try {
    const { url } = req.body || {};

    if (!url || typeof url !== 'string') {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Gather all available API keys
    const apiKeys = {
      googleSafeBrowsing: process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.GSB_API_KEY || null,
      virusTotal: process.env.VIRUSTOTAL_API_KEY || null,
      abuseIPDB: process.env.ABUSEIPDB_API_KEY || null,
      shodan: process.env.SHODAN_API_KEY || null,
      urlhaus: process.env.URLHAUS_API_KEY || null,
      huggingFace: process.env.HUGGINGFACE_API_TOKEN || null,
      // Shodan InternetDB, URLhaus (sans auth), URL Heuristics, and HF free tier work without keys
    };

    // Check that at least one API is configured
    const hasAnyKey = apiKeys.googleSafeBrowsing || apiKeys.virusTotal || apiKeys.abuseIPDB || apiKeys.shodan;
    if (!hasAnyKey) {
      return res.status(500).json({
        success: false,
        message: 'No threat intelligence APIs configured'
      });
    }

    // Run multi-source scan (all APIs in parallel)
    const { scanUrlMultiSource } = require('../utils/threatIntel');
    const result = await scanUrlMultiSource(url, apiKeys);
    const { status, threats, sources, sourcesChecked, errors, score, risk_score, infra_risk, lexical_risk, combined_risk, contributions, deescalated, explanation, earlyExit, temporal_risk, temporal_trust, domain_age_days, trusted_domain, trusted_reduction } = result;

    // Save scan to MongoDB — use auth token if present, otherwise fall back to most recently active user
    try {
      let userId = null;

      // Try 1: Extract user ID from auth token
      const token = req.headers.authorization?.split(' ')[1];
      if (token) {
        try {
          const decoded = verifyAccessToken(token);
          if (decoded && decoded.id) {
            userId = decoded.id;
            console.log(`[Scan] Auth token valid for user ${userId}`);
          }
        } catch (tokenErr) {
          console.log(`[Scan] Auth token invalid/expired: ${tokenErr.message}`);
        }
      }

      // No valid token — scan result will not be saved to any user's history
      if (!userId) {
        console.log(`[Scan] No auth token — scan for ${url} will NOT be saved to any user history`);
      }

      // Save to DB if we identified a user
      if (userId) {
          let domain = '';
          try { domain = new URL(url).hostname; } catch (e) { domain = url; }
          
          const dbStatus = (status === 'SAFE') ? 'safe' : 'unsafe';
          const reasonStrings = threats.map(t => `${t.source}: ${t.type}`);
          const confidence = (status === 'SAFE') ? Math.max(0, 100 - (score || 0)) : Math.min(100, Math.max(score || 0, 50));
          const threatLevel = (status === 'SAFE') ? 'safe' : (score >= 70 ? 'high' : (score >= 40 ? 'medium' : 'low'));
          const indicatorStrings = threats.map(t => t.type || t.threatType || 'THREAT');
          const issueStrings = (status === 'SAFE')
            ? ['No security threats detected']
            : threats.map(t => `${(t.type || 'THREAT').replace(/_/g, ' ')}: ${t.detail || t.source || ''}`);
          await URLCheckHistory.create({
            userId: userId,
            url: url.toLowerCase(),
            domain,
            status: dbStatus,
            reasons: reasonStrings,
            userAction: 'visited',
            wasWarned: status !== 'SAFE',
            threatScore: score || 0,
            confidence: confidence,
            scanType: 'url',
            threatLevel: threatLevel,
            threatType: threats.length > 0 ? (threats[0].type || 'unknown') : null,
            isSafe: status === 'SAFE',
            summary: explanation || null,
            indicators: indicatorStrings,
            issues: issueStrings
          });
          console.log(`[Scan] Saved to DB for user ${userId}: ${url} -> ${dbStatus} (score: ${score})`);
          req._scanSavedToDb = true;
      }
    } catch (saveErr) {
      // Don't fail the scan if DB save fails
      console.warn('[Scan] Failed to save scan to DB (non-fatal):', saveErr.message);
    }
    // Compute confidence percentage
    const confidence = (status === 'SAFE') ? Math.max(0, 100 - (score || 0)) : Math.min(100, Math.max(score || 0, 50));
    
    res.status(200).json({
      success: true,
      savedToDb: !!req._scanSavedToDb,
      status,
      score,
      risk_score: risk_score || 0,
      infra_risk: infra_risk || 0,
      lexical_risk: lexical_risk || 0,
      combined_risk: combined_risk || 0,
      confidence,
      threats: threats || [],
      sources: sourcesChecked || [],
      sourceDetails: sources || [],
      contributions: contributions || {},
      deescalated: deescalated || false,
      earlyExit: earlyExit || false,
      temporal_risk: temporal_risk || 0,
      temporal_trust: temporal_trust || 0,
      domain_age_days: domain_age_days ?? null,
      trusted_domain: trusted_domain || false,
      trusted_reduction: trusted_reduction || false,
      explanation: explanation || '',
      errors: errors || [],
      meta: { url, timestamp: new Date().toISOString() }
    });
  } catch (error) {
    console.error('Scan URL error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Scan failed'
    });
  }
});

// @route   POST /api/v1/urls/check
// @desc    Check and record URL
// @access  Private
router.post('/check', authenticate, validateUrl, handleValidationErrors, checkUrl);

// @route   GET /api/v1/urls/history
// @desc    Get user's URL check history
// @access  Private
router.get('/history', authenticate, getUrlHistory);

// @route   GET /api/v1/urls/unsafe
// @desc    Get user's unsafe URLs
// @access  Private
router.get('/unsafe', authenticate, getUnsafeUrls);

// @route   GET /api/v1/urls/check-history/:url
// @desc    Check URL history for specific URL
// @access  Private
router.get('/check-history/:url', authenticate, checkUrlHistory);

// @route   PUT /api/v1/urls/:id
// @desc    Update URL check status
// @access  Private
router.put('/:id', authenticate, validateUrlStatus, handleValidationErrors, updateUrlStatus);

// @route   DELETE /api/v1/urls/:id
// @desc    Delete URL record
// @access  Private
router.delete('/:id', authenticate, deleteUrlRecord);

// ── User Feedback Routes (online learning) ──

// @route   POST /api/v1/urls/feedback
// @desc    Submit user feedback on a scan result (mark as safe/phishing)
// @access  Private
router.post('/feedback', authenticate, async (req, res) => {
  try {
    let feedbackModule;
    try { feedbackModule = require('../utils/userFeedback'); } catch (_) {
      return res.status(501).json({ success: false, message: 'Feedback module not available' });
    }

    const { url, modelVerdict, modelScore, modelContributions, userVerdict, sourceResults } = req.body;
    if (!url || !userVerdict) {
      return res.status(400).json({ success: false, message: 'url and userVerdict are required' });
    }
    if (!['safe', 'phishing'].includes(userVerdict)) {
      return res.status(400).json({ success: false, message: 'userVerdict must be "safe" or "phishing"' });
    }

    const result = await feedbackModule.recordFeedback({
      userId: req.user.id || req.user._id,
      url,
      modelVerdict: (modelVerdict || 'safe').toLowerCase(),
      modelScore: (modelScore > 1) ? modelScore / 100 : (modelScore || 0),
      modelContributions: modelContributions || {},
      userVerdict,
      sourceResults: sourceResults || []
    });

    res.status(201).json({ success: true, feedback: result });
  } catch (error) {
    console.error('[Feedback] Error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// @route   GET /api/v1/urls/feedback/stats
// @desc    Get feedback statistics (total, accuracy, FP/FN rates)
// @access  Private
router.get('/feedback/stats', authenticate, async (req, res) => {
  try {
    let feedbackModule;
    try { feedbackModule = require('../utils/userFeedback'); } catch (_) {
      return res.status(501).json({ success: false, message: 'Feedback module not available' });
    }

    const stats = await feedbackModule.getFeedbackStats();
    res.status(200).json({ success: true, stats });
  } catch (error) {
    console.error('[Feedback] Stats error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// @route   GET /api/v1/urls/feedback/export
// @desc    Export feedback data as JSON or CSV
// @access  Private
router.get('/feedback/export', authenticate, async (req, res) => {
  try {
    let feedbackModule;
    try { feedbackModule = require('../utils/userFeedback'); } catch (_) {
      return res.status(501).json({ success: false, message: 'Feedback module not available' });
    }

    const format = req.query.format || 'json';
    const limit = parseInt(req.query.limit) || 1000;
    const data = await feedbackModule.exportFeedbackData({ format, limit });

    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=feedback_export.csv');
      return res.send(data);
    }
    res.status(200).json({ success: true, data });
  } catch (error) {
    console.error('[Feedback] Export error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// @route   POST /api/v1/urls/feedback/recalibrate
// @desc    Manually trigger weight recalibration from feedback data
// @access  Private
router.post('/feedback/recalibrate', authenticate, async (req, res) => {
  try {
    let feedbackModule;
    try { feedbackModule = require('../utils/userFeedback'); } catch (_) {
      return res.status(501).json({ success: false, message: 'Feedback module not available' });
    }

    const result = await feedbackModule.recalibrateWeights();
    res.status(200).json({ success: true, calibration: result });
  } catch (error) {
    console.error('[Feedback] Recalibrate error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// ── Adversarial Testing Route ──

// @route   POST /api/v1/urls/stress-test
// @desc    Stress-test the scanner against adversarial mutations of a domain
// @access  Private
router.post('/stress-test', authenticate, async (req, res) => {
  try {
    let adversarialTesting;
    try { adversarialTesting = require('../utils/adversarialTesting'); } catch (_) {
      return res.status(501).json({ success: false, message: 'Adversarial testing module not available' });
    }

    const { domain, minScore, maxMutations } = req.body;
    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ success: false, message: 'domain is required' });
    }

    const { scanUrlMultiSource } = require('../utils/threatIntel');

    // Gather API keys
    const apiKeys = {
      googleSafeBrowsing: process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.GSB_API_KEY || null,
      virusTotal: process.env.VIRUSTOTAL_API_KEY || null,
      abuseIPDB: process.env.ABUSEIPDB_API_KEY || null,
      shodan: process.env.SHODAN_API_KEY || null,
      urlhaus: process.env.URLHAUS_API_KEY || null,
      huggingFace: process.env.HUGGINGFACE_API_TOKEN || null,
    };

    const scanFunction = (url) => scanUrlMultiSource(url, apiKeys);

    const result = await adversarialTesting.stressTestDomain(domain, scanFunction, {
      minScore: minScore || 0.30,
      maxMutations: maxMutations || 50
    });

    res.status(200).json({ success: true, result });
  } catch (error) {
    console.error('[StressTest] Error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
