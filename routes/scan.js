/**
 * Scanning Routes
 * Endpoints for URL, email, and domain scanning using the phishing detection model
 * Now with Advanced URL Scanner (multi-layer analysis)
 * Includes: VirusTotal, PhishTank, WHOIS, ML Training
 */

import express from 'express';
import phishingDetector from '../models/phishing-detector.js';
import domainChecker from '../utils/domain-checker.js';
import urlScanner from '../utils/url-scanner.js';
import threatIntelligence from '../utils/threat-intelligence.js';
import mlTraining from '../utils/ml-training.js';

const router = express.Router();

/**
 * POST /scan-url
 * Scan a URL for phishing indicators using Advanced URL Scanner
 */
router.post('/scan-url', async (req, res) => {
  try {
    const { url, deepScan = true } = req.body;

    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Use Advanced URL Scanner for comprehensive analysis
    const urlResult = await urlScanner.scanURL(url);

    // Also run ML analysis on the URL
    const mlResult = await phishingDetector.classifyEmail('Check this link', url);

    // Combine results
    const combinedRiskScore = Math.max(urlResult.riskScore, mlResult.confidenceScore * 100);
    const isPhishing = urlResult.isPhishing || mlResult.isPhishing;

    res.json({
      success: true,
      data: {
        url,
        isPhishing,
        riskScore: combinedRiskScore,
        riskLevel: urlResult.riskLevel,
        confidence: `${combinedRiskScore.toFixed(1)}%`,
        
        // Advanced URL Analysis
        urlAnalysis: {
          structure: urlResult.checks.structure,
          ssl: urlResult.checks.ssl,
          redirects: urlResult.checks.redirects,
          typosquatting: urlResult.checks.typosquatting,
          threatIntel: urlResult.checks.threatIntel
        },
        
        // Domain Analysis
        domainAnalysis: urlResult.checks.domain,
        
        // ML Analysis
        mlAnalysis: {
          classification: mlResult.classification,
          confidence: mlResult.confidence,
          method: mlResult.detectionMethod
        },
        
        // Risk Factors & Safety
        riskFactors: urlResult.riskFactors,
        safetyIndicators: urlResult.safetyIndicators,
        
        // Metadata
        scanTime: urlResult.scanTime,
        timestamp: urlResult.timestamp
      }
    });
  } catch (error) {
    console.error('URL scan error:', error);
    res.status(500).json({
      success: false,
      message: 'Scan failed',
      error: error.message
    });
  }
});

/**
 * POST /url-quick
 * Quick URL scan (structure + domain only, no external API calls)
 */
router.post('/url-quick', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Quick scan - just structure and basic checks
    const urlResult = await urlScanner.scanURL(url);

    res.json({
      success: true,
      data: {
        url,
        isPhishing: urlResult.isPhishing,
        riskScore: urlResult.riskScore,
        riskLevel: urlResult.riskLevel,
        riskFactors: urlResult.riskFactors,
        safetyIndicators: urlResult.safetyIndicators,
        scanTime: urlResult.scanTime
      }
    });
  } catch (error) {
    console.error('Quick URL scan error:', error);
    res.status(500).json({
      success: false,
      message: 'Quick scan failed',
      error: error.message
    });
  }
});

/**
 * POST /email
 * Scan an email for phishing
 */
router.post('/email', async (req, res) => {
  try {
    const { subject, body, sender = '', emailContent } = req.body;

    // Support both formats: {subject, body} or {emailContent}
    const emailSubject = subject || '';
    const emailBody = body || emailContent || '';

    if (!emailSubject && !emailBody) {
      return res.status(400).json({
        success: false,
        message: 'Email subject and/or body are required'
      });
    }

    const result = await phishingDetector.classifyEmail(emailSubject, emailBody);

    res.json({
      success: true,
      data: {
        sender,
        subject: emailSubject,
        bodyPreview: emailBody ? emailBody.substring(0, 200) : '',
        ...result
      }
    });
  } catch (error) {
    console.error('Email scan error:', error);
    res.status(500).json({
      success: false,
      message: 'Email scan failed',
      error: error.message
    });
  }
});

/**
 * POST /domain
 * Scan a domain for phishing indicators
 */
router.post('/domain', async (req, res) => {
  try {
    const { domain, context = '' } = req.body;

    if (!domain) {
      return res.status(400).json({
        success: false,
        message: 'Domain is required'
      });
    }

    // Analyze domain in context
    const analysisText = `${domain} ${context}`;
    const result = await phishingDetector.classifyEmail(analysisText);

    res.json({
      success: true,
      data: {
        domain,
        ...result
      }
    });
  } catch (error) {
    console.error('Domain scan error:', error);
    res.status(500).json({
      success: false,
      message: 'Domain scan failed',
      error: error.message
    });
  }
});

/**
 * POST /batch
 * Batch scan multiple emails
 */
router.post('/batch', async (req, res) => {
  try {
    const { emails } = req.body;

    if (!Array.isArray(emails)) {
      return res.status(400).json({
        success: false,
        message: 'Emails must be an array'
      });
    }

    if (emails.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Maximum 50 emails per batch'
      });
    }

    const results = await phishingDetector.classifyBatch(emails);

    res.json({
      success: true,
      data: {
        totalScanned: emails.length,
        results
      }
    });
  } catch (error) {
    console.error('Batch scan error:', error);
    res.status(500).json({
      success: false,
      message: 'Batch scan failed',
      error: error.message
    });
  }
});

/**
 * GET /model-info
 * Get model information
 */
router.get('/model-info', (req, res) => {
  try {
    const modelInfo = phishingDetector.getModelInfo();
    res.json({
      success: true,
      data: modelInfo
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get model info',
      error: error.message
    });
  }
});

/**
 * POST /verify-domain
 * Verify a domain's authenticity with real DNS lookups
 */
router.post('/verify-domain', async (req, res) => {
  try {
    const { domain, brand } = req.body;

    if (!domain) {
      return res.status(400).json({
        success: false,
        message: 'Domain is required'
      });
    }

    // Clean domain (remove protocol, path, etc.)
    let cleanDomain = domain.toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
      .replace(/^www\./, '');

    const result = await domainChecker.verifyDomain(cleanDomain, brand);

    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('Domain verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Domain verification failed',
      error: error.message
    });
  }
});

/**
 * POST /verify-sender
 * Verify if an email sender matches claimed brand
 */
router.post('/verify-sender', async (req, res) => {
  try {
    const { senderEmail, claimedBrand } = req.body;

    if (!senderEmail) {
      return res.status(400).json({
        success: false,
        message: 'Sender email is required'
      });
    }

    const domain = senderEmail.split('@')[1];
    if (!domain) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    const result = await domainChecker.verifyDomain(domain, claimedBrand);
    const brandCheck = domainChecker.verifyBrandDomain(domain, claimedBrand);

    res.json({
      success: true,
      data: {
        senderEmail,
        domain,
        claimedBrand,
        isVerified: brandCheck.verified === true,
        brandVerification: brandCheck,
        domainAnalysis: result
      }
    });
  } catch (error) {
    console.error('Sender verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Sender verification failed',
      error: error.message
    });
  }
});

// ============================================================
// THREAT INTELLIGENCE ENDPOINTS
// ============================================================

/**
 * POST /threat-intel
 * Full threat intelligence analysis (VirusTotal, PhishTank, WHOIS, blacklist)
 */
router.post('/threat-intel', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    const result = await threatIntelligence.analyzeURL(url);

    res.json({
      success: true,
      data: {
        url,
        isPhishing: result.isPhishing,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        riskFactors: result.riskFactors,
        threats: result.threats,
        sources: result.sources,
        details: {
          blacklist: result.details.blacklist,
          patterns: result.details.patterns,
          whois: result.details.whois,
          virusTotal: result.details.virusTotal,
          phishTank: result.details.phishTank
        },
        timestamp: result.timestamp
      }
    });
  } catch (error) {
    console.error('Threat intelligence error:', error);
    res.status(500).json({
      success: false,
      message: 'Threat intelligence analysis failed',
      error: error.message
    });
  }
});

/**
 * GET /threat-intel/stats
 * Get threat intelligence database statistics
 */
router.get('/threat-intel/stats', (req, res) => {
  const stats = threatIntelligence.getStats();
  res.json({
    success: true,
    data: stats
  });
});

/**
 * POST /threat-intel/blacklist
 * Add a domain to the local blacklist
 */
router.post('/threat-intel/blacklist', (req, res) => {
  try {
    const { domain } = req.body;

    if (!domain) {
      return res.status(400).json({
        success: false,
        message: 'Domain is required'
      });
    }

    const added = threatIntelligence.addToBlacklist(domain);

    res.json({
      success: true,
      data: {
        domain,
        added,
        message: added ? 'Domain added to blacklist' : 'Domain already in blacklist'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to add to blacklist',
      error: error.message
    });
  }
});

// ============================================================
// ML TRAINING ENDPOINTS
// ============================================================

/**
 * POST /training/sample/phishing
 * Add a phishing sample to the training dataset
 */
router.post('/training/sample/phishing', (req, res) => {
  try {
    const { text, source, confidence } = req.body;

    if (!text) {
      return res.status(400).json({
        success: false,
        message: 'Text content is required'
      });
    }

    const sample = mlTraining.addPhishingSample(text, { source, confidence });

    res.json({
      success: true,
      data: {
        message: 'Phishing sample added',
        features: sample.features
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to add sample',
      error: error.message
    });
  }
});

/**
 * POST /training/sample/legitimate
 * Add a legitimate sample to the training dataset
 */
router.post('/training/sample/legitimate', (req, res) => {
  try {
    const { text, source, confidence } = req.body;

    if (!text) {
      return res.status(400).json({
        success: false,
        message: 'Text content is required'
      });
    }

    const sample = mlTraining.addLegitimateSample(text, { source, confidence });

    res.json({
      success: true,
      data: {
        message: 'Legitimate sample added',
        features: sample.features
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to add sample',
      error: error.message
    });
  }
});

/**
 * POST /training/sample/url
 * Add a URL sample to the training dataset
 */
router.post('/training/sample/url', (req, res) => {
  try {
    const { url, isPhishing, riskFactors = [] } = req.body;

    if (!url || isPhishing === undefined) {
      return res.status(400).json({
        success: false,
        message: 'URL and isPhishing flag are required'
      });
    }

    const sample = mlTraining.addURLSample(url, isPhishing, { riskFactors });

    res.json({
      success: true,
      data: {
        message: 'URL sample added',
        sample
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to add URL sample',
      error: error.message
    });
  }
});

/**
 * POST /training/feedback
 * Record user feedback for model improvement
 */
router.post('/training/feedback', (req, res) => {
  try {
    const { input, predictedLabel, correctLabel, inputType = 'email' } = req.body;

    if (!input || !predictedLabel || !correctLabel) {
      return res.status(400).json({
        success: false,
        message: 'Input, predictedLabel, and correctLabel are required'
      });
    }

    const feedback = mlTraining.addFeedback(input, predictedLabel, correctLabel, inputType);

    res.json({
      success: true,
      data: {
        message: 'Feedback recorded',
        isCorrect: feedback.isCorrect
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to record feedback',
      error: error.message
    });
  }
});

/**
 * GET /training/data
 * Get all training data statistics
 */
router.get('/training/data', (req, res) => {
  try {
    const data = mlTraining.getAllTrainingData();
    
    res.json({
      success: true,
      data: {
        stats: data.stats,
        improvementSuggestions: mlTraining.getImprovementSuggestions()
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get training data',
      error: error.message
    });
  }
});

/**
 * POST /training/export
 * Export training data in specified format
 */
router.post('/training/export', (req, res) => {
  try {
    const { format = 'csv' } = req.body;

    const result = mlTraining.exportTrainingData(format);

    res.json({
      success: true,
      data: {
        message: `Training data exported in ${format} format`,
        files: result
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to export training data',
      error: error.message
    });
  }
});

/**
 * GET /training/suggestions
 * Get model improvement suggestions based on feedback
 */
router.get('/training/suggestions', (req, res) => {
  try {
    const suggestions = mlTraining.getImprovementSuggestions();
    
    res.json({
      success: true,
      data: suggestions
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to get suggestions',
      error: error.message
    });
  }
});

export default router;
