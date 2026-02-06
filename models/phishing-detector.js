/**
 * Phishing Detection Model Integration
 * Hybrid: Uses ML model (DistilBERT) when available, combines with heuristic detection
 * Supports both classification and embedding generation
 */

import mlDetector from './ml-phishing-detector.js';

class PhishingDetector {
  constructor() {
    this.model = null;
    this.tokenizer = null;
    this.modelPath = null;
    this.isLoaded = false;
    this.mlAvailable = false;
    this.useHeuristics = true;
    this.specialTokens = {
      SUBJECT_START: '[SSUB]',
      SUBJECT_END: '[ESUB]',
      BODY_START: '[SBODY]',
      BODY_END: '[EBODY]',
      LINK: '[LINK]',
      PHONE: '[PHONE]'
    };
    this.labels = {
      0: 'legitimate',
      1: 'phishing'
    };
  }

  /**
   * Initialize the model - Try ML first, fallback to heuristics
   */
  async initialize(modelPath = null) {
    try {
      console.log('🤖 Initializing Phishing Detection...');
      
      // Try to load ML model
      console.log('🧠 Attempting to load ML model...');
      const mlLoaded = await mlDetector.initialize();
      
      if (mlLoaded && mlDetector.isLoaded) {
        this.mlAvailable = true;
        this.useHeuristics = false;
        this.modelPath = mlDetector.getModelInfo().modelName;
        console.log('✅ ML model loaded successfully!');
        console.log(`📊 Model: ${this.modelPath}`);
      } else {
        console.log('⚠️ ML model not available, using heuristics');
        this.useHeuristics = true;
        this.modelPath = 'heuristic-detection';
      }
      
      this.isLoaded = true;
      return true;
    } catch (error) {
      console.error('⚠️ ML initialization failed:', error.message);
      console.log('📌 Falling back to heuristic detection');
      this.useHeuristics = true;
      this.mlAvailable = false;
      this.isLoaded = true;
      return true;
    }
  }

  /**
   * Format email text with special tokens for the model
   * @param {string} subject - Email subject line
   * @param {string} body - Email body content
   * @returns {string} Formatted text with special tokens
   */
  formatEmailText(subject, body) {
    const formattedText = 
      `${this.specialTokens.SUBJECT_START} ${subject} ${this.specialTokens.SUBJECT_END} ` +
      `${this.specialTokens.BODY_START} ${body} ${this.specialTokens.BODY_END}`;
    
    return formattedText;
  }

  /**
   * Replace URLs and phone numbers with special tokens
   * @param {string} text - Input text
   * @returns {string} Text with URLs and phone numbers replaced
   */
  preprocessText(text) {
    // Replace URLs with [LINK] token
    const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+)/gi;
    text = text.replace(urlRegex, this.specialTokens.LINK);

    // Replace phone numbers with [PHONE] token
    const phoneRegex = /(\+?1?\s?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})/g;
    text = text.replace(phoneRegex, this.specialTokens.PHONE);

    return text;
  }

  /**
   * Parse email headers from raw email text
   */
  parseEmailHeaders(rawEmail) {
    const headers = {
      from: null,
      fromDomain: null,
      replyTo: null,
      returnPath: null,
      receivedFrom: [],
      spf: null,
      dkim: null,
      dmarc: null,
      xOriginalFrom: null
    };

    const lines = rawEmail.split('\n');
    
    for (const line of lines) {
      const lowerLine = line.toLowerCase();
      
      // Extract From header
      if (lowerLine.startsWith('from:')) {
        const match = line.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (match) {
          headers.from = match[0].toLowerCase();
          headers.fromDomain = headers.from.split('@')[1];
        }
      }
      
      // Extract Reply-To
      if (lowerLine.startsWith('reply-to:')) {
        const match = line.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (match) headers.replyTo = match[0].toLowerCase();
      }
      
      // Extract Return-Path
      if (lowerLine.startsWith('return-path:')) {
        const match = line.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (match) headers.returnPath = match[0].toLowerCase();
      }
      
      // Extract Received headers (mail path)
      if (lowerLine.startsWith('received:')) {
        headers.receivedFrom.push(line);
      }
      
      // Extract SPF result
      if (lowerLine.includes('spf=')) {
        if (lowerLine.includes('spf=pass')) headers.spf = 'pass';
        else if (lowerLine.includes('spf=fail')) headers.spf = 'fail';
        else if (lowerLine.includes('spf=softfail')) headers.spf = 'softfail';
        else if (lowerLine.includes('spf=neutral')) headers.spf = 'neutral';
      }
      
      // Extract DKIM result
      if (lowerLine.includes('dkim=')) {
        if (lowerLine.includes('dkim=pass')) headers.dkim = 'pass';
        else if (lowerLine.includes('dkim=fail')) headers.dkim = 'fail';
      }
      
      // Extract DMARC result
      if (lowerLine.includes('dmarc=')) {
        if (lowerLine.includes('dmarc=pass')) headers.dmarc = 'pass';
        else if (lowerLine.includes('dmarc=fail')) headers.dmarc = 'fail';
      }
    }
    
    return headers;
  }

  /**
   * Analyze email headers for phishing indicators
   */
  analyzeHeaders(headers, claimedBrand) {
    let score = 0;
    let factors = [];
    
    // Known legitimate domains for popular brands
    const legitimateDomains = {
      netflix: ['netflix.com', 'netflix.net'],
      amazon: ['amazon.com', 'amazon.co.uk', 'amazonses.com'],
      paypal: ['paypal.com', 'paypal.co.uk'],
      microsoft: ['microsoft.com', 'microsoftonline.com', 'outlook.com'],
      apple: ['apple.com', 'icloud.com'],
      google: ['google.com', 'gmail.com', 'googlemail.com'],
      chase: ['chase.com', 'jpmchase.com'],
      bankofamerica: ['bankofamerica.com', 'bofa.com'],
      linkedin: ['linkedin.com', 'limail.com'],
      facebook: ['facebook.com', 'fb.com', 'meta.com']
    };
    
    let isVerifiedLegitimate = false;
    
    if (headers.fromDomain) {
      // Check if brand is mentioned but domain doesn't match
      for (const [brand, domains] of Object.entries(legitimateDomains)) {
        if (claimedBrand && claimedBrand.toLowerCase().includes(brand)) {
          if (!domains.some(d => headers.fromDomain.endsWith(d))) {
            score += 0.4; // High risk - brand mismatch
            factors.push(`sender_domain_mismatch_${brand}`);
          } else {
            score -= 0.3; // Legitimate domain match - stronger bonus
            factors.push(`verified_${brand}_domain`);
            isVerifiedLegitimate = true;
          }
        }
        // Also check if sender domain IS a legitimate domain (even without brand mention in content)
        if (domains.some(d => headers.fromDomain.endsWith(d))) {
          isVerifiedLegitimate = true;
          if (!factors.includes(`verified_${brand}_domain`)) {
            factors.push(`verified_${brand}_domain`);
            score -= 0.2;
          }
        }
      }
      
      // Check for suspicious domain patterns (only if not verified legitimate)
      if (!isVerifiedLegitimate && /\d{3,}/.test(headers.fromDomain)) {
        score += 0.15;
        factors.push('domain_contains_numbers');
      }
      
      // Check for look-alike domains
      if (/(netflix|amazon|paypal|microsoft|google|apple|chase|bank).*\.(xyz|info|top|click|link|online|site)/i.test(headers.fromDomain)) {
        score += 0.35;
        factors.push('lookalike_domain_detected');
      }
    }
    
    // Check Reply-To mismatch (only flag if domains are different AND not verified legitimate)
    if (headers.replyTo && headers.from && headers.replyTo !== headers.from) {
      const replyToDomain = headers.replyTo.split('@')[1];
      if (replyToDomain !== headers.fromDomain && !isVerifiedLegitimate) {
        score += 0.25;
        factors.push('reply_to_domain_mismatch');
      }
    }
    
    // Check authentication results - give STRONGER bonuses for passing
    if (headers.spf === 'fail') {
      score += 0.3;
      factors.push('spf_failed');
    } else if (headers.spf === 'pass') {
      score -= 0.15; // Stronger bonus
      factors.push('spf_passed');
    }
    
    if (headers.dkim === 'fail') {
      score += 0.25;
      factors.push('dkim_failed');
    } else if (headers.dkim === 'pass') {
      score -= 0.15; // Stronger bonus
      factors.push('dkim_passed');
    }
    
    if (headers.dmarc === 'fail') {
      score += 0.3;
      factors.push('dmarc_failed');
    } else if (headers.dmarc === 'pass') {
      score -= 0.15; // Stronger bonus
      factors.push('dmarc_passed');
    }
    
    // If ALL authentication passed AND domain is verified, give extra trust bonus
    if (headers.spf === 'pass' && headers.dkim === 'pass' && headers.dmarc === 'pass' && isVerifiedLegitimate) {
      score -= 0.3; // Extra bonus for fully authenticated legitimate email
      factors.push('fully_authenticated_legitimate');
    }
    
    return { score: Math.max(0, score), factors, isVerifiedLegitimate };
  }

  /**
   * Heuristic-based phishing detection using pattern matching
   */
  detectPhishingHeuristic(subject, body) {
    const text = `${subject} ${body}`.toLowerCase();
    let phishingScore = 0;
    let factors = [];
    let isVerifiedLegitimate = false;
    
    // Check if email contains headers (user pasted full email with headers)
    const hasHeaders = /^(from:|received:|return-path:|reply-to:|authentication-results:)/im.test(body);
    let headerAnalysis = null;
    
    if (hasHeaders) {
      const headers = this.parseEmailHeaders(body);
      
      // Detect claimed brand from content
      let claimedBrand = null;
      const brandMatches = text.match(/(netflix|amazon|paypal|microsoft|google|apple|chase|bank of america|linkedin|facebook)/i);
      if (brandMatches) claimedBrand = brandMatches[0];
      
      headerAnalysis = this.analyzeHeaders(headers, claimedBrand);
      phishingScore += headerAnalysis.score;
      factors.push(...headerAnalysis.factors);
      isVerifiedLegitimate = headerAnalysis.isVerifiedLegitimate || false;
    }

    // If email is from verified legitimate source, reduce content-based penalties
    const contentPenaltyMultiplier = isVerifiedLegitimate ? 0.3 : 1.0; // 70% reduction for verified emails

    // Check for urgency keywords (high weight) - but less weight if verified legitimate
    const urgencyPatterns = /urgent|immediately|asap|click now|verify now|act now|expire|suspended|locked|compromised|unusual activity|unauthorized/gi;
    if (urgencyPatterns.test(text)) {
      phishingScore += 0.15 * contentPenaltyMultiplier;
      factors.push('urgency_keywords');
    }

    // Check for financial/credential keywords (high weight) - less weight if legitimate
    // Note: "password", "confirm" are common in legitimate account notifications
    const financialPatterns = /payment|wire|credit card|bank account|routing|swift/gi;
    if (financialPatterns.test(text)) {
      phishingScore += 0.15 * contentPenaltyMultiplier;
      factors.push('financial_keywords');
    }
    
    // Separate check for sensitive words that ARE common in legitimate emails
    const commonLegitPatterns = /password|verify|confirm|identity/gi;
    if (commonLegitPatterns.test(text) && !isVerifiedLegitimate) {
      phishingScore += 0.1; // Only penalize if NOT from verified source
      factors.push('credential_keywords');
    }

    // Check for suspicious URLs
    const urlMatches = text.match(/https?:\/\/([^\s]+)/gi) || [];
    if (urlMatches.length > 0 && !isVerifiedLegitimate) {
      phishingScore += 0.1 * contentPenaltyMultiplier;
      factors.push(`urls_found_${urlMatches.length}`);
      
      // Check for URL spoofing (e.g., secure-paypal-verify.com)
      const spoofPatterns = /secure[.-]|verify[.-]|confirm[.-]|update[.-]|alert[.-]/gi;
      if (urlMatches.some(url => spoofPatterns.test(url))) {
        phishingScore += 0.15;
        factors.push('suspicious_url_naming');
      }
    }

    // Check for missing personalization (less relevant for verified legitimate emails)
    const impersonalGreetings = /dear (customer|user|friend|sir|madam)|valued|account holder/gi;
    if (impersonalGreetings.test(text) && !isVerifiedLegitimate) {
      phishingScore += 0.1;
      factors.push('impersonal_greeting');
    }

    // Check for pressure tactics
    const pressurePatterns = /act now|do not ignore|do not delete|urgent action|immediate attention|time sensitive/gi;
    if (pressurePatterns.test(text)) {
      phishingScore += 0.1;
      factors.push('pressure_tactics');
    }

    // Check for grammar/spelling issues (common in phishing)
    const commonMisspellings = /occured|recieved|seperate|bussiness|adress|alot|their's/gi;
    if (commonMisspellings.test(text)) {
      phishingScore += 0.05;
      factors.push('spelling_errors');
    }

    // Check for phone numbers (unusual in legitimate emails)
    const phonePatterns = /\+?1?\s?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})/g;
    const phoneMatches = text.match(phonePatterns) || [];
    if (phoneMatches.length > 0) {
      phishingScore += 0.08;
      factors.push(`phone_numbers_${phoneMatches.length}`);
    }

    // Check for suspicious attachments mentioned
    if (/attachment|attached|download|click.*file|open.*file/gi.test(text)) {
      phishingScore += 0.05;
      factors.push('suspicious_attachment_reference');
    }

    // Check for generic signature (no real company name)
    if (!/regards|sincerely|best|thanks|cheers/i.test(body) || 
        !/best regards|yours truly|warm regards/i.test(body)) {
      phishingScore += 0.05;
      factors.push('generic_signature');
    }

    // Cap the score at 0.99
    phishingScore = Math.min(phishingScore, 0.99);

    return {
      score: phishingScore,
      factors,
      isPhishing: phishingScore > 0.5,
      isVerifiedLegitimate
    };
  }

  /**
   * Classify a single email or text using HYBRID approach (ML + Heuristics)
   */
  async classifyEmail(subject, body = '') {
    if (!this.isLoaded) {
      throw new Error('Model not initialized. Call initialize() first.');
    }

    try {
      // Get heuristic analysis
      const heuristicResult = this.detectPhishingHeuristic(subject, body);
      let mlResult = null;
      let finalScore = heuristicResult.score;
      let detectionMethod = 'heuristic-analysis';

      // Try ML classification if available
      if (this.mlAvailable) {
        try {
          mlResult = await mlDetector.classifyWithML(subject, body);
          
          if (mlResult && mlResult.confidence) {
            const mlScore = mlResult.isPhishing ? mlResult.confidence : (1 - mlResult.confidence);
            
            // SMART HYBRID SCORING based on agreement and context
            // When ML and heuristics disagree significantly, use context to decide
            const mlSaysPhishing = mlScore > 0.5;
            const heuristicSaysPhishing = heuristicResult.score > 0.5;
            const heuristicIsLow = heuristicResult.score < 0.3; // Heuristics think it's likely safe
            
            if (mlSaysPhishing && heuristicIsLow && !heuristicResult.isVerifiedLegitimate) {
              // ML says phishing but heuristics say safe - use weighted average but favor heuristics
              // This reduces ML false positives on legitimate emails
              finalScore = (mlScore * 0.35) + (heuristicResult.score * 0.65);
              console.log(`⚖️ Conflict: ML=phishing, Heuristic=safe → Favoring heuristics`);
            } else if (mlSaysPhishing && heuristicSaysPhishing) {
              // Both agree it's phishing - high confidence
              finalScore = (mlScore * 0.6) + (heuristicResult.score * 0.4);
              console.log(`✓ Agreement: Both say phishing`);
            } else if (!mlSaysPhishing && !heuristicSaysPhishing) {
              // Both agree it's legitimate - high confidence
              finalScore = (mlScore * 0.5) + (heuristicResult.score * 0.5);
              console.log(`✓ Agreement: Both say legitimate`);
            } else {
              // Mixed signals - use balanced weights
              finalScore = (mlScore * 0.5) + (heuristicResult.score * 0.5);
              console.log(`⚖️ Mixed signals: Using balanced weights`);
            }
            
            // If heuristics found verified legitimate headers, trust that strongly
            if (heuristicResult.isVerifiedLegitimate) {
              finalScore = Math.min(finalScore * 0.4, 0.25); // Cap at 25% if verified
              console.log(`🔒 Verified legitimate headers detected - capping score`);
            }
            
            detectionMethod = `hybrid-ml-heuristic (${mlResult.method})`;
            console.log(`🔬 Hybrid score: ML=${mlScore.toFixed(3)}, Heuristic=${heuristicResult.score.toFixed(3)}, Final=${finalScore.toFixed(3)}`);
          }
        } catch (mlError) {
          console.warn('ML classification failed, using heuristics only:', mlError.message);
        }
      }

      const isPhishing = finalScore > 0.5;
      const riskLevel = this.calculateRiskLevel(finalScore);

      const predictions = [
        { 
          label: isPhishing ? 'phishing' : 'legitimate', 
          score: isPhishing ? finalScore : (1 - finalScore), 
          confidence: ((isPhishing ? finalScore : (1 - finalScore)) * 100).toFixed(2) + '%' 
        },
        { 
          label: isPhishing ? 'legitimate' : 'phishing', 
          score: isPhishing ? (1 - finalScore) : finalScore, 
          confidence: ((isPhishing ? (1 - finalScore) : finalScore) * 100).toFixed(2) + '%' 
        }
      ];

      return {
        success: true,
        isPhishing,
        classification: isPhishing ? 'phishing' : 'legitimate',
        confidence: predictions[0].confidence,
        confidenceScore: finalScore,
        riskLevel,
        allPredictions: predictions,
        detectionMethod,
        riskFactors: heuristicResult.factors,
        mlResult: mlResult ? {
          confidence: mlResult.confidence,
          label: mlResult.label,
          inferenceTime: mlResult.inferenceTime
        } : null,
        heuristicScore: heuristicResult.score,
        isVerifiedLegitimate: heuristicResult.isVerifiedLegitimate || false,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Classification error:', error);
      throw new Error(`Classification failed: ${error.message}`);
    }
  }

  /**
   * Batch classify multiple emails
   * @param {Array<Object>} emails - Array of {subject, body} objects
   * @returns {Promise<Array<Object>>} Array of classification results
   */
  async classifyBatch(emails) {
    if (!Array.isArray(emails)) {
      throw new Error('Input must be an array of email objects');
    }

    try {
      const results = await Promise.all(
        emails.map(email => 
          this.classifyEmail(email.subject || '', email.body || '')
        )
      );
      return results;
    } catch (error) {
      console.error('Batch classification error:', error);
      throw new Error(`Batch classification failed: ${error.message}`);
    }
  }

  /**
   * Calculate risk level based on confidence score
   * @param {number} score - Confidence score (0-1)
   * @returns {string} Risk level: 'low', 'medium', 'high', or 'critical'
   */
  calculateRiskLevel(score) {
    if (score < 0.3) return 'low';
    if (score < 0.6) return 'medium';
    if (score < 0.85) return 'high';
    return 'critical';
  }

  /**
   * Get model information
   * @returns {Object} Model metadata
   */
  getModelInfo() {
    return {
      name: 'PhishingDistilBERT',
      baseModel: 'distilbert-base-uncased',
      isLoaded: this.isLoaded,
      modelPath: this.modelPath,
      specialTokens: this.specialTokens,
      maxSequenceLength: 512,
      supportedLabels: this.labels
    };
  }
}

// Create and export singleton instance
const detectorInstance = new PhishingDetector();

export default detectorInstance;
export { PhishingDetector };
