/**
 * Utility Functions for the Backend
 */

/**
 * Validate email text input
 */
export function validateEmailInput(subject, body) {
  if (!subject && !body) {
    throw new Error('Email subject and/or body are required');
  }

  const maxLength = 5000;
  if ((subject || '').length + (body || '').length > maxLength) {
    throw new Error(`Email content exceeds maximum length of ${maxLength} characters`);
  }

  return true;
}

/**
 * Validate URL
 */
export function validateUrl(url) {
  try {
    new URL(url);
    return true;
  } catch (error) {
    throw new Error('Invalid URL format');
  }
}

/**
 * Validate domain
 */
export function validateDomain(domain) {
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domainRegex.test(domain)) {
    throw new Error('Invalid domain format');
  }
  return true;
}

/**
 * Format classification response
 */
export function formatScanResponse(classification, metadata = {}) {
  return {
    success: true,
    timestamp: new Date().toISOString(),
    ...classification,
    ...metadata
  };
}

/**
 * Extract features from email
 */
export function extractEmailFeatures(subject, body) {
  const text = `${subject} ${body}`.toLowerCase();
  
  return {
    hasUrgency: /urgent|immediate|act now|click here|verify|confirm/i.test(text),
    hasFinancialRefs: /payment|wire|money|account|credit card|bank/i.test(text),
    hasUrls: /https?:\/\/|www\./i.test(text),
    urlCount: (text.match(/https?:\/\/|www\./gi) || []).length,
    hasPhoneNumbers: /\+?1?\s?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})/g.test(text),
    bodyLength: body.length,
    subjectLength: subject.length
  };
}

/**
 * Calculate additional risk factors
 */
export function calculateAdditionalRiskFactors(subject, body) {
  const features = extractEmailFeatures(subject, body);
  let riskScore = 0;

  if (features.hasUrgency) riskScore += 0.15;
  if (features.hasFinancialRefs) riskScore += 0.15;
  if (features.hasUrls && features.urlCount > 3) riskScore += 0.1;
  if (features.hasPhoneNumbers) riskScore += 0.1;
  if (features.bodyLength < 50) riskScore += 0.05; // Very short emails

  return {
    features,
    additionalRiskScore: Math.min(riskScore, 0.5), // Cap at 0.5
    riskFactors: Object.entries(features)
      .filter(([_, value]) => value === true || (typeof value === 'number' && value > 0))
      .map(([key]) => key)
  };
}

export default {
  validateEmailInput,
  validateUrl,
  validateDomain,
  formatScanResponse,
  extractEmailFeatures,
  calculateAdditionalRiskFactors
};
