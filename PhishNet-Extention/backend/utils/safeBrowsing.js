const axios = require('axios');

const SAFE_BROWSING_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

const normalizeThreatType = (rawType = '') => String(rawType || '')
  .trim()
  .toUpperCase();

const normalizePlatform = (rawPlatform = '') => String(rawPlatform || '')
  .trim()
  .toUpperCase() || 'ANY_PLATFORM';

async function scanUrlWithGoogleSafeBrowsing(url, apiKey) {
  if (!apiKey) {
    throw new Error('Threat detection API key is not configured');
  }

  const payload = {
    client: {
      clientId: 'phishnet-extension',
      clientVersion: '1.0.0'
    },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  try {
    const { data } = await axios.post(
      `${SAFE_BROWSING_ENDPOINT}?key=${apiKey}`,
      payload,
      { timeout: 6000 }
    );

    const matches = Array.isArray(data?.matches) ? data.matches : [];
    const threats = matches.map((match) => ({
      type: normalizeThreatType(match.threatType || match.type),
      platform: normalizePlatform(match.platformType || match.platform),
      url,
    }));

    const hasThreats = threats.length > 0;
    const severeThreat = threats.some((t) => t.type === 'MALWARE' || t.type === 'SOCIAL_ENGINEERING' || t.type === 'PHISHING');
    const status = hasThreats ? (severeThreat ? 'MALICIOUS' : 'SUSPICIOUS') : 'SAFE';

    return { status, threats };
  } catch (error) {
    const message = error?.response?.data?.error?.message || error.message || 'Threat detection lookup failed';
    const err = new Error(message);
    err.statusCode = error?.response?.status || 502;
    throw err;
  }
}

module.exports = {
  scanUrlWithGoogleSafeBrowsing,
};
