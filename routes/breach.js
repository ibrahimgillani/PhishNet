import express from 'express';
import { verifyToken } from '../middleware/auth.js';
import https from 'https';

const router = express.Router();

/**
 * GET /api/breach/check
 * Checks if the logged-in user's email has been found in any data breaches.
 * Requires Authentication.
 */
router.get('/check', verifyToken, async (req, res) => {
  try {
    const email = req.user.email;
    const apiKey = process.env.HIBP_API_KEY;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Email not found in token' });
    }

    // If no API key is provided, simulate a realistic breach response for presentation purposes
    if (!apiKey || apiKey === 'your_key_here') {
      console.log(`[BreachScanner] No HIBP API key found. Simulating data breach check for ${email}...`);
      
      // We will fake a small delay to make it look realistic
      await new Promise(resolve => setTimeout(resolve, 800));

      // Simulate a breach response
      const mockBreaches = [
        {
          Name: 'LinkedIn',
          Title: 'LinkedIn (2016 Breach)',
          Domain: 'linkedin.com',
          BreachDate: '2016-05-01',
          PwnCount: 164611595,
          Description: 'In May 2016, LinkedIn had 164 million email addresses and passwords exposed.',
          DataClasses: ['Email addresses', 'Passwords']
        },
        {
          Name: 'Canva',
          Title: 'Canva',
          Domain: 'canva.com',
          BreachDate: '2019-05-24',
          PwnCount: 137339239,
          Description: 'In May 2019, graphic-design tool site Canva suffered a data breach that impacted 137 million subscribers.',
          DataClasses: ['Email addresses', 'Passwords', 'Usernames', 'Geographic locations']
        }
      ];

      return res.json({
        success: true,
        data: {
          email: email,
          breachCount: mockBreaches.length,
          breaches: mockBreaches,
          isMockData: true // Flag to indicate to frontend that this is simulated
        }
      });
    }

    // --- Real HIBP API Call ---
    console.log(`[BreachScanner] Checking real HIBP API for ${email}...`);
    
    const options = {
      hostname: 'haveibeenpwned.com',
      path: `/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      method: 'GET',
      headers: {
        'hibp-api-key': apiKey,
        'user-agent': 'PhishNet-Security-Dashboard'
      }
    };

    const request = https.request(options, (response) => {
      let data = '';

      response.on('data', (chunk) => {
        data += chunk;
      });

      response.on('end', () => {
        if (response.statusCode === 404) {
          // 404 means no breaches found (which is good!)
          return res.json({
            success: true,
            data: {
              email: email,
              breachCount: 0,
              breaches: [],
              isMockData: false
            }
          });
        }

        if (response.statusCode === 200) {
          try {
            const breaches = JSON.parse(data);
            return res.json({
              success: true,
              data: {
                email: email,
                breachCount: breaches.length,
                breaches: breaches,
                isMockData: false
              }
            });
          } catch (e) {
            return res.status(500).json({ success: false, message: 'Error parsing HIBP response' });
          }
        }

        // Handle rate limiting or other errors
        console.error(`[BreachScanner] HIBP API Error: ${response.statusCode} - ${data}`);
        res.status(response.statusCode).json({
          success: false,
          message: `HIBP API Error: ${response.statusCode}`
        });
      });
    });

    request.on('error', (error) => {
      console.error('[BreachScanner] Network error:', error);
      res.status(500).json({ success: false, message: 'Network error connecting to breach database' });
    });

    request.end();

  } catch (error) {
    console.error('[BreachScanner] Unexpected error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during breach check' });
  }
});

export default router;
