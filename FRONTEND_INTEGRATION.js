/**
 * Frontend Integration Examples
 * How to call the backend API from your frontend
 */

// ==================== SCAN EMAIL ====================
async function scanEmail(subject, body) {
  try {
    const response = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.scan.email), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        subject: subject,
        body: body
      })
    });

    const result = await response.json();
    
    if (result.success) {
      console.log('Email Analysis:', result.data);
      console.log('Is Phishing:', result.data.isPhishing);
      console.log('Confidence:', result.data.confidence);
      console.log('Risk Level:', result.data.riskLevel);
      
      // Display to user
      displayResult(result.data);
    }
    
    return result;
  } catch (error) {
    console.error('Scan failed:', error);
    showToast('Failed to scan email', 'error');
  }
}

// ==================== SCAN URL ====================
async function scanURL(url, subject = '', body = '') {
  try {
    const response = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.scan.url), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: url,
        subject: subject,
        body: body
      })
    });

    const result = await response.json();
    return result;
  } catch (error) {
    console.error('URL scan failed:', error);
  }
}

// ==================== BATCH SCAN ====================
async function batchScanEmails(emails) {
  try {
    const response = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.scan.batch), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        emails: emails // Array of {subject, body}
      })
    });

    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Batch scan failed:', error);
  }
}

// ==================== GET MODEL INFO ====================
async function getModelInfo() {
  try {
    const response = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.scan.modelInfo));
    const result = await response.json();
    console.log('Model Info:', result.data);
    return result;
  } catch (error) {
    console.error('Failed to get model info:', error);
  }
}

// ==================== DISPLAY RESULT ====================
function displayResult(data) {
  let message = '';
  
  if (data.isPhishing) {
    message = `⚠️ PHISHING DETECTED!
    
Confidence: ${data.confidence}
Risk Level: ${data.riskLevel.toUpperCase()}

Detected Factors:
${data.riskFactors?.map(f => `• ${f}`).join('\n')}`;
    showToast(message, 'error', 5000);
  } else {
    message = `✅ LEGITIMATE EMAIL

Confidence: ${data.confidence}
Risk Level: ${data.riskLevel}`;
    showToast(message, 'success', 3000);
  }
}

// ==================== USAGE EXAMPLES ====================

/*
// Example 1: Scan an email from a form
document.getElementById('scanBtn')?.addEventListener('click', async () => {
  const subject = document.getElementById('emailSubject').value;
  const body = document.getElementById('emailBody').value;
  
  const result = await scanEmail(subject, body);
});

// Example 2: Scan multiple emails at once
async function scanMultiple() {
  const emails = [
    {
      subject: 'Invoice #12345',
      body: 'Please review the attached invoice'
    },
    {
      subject: 'URGENT: Verify Your Account',
      body: 'Click [LINK] to verify your credentials'
    }
  ];
  
  const result = await batchScanEmails(emails);
  console.log('Results:', result.data.results);
}

// Example 3: Check if backend is ready
async function checkBackend() {
  const info = await getModelInfo();
  if (info.success) {
    console.log('✅ Backend is ready!');
    console.log('Detection method:', info.data.name);
  }
}
*/

// ==================== INTEGRATION CHECKLIST ====================
/*
✅ 1. Update config.js (DONE - now points to http://localhost:3000)
✅ 2. Add these functions to your frontend JavaScript
✅ 3. Call scanEmail() when user submits email to scan
✅ 4. Call scanURL() when user submits URL
✅ 5. Call batchScanEmails() for bulk scanning
✅ 6. Display results using displayResult()

ENDPOINTS AVAILABLE:
- POST /api/scan/email → scanEmail(subject, body)
- POST /api/scan/scan-url → scanURL(url, subject, body)
- POST /api/scan/domain → scanDomain(domain, context)
- POST /api/scan/batch → batchScanEmails(emails)
- GET /api/scan/model-info → getModelInfo()
*/
