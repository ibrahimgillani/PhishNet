/**
 * PhishNet Model Performance Testing Suite
 * Tests both Email (ML) and URL detection accuracy
 * Run: node tests/model-performance.js
 */

import fetch from 'node-fetch';

const API_BASE = 'http://localhost:3000/api/scan';

// ============================================================
// TEST DATASETS
// ============================================================

// Known phishing emails (should be detected as phishing)
const PHISHING_EMAILS = [
  {
    id: 'PE001',
    subject: 'Urgent: Your account has been compromised',
    body: 'Dear Customer, We have detected suspicious activity on your PayPal account. Your account access has been temporarily limited. Please verify your identity immediately by clicking the link below: http://paypa1-secure.xyz/verify. Failure to verify within 24 hours will result in permanent account suspension. Security Team'
  },
  {
    id: 'PE002',
    subject: 'Action Required: Verify Your Payment Information',
    body: 'Your Amazon payment method needs to be updated. We were unable to process your recent transaction. Click here to update your billing information: http://amaz0n-billing.tk/update. If you do not update within 48 hours, your account will be closed.'
  },
  {
    id: 'PE003',
    subject: 'You have won $1,000,000!',
    body: 'CONGRATULATIONS! You have been selected as the winner of our monthly lottery! To claim your prize, click here: http://lottery-winner.xyz/claim. Act now - this offer expires in 24 hours!'
  },
  {
    id: 'PE004',
    subject: 'Your password will expire in 24 hours',
    body: 'Dear User, Your Microsoft Office 365 password will expire soon. To avoid being locked out, please reset your password immediately at: http://microsoft-security.ml/reset. IT Security Department'
  },
  {
    id: 'PE005',
    subject: 'IRS Tax Refund Notification',
    body: 'Dear Taxpayer, After review of your tax documents, you are eligible for a refund of $3,247.00. To receive your refund, verify your information at: http://irs-refund.xyz/verify. Internal Revenue Service'
  },
  {
    id: 'PE006',
    subject: 'Netflix: Payment Failed',
    body: 'We were unable to process your payment for Netflix subscription. Your account will be suspended unless you update your payment details at: http://netflix-billing.tk/update within 24 hours.'
  },
  {
    id: 'PE007',
    subject: 'Bank of America Security Alert',
    body: 'We detected unusual activity on your account. For your security, we have temporarily limited access. Please verify your identity at: http://bankofamerica-secure.xyz/verify to restore full access.'
  },
  {
    id: 'PE008',
    subject: 'Apple ID Locked',
    body: 'Your Apple ID has been locked for security reasons. Someone tried to access your account from an unknown device. Unlock your account now: http://apple-id-verify.ml/unlock'
  },
  {
    id: 'PE009',
    subject: 'LinkedIn: Someone viewed your profile',
    body: 'Hi, 50 people viewed your profile this week! But we noticed suspicious login attempts. Secure your account now: http://linkedin-security.xyz/secure before its too late!'
  },
  {
    id: 'PE010',
    subject: 'Crypto Wallet Alert',
    body: 'Your Bitcoin wallet has received 2.5 BTC! To claim, verify your wallet at: http://bitcoin-claim.tk/verify. This transfer will expire in 12 hours if unclaimed.'
  }
];

// Known legitimate emails (should NOT be detected as phishing)
const LEGITIMATE_EMAILS = [
  {
    id: 'LE001',
    subject: 'Your Amazon order has shipped',
    body: 'Hello, Great news! Your order #123-4567890 has shipped and is on its way. Tracking number: 1Z999AA10123456784. You can track your package at amazon.com/orders. Thank you for shopping with us!'
  },
  {
    id: 'LE002',
    subject: 'Weekly Newsletter - Tech Updates',
    body: 'Hello, Here is what is new this week in technology: 1. New AI developments 2. Cloud computing trends 3. Cybersecurity best practices. As always, thank you for being part of our community. Best regards, The Tech Team'
  },
  {
    id: 'LE003',
    subject: 'Meeting reminder: Project Review',
    body: 'Hi, This is a reminder that we have a project review meeting scheduled for tomorrow at 2pm in Conference Room B. Agenda: Project updates, Q&A session, Next steps. Please let me know if you have any questions. Best, John'
  },
  {
    id: 'LE004',
    subject: 'Your receipt from Apple Store',
    body: 'Thank you for your purchase! Order Details: MacBook Pro 14-inch, Price: $1,999.00, Tax: $160.00, Total: $2,159.00. Your card ending in 4242 was charged. Download your receipt at apple.com/receipts'
  },
  {
    id: 'LE005',
    subject: 'GitHub: New pull request on your repository',
    body: 'Hey there, A new pull request was opened on your repository phishnet-project by user contributor123. Title: Fix typo in README. Review the changes at github.com/yourrepo/pull/42'
  },
  {
    id: 'LE006',
    subject: 'LinkedIn: New connection request',
    body: 'Hi, John Smith wants to connect with you on LinkedIn. John is a Software Engineer at Google. View profile and accept at linkedin.com. Best regards, The LinkedIn Team'
  },
  {
    id: 'LE007',
    subject: 'Your Spotify Wrapped 2025 is here!',
    body: 'Your year in music is ready! You listened to 45,000 minutes of music this year. Your top artist was The Weeknd. See your full Wrapped at spotify.com/wrapped'
  },
  {
    id: 'LE008',
    subject: 'Flight confirmation - Delta Airlines',
    body: 'Your flight is confirmed! Flight DL1234 from New York (JFK) to Los Angeles (LAX) on March 15, 2026 at 8:00 AM. Confirmation code: ABC123. Manage your booking at delta.com'
  },
  {
    id: 'LE009',
    subject: 'Your monthly bank statement is ready',
    body: 'Hello, Your January 2026 statement is now available. Log in to your online banking at bankofamerica.com to view your statement. For questions, call 1-800-432-1000.'
  },
  {
    id: 'LE010',
    subject: 'Team standup notes - January 15',
    body: 'Hi team, Here are the notes from today standup: Completed: API refactoring, bug fixes. In progress: Frontend redesign, testing. Blockers: None. Next standup: Tomorrow 9am.'
  }
];

// Known phishing URLs (should be detected as malicious)
const PHISHING_URLS = [
  { id: 'PU001', url: 'http://paypal-secure-login.xyz/verify', description: 'PayPal typosquatting' },
  { id: 'PU002', url: 'http://amaz0n-verify.tk/account', description: 'Amazon homograph attack' },
  { id: 'PU003', url: 'http://g00gle-login.ml/signin', description: 'Google homograph' },
  { id: 'PU004', url: 'http://microsoft-verify.xyz/office365', description: 'Microsoft impersonation' },
  { id: 'PU005', url: 'http://apple-id-update.cf/verify', description: 'Apple impersonation' },
  { id: 'PU006', url: 'http://netflix-billing-update.tk/payment', description: 'Netflix phishing' },
  { id: 'PU007', url: 'http://chase-secure-login.xyz/verify', description: 'Chase bank phishing' },
  { id: 'PU008', url: 'http://facebook-security.ml/confirm', description: 'Facebook impersonation' },
  { id: 'PU009', url: 'http://instagram-verify.ga/login', description: 'Instagram phishing' },
  { id: 'PU010', url: 'http://coinbase-wallet.xyz/verify', description: 'Crypto scam' },
  { id: 'PU011', url: 'http://dropbox-share.tk/file', description: 'Dropbox impersonation' },
  { id: 'PU012', url: 'http://docusign-document.ml/sign', description: 'DocuSign phishing' },
  { id: 'PU013', url: 'http://wellsfargo-alert.xyz/secure', description: 'Wells Fargo phishing' },
  { id: 'PU014', url: 'http://linkedin-message.cf/view', description: 'LinkedIn phishing' },
  { id: 'PU015', url: 'http://twitter-verify.gq/badge', description: 'Twitter impersonation' }
];

// Known legitimate URLs (should NOT be flagged)
const LEGITIMATE_URLS = [
  { id: 'LU001', url: 'https://www.google.com', description: 'Google homepage' },
  { id: 'LU002', url: 'https://www.amazon.com', description: 'Amazon homepage' },
  { id: 'LU003', url: 'https://www.paypal.com', description: 'PayPal homepage' },
  { id: 'LU004', url: 'https://www.microsoft.com', description: 'Microsoft homepage' },
  { id: 'LU005', url: 'https://www.apple.com', description: 'Apple homepage' },
  { id: 'LU006', url: 'https://www.netflix.com', description: 'Netflix homepage' },
  { id: 'LU007', url: 'https://www.github.com', description: 'GitHub homepage' },
  { id: 'LU008', url: 'https://www.linkedin.com', description: 'LinkedIn homepage' },
  { id: 'LU009', url: 'https://www.facebook.com', description: 'Facebook homepage' },
  { id: 'LU010', url: 'https://www.youtube.com', description: 'YouTube homepage' },
  { id: 'LU011', url: 'https://stackoverflow.com', description: 'Stack Overflow' },
  { id: 'LU012', url: 'https://www.wikipedia.org', description: 'Wikipedia' },
  { id: 'LU013', url: 'https://www.reddit.com', description: 'Reddit' },
  { id: 'LU014', url: 'https://www.twitter.com', description: 'Twitter/X' },
  { id: 'LU015', url: 'https://www.instagram.com', description: 'Instagram' }
];

// ============================================================
// TEST FUNCTIONS
// ============================================================

async function testEmail(email) {
  try {
    const response = await fetch(`${API_BASE}/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        subject: email.subject, 
        body: email.body 
      })
    });
    
    const result = await response.json();
    const data = result.data || result;
    
    return {
      id: email.id,
      classification: data.classification,
      confidence: data.confidence,
      isPhishing: data.classification === 'phishing'
    };
  } catch (error) {
    return { id: email.id, error: error.message };
  }
}

async function testURL(urlTest) {
  try {
    const response = await fetch(`${API_BASE}/scan-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: urlTest.url })
    });
    
    const result = await response.json();
    const data = result.data || result;
    
    return {
      id: urlTest.id,
      url: urlTest.url,
      isPhishing: data.isPhishing,
      riskScore: data.riskScore,
      riskLevel: data.riskLevel
    };
  } catch (error) {
    return { id: urlTest.id, url: urlTest.url, error: error.message };
  }
}

async function runTests() {
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║          PhishNet Model Performance Test Suite                 ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');
  
  const results = {
    email: { truePositives: 0, trueNegatives: 0, falsePositives: 0, falseNegatives: 0 },
    url: { truePositives: 0, trueNegatives: 0, falsePositives: 0, falseNegatives: 0 }
  };

  // ============================================================
  // EMAIL TESTS
  // ============================================================
  console.log('📧 TESTING EMAIL DETECTION (PhishingDistilBERT Model)\n');
  console.log('─'.repeat(60));
  
  // Test phishing emails
  console.log('\n🔴 Testing PHISHING emails (should detect as phishing):');
  for (const email of PHISHING_EMAILS) {
    const result = await testEmail(email);
    if (result.error) {
      console.log(`   ${email.id}: ❌ Error - ${result.error}`);
    } else if (result.isPhishing) {
      results.email.truePositives++;
      console.log(`   ${email.id}: ✅ Correctly detected as PHISHING (${(result.confidence * 100).toFixed(1)}%)`);
    } else {
      results.email.falseNegatives++;
      console.log(`   ${email.id}: ❌ MISSED - classified as legitimate (${(result.confidence * 100).toFixed(1)}%)`);
    }
  }
  
  // Test legitimate emails
  console.log('\n🟢 Testing LEGITIMATE emails (should NOT detect as phishing):');
  for (const email of LEGITIMATE_EMAILS) {
    const result = await testEmail(email);
    if (result.error) {
      console.log(`   ${email.id}: ❌ Error - ${result.error}`);
    } else if (!result.isPhishing) {
      results.email.trueNegatives++;
      console.log(`   ${email.id}: ✅ Correctly identified as LEGITIMATE (${((1 - result.confidence) * 100).toFixed(1)}%)`);
    } else {
      results.email.falsePositives++;
      console.log(`   ${email.id}: ❌ FALSE POSITIVE - wrongly flagged as phishing (${(result.confidence * 100).toFixed(1)}%)`);
    }
  }

  // ============================================================
  // URL TESTS
  // ============================================================
  console.log('\n\n🔗 TESTING URL DETECTION (Advanced URL Scanner)\n');
  console.log('─'.repeat(60));
  
  // Test phishing URLs
  console.log('\n🔴 Testing PHISHING URLs (should detect as malicious):');
  for (const urlTest of PHISHING_URLS) {
    const result = await testURL(urlTest);
    if (result.error) {
      console.log(`   ${urlTest.id}: ❌ Error - ${result.error}`);
    } else if (result.isPhishing) {
      results.url.truePositives++;
      console.log(`   ${urlTest.id}: ✅ Correctly detected as PHISHING (Risk: ${result.riskScore}%)`);
    } else {
      results.url.falseNegatives++;
      console.log(`   ${urlTest.id}: ❌ MISSED - Risk only ${result.riskScore}% (${urlTest.description})`);
    }
    // Rate limiting for VirusTotal
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  
  // Test legitimate URLs
  console.log('\n🟢 Testing LEGITIMATE URLs (should NOT flag as malicious):');
  for (const urlTest of LEGITIMATE_URLS) {
    const result = await testURL(urlTest);
    if (result.error) {
      console.log(`   ${urlTest.id}: ❌ Error - ${result.error}`);
    } else if (!result.isPhishing) {
      results.url.trueNegatives++;
      console.log(`   ${urlTest.id}: ✅ Correctly identified as SAFE (Risk: ${result.riskScore?.toFixed(0) || 0}%)`);
    } else {
      results.url.falsePositives++;
      console.log(`   ${urlTest.id}: ❌ FALSE POSITIVE - wrongly flagged (Risk: ${result.riskScore}%)`);
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  // ============================================================
  // CALCULATE METRICS
  // ============================================================
  console.log('\n\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║                    PERFORMANCE METRICS                         ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');
  
  // Email metrics
  const emailTP = results.email.truePositives;
  const emailTN = results.email.trueNegatives;
  const emailFP = results.email.falsePositives;
  const emailFN = results.email.falseNegatives;
  
  const emailPrecision = emailTP / (emailTP + emailFP) || 0;
  const emailRecall = emailTP / (emailTP + emailFN) || 0;
  const emailF1 = 2 * (emailPrecision * emailRecall) / (emailPrecision + emailRecall) || 0;
  const emailAccuracy = (emailTP + emailTN) / (emailTP + emailTN + emailFP + emailFN) || 0;

  console.log('📧 EMAIL DETECTION (PhishingDistilBERT):');
  console.log('─'.repeat(40));
  console.log(`   True Positives:  ${emailTP} (phishing correctly detected)`);
  console.log(`   True Negatives:  ${emailTN} (legitimate correctly identified)`);
  console.log(`   False Positives: ${emailFP} (legitimate wrongly flagged)`);
  console.log(`   False Negatives: ${emailFN} (phishing missed)`);
  console.log('');
  console.log(`   📊 Accuracy:  ${(emailAccuracy * 100).toFixed(1)}%`);
  console.log(`   📊 Precision: ${(emailPrecision * 100).toFixed(1)}%`);
  console.log(`   📊 Recall:    ${(emailRecall * 100).toFixed(1)}%`);
  console.log(`   📊 F1 Score:  ${(emailF1 * 100).toFixed(1)}%`);
  
  // URL metrics
  const urlTP = results.url.truePositives;
  const urlTN = results.url.trueNegatives;
  const urlFP = results.url.falsePositives;
  const urlFN = results.url.falseNegatives;
  
  const urlPrecision = urlTP / (urlTP + urlFP) || 0;
  const urlRecall = urlTP / (urlTP + urlFN) || 0;
  const urlF1 = 2 * (urlPrecision * urlRecall) / (urlPrecision + urlRecall) || 0;
  const urlAccuracy = (urlTP + urlTN) / (urlTP + urlTN + urlFP + urlFN) || 0;

  console.log('\n🔗 URL DETECTION (Advanced Scanner + VirusTotal):');
  console.log('─'.repeat(40));
  console.log(`   True Positives:  ${urlTP} (phishing correctly detected)`);
  console.log(`   True Negatives:  ${urlTN} (legitimate correctly identified)`);
  console.log(`   False Positives: ${urlFP} (legitimate wrongly flagged)`);
  console.log(`   False Negatives: ${urlFN} (phishing missed)`);
  console.log('');
  console.log(`   📊 Accuracy:  ${(urlAccuracy * 100).toFixed(1)}%`);
  console.log(`   📊 Precision: ${(urlPrecision * 100).toFixed(1)}%`);
  console.log(`   📊 Recall:    ${(urlRecall * 100).toFixed(1)}%`);
  console.log(`   📊 F1 Score:  ${(urlF1 * 100).toFixed(1)}%`);

  // Overall
  const totalTP = emailTP + urlTP;
  const totalTN = emailTN + urlTN;
  const totalFP = emailFP + urlFP;
  const totalFN = emailFN + urlFN;
  const overallAccuracy = (totalTP + totalTN) / (totalTP + totalTN + totalFP + totalFN) || 0;

  console.log('\n═'.repeat(60));
  console.log(`\n🏆 OVERALL ACCURACY: ${(overallAccuracy * 100).toFixed(1)}%\n`);
  
  // Grade
  let grade = 'F';
  if (overallAccuracy >= 0.95) grade = 'A+';
  else if (overallAccuracy >= 0.90) grade = 'A';
  else if (overallAccuracy >= 0.85) grade = 'B+';
  else if (overallAccuracy >= 0.80) grade = 'B';
  else if (overallAccuracy >= 0.75) grade = 'C+';
  else if (overallAccuracy >= 0.70) grade = 'C';
  else if (overallAccuracy >= 0.60) grade = 'D';
  
  console.log(`   Grade: ${grade}`);
  console.log(`   Ready for Browser Extension: ${overallAccuracy >= 0.85 ? '✅ YES' : '⚠️ Needs improvement'}`);
  
  console.log('\n' + '═'.repeat(60));
  
  return results;
}

// Run tests
runTests().catch(console.error);
