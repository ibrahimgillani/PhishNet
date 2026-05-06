# 🔌 Frontend Integration Guide

## ✅ Step 1: Config.js Updated

Your `config.js` now points to: **`http://localhost:3000`**

---

## ✅ Step 2: Add Integration Code

Copy the functions from `FRONTEND_INTEGRATION.js` into your JavaScript:

```javascript
// Scan an email
async function scanEmail(subject, body) {
  const response = await fetch(getApiUrl(window.API_CONFIG.api.endpoints.scan.email), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, body })
  });
  return await response.json();
}
```

---

## ✅ Step 3: Use in Your Forms

### Scan Email Form
```html
<form id="emailScanForm">
  <input type="text" id="emailSubject" placeholder="Email Subject">
  <textarea id="emailBody" placeholder="Email Body"></textarea>
  <button type="submit">Scan Email</button>
</form>

<script>
document.getElementById('emailScanForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const subject = document.getElementById('emailSubject').value;
  const body = document.getElementById('emailBody').value;
  
  const result = await scanEmail(subject, body);
  
  if (result.data.isPhishing) {
    alert('⚠️ PHISHING DETECTED!\n\nConfidence: ' + result.data.confidence);
  } else {
    alert('✅ Email looks legitimate');
  }
});
</script>
```

---

## 🧪 Test It

1. **Open your frontend** (e.g., `index.html`)
2. **Open browser console** (F12)
3. **Run this in console**:

```javascript
// Test if backend is connected
fetch('http://localhost:3000/health')
  .then(r => r.json())
  .then(d => console.log('✅ Connected!', d))
  .catch(e => console.log('❌ Failed:', e));
```

---

## 📡 API Endpoints Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/scan/email` | POST | Scan email for phishing |
| `/api/scan/scan-url` | POST | Scan URL |
| `/api/scan/domain` | POST | Scan domain |
| `/api/scan/batch` | POST | Scan 50 emails |
| `/api/scan/model-info` | GET | Get model details |

---

## 💻 Example Integration

### Dashboard Page
```javascript
// dashboard.html or dashboard.js

// Add this near the top
const API_BASE = 'http://localhost:3000';

// Function to scan email
async function analyzeEmail() {
  const subject = document.getElementById('emailSubject').value;
  const body = document.getElementById('emailBody').value;
  
  try {
    const response = await fetch(`${API_BASE}/api/scan/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, body })
    });
    
    const result = await response.json();
    
    // Update UI with results
    document.getElementById('result').innerHTML = `
      <h3>Analysis Result</h3>
      <p>Classification: ${result.data.classification}</p>
      <p>Confidence: ${result.data.confidence}</p>
      <p>Risk Level: ${result.data.riskLevel}</p>
      <p>Is Phishing: ${result.data.isPhishing ? 'Yes ⚠️' : 'No ✅'}</p>
    `;
    
    // Show toast
    showToast(
      result.data.isPhishing ? '⚠️ Phishing detected!' : '✅ Email looks safe',
      result.data.isPhishing ? 'error' : 'success'
    );
    
  } catch (error) {
    console.error('Error:', error);
    showToast('Failed to scan email', 'error');
  }
}
```

---

## 🚀 What You Can Do Now

✅ **Scan individual emails** - Get phishing classification
✅ **Scan URLs** - Analyze suspicious links
✅ **Batch scan** - Scan up to 50 emails at once
✅ **Display results** - Show confidence, risk level, detected factors
✅ **Store history** - Save scan results

---

## 📝 Common Questions

**Q: Where do I add the API calls?**
A: In any JavaScript file that handles form submissions or button clicks

**Q: How do I display the results?**
A: Use the `result.data` object which contains:
- `isPhishing` (true/false)
- `classification` (phishing/legitimate)
- `confidence` (percentage)
- `riskLevel` (low/medium/high/critical)
- `riskFactors` (array of detected issues)

**Q: Can I test without a UI?**
A: Yes! Use the browser console:
```javascript
fetch('http://localhost:3000/api/scan/email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    subject: 'Test',
    body: 'Click link now'
  })
}).then(r => r.json()).then(d => console.log(d));
```

---

## ✅ Integration Checklist

- [ ] Backend running at `http://localhost:3000`
- [ ] `config.js` points to backend
- [ ] Added integration code to frontend
- [ ] Can call `/api/scan/email` from console
- [ ] Form submissions call `scanEmail()`
- [ ] Results display in UI
- [ ] Tested with real emails
- [ ] Ready to deploy!

---

**Your frontend is now connected! 🎉**

Start using the phishing detection in your UI!
