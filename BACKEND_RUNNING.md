# ✅ BACKEND IS RUNNING!

## 🎉 Your PhishNet Backend is Live

**Server Status:** ✅ Running
**Address:** http://localhost:3000
**Mode:** Heuristic Phishing Detection

---

## 🧪 Test It Now

### Health Check
```powershell
(Invoke-WebRequest -Uri "http://localhost:3000/health").Content
```

### Scan an Email
```powershell
$body = @{
  subject="URGENT: Verify Your Account"
  body="Click [LINK] to verify your credentials"
} | ConvertTo-Json

(Invoke-WebRequest -Uri "http://localhost:3000/api/scan/email" `
  -Method POST `
  -ContentType "application/json" `
  -Body $body).Content
```

### Response Example
```json
{
  "success": true,
  "data": {
    "isPhishing": false,
    "classification": "legitimate",
    "confidence": "55.00%",
    "confidenceScore": 0.45,
    "riskLevel": "medium",
    "detectionMethod": "heuristic-analysis",
    "riskFactors": ["urgency_keywords", "financial_keywords"]
  }
}
```

---

## 📡 Available Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Server health |
| `/api/scan/email` | POST | Scan email |
| `/api/scan/scan-url` | POST | Scan URL |
| `/api/scan/domain` | POST | Scan domain |
| `/api/scan/batch` | POST | Batch scan |
| `/api/scan/model-info` | GET | Model info |

---

## 🔍 Detection Features

The heuristic-based detector checks for:

✅ **Urgency Keywords** - "urgent", "immediately", "act now"
✅ **Financial References** - "payment", "credit card", "bank"
✅ **Suspicious URLs** - Pattern analysis and spoofing detection
✅ **Impersonal Greetings** - "Dear Customer", "Valued User"
✅ **Pressure Tactics** - "do not ignore", "time sensitive"
✅ **Grammar Issues** - Common misspellings
✅ **Phone Numbers** - Unusual in legitimate emails
✅ **Suspicious Attachments** - References to downloads/files

---

## 🚀 Next Steps

1. **Connect Frontend**: Update `config.js` to use `http://localhost:3000`
2. **Test More Emails**: Send various emails to test detection
3. **Upgrade Model**: When internet is available, add ML model
4. **Deploy**: Push to production (Render, Heroku, etc.)

---

## 📝 Request Format

### Email Scan
```json
{
  "subject": "Email Subject",
  "body": "Email body content",
  "sender": "sender@example.com"
}
```

### URL Scan
```json
{
  "url": "https://example.com",
  "subject": "Optional subject",
  "body": "Optional body"
}
```

### Domain Scan
```json
{
  "domain": "example.com",
  "context": "Optional context about where it was found"
}
```

### Batch Scan
```json
{
  "emails": [
    {"subject": "...", "body": "..."},
    {"subject": "...", "body": "..."}
  ]
}
```

---

## 💡 Current Features

- ✅ **Heuristic Detection** - Pattern-based analysis
- ✅ **Risk Levels** - Low/Medium/High/Critical
- ✅ **Confidence Scores** - 0-100%
- ✅ **Batch Processing** - Up to 50 emails
- ✅ **Detailed Factors** - Shows what triggered detection
- ✅ **Production Ready** - CORS, rate limiting, security headers

---

## 🔄 To Stop Server

```powershell
Get-Process -Name "node" | Stop-Process -Force
```

---

## 📚 Documentation

- [00_START_HERE.md](./00_START_HERE.md)
- [QUICK_START.md](./QUICK_START.md)
- [MODEL_INTEGRATION_GUIDE.md](./MODEL_INTEGRATION_GUIDE.md)
- [ARCHITECTURE.md](./ARCHITECTURE.md)

---

**Backend is ready! 🚀**

Connect your frontend and start scanning for phishing emails!
