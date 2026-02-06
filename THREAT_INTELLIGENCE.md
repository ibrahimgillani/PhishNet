# PhishNet Threat Intelligence API

## Overview

PhishNet now includes comprehensive threat intelligence capabilities:

- **VirusTotal API** - Multi-engine URL scanning (70+ antivirus engines)
- **WHOIS Lookup** - Check domain registration age (new domains = suspicious)
- **PhishTank Database** - Known phishing URL database
- **Expanded Blacklist** - 100+ suspicious patterns and domains
- **ML Training System** - Collect data to fine-tune your own model

---

## API Endpoints

### 1. Threat Intelligence

#### Full Analysis
```
POST /api/scan/threat-intel
Content-Type: application/json

{
  "url": "http://suspicious-site.xyz/login"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "url": "http://suspicious-site.xyz/login",
    "isPhishing": true,
    "riskScore": 85,
    "riskLevel": "critical",
    "riskFactors": [
      "Domain registered 5 days ago (very new)",
      "High-risk TLD: .xyz",
      "VirusTotal: 12/70 engines detected threat"
    ],
    "threats": [],
    "sources": ["Local Blacklist", "WHOIS Lookup", "VirusTotal", "PhishTank"],
    "details": {
      "blacklist": { "blacklisted": false },
      "patterns": { "suspicious": true, "matches": ["login.*verify"] },
      "whois": { "available": true, "ageInDays": 5 },
      "virusTotal": { "checked": true, "malicious": 12, "total": 70 },
      "phishTank": { "checked": true, "isPhishing": false }
    }
  }
}
```

#### Get Statistics
```
GET /api/scan/threat-intel/stats
```

#### Add to Blacklist
```
POST /api/scan/threat-intel/blacklist
Content-Type: application/json

{
  "domain": "malicious-site.xyz"
}
```

---

### 2. ML Training System

#### Add Phishing Sample
```
POST /api/scan/training/sample/phishing
Content-Type: application/json

{
  "text": "Urgent: Your account has been suspended. Click here to verify: http://fake-bank.xyz",
  "source": "user_report",
  "confidence": 1.0
}
```

#### Add Legitimate Sample
```
POST /api/scan/training/sample/legitimate
Content-Type: application/json

{
  "text": "Your order #12345 has shipped. Track your package on our website.",
  "source": "verified",
  "confidence": 1.0
}
```

#### Add URL Sample
```
POST /api/scan/training/sample/url
Content-Type: application/json

{
  "url": "http://fake-paypal-login.xyz",
  "isPhishing": true,
  "riskFactors": ["typosquatting", "suspicious TLD"]
}
```

#### Record Feedback (for model improvement)
```
POST /api/scan/training/feedback
Content-Type: application/json

{
  "input": "Email content that was misclassified...",
  "predictedLabel": "legitimate",
  "correctLabel": "phishing",
  "inputType": "email"
}
```

#### Get Training Data Stats
```
GET /api/scan/training/data
```

**Response:**
```json
{
  "success": true,
  "data": {
    "stats": {
      "phishingSamples": 150,
      "legitimateSamples": 200,
      "urlSamples": 75,
      "feedbackEntries": 25,
      "totalEmailSamples": 350
    },
    "improvementSuggestions": {
      "accuracy": "92.5%",
      "falsePositives": 3,
      "falseNegatives": 5,
      "suggestions": ["Model is missing phishing - consider adding more phishing samples"]
    }
  }
}
```

#### Export Training Data
```
POST /api/scan/training/export
Content-Type: application/json

{
  "format": "csv"  // Options: "csv", "json", "huggingface"
}
```

#### Get Improvement Suggestions
```
GET /api/scan/training/suggestions
```

---

## Configuration

### Environment Variables (.env)

```bash
# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your_api_key_here
PHISHTANK_API_KEY=your_api_key_here

# Enable training data collection
TRAINING_DATA_COLLECTION=true
```

### API Key Registration

1. **VirusTotal** (Free tier: 4 requests/minute, 500/day)
   - Register at: https://www.virustotal.com/gui/my-apikey
   - Provides multi-engine malware/phishing scanning

2. **PhishTank** (Free, optional for higher limits)
   - Register at: https://phishtank.org/api_register.php
   - Provides known phishing URL database

---

## Features Explained

### 1. VirusTotal Integration
Scans URLs against 70+ antivirus engines simultaneously. Each detection adds to the risk score.

### 2. WHOIS Domain Age Check
Uses RDAP (Registration Data Access Protocol) to check when a domain was registered:
- < 7 days: **Very Suspicious** (+25 risk score)
- < 30 days: **Suspicious** (+15 risk score)
- < 90 days: **Caution** (+5 risk score)
- > 365 days: Established domain (safety indicator)

### 3. PhishTank Database
Checks if a URL is in the PhishTank database of known phishing sites. Verified phishing URLs add +40 to risk score.

### 4. Expanded Blacklist
Local database of 100+ known malicious domains including:
- PayPal, Amazon, Microsoft, Google impersonators
- Banking phishing domains
- Cryptocurrency scam domains
- Social media phishing

### 5. Pattern Detection
Regex-based detection of suspicious URL patterns:
- Brand impersonation with character substitution (paypa1, amaz0n, g00gle)
- Urgency words (urgent, immediate, suspended)
- Credential harvesting patterns (verify, login, password)
- Prize/lottery scams

### 6. ML Training System
Collect your own training data to fine-tune the model:
- Add phishing/legitimate email samples
- Record user feedback on misclassifications
- Export data in CSV, JSON, or HuggingFace format
- Get suggestions for model improvement

---

## Training Data Location

Training data is stored in: `training_data/`

```
training_data/
├── phishing_samples.jsonl
├── legitimate_samples.jsonl
├── url_samples.jsonl
├── user_feedback.jsonl
└── exports/
    ├── email_training_2024-01-15.csv
    └── huggingface_dataset_2024-01-15.json
```

---

## Risk Score Calculation

| Source | Risk Points |
|--------|-------------|
| Blacklisted domain | +50 |
| VirusTotal detection | +10 per engine (max 40) |
| PhishTank match | +40 |
| Domain < 7 days old | +25 |
| Domain < 30 days old | +15 |
| Suspicious pattern | +15 per match |
| High-risk TLD (.xyz, .tk) | +15 |
| Typosquatting detected | +40 |
| SSL issue | +25 |
| Whitelisted domain | -50 (bonus) |

**Risk Levels:**
- **Critical** (70-100): Confirmed threat
- **High** (50-69): Likely phishing
- **Medium** (30-49): Use caution
- **Low** (0-29): Likely safe
