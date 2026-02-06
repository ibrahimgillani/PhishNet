# 🚀 Quick Start Reference

## ⚡ 30-Second Setup

```bash
# 1. Install dependencies
npm install

# 2. Setup environment
cp .env.example .env

# 3. Start server
npm start

# 4. Test it
curl http://localhost:3000/health
```

## 🧪 Common API Calls

### Scan Email
```bash
curl -X POST http://localhost:3000/api/scan/email \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Verify Your Account",
    "body": "Click [LINK] to verify your credentials"
  }'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "isPhishing": true,
    "classification": "phishing",
    "confidence": "94.32%",
    "riskLevel": "critical"
  }
}
```

### Scan URL
```bash
curl -X POST http://localhost:3000/api/scan/scan-url \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.com",
    "subject": "Important Update",
    "body": "Click the link above"
  }'
```

### Batch Scan
```bash
curl -X POST http://localhost:3000/api/scan/batch \
  -H "Content-Type: application/json" \
  -d '{
    "emails": [
      {"subject": "Invoice", "body": "Please review"},
      {"subject": "URGENT", "body": "Click [LINK] now"}
    ]
  }'
```

### Get Model Info
```bash
curl http://localhost:3000/api/scan/model-info
```

### Health Check
```bash
curl http://localhost:3000/health
```

## 📁 Important Files

| File | Purpose |
|------|---------|
| `server.js` | Main server |
| `models/phishing-detector.js` | AI model |
| `routes/scan.js` | API endpoints |
| `.env` | Configuration |
| `package.json` | Dependencies |

## 🔧 Common Tasks

### Change Port
Edit `.env`:
```env
PORT=3001
```

### Use Local Model
Edit `.env`:
```env
LOCAL_MODEL_PATH=./PhishingDistilBERT
```

### Update CORS
Edit `.env`:
```env
CORS_ORIGIN=http://localhost:5000,http://your-domain.com
```

### Run Tests
```bash
npm test
```

### Development Mode
```bash
npm run dev
```

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| Port already in use | Change PORT in `.env` |
| CORS error | Update CORS_ORIGIN in `.env` |
| Model download slow | First time takes 1-5 min |
| Out of memory | Restart server (quantized model enabled) |
| Dependencies not found | Run `npm install` again |

## 📊 Classification Codes

```
Classification: "phishing" or "legitimate"
Risk Levels:
  - "low": < 30% confidence
  - "medium": 30-60% confidence
  - "high": 60-85% confidence
  - "critical": > 85% confidence
```

## 🔌 Endpoints Summary

```
GET  /health              - Server status
GET  /                    - API info
POST /api/scan/email      - Scan email
POST /api/scan/scan-url   - Scan URL
POST /api/scan/domain     - Scan domain
POST /api/scan/batch      - Batch scan
GET  /api/scan/model-info - Model details
```

## 💻 Frontend Integration

```javascript
// Scan email
const response = await fetch('http://localhost:3000/api/scan/email', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    subject: 'Email Subject',
    body: 'Email body content'
  })
});

const result = await response.json();
console.log(result.data.isPhishing); // true/false
console.log(result.data.confidence); // "94.32%"
console.log(result.data.riskLevel);  // "critical"
```

## 🚀 Deployment Commands

### Render
```bash
git push heroku main
```

### Docker
```bash
docker build -t phishnet .
docker run -p 3000:3000 phishnet
```

### Vercel
```bash
npm run build
vercel deploy
```

## 📚 Documentation

- [MODEL_INTEGRATION_GUIDE.md](./MODEL_INTEGRATION_GUIDE.md) - Full setup
- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design
- [INTEGRATION_COMPLETE.md](./INTEGRATION_COMPLETE.md) - What's included

## 🎯 Next Steps

1. ✅ Install: `npm install`
2. ✅ Setup: `cp .env.example .env`
3. ✅ Test: `npm test`
4. ✅ Run: `npm start`
5. ✅ Integrate with frontend
6. ✅ Deploy to production

---

**Need help?** Check [MODEL_INTEGRATION_GUIDE.md](./MODEL_INTEGRATION_GUIDE.md) for detailed documentation.
