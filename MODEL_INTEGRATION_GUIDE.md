# ✅ Model Integration Complete - Quick Start Guide

## 🚀 Quick Setup

Your PhishingDistilBERT model has been successfully integrated! Follow these steps:

### 1. **Install Dependencies**
```bash
npm install
```

Or use the setup script:
- **Windows**: `setup.bat`
- **macOS/Linux**: `bash setup.sh`

### 2. **Configure Environment**

Copy and edit the `.env` file:
```bash
cp .env.example .env
```

Key configurations:
```env
PORT=3000
NODE_ENV=development
CORS_ORIGIN=http://localhost:5000,http://localhost:3000

# Model Configuration
MODEL_PATH=Gaykar/PhishingDistilBERT
# Or use local model:
# LOCAL_MODEL_PATH=./PhishingDistilBERT
```

### 3. **Start the Server**

**Development mode** (with hot reload):
```bash
npm run dev
```

**Production mode**:
```bash
npm start
```

### 4. **Test the API**

Once running, test these endpoints:

#### Health Check
```bash
curl http://localhost:3000/health
```

#### Scan URL
```bash
curl -X POST http://localhost:3000/api/scan/scan-url \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.com",
    "subject": "Verify Your Account"
  }'
```

#### Scan Email
```bash
curl -X POST http://localhost:3000/api/scan/email \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Verify Your Password",
    "body": "Click here to verify your account: [LINK]"
  }'
```

#### Batch Scan
```bash
curl -X POST http://localhost:3000/api/scan/batch \
  -H "Content-Type: application/json" \
  -d '{
    "emails": [
      {"subject": "Invoice #12345", "body": "Please review attached invoice"},
      {"subject": "Urgent Action Required", "body": "Click [LINK] to verify your account"}
    ]
  }'
```

#### Get Model Info
```bash
curl http://localhost:3000/api/scan/model-info
```

## 📁 Project Structure

```
PhishNet/
├── server.js                    # Main Express server
├── package.json                 # Node dependencies
├── .env.example                 # Environment template
├── models/
│   └── phishing-detector.js     # PhishingDistilBERT integration
├── routes/
│   ├── scan.js                  # Scanning endpoints
│   └── auth.js                  # Authentication endpoints
├── utils/
│   └── validators.js            # Utility functions
└── PhishingDistilBERT/          # Model files
    ├── config.json
    ├── model.safetensors
    ├── tokenizer.json
    └── ...
```

## 🎯 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/scan/scan-url` | POST | Scan a URL |
| `/api/scan/email` | POST | Scan an email |
| `/api/scan/domain` | POST | Scan a domain |
| `/api/scan/batch` | POST | Batch scan emails |
| `/api/scan/model-info` | GET | Get model information |

## 🔧 Model Features

The integrated PhishingDistilBERT model:

✅ **Specializes in email phishing detection**
✅ **Uses special tokens** for email structure:
- `[SSUB]` / `[ESUB]` - Subject delimiters
- `[SBODY]` / `[EBODY]` - Body delimiters
- `[LINK]` - URL replacement
- `[PHONE]` - Phone number replacement

✅ **Provides confidence scores** (0-1)
✅ **Classifies as**: Phishing or Legitimate
✅ **Calculates risk levels**: Low, Medium, High, Critical

## 📊 Response Format

```json
{
  "success": true,
  "data": {
    "isPhishing": true,
    "classification": "phishing",
    "confidence": "92.45%",
    "confidenceScore": 0.9245,
    "riskLevel": "critical",
    "allPredictions": [
      {"label": "phishing", "score": 0.9245, "confidence": "92.45%"},
      {"label": "legitimate", "score": 0.0755, "confidence": "7.55%"}
    ],
    "timestamp": "2026-02-06T10:30:00.000Z"
  }
}
```

## 🌐 Frontend Integration

Update `config.js` to point to your backend:

```javascript
// config.js
const API_BASE_URL = 'http://localhost:3000';

// Or set in HTML before loading config.js:
// <script>
//   window.API_BASE_URL = 'http://localhost:3000';
// </script>
// <script src="config.js"></script>
```

## 🚀 Deployment

### Using Render.com (Free)

1. Push to GitHub
2. Connect to Render
3. Set environment variables
4. Deploy

### Using Heroku

```bash
heroku create your-app-name
git push heroku main
heroku config:set JWT_SECRET=your_secret
```

### Using Docker

```bash
docker build -t phishnet .
docker run -p 3000:3000 phishnet
```

## 🐛 Troubleshooting

**Model download slow?**
- The model (~500MB) downloads on first run
- Internet connection required
- Or use local model path in `.env`

**Port already in use?**
```bash
# Change PORT in .env
PORT=3001
```

**CORS errors?**
- Update `CORS_ORIGIN` in `.env`
- Add your frontend URL

**Model loading errors?**
- Check internet connection
- Verify Node.js version >= 14
- Check console for detailed errors

## 📖 Documentation

- [Hugging Face Model](https://huggingface.co/Gaykar/PhishingDistilBERT)
- [Express.js Docs](https://expressjs.com/)
- [Transformers.js Docs](https://xenova.github.io/transformers.js/)

## ✨ Next Steps

1. ✅ Integrate with frontend (update API calls)
2. ✅ Add database for storing scan history
3. ✅ Implement user authentication
4. ✅ Add email webhook integration
5. ✅ Deploy to production

## 📞 Support

For issues or questions:
- Check `.gitignore` is set up
- Verify all dependencies installed
- Review server logs for errors
- Test API with curl or Postman

---

**Happy phishing detection! 🎣🛡️**
