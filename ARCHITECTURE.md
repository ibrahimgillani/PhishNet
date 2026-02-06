# 🏗️ PhishNet Architecture with DistilBERT Integration

## 📐 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       FRONTEND (HTML/JS)                        │
│  ┌────────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │ index.html     │  │ dashboard.html│  │ other pages...   │    │
│  │ login.html     │  │ reports.html  │  │                  │    │
│  └────────────────┘  └──────────────┘  └──────────────────┘    │
│           ↓                 ↓                      ↓             │
│  ┌────────────────────────────────────────────────────────┐     │
│  │          app.js (Client-side JavaScript)              │     │
│  │  - AuthManager     - ScanManager     - UI Handlers    │     │
│  └────────────────────────────────────────────────────────┘     │
│           ↓                 ↓                      ↓             │
│  ┌────────────────────────────────────────────────────────┐     │
│  │           config.js (API Configuration)               │     │
│  │  - API_BASE_URL: http://localhost:3000                │     │
│  │  - Endpoints: scan/email, scan/url, scan/domain       │     │
│  └────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                     HTTP/CORS Requests
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      BACKEND (Node.js)                          │
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐     │
│  │              server.js (Express Server)                │     │
│  │  - Middleware: CORS, Helmet, Rate Limiting             │     │
│  │  - Model initialization on startup                     │     │
│  │  - Error handling & logging                            │     │
│  └────────────────────────────────────────────────────────┘     │
│           ↓                 ↓                      ↓             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐   │
│  │   routes/        │  │   models/        │  │  utils/      │   │
│  │   scan.js        │  │ distil-detector  │  │ validators.js│   │
│  │                  │  │                  │  │              │   │
│  │ POST /scan/email │  │ Classify emails  │  │ Validate     │   │
│  │ POST /scan/url   │  │ Batch process    │  │ URLs         │   │
│  │ POST /scan/domain│  │ Risk calculation │  │ Domains      │   │
│  │ POST /scan/batch │  │ Feature extract  │  │ Emails       │   │
│  │                  │  │                  │  │              │   │
│  └──────────────────┘  └──────────────────┘  └──────────────┘   │
│           ↓                 ↓                                    │
│           └─────────────────┴────────────────────────────────┐  │
│                                                               ↓  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │   PhishingDistilBERT Model (Transformers.js)             │   │
│  │                                                           │   │
│  │  ┌─────────────────────────────────────────────────┐     │   │
│  │  │ Input Processing                               │     │   │
│  │  │  - Format: [SSUB] subject [ESUB] [SBODY]...   │     │   │
│  │  │  - Replace URLs with [LINK]                    │     │   │
│  │  │  - Replace phones with [PHONE]                 │     │   │
│  │  │  - Tokenize & truncate (max 512 tokens)        │     │   │
│  │  └─────────────────────────────────────────────────┘     │   │
│  │                          ↓                                │   │
│  │  ┌─────────────────────────────────────────────────┐     │   │
│  │  │ DistilBERT (6 layers, 12 heads)                │     │   │
│  │  │  - Fine-tuned on phishing email datasets       │     │   │
│  │  │  - Transformer attention mechanism            │     │   │
│  │  │  - Binary classification head                 │     │   │
│  │  └─────────────────────────────────────────────────┘     │   │
│  │                          ↓                                │   │
│  │  ┌─────────────────────────────────────────────────┐     │   │
│  │  │ Output                                          │     │   │
│  │  │  - Phishing probability: 0-1                   │     │   │
│  │  │  - Legitimate probability: 0-1                 │     │   │
│  │  │  - Classification: phishing/legitimate         │     │   │
│  │  │  - Risk level: low/medium/high/critical        │     │   │
│  │  └─────────────────────────────────────────────────┘     │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                          ↓                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Response Formatting                                      │   │
│  │  - success: true/false                                  │   │
│  │  - data: { isPhishing, classification, confidence... } │   │
│  │  - timestamp                                            │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              ↑
                     HTTP/JSON Responses
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                    FRONTEND RECEIVES RESULT                     │
│  - Update UI with classification                               │
│  - Show confidence score                                       │
│  - Display risk level                                          │
│  - Store in scan history                                       │
└─────────────────────────────────────────────────────────────────┘
```

## 🔄 Request Flow Example

### Email Scanning Flow:

```
1. User enters email in frontend
   ↓
2. Frontend sends POST /api/scan/email
   {subject: "...", body: "..."}
   ↓
3. Backend receives request
   ↓
4. Input validation in utils/validators.js
   ↓
5. routes/scan.js calls phishingDetector.classifyEmail()
   ↓
6. models/phishing-detector.js:
   - Preprocess text (replace URLs, phone numbers)
   - Format with special tokens
   - Tokenize using DistilBERT tokenizer
   ↓
7. Model inference:
   - Input → DistilBERT → Classification head
   - Output: [phishing_score, legitimate_score]
   ↓
8. Post-process results:
   - Calculate risk level
   - Extract features
   - Format response
   ↓
9. Send JSON response to frontend
   ↓
10. Frontend displays results
```

## 📦 Data Flow

### Input → Model → Output

```
┌─────────────────────────┐
│  Raw Email Input        │
│  Subject: "Verify..."   │
│  Body: "Click [LINK]"   │
└────────────┬────────────┘
             ↓
┌─────────────────────────────────────────┐
│  Text Preprocessing                     │
│  - URL replacement: [LINK]              │
│  - Phone: [PHONE]                       │
│  - Format: [SSUB]subject[ESUB][SBODY]...│
└────────────┬────────────────────────────┘
             ↓
┌─────────────────────────┐
│  Tokenization           │
│  (DistilBERT tokenizer) │
│  Max length: 512        │
└────────────┬────────────┘
             ↓
┌────────────────────────────────────────┐
│  Model Inference                       │
│  Input embeddings → 6 Transformer      │
│  layers → Classification head          │
└────────────┬───────────────────────────┘
             ↓
┌──────────────────────────────────────────┐
│  Model Output (Logits)                   │
│  [phishing_logit, legitimate_logit]      │
└────────────┬─────────────────────────────┘
             ↓
┌──────────────────────────────────────────┐
│  Post-processing                         │
│  - Apply softmax: [0.92, 0.08]          │
│  - Risk level: 0.92 → "critical"        │
│  - Classification: phishing              │
└────────────┬─────────────────────────────┘
             ↓
┌──────────────────────────────────────────┐
│  JSON Response                           │
│  {                                       │
│    success: true,                        │
│    isPhishing: true,                     │
│    confidence: "92%",                    │
│    riskLevel: "critical"                 │
│  }                                       │
└──────────────────────────────────────────┘
```

## 🛠️ Technology Stack

```
FRONTEND                 BACKEND              AI/ML
─────────────           ─────────────        ─────────────
HTML                    Node.js              DistilBERT
CSS                     Express.js           Transformers.js
JavaScript              Mongoose (DB opt.)   PyTorch (backend)
                        MongoDB (opt.)       
                        JWT (Auth)           
                        Helmet (Security)    
```

## 📊 API Endpoints Architecture

```
┌─ GET /health
│  └─ Health check response
│
├─ GET /
│  └─ API information
│
└─ /api/scan/ [Protected endpoints]
   ├─ POST /scan-url
   │  ├─ Input: {url, subject?, body?}
   │  └─ Output: Phishing classification
   │
   ├─ POST /email
   │  ├─ Input: {subject, body, sender?}
   │  └─ Output: Email classification
   │
   ├─ POST /domain
   │  ├─ Input: {domain, context?}
   │  └─ Output: Domain analysis
   │
   ├─ POST /batch
   │  ├─ Input: {emails: [...]}
   │  └─ Output: Array of classifications
   │
   └─ GET /model-info
      └─ Output: Model metadata
```

## 🔐 Security Layers

```
Request → Helmet Headers → CORS Check → Rate Limit → 
Validation → Processing → Response
```

## 📈 Performance Pipeline

```
User Request (T0)
     ↓
Server Receive (T0 + ~1ms)
     ↓
Validation (T0 + ~10ms)
     ↓
Preprocessing (T0 + ~50ms)
     ↓
Model Inference (T0 + ~500-1000ms) ← Most time here
     ↓
Post-processing (T0 + ~1050ms)
     ↓
Response Sent (T0 + ~1050ms)
     ↓
Frontend Render (T0 + ~1100ms)
```

## 🎯 Integration Points

```
┌──────────────────┐
│ Frontend Config  │
│ (config.js)      │
└────────┬─────────┘
         ↓
   ┌─────────────────────────────────┐
   │ API_BASE_URL = localhost:3000    │
   │ Endpoints configuration          │
   └─────────────┬───────────────────┘
                 ↓
          ┌─────────────────────────────────┐
          │ Server.js                        │
          │ (Express + Model Loading)        │
          └──────────┬──────────────────────┘
                     ↓
   ┌─────────────────────────────────────────────┐
   │ Routes (scan.js)                            │
   │  ├─ /api/scan/scan-url                     │
   │  ├─ /api/scan/email                        │
   │  ├─ /api/scan/domain                       │
   │  ├─ /api/scan/batch                        │
   │  └─ /api/scan/model-info                   │
   └──────────────┬────────────────────────────┘
                  ↓
        ┌──────────────────────────────┐
        │ Models (phishing-detector.js) │
        │ PhishingDistilBERT           │
        └──────────────────────────────┘
```

## ✨ Model Processing Steps

```
Email Input
    ↓
1. Preprocessing
   - Remove extra whitespace
   - Replace URLs → [LINK]
   - Replace phones → [PHONE]
    ↓
2. Formatting
   - Add [SSUB]subject[ESUB]
   - Add [SBODY]body[EBODY]
    ↓
3. Tokenization
   - Convert to token IDs
   - Add [CLS], [SEP] tokens
   - Pad/truncate to 512
    ↓
4. Model Inference
   - DistilBERT encoder
   - Attention layers
   - Classification head
    ↓
5. Post-processing
   - Softmax normalization
   - Get probabilities
   - Determine risk level
    ↓
Classification Result
```

---

**This architecture enables real-time phishing detection with high accuracy!** 🎯

For more details, see:
- [MODEL_INTEGRATION_GUIDE.md](./MODEL_INTEGRATION_GUIDE.md)
- [INTEGRATION_COMPLETE.md](./INTEGRATION_COMPLETE.md)
