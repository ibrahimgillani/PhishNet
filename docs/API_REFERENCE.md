# 🔌 PhishNet API Endpoints Reference

## Base URL
```
http://localhost:3000/api
```

All protected endpoints require:
```
Authorization: Bearer <JWT_TOKEN>
```

---

## 📋 Authentication Endpoints

### 1. Register User
```http
POST /auth/register
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!"
}
```
**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": { /* user profile */ },
    "token": "eyJhbGciOiJIUzI1NiIs..."
  }
}
```

### 2. Login User
```http
POST /auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```
**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": { /* user profile */ },
    "token": "eyJhbGciOiJIUzI1NiIs..."
  }
}
```

### 3. Logout User [PROTECTED]
```http
POST /auth/logout
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

### 4. Verify Token [PROTECTED]
```http
POST /auth/verify
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Token is valid",
  "data": {
    "user": { /* user profile */ }
  }
}
```

### 5. Refresh Token [PROTECTED]
```http
POST /auth/refresh
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "token": "new_jwt_token"
  }
}
```

---

## 🔗 URL Scanning Endpoints

### 1. Check URL Safety
```http
POST /scan/url
Content-Type: application/json

{
  "url": "https://example.com"
}
```
**Response:**
```json
{
  "success": true,
  "message": "URL is safe",
  "data": {
    "url": "https://example.com",
    "domain": "example.com",
    "isSafe": true,
    "threatType": "safe",
    "threatLevel": "safe",
    "confidence": 95,
    "recommendation": "This URL appears to be safe...",
    "checkId": "507f1f77bcf86cd799439011"
  }
}
```

### 2. Check Email Safety
```http
POST /scan/email
Content-Type: application/json

{
  "senderEmail": "sender@example.com",
  "emailContent": "Click here: https://suspicious-site.com",
  "subject": "Verify your account"
}
```
**Response:**
```json
{
  "success": true,
  "message": "Email contains suspicious elements",
  "data": {
    "isSafe": false,
    "senderEmail": "sender@example.com",
    "senderDomain": "example.com",
    "isSuspiciousSender": false,
    "urlsFound": 1,
    "urlChecks": [
      {
        "url": "https://suspicious-site.com",
        "isSafe": false,
        "threatType": "phishing"
      }
    ],
    "recommendation": "This email shows signs of being a phishing attempt..."
  }
}
```

### 3. Batch Check URLs [PROTECTED]
```http
POST /scan/batch
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "urls": [
    "https://example1.com",
    "https://example2.com",
    "https://example3.com"
  ]
}
```
**Response:**
```json
{
  "success": true,
  "message": "Batch check complete. 2 safe, 1 unsafe.",
  "data": {
    "total": 3,
    "safeCount": 2,
    "unsafeCount": 1,
    "results": [
      {
        "url": "https://example1.com",
        "domain": "example1.com",
        "isSafe": true,
        "threatType": "safe",
        "threatLevel": "safe",
        "confidence": 95
      }
    ]
  }
}
```

---

## 👤 User Profile Endpoints [ALL PROTECTED]

### 1. Get User Profile
```http
GET /users/profile
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Profile retrieved successfully",
  "data": {
    "user": {
      "id": "507f1f77bcf86cd799439011",
      "firstName": "John",
      "lastName": "Doe",
      "email": "john@example.com",
      "isVerified": true,
      "lastLogin": "2026-01-13T10:30:00Z",
      "createdAt": "2026-01-01T00:00:00Z",
      "safeWebsitesVisited": 150,
      "unsafeUrlsDetected": 12,
      "phishingUrlsDetected": 8,
      "threatUrlsDetected": 4,
      "totalProtectionWarnings": 24,
      "totalUrlsChecked": 162,
      "protectionRatio": 13.58
    }
  }
}
```

### 2. Update User Profile
```http
PUT /users/profile
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "firstName": "Johnny",
  "lastName": "Doe",
  "email": "johnny@example.com"
}
```
**Response:** Same as Get Profile

### 3. Update Password
```http
PUT /users/password
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "currentPassword": "OldPass123!",
  "newPassword": "NewPass456!",
  "confirmPassword": "NewPass456!"
}
```
**Response:**
```json
{
  "success": true,
  "message": "Password changed successfully. Please login again."
}
```

### 4. Update Preferences
```http
PUT /users/preferences
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "emailNotifications": true,
  "weeklyReportEmail": false,
  "twoFactorEnabled": false
}
```
**Response:**
```json
{
  "success": true,
  "message": "Preferences updated successfully",
  "data": {
    "preferences": {
      "emailNotifications": true,
      "weeklyReportEmail": false,
      "twoFactorEnabled": false
    }
  }
}
```

### 5. Get Check History
```http
GET /users/history?page=1&limit=20&threatType=phishing&isSafe=false
Authorization: Bearer <JWT_TOKEN>
```
**Query Parameters:**
- `page` (default: 1)
- `limit` (default: 20)
- `threatType` (optional: safe, phishing, malware, unsafe, suspicious, unknown)
- `isSafe` (optional: true, false)

**Response:**
```json
{
  "success": true,
  "message": "Check history retrieved successfully",
  "data": {
    "history": [
      {
        "_id": "507f1f77bcf86cd799439011",
        "url": "https://example.com",
        "domain": "example.com",
        "isSafe": false,
        "threatType": "phishing",
        "threatLevel": "high",
        "checkedAt": "2026-01-13T10:30:00Z"
      }
    ],
    "pagination": {
      "total": 100,
      "page": 1,
      "limit": 20,
      "pages": 5
    }
  }
}
```

### 6. Get Threat Statistics
```http
GET /users/stats
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "User statistics retrieved successfully",
  "data": {
    "stats": {
      "totalChecks": 162,
      "safeUrls": 150,
      "unsafeUrls": 12,
      "phishingDetected": 8,
      "malwareDetected": 0,
      "warningsTriggered": 24
    },
    "userMetrics": {
      "safeWebsitesVisited": 150,
      "unsafeUrlsDetected": 12,
      "phishingUrlsDetected": 8,
      "threatUrlsDetected": 4,
      "totalProtectionWarnings": 24,
      "totalUrlsChecked": 162,
      "protectionRatio": 13.58
    }
  }
}
```

### 7. Get Recent Activity
```http
GET /users/activity?days=7
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Recent activity retrieved successfully",
  "data": {
    "days": 7,
    "activity": [
      {
        "url": "https://example.com",
        "domain": "example.com",
        "isSafe": true,
        "threatType": "safe",
        "checkedAt": "2026-01-13T10:30:00Z",
        "userWarned": false,
        "userAction": "pending"
      }
    ]
  }
}
```

### 8. Delete Account
```http
DELETE /users/account
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "password": "SecurePass123!"
}
```
**Response:**
```json
{
  "success": true,
  "message": "Account deleted successfully"
}
```

---

## 📊 Analytics Endpoints [ALL PROTECTED]

### 1. Get Dashboard Data
```http
GET /analytics/dashboard
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Dashboard data retrieved successfully",
  "data": {
    "platformMetrics": {
      "overview": {
        "totalUsers": 5000,
        "activeUsers": 1200,
        "totalUrlsChecked": 500000,
        "totalProtectionWarnings": 45000
      },
      "threats": {
        "phishingUrls": 8500,
        "unsafeUrls": 6200,
        "threatUrls": 3100,
        "totalThreatsDetected": 17800
      },
      "safeWebsites": 482200,
      "platformThreatDetectionRate": 3.56,
      "topPhishingDomains": [
        {
          "domain": "phishing-bank.com",
          "detectionCount": 450,
          "lastDetected": "2026-01-13T15:45:00Z"
        }
      ]
    },
    "userMetrics": {
      "safeWebsitesVisited": 150,
      "unsafeUrlsDetected": 12,
      "phishingUrlsDetected": 8,
      "threatUrlsDetected": 4,
      "totalProtectionWarnings": 24,
      "totalUrlsChecked": 162,
      "protectionRatio": 13.58
    }
  }
}
```

### 2. Get Trending Data
```http
GET /analytics/trends?days=30
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Trending data retrieved successfully",
  "data": {
    "days": 30,
    "trends": [
      {
        "date": "2026-01-01",
        "urlsChecked": 150,
        "threatsDetected": 12,
        "protectionWarnings": 12,
        "activeUsers": 500,
        "newUsers": 10
      }
    ],
    "summary": {
      "totalUrlsChecked": 5000,
      "totalThreatsDetected": 500,
      "averageUrlsPerDay": 167,
      "averageThreatsPerDay": 17
    }
  }
}
```

### 3. Get Platform Summary
```http
GET /analytics/summary
Authorization: Bearer <JWT_TOKEN>
```
**Response:** Same as dashboard platform metrics

### 4. Get Top Phishing Domains
```http
GET /analytics/top-domains?limit=10
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Top phishing domains retrieved successfully",
  "data": {
    "topDomains": [
      {
        "_id": "phishing-bank.com",
        "detectionCount": 450,
        "threatTypes": ["phishing"],
        "lastDetected": "2026-01-13T15:45:00Z"
      }
    ],
    "totalDomains": 1
  }
}
```

### 5. Get Dangerous URLs Today
```http
GET /analytics/dangerous-today
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Dangerous URLs detected today retrieved successfully",
  "data": {
    "count": 25,
    "urls": [
      {
        "url": "https://phishing-site.com",
        "isSafe": false,
        "threatType": "phishing",
        "checkedAt": "2026-01-13T10:30:00Z"
      }
    ]
  }
}
```

### 6. Get User Rankings
```http
GET /analytics/rankings?type=urls_checked&limit=10
Authorization: Bearer <JWT_TOKEN>
```
**Query Parameters:**
- `type`: urls_checked, threats_detected, protection
- `limit` (default: 10)

**Response:**
```json
{
  "success": true,
  "message": "User rankings retrieved successfully",
  "data": {
    "type": "urls_checked",
    "label": "Most URLs Checked",
    "rankings": [
      {
        "rank": 1,
        "name": "John Doe",
        "email": "john@example.com",
        "value": 500,
        "joinedAt": "2026-01-01T00:00:00Z"
      }
    ]
  }
}
```

### 7. Get Threat Distribution
```http
GET /analytics/threat-distribution
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Threat distribution retrieved successfully",
  "data": {
    "distribution": [
      {
        "threatType": "phishing",
        "count": 8500,
        "percentage": 47.75
      },
      {
        "threatType": "malware",
        "count": 6200,
        "percentage": 34.83
      }
    ],
    "totalThreats": 17800
  }
}
```

### 8. Get Recent Activity (Platform)
```http
GET /analytics/recent-activity?limit=20
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Recent platform activity retrieved successfully",
  "data": {
    "activity": [
      {
        "domain": "phishing-site.com",
        "threatType": "phishing",
        "threatLevel": "high",
        "checkedAt": "2026-01-13T15:45:00Z",
        "userWarned": true,
        "userId": {
          "firstName": "John",
          "lastName": "Doe",
          "email": "john@example.com"
        }
      }
    ],
    "count": 1
  }
}
```

### 9. Get Analytics Overview
```http
GET /analytics/overview
Authorization: Bearer <JWT_TOKEN>
```
**Response:**
```json
{
  "success": true,
  "message": "Analytics overview retrieved successfully",
  "data": {
    "overview": {
      "totalUsers": 5000,
      "activeUsers": 1200,
      "totalUrlsChecked": 500000,
      "totalThreatsDetected": 17800,
      "totalProtectionWarnings": 45000,
      "platformThreatDetectionRate": 3.56
    },
    "last7Days": {
      "totalChecks": 5000,
      "avgPerDay": 714,
      "percentageChange": 12.5
    },
    "topDomains": [
      {
        "domain": "phishing-bank.com",
        "detectionCount": 450
      }
    ]
  }
}
```

---

## 🏥 Health Check

### Server Health
```http
GET /health
```
**Response:**
```json
{
  "status": "Server is running",
  "timestamp": "2026-01-13T16:00:00Z",
  "environment": "development"
}
```

---

## ⚠️ Error Responses

### Validation Error
```json
{
  "success": false,
  "message": "Validation error",
  "errors": [
    "Email is required",
    "Password must be at least 8 characters"
  ]
}
```

### Authentication Error
```json
{
  "success": false,
  "message": "Invalid email or password"
}
```

### Unauthorized (No Token)
```json
{
  "success": false,
  "message": "No authentication token, access denied"
}
```

### Token Expired
```json
{
  "success": false,
  "message": "Token has expired"
}
```

---

## 📝 Request Examples Using cURL

### Register
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "confirmPassword": "SecurePass123!"
  }'
```

### Login
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### Check URL (Save Token from Login Response)
```bash
curl -X POST http://localhost:3000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Get Profile (With Token)
```bash
curl -X GET http://localhost:3000/api/users/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

### Get Dashboard (With Token)
```bash
curl -X GET http://localhost:3000/api/analytics/dashboard \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

---

## 🔐 Token Handling

1. Register or Login to get a JWT token
2. Add token to every protected request:
   ```
   Authorization: Bearer <token>
   ```
3. Token expires after 7 days
4. Use `/auth/refresh` to get a new token
5. Token is automatically invalidated on logout

---

**All endpoints are fully functional and ready to use!** ✅
