# PhishNet Database Schema Documentation

## Overview
This document outlines the MongoDB schema design for the PhishNet website, a phishing protection platform. The schema is designed with security, scalability, and analytics in mind.

---

## 1. User Collection (`users`)

### Purpose
Stores all user account information, authentication data, and per-user safety metrics.

### Key Fields

#### Basic Information
- **firstName** (String): User's first name (2-50 characters)
- **lastName** (String): User's last name (2-50 characters)
- **email** (String, Unique, Indexed): User's email address (validated format)

#### Authentication & Security
- **passwordHash** (String, Hidden by default): Bcrypt hashed password (min 8 characters)
- **jwtTokens** (Array): Active JWT tokens with creation timestamps
  - Auto-expires after 7 days
  - Enables token rotation and multiple device support
- **isVerified** (Boolean): Email verification status
- **verificationToken** (String): Token for email verification
- **verificationTokenExpiry** (Date): Expiration time for verification token
- **passwordResetToken** (String): Token for password reset
- **passwordResetExpiry** (Date): Expiration time for reset token

#### Account Activity
- **lastLogin** (Date): Timestamp of last login
- **isActive** (Boolean, Indexed): Account active status
- **loginAttempts** (Number): Failed login attempt counter
- **accountLockedUntil** (Date): Account lock timestamp (auto-unlock after 30 minutes)

#### User Safety Metrics (Per-User Analytics)
- **safeWebsitesVisited** (Number): Count of safe websites visited
- **unsafeUrlsDetected** (Number): Count of unsafe URLs detected
- **phishingUrlsDetected** (Number): Count of phishing URLs detected
- **threatUrlsDetected** (Number): Count of threat URLs detected
- **totalProtectionWarnings** (Number): Count of times user was warned
- **totalUrlsChecked** (Number, Indexed): Sum of all URL checks
- **protectionRatio** (Number): Percentage of threats detected vs total checks

#### Preferences
- **preferences** (Object):
  - `emailNotifications` (Boolean): Enable/disable email notifications
  - `weeklyReportEmail` (Boolean): Enable/disable weekly security report
  - `twoFactorEnabled` (Boolean): 2FA status

#### Audit Trail
- **ipAddresses** (Array): List of IP addresses used for login
  - Tracks last seen timestamp
- **createdAt** (Date, Indexed): Account creation timestamp
- **updatedAt** (Date): Last update timestamp

### Indexes
```
- email (unique)
- { email: 1, isActive: 1 }
- createdAt (descending)
- totalUrlsChecked (descending) - for leaderboards
```

### Key Methods
- `comparePassword(plainPassword)`: Verify password during login
- `generateJWTToken(secret, expiresIn)`: Generate JWT token
- `addJWTToken(token)`: Add new token to active tokens list
- `updateMetrics(metrics)`: Safely update user safety metrics
- `lockAccount(minutes)`: Lock account after failed attempts
- `unlockAccount()`: Unlock account
- `getProfile()`: Get safe user profile (excludes sensitive data)

### Security Features
- Passwords are hashed with bcrypt (salt rounds: 10)
- Sensitive fields hidden by default (passwordHash, tokens)
- Automatic account locking after failed login attempts
- JWT token expiration and rotation support
- Email validation and verification

---

## 2. Analytics Collection (`analytics`)

### Purpose
Stores platform-wide aggregated statistics and trends. Singleton pattern (typically one document).

### Key Fields

#### Platform Metrics (Aggregated)
- **totalUsersOnboarded** (Number): Total users registered
- **activeUsers** (Number): Currently active users
- **totalPhishingUrlsDetected** (Number): Platform-wide phishing count
- **totalUnsafeUrlsDetected** (Number): Platform-wide unsafe URL count
- **totalThreatUrlsDetected** (Number): Platform-wide threat count
- **totalSafeWebsitesVisited** (Number): Total safe website visits
- **totalProtectionWarnings** (Number): Total user warnings issued
- **totalUrlsChecked** (Number): Total URLs checked on platform
- **platformThreatDetectionRate** (Number): Overall threat detection percentage

#### Daily Statistics
- **dailyStats** (Array of Objects): Time-series data
  - `date` (Date, Indexed): Date of statistics
  - `usersOnboardedToday` (Number)
  - `urlsCheckedToday` (Number)
  - `threatsDetectedToday` (Number)
  - `protectionWarningsToday` (Number)
  - `activeUsersToday` (Number)
  - Kept for last 90 days

#### Threat Intelligence
- **topPhishingDomains** (Array): Top 50 most dangerous domains
  - `domain` (String)
  - `detectionCount` (Number)
  - `lastDetected` (Date)

#### Performance Metrics
- **averageResponseTime** (Number): Average check processing time (ms)
- **systemUptime** (Number): System uptime percentage
- **lastUpdated** (Date, Indexed): Last update timestamp

### Indexes
```
- lastUpdated (descending)
- { dailyStats.date: -1 }
```

### Key Methods
- `getAnalytics()`: Static method to get or create singleton document
- `updatePlatformMetrics(userMetrics)`: Update aggregated metrics
- `updateDailyStats(dailyMetrics)`: Add/update daily statistics
- `updateTopPhishingDomains(domain)`: Track dangerous domains
- `getDashboardSummary()`: Get formatted data for admin dashboard
- `getTrendingData(days)`: Get trending data for specified period

### Use Cases
- Admin dashboard displays
- Real-time platform statistics
- Trending analysis (30-day, 90-day trends)
- System health monitoring

---

## 3. URL Check History Collection (`urlCheckHistory`)

### Purpose
Tracks individual URL checks for audit trail, detailed analytics, and threat intelligence.

### Key Fields

#### Check Metadata
- **userId** (ObjectId, Indexed, Ref: User): User who performed check
- **url** (String): Full URL checked (lowercase, trimmed)
- **domain** (String, Indexed): Domain extracted from URL

#### Threat Assessment
- **isSafe** (Boolean): Safety classification
- **threatType** (String, Indexed): Enum - ['safe', 'phishing', 'malware', 'unsafe', 'suspicious', 'unknown']
- **threatLevel** (String): Severity - ['safe', 'low', 'medium', 'high', 'critical']
- **threatCategories** (Array of Strings): Specific threat types
- **threatsDetected** (Array): Detailed threat information
  - `name`: Threat name
  - `severity`: Threat severity
  - `description`: Threat description

#### Detection Information
- **detectionSource** (String): How threat was detected
  - Enum: ['database', 'api', 'machine_learning', 'user_report']
- **confidence** (Number): Confidence percentage (0-100)

#### User Response
- **userWarned** (Boolean): Whether user was warned
- **warningType** (String): Type of warning - ['none', 'banner', 'modal', 'block']
- **userAction** (String): User's action after warning
  - Enum: ['proceeded', 'blocked', 'reported', 'whitelisted', 'pending']

#### Timestamps
- **checkedAt** (Date, Indexed): When URL was checked
- **createdAt** (Date, Indexed, TTL=1 year): Auto-delete after 1 year for GDPR compliance

### Indexes
```
- { userId: 1, checkedAt: -1 }
- { domain: 1, threatType: 1 }
- checkedAt (descending)
- { isSafe: 1, checkedAt: -1 }
- { threatType: 1, checkedAt: -1 }
- createdAt (TTL = 365 days) - auto-delete old records
```

### Key Methods
- `getUserHistory(userId, filters, limit, skip)`: Get user's check history with filtering
- `getDangerousUrlsToday()`: Get all dangerous URLs detected today
- `getMostDangerousDomains(limit, days)`: Aggregate dangerous domains
- `getUserThreatStats(userId)`: Get user's threat statistics

---

## 4. Database Schema Design Best Practices Applied

### Performance Optimization
1. **Indexing Strategy**
   - Single field indexes for frequent queries
   - Compound indexes for common filter combinations
   - TTL indexes for automatic data cleanup

2. **Denormalization**
   - User metrics denormalized in User collection for fast reads
   - Platform metrics aggregated in Analytics collection
   - Avoids expensive joins (MongoDB native limitation)

3. **Time-Series Data**
   - Daily stats stored as embedded array (hot data)
   - Auto-cleanup of old records (90-day retention)
   - Separate TTL index for URL history (1 year retention)

### Security Best Practices
1. **Password Security**
   - Bcrypt hashing with salt rounds: 10
   - Passwords selected out by default
   - Never log or expose password hashes

2. **Authentication**
   - JWT tokens with expiration
   - Token rotation support
   - Separate verification and reset tokens

3. **Data Validation**
   - Field-level validation (type, length, format)
   - Enum validation for threat types
   - Email format validation

4. **Audit Trail**
   - Timestamps on all documents
   - IP address tracking
   - Login attempt monitoring

### Scalability Considerations
1. **Document Size**
   - User documents: ~2-5KB (efficient)
   - Daily stats array capped at 90 days
   - URL history records: ~1-2KB each

2. **Query Patterns**
   - Indexed fields for all common filters
   - Aggregation pipelines for analytics
   - Pagination support for large result sets

3. **Data Retention**
   - URL history: Auto-delete after 1 year
   - Daily stats: Keep 90 days
   - User data: Indefinite (with deletion option)

---

## 5. Setup Instructions

### Environment Configuration
1. Create `.env` file (copy from `.env.example`)
2. Add MongoDB Atlas URI
3. Configure JWT secret
4. Set bcrypt rounds

### MongoDB Atlas Setup
1. Create cluster on MongoDB Atlas
2. Create database: `phishnet`
3. Add connection string to `.env`
4. Create indexes (Mongoose auto-creates them)

### Connection Example
```javascript
const { connectDB } = require('./config/database');
const User = require('./models/User');
const Analytics = require('./models/Analytics');
const URLCheckHistory = require('./models/URLCheckHistory');

// Connect to database
await connectDB();

// Schemas are now ready to use
```

---

## 6. Query Examples

### Create User
```javascript
const user = await User.create({
  firstName: 'John',
  lastName: 'Doe',
  email: 'john@example.com',
  passwordHash: 'plain_password_here', // Auto-hashed on save
});
```

### Update User Metrics
```javascript
await user.updateMetrics({
  safeWebsites: 5,
  phishingUrls: 2,
  protectionWarnings: 2,
});
```

### Track URL Check
```javascript
const checkRecord = await URLCheckHistory.create({
  userId: userId,
  url: 'https://dangerous-site.com',
  domain: 'dangerous-site.com',
  isSafe: false,
  threatType: 'phishing',
  threatLevel: 'critical',
  userWarned: true,
  warningType: 'modal',
});
```

### Update Platform Analytics
```javascript
const analytics = await Analytics.getAnalytics();
await analytics.updatePlatformMetrics({
  newUsersCount: 1,
  phishingUrls: 2,
  protectionWarnings: 2,
});
await analytics.updateDailyStats({
  urlsChecked: 10,
  threatsDetected: 2,
});
```

### Get User Check History
```javascript
const history = await URLCheckHistory.getUserHistory(
  userId,
  { threatType: 'phishing', isSafe: false },
  50, // limit
  0   // skip
);
```

### Get Dashboard Summary
```javascript
const analytics = await Analytics.getAnalytics();
const summary = analytics.getDashboardSummary();
```

---

## 7. Database Maintenance

### Regular Tasks
1. **Monitor Index Performance**
   - Check slow query logs in MongoDB Atlas
   - Add indexes if needed

2. **Data Cleanup**
   - TTL index automatically deletes old URL history
   - Monitor daily stats array size

3. **Backup Strategy**
   - Use MongoDB Atlas automated backups
   - Backup frequency: Daily
   - Retention: 35 days

4. **Security Audits**
   - Rotate JWT secrets periodically
   - Review user IP addresses
   - Monitor failed login attempts

---

## 8. Scalability Roadmap

### Phase 1: Current Design (0-100K Users)
- Single MongoDB cluster
- Current schema performs well

### Phase 2: Medium Scale (100K-1M Users)
- Consider sharding on `userId` for URL history
- Archive old daily stats to separate collection

### Phase 3: Enterprise Scale (1M+ Users)
- Implement time-series collection for daily stats
- Use MongoDB Change Streams for real-time analytics
- Consider separate read replicas for reporting

---

## 9. API Response Examples

### User Profile
```json
{
  "id": "507f1f77bcf86cd799439011",
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  "isVerified": true,
  "lastLogin": "2024-01-13T10:30:00Z",
  "createdAt": "2024-01-01T00:00:00Z",
  "safeWebsitesVisited": 150,
  "unsafeUrlsDetected": 12,
  "phishingUrlsDetected": 8,
  "threatUrlsDetected": 4,
  "totalProtectionWarnings": 24,
  "totalUrlsChecked": 162,
  "protectionRatio": 13.58
}
```

### Platform Dashboard Summary
```json
{
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
      "lastDetected": "2024-01-13T15:45:00Z"
    }
  ],
  "lastUpdated": "2024-01-13T16:00:00Z"
}
```

---

## Summary

This schema design provides:
✓ Secure user authentication with JWT
✓ Per-user safety tracking and analytics
✓ Platform-wide aggregated statistics
✓ Individual URL check audit trail
✓ Automatic data cleanup (1-year retention)
✓ Optimized for read-heavy analytics queries
✓ Scalable to millions of users
✓ GDPR-compliant data retention
✓ Production-ready security practices
