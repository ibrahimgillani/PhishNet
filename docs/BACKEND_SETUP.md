# PhishNet Backend Setup Guide

## 🚀 Quick Start

Your backend and frontend are now fully integrated! Follow these steps to get the application running.

---

## 📋 Prerequisites

- **Node.js** (v14 or higher) - [Download](https://nodejs.org/)
- **npm** (v6 or higher) - comes with Node.js
- **MongoDB Atlas Account** - [Create Free Account](https://www.mongodb.com/cloud/atlas)
- **Git** (optional) - [Download](https://git-scm.com/)

---

## 🛠️ Step 1: Install Dependencies

Navigate to your project directory and install all required packages:

```bash
npm install
```

This will install:
- express - Web server framework
- mongoose - MongoDB object modeling
- bcrypt - Password hashing
- jsonwebtoken - JWT authentication
- cors - Cross-Origin Resource Sharing
- helmet - Security headers
- express-rate-limit - Rate limiting
- dotenv - Environment variables
- And more...

---

## 🔑 Step 2: Configure Environment Variables

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` file with your settings:

   ```env
   # MongoDB Connection
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/phishnet?retryWrites=true&w=majority

   # JWT Secret (change this!)
   JWT_SECRET=your_super_secret_jwt_key_here_min_32_chars

   # Application Port
   PORT=3000
   NODE_ENV=development

   # CORS Origins (frontend URLs)
   CORS_ORIGIN=http://localhost:3000,http://localhost:5000,http://127.0.0.1:3000

   # Rate Limiting
   RATE_LIMIT_WINDOW_MS=900000
   RATE_LIMIT_MAX_REQUESTS=100
   ```

### Getting Your MongoDB URI:

1. Go to [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Create a free cluster
3. Click "Connect"
4. Choose "Connect your application"
5. Copy the connection string
6. Replace `<username>` and `<password>` with your credentials
7. Replace database name with `phishnet`

**Example:**
```
mongodb+srv://admin:MyPassword123@mycluster.mongodb.net/phishnet?retryWrites=true&w=majority
```

---

## ▶️ Step 3: Start the Backend Server

### Development Mode (with auto-restart):
```bash
npm run dev
```

### Production Mode:
```bash
npm start
```

### Expected Output:
```
✓ Database connected successfully
✓ PhishNet Server is running on port 3000
✓ Environment: development
✓ API endpoint: http://localhost:3000/api

Available endpoints:
  POST   /api/auth/register         - Register new user
  POST   /api/auth/login            - Login user
  POST   /api/auth/logout           - Logout user (protected)
  POST   /api/scan/url              - Check URL safety
  POST   /api/scan/email            - Check email safety
  GET    /api/users/profile         - Get user profile (protected)
  PUT    /api/users/profile         - Update user profile (protected)
  GET    /api/users/history         - Get check history (protected)
  GET    /api/analytics/dashboard   - Get dashboard data (protected)
```

---

## 🌐 Step 4: Access the Website

1. Open your browser
2. Go to `http://localhost:3000`
3. The frontend will automatically connect to the backend API

### Test the Integration:

**Register a new account:**
- Click "Sign Up"
- Fill in your details
- Submit the form
- Data is saved to MongoDB and you're logged in with JWT

**Check URL Safety:**
- Scan a URL (login required for saved history)
- Results are recorded in your user history
- Platform analytics are updated

**View Dashboard:**
- Login and go to dashboard
- See your personal statistics
- View platform-wide analytics

---

## 📁 Project Structure

```
phishnet-website/
├── server.js                 # Main Express server
├── package.json             # Dependencies and scripts
├── .env.example            # Environment variables template
├── .env                    # Your actual environment variables (DON'T COMMIT)
│
├── config/
│   └── database.js         # MongoDB connection
│
├── models/
│   ├── User.js            # User schema with JWT, metrics
│   ├── Analytics.js       # Platform analytics schema
│   └── URLCheckHistory.js # URL check audit trail
│
├── routes/
│   ├── auth.js            # Authentication endpoints
│   ├── scan.js            # URL/Email scanning endpoints
│   ├── users.js           # User profile endpoints
│   └── analytics.js       # Analytics endpoints
│
├── middleware/
│   ├── auth.js            # JWT verification
│   └── errorHandler.js    # Error handling
│
├── utils/
│   ├── api.js             # Frontend API client
│   ├── jwt.js             # JWT utilities
│   └── validators.js      # Input validation & URL checking
│
├── (Frontend Files)
├── index.html
├── login.html
├── signup.html
├── dashboard.html
├── app.js                 # Updated with real API calls
├── styles.css
└── (Other HTML pages)
```

---

## 🔌 API Endpoints Reference

### Authentication
- `POST /api/auth/register` - Create new account
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/logout` - Logout (requires token)
- `POST /api/auth/verify` - Verify token is valid
- `POST /api/auth/refresh` - Get new token

### URL Scanning (Public + Protected)
- `POST /api/scan/url` - Check single URL
- `POST /api/scan/email` - Check email for threats
- `POST /api/scan/batch` - Check multiple URLs (requires login)

### User Profile (Protected)
- `GET /api/users/profile` - Get user info & metrics
- `PUT /api/users/profile` - Update profile
- `PUT /api/users/password` - Change password
- `PUT /api/users/preferences` - Update settings
- `GET /api/users/history` - Get check history
- `GET /api/users/stats` - Get threat statistics
- `GET /api/users/activity` - Get recent activity
- `DELETE /api/users/account` - Delete account

### Analytics (Protected)
- `GET /api/analytics/dashboard` - User & platform metrics
- `GET /api/analytics/trends` - Historical trends (30 days)
- `GET /api/analytics/summary` - Platform summary
- `GET /api/analytics/top-domains` - Dangerous domains
- `GET /api/analytics/threat-distribution` - Threat types
- `GET /api/analytics/rankings` - Top users
- `GET /api/analytics/overview` - Complete overview

---

## 🔐 Security Features

✅ **Password Security**
- Bcrypt hashing with 10 salt rounds
- Passwords never logged or exposed
- Password reset flow with tokens

✅ **JWT Authentication**
- Token expiration (7 days)
- Token rotation support
- Automatic logout on expiration

✅ **Account Protection**
- Automatic locking after 5 failed login attempts
- IP address tracking
- Login attempt monitoring

✅ **Data Validation**
- Input sanitization
- NoSQL injection prevention
- Rate limiting (100 requests/15 min per IP)

✅ **CORS Security**
- Whitelisted frontend origins
- Credentials support
- Helmet.js security headers

---

## 📊 Database Collections

### Users Collection
Stores user accounts with authentication and metrics:
- Basic info (name, email, password hash)
- JWT tokens and verification status
- Per-user metrics (safe visits, threats detected, warnings)
- Account activity (last login, IP addresses)

### Analytics Collection
Platform-wide aggregated statistics (singleton):
- Total users, active users
- Total URLs checked, threats detected
- Daily statistics (90-day history)
- Top phishing domains
- Threat detection rates

### URL Check History Collection
Audit trail of every URL checked:
- User who checked it
- URL and domain
- Threat assessment results
- Confidence score
- Auto-deletes after 1 year (TTL index)

---

## 🐛 Troubleshooting

### Backend won't start
```bash
# Check Node.js version
node --version  # Should be v14 or higher

# Reinstall dependencies
rm -rf node_modules
npm install

# Check if port 3000 is in use
lsof -i :3000  # Kill process: kill -9 <PID>
```

### Database connection fails
```bash
# Verify MongoDB URI is correct
echo $MONGODB_URI

# Check MongoDB Atlas:
# 1. Cluster is running
# 2. IP whitelist includes your IP (or 0.0.0.0)
# 3. Username/password are correct
# 4. Network access is enabled
```

### Frontend can't connect to backend
```bash
# Check CORS configuration in server.js
# Verify CORS_ORIGIN includes your frontend URL
# Make sure port 3000 is accessible: curl http://localhost:3000/api/health
```

### Authentication token issues
```bash
# Clear browser storage and login again
# Check JWT_SECRET matches between login/requests
# Verify token hasn't expired: tokens expire after 7 days
```

---

## 🚀 Deployment

### For Production:

1. **Set environment variables:**
   ```bash
   NODE_ENV=production
   JWT_SECRET=<very-long-random-string>
   MONGODB_URI=<production-mongodb>
   ```

2. **Install PM2 for process management:**
   ```bash
   npm install -g pm2
   pm2 start server.js --name "phishnet"
   ```

3. **Enable HTTPS:**
   - Use reverse proxy (nginx, Apache)
   - Or use Node.js with SSL certificates

4. **Backup MongoDB:**
   - Enable MongoDB Atlas automated backups
   - Test restore procedure

---

## 📚 Next Steps

1. **Test Authentication:**
   - Register a new user
   - Login with credentials
   - Verify JWT token is saved

2. **Test URL Scanning:**
   - Submit URLs for checking
   - Verify results are saved to database
   - Check user metrics are updated

3. **View Analytics:**
   - Login to dashboard
   - View personal metrics
   - See platform statistics

4. **Customize:**
   - Add integration with real threat detection APIs
   - Implement email verification
   - Add password reset email flow
   - Enable two-factor authentication

---

## 📖 API Usage Examples

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

### Check URL
```bash
curl -X POST http://localhost:3000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Get Profile (with token)
```bash
curl -X GET http://localhost:3000/api/users/profile \
  -H "Authorization: Bearer <your-jwt-token>"
```

---

## 💡 Additional Resources

- [Express.js Documentation](https://expressjs.com/)
- [Mongoose Documentation](https://mongoosejs.com/)
- [MongoDB Atlas Guide](https://docs.atlas.mongodb.com/)
- [JWT Authentication](https://jwt.io/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

---

## ✅ Verification Checklist

Before considering setup complete:

- [ ] Dependencies installed (`npm install`)
- [ ] `.env` file created with MongoDB URI
- [ ] Server starts without errors (`npm run dev`)
- [ ] Frontend loads at `http://localhost:3000`
- [ ] Can register new account
- [ ] Can login with credentials
- [ ] Can check URL and see results
- [ ] Dashboard loads and shows data
- [ ] Database has collections created

---

## Support

If you encounter issues:
1. Check the console for error messages
2. Verify all environment variables are set
3. Ensure MongoDB Atlas cluster is running
4. Check that ports 3000 is not in use
5. Review the troubleshooting section above

---

**Your PhishNet backend is ready to protect users from phishing attacks! 🛡️**
