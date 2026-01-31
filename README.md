# PhishNet Frontend - AI-Powered Phishing Detection Platform

This is the frontend component of PhishNet, a comprehensive AI-powered phishing detection and security platform. The frontend is built with vanilla JavaScript, HTML5, and CSS3, providing a responsive and modern user experience.

## 🌟 Key Features

### 🔒 Security Scanning Interface
- **URL Scanning**: Real-time phishing detection for suspicious links
- **Email Scanning**: AI-powered email content analysis for phishing attempts
- **Confidence Scoring**: Detailed threat confidence percentages (0-100%)
- **Risk Level Assessment**: Categorized as Safe, Suspicious, or Malicious
- **Real-time Results**: Instant scan feedback with threat indicators

### 📊 Dashboard & Analytics
- **User Dashboard**: Personalized dashboard with scan statistics
- **Threat Overview Chart**: Visual 7-day threat trend analysis using Chart.js
- **Scan History**: Complete history of all URL and email scans
- **Statistics Cards**: Total scans, threats detected, and safe scans metrics
- **Responsive Tables**: Mobile-optimized recent scans table

### 📝 Advanced Reporting
- **Detailed Scan Reports**: Comprehensive analysis of each scan
- **PDF Export**: Professional PDF report generation with custom layouts
- **Threat Indicators**: Visual display of security features and detected issues
- **Report Filtering**: Filter by scan type, threat level, and date range
- **Modal Preview**: Detailed report preview with expandable sections

### 🤖 AI Chatbot (Google Gemini)
- **Interactive Support**: AI-powered chatbot for instant help
- **Greeting Bubble**: Professional welcome message
- **Wink Animation**: Friendly bot eye animation
- **Available Everywhere**: Persistent chatbot across all pages
- **Secure Integration**: Backend proxy protects API keys

### 🎨 User Interface
- **Modern Dark Theme**: Professional design with PhishNet branding
- **Responsive Design**: Fully optimized for desktop, tablet, and mobile
- **Smooth Animations**: Fade-in animations and transitions
- **Interactive Cards**: Hover effects and smooth interactions
- **Professional Badges**: Color-coded threat level indicators

### 👤 User Management
- **Secure Authentication**: JWT token-based login/signup
- **Profile Management**: Update personal information and avatar
- **Settings Page**: Comprehensive user preferences
- **Password Reset**: Forgot password functionality
- **Session Management**: Secure token-based authentication

### 📰 Content Pages
- **Blog System**: Cybersecurity blog with RSS feed integration
- **About Page**: Company information and mission
- **FAQ Page**: Interactive FAQ accordion
- **Pricing Page**: Tiered pricing plans (Free, Pro, Enterprise)
- **Privacy Policy**: Comprehensive privacy documentation
- **Terms of Service**: Legal terms and conditions

## 📁 Project Structure

```
website/
├─ Frontend Pages (HTML)
│  ├─ index.html             # Landing page with hero section
│  ├─ dashboard.html         # User dashboard with charts
│  ├─ login.html             # Login page
│  ├─ signup.html            # Registration page
│  ├─ reports.html           # Scan reports with filtering
│  ├─ scan-results.html      # Scan results display
│  ├─ settings.html          # User settings & profile
│  ├─ about.html             # About us page
│  ├─ blog.html              # Cybersecurity blog
│  ├─ faq.html               # FAQ accordion
│  ├─ pricing.html           # Pricing plans
│  ├─ privacy.html           # Privacy policy
│  ├─ terms.html             # Terms of service
│  ├─ forgot-password.html   # Password reset
│  ├─ demo.html              # Product demos
│  └─ warning.html           # Alert/warning pages
│
├─ JavaScript Logic
│  ├─ app.js                 # Core app logic, navigation, auth
│  ├─ config.js              # API endpoints & configuration
│  ├─ chart-init.js          # Chart.js initialization
│  ├─ report-viewer.js       # Report viewing functionality
│  ├─ reports.js             # Report management & PDF export
│  ├─ settings.js            # Settings page logic
│  ├─ blog.js                # Blog feed parser
│  ├─ scanning-system.js     # URL/Email scanning system
│  ├─ scan-results.js        # Scan results display
│  ├─ dashboard-security-tips.js # Dashboard security tips
│  └─ chatbot.js             # Chatbot logic (Gemini integration)
│
├─ Chatbot Widget
│  ├─ chatbot-widget.html    # Reusable chatbot component
│  ├─ chatbot.css            # Chatbot styles & animations
│  └─ warning.js             # Alert handling
│
├─ Styles
│  └─ styles.css             # Main stylesheet (complete design)
│
├─ Configuration
│  ├─ config.js              # API endpoints & settings
│  ├─ .env                   # Local development variables
│  └─ .env.example           # Environment template
│
├─ Assets
│  ├─ favicon.png            # Website icon (PNG)
│  ├─ favicon.svg            # Website icon (SVG)
│  └─ .nojekyll              # GitHub Pages configuration
│
└─ Documentation
   ├─ README.md              # This file
   ├─ API_REFERENCE.md       # API endpoints documentation
   ├─ QUICKSTART.md          # 5-minute quick start guide
   ├─ MODAL_QUICK_REFERENCE.md # UI component guide
   └─ SCHEMA_DOCUMENTATION.md # Database schemas
```

## 🚀 Quick Start

### Prerequisites
- Node.js >= 14.0.0 (optional, for running local server)
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Backend API running or accessible (see backend setup)

### Installation & Setup

**1. Navigate to Website Folder**
```bash
cd phishnet/website
```

**2. Update Backend Configuration**

Edit `config.js` and set your backend API URL:

```javascript
// For local development
const API_BASE_URL = window.API_BASE_URL || 'http://localhost:3000';

// For production (Render/other hosting)
// const API_BASE_URL = 'https://your-backend-domain.com';
```

**3. Start Frontend Server**

Choose one of these options:

**Option A: Python (Recommended)**
```bash
python -m http.server 8000
# Then open: http://localhost:8000
```

**Option B: Node.js (http-server)**
```bash
npx http-server -p 8000
# Then open: http://localhost:8000
```

**Option C: VS Code Live Server**
- Install "Live Server" extension (by Ritwick Dey)
- Right-click `index.html`
- Select "Open with Live Server"
- Automatically opens at `http://localhost:5500`

**4. Verify Backend Connection**
- Make sure backend API is running on the configured URL
- Check browser console (F12) for any errors
- Test by logging in or creating an account

## 🔧 Configuration

### API Configuration (`config.js`)

Update the API base URL to match your backend:

```javascript
// Development (local backend)
const API_BASE_URL = 'http://localhost:3000';

// Production (Render backend)
const API_BASE_URL = 'https://phishnet-backend.onrender.com';
```

### Environment Variables (`.env`)

Create `.env` file in website root:

```env
# Backend API
API_BASE_URL=http://localhost:3000

# Feature flags
CHATBOT_ENABLED=true
PDF_EXPORT_ENABLED=true

# UI Settings
THEME=dark
ANIMATIONS_ENABLED=true
```

## 📡 Backend API Integration

The frontend communicates with the backend API for:

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh` - Refresh JWT token
- `GET /api/auth/verify` - Verify token validity

### Scanning
- `POST /api/scan/url` - Scan URL for phishing
- `POST /api/scan/email` - Scan email content
- `GET /api/users/history` - Get scan history

### Analytics
- `GET /api/analytics/stats` - Dashboard statistics
- `GET /api/dashboard/security-tips` - Security tips

### Chatbot
- `POST /api/chatbot/message` - Send message to AI chatbot

### Blog
- `GET /api/blog/posts` - Fetch blog posts

See [API_REFERENCE.md](API_REFERENCE.md) for complete documentation.

## 🎨 Frontend Features

### Pages & Routes

| Page | Route | Purpose |
|------|-------|---------|
| Landing Page | `/` | Hero, features, CTA |
| Login | `/login.html` | User authentication |
| Signup | `/signup.html` | User registration |
| Dashboard | `/dashboard.html` | Stats & charts |
| Scan | `/` (modal) | URL/Email scanning |
| Reports | `/reports.html` | Report management |
| Settings | `/settings.html` | Profile & preferences |
| Blog | `/blog.html` | Security articles |
| About | `/about.html` | Company info |
| FAQ | `/faq.html` | Common questions |
| Pricing | `/pricing.html` | Pricing plans |
| Privacy | `/privacy.html` | Privacy policy |
| Terms | `/terms.html` | Terms of service |

### UI Components

**Modals**
- Scan URL modal
- Scan Email modal
- Report details
- Confirmation dialogs
- Loading states

**Notifications**
- Toast messages (success, error, info, warning)
- Toast icon indicators
- Auto-dismiss functionality
- Custom messages

**Charts**
- 7-day threat trend (Chart.js)
- Statistics cards
- Pie charts for categorization
- Responsive sizing

**Forms**
- Login/Signup forms
- URL/Email input validation
- Settings form
- Profile update form

## 🛠️ Development Guide

### Technologies Used
- **HTML5**: Semantic markup
- **CSS3**: Custom styling with animations
- **JavaScript**: Vanilla JS (no frameworks)
- **Chart.js**: Data visualization
- **jsPDF + html2canvas**: PDF generation
- **Fetch API**: HTTP requests

### Customization

**Change Theme Colors**

Edit `styles.css` CSS variables:
```css
:root {
  --primary-color: #3b82f6;      /* Blue */
  --success-color: #10b981;      /* Green */
  --danger-color: #ef4444;       /* Red */
  --warning-color: #f59e0b;      /* Orange */
  --background: #1a1a1a;         /* Dark background */
  --text-primary: #ffffff;       /* Light text */
}
```

**Add New Page**
1. Create `newpage.html` in root
2. Include common header/nav via app.js
3. Add route handler:
   ```javascript
   case 'newpage.html':
     initNewPage();
     break;
   ```
4. Include chatbot widget

**Customize Chatbot**
- Edit `chatbot.css` for styling
- Modify `chatbot.js` for behavior
- Update prompt in `chatbot-widget.html`

### Debugging

**Check API Calls**
1. Open DevTools (F12)
2. Go to Network tab
3. Click "XHR" filter
4. Perform action
5. Check response and status codes

**Check Errors**
1. Open Console tab
2. Look for red error messages
3. Check backend logs simultaneously

**Local Testing**
```bash
# Terminal 1: Backend
cd backend && npm run dev

# Terminal 2: Frontend
cd website && python -m http.server 8000
```

## 🚀 Deployment

### Static Hosting Options

**Netlify**
1. Push code to GitHub
2. Connect repo to Netlify
3. Set build command: (none, static files)
4. Set publish directory: `.` (root)
5. Add environment variable: `API_BASE_URL`
6. Deploy automatically on push

**GitHub Pages**
1. Push to `gh-pages` branch
2. Enable Pages in repo settings
3. Source: gh-pages branch
4. Update `config.js` for GitHub Pages domain

**Vercel**
1. Connect GitHub repo
2. Framework: Other
3. Root directory: `website`
4. Add environment variable: `API_BASE_URL`
5. Deploy

**Render**
1. Create static site on Render
2. Connect GitHub repo
3. Publish directory: `website`
4. Environment: Add `API_BASE_URL`
5. Deploy

### Pre-Deployment Checklist
- [ ] Update `config.js` with production API URL
- [ ] Set environment variables on hosting platform
- [ ] Test all forms and authentication
- [ ] Test PDF export functionality
- [ ] Test chatbot integration
- [ ] Test mobile responsiveness
- [ ] Clear browser cache
- [ ] Test across browsers

## 🔒 Security Best Practices

- Never commit `.env` files with secrets
- API keys stored on backend only
- JWT tokens stored in localStorage
- Input validation on all forms
- HTTPS required for production
- CORS properly configured on backend
- Content Security Policy headers set

## 📱 Mobile Optimization

- Responsive design for all screen sizes
- Touch-friendly buttons and inputs
- Mobile-optimized modals
- Simplified table views on mobile
- Fast loading on 4G connections
- Responsive images

## ⚙️ Troubleshooting

### CORS Errors
```
Access to XMLHttpRequest blocked by CORS policy
```
**Solution:**
- Check backend `.env` has correct `CORS_ORIGIN`
- Verify backend is running
- Check `config.js` API URL is correct

### API Not Responding
```
Failed to fetch from API
```
**Solution:**
- Ensure backend is running
- Verify `config.js` points to correct backend URL
- Check network tab in DevTools
- Check backend logs for errors

### Chatbot Not Working
```
Chatbot messages not sending
```
**Solution:**
- Check `GEMINI_API_KEY` in backend `.env`
- Verify backend `/api/chatbot/message` endpoint exists
- Check browser console for errors
- Clear cache and reload

### Authentication Failing
```
Login/Signup not working
```
**Solution:**
- Clear localStorage and cookies
- Check backend `/api/auth` endpoints are working
- Verify `JWT_SECRET` is set in backend
- Check form submission in Network tab

### PDF Export Not Working
```
Unable to generate PDF
```
**Solution:**
- Ensure `jsPDF` and `html2canvas` are loaded
- Check browser console for errors
- Try in Chrome (best compatibility)
- Check page has enough data to export

## 📊 Browser Support

| Browser | Support | Notes |
|---------|---------|-------|
| Chrome | ✅ Full | Recommended |
| Firefox | ✅ Full | Good support |
| Safari | ✅ Full | Latest versions |
| Edge | ✅ Full | Chromium-based |
| Mobile | ✅ Full | Responsive design |

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes
4. Test thoroughly
5. Commit: `git commit -m 'Add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Open Pull Request

## 📄 License

MIT License - See LICENSE file for details

## 👥 Support & Feedback

- **Issues**: Open GitHub issue for bugs
- **Features**: Request features via GitHub issues
- **Questions**: Check documentation first
- **Security**: Report security issues privately

## 📚 Additional Resources

- [Backend Setup Guide](../backend/README.md)
- [API Reference](API_REFERENCE.md)
- [Quick Start Guide](QUICKSTART.md)
- [Modal Components](MODAL_QUICK_REFERENCE.md)
- [Database Schema](SCHEMA_DOCUMENTATION.md)

---

**Made with ❤️ for cybersecurity**

Last Updated: January 2026
