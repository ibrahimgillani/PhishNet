# 🚀 Quick Setup Guide - Extension with Website Login/Signup

## ✅ What Changed

The PhishNet extension now uses the **same login/signup pages as the website** instead of having separate forms. When users click "Login" or "Sign Up" in the extension, they're redirected to the website.

---

## 📋 Setup Steps

### Step 1: Get Your Extension ID

1. Open Chrome and go to `chrome://extensions/`
2. Enable **"Developer mode"** (toggle in top-right corner)
3. Click **"Load unpacked"**
4. Select the `Extention Page` folder
5. **Copy the Extension ID** (it will look like: `abcdefghijklmnopqrstuvwxyz123456`)

---

### Step 2: Update Website with Extension ID

Open [Webpage/app.js](../Webpage/app.js) and find line 3:

```javascript
const PHISHNET_EXTENSION_ID = 'UPDATE_WITH_YOUR_EXTENSION_ID';
```

**Replace** `'UPDATE_WITH_YOUR_EXTENSION_ID'` with your actual extension ID:

```javascript
const PHISHNET_EXTENSION_ID = 'abcdefghijklmnopqrstuvwxyz123456'; // Your ID here
```

---

### Step 3: Start the Website

```bash
cd Webpage
# If you have a server
npm start

# OR use Python
python -m http.server 3000

# OR use Node.js http-server
npx http-server -p 3000
```

The website should now be running at `http://localhost:3000`

---

### Step 4: Update Website URL (if different)

If your website is NOT on `http://localhost:3000`, update the extension:

Open [Extention Page/popup.js](popup.js) line 5:

```javascript
const WEBSITE_URL = 'http://localhost:3000'; // Change if needed
```

Also update [Extention Page/manifest.json](manifest.json):

```json
{
  "externally_connectable": {
    "matches": [
      "http://localhost:3000/*",  // Change to your URL
      "http://localhost:5000/*"
    ]
  }
}
```

---

### Step 5: Reload Extension

After making changes:
1. Go to `chrome://extensions/`
2. Click the **refresh icon** on PhishNet Extension
3. Or click "Remove" and re-load the extension

---

## 🧪 Test the Integration

### Test Login Flow:

1. **Click extension icon** in Chrome toolbar
2. **Click "Login"** button
3. ✅ New tab should open to `http://localhost:3000/login.html?source=extension`
4. **Enter any email** (e.g., `test@example.com`) and click Continue
5. **Enter any password** and click Continue
6. ✅ You should see: **"Authentication complete! You can close this tab now."**
7. **Go back to extension popup**
8. ✅ Extension should now show the Dashboard (logged in state)

### Test Signup Flow:

1. **Click extension icon**
2. **Click "Sign Up"** button
3. ✅ New tab opens to `http://localhost:3000/signup.html?source=extension`
4. **Fill in all fields**:
   - First Name: John
   - Last Name: Doe
   - Email: john@example.com
   - Phone: (optional)
   - Company: (optional)
   - Security Question: (select one)
   - Security Answer: (any answer)
   - Password: (must be Good or Strong)
   - Confirm Password: (same as above)
5. **Click "Create Account"**
6. ✅ See: **"Authentication complete! You can close this tab now."**
7. ✅ Extension popup shows logged-in Dashboard

---

## 🔧 Troubleshooting

### Issue: "Please ensure PhishNet extension is installed and enabled"

**Solution:**
- Make sure extension is loaded in Chrome
- Verify you updated the Extension ID in `app.js`
- Check extension ID matches exactly (no spaces)
- Reload the extension

### Issue: Tab doesn't open when clicking Login/Signup

**Solution:**
- Check browser console for errors
- Verify `WEBSITE_URL` is correct in `popup.js`
- Make sure website is running
- Check permissions in `manifest.json` include `"tabs"`

### Issue: Authentication works but extension doesn't update

**Solution:**
- Open extension popup
- Right-click → "Inspect"
- Check Console for errors
- Verify message listener is working
- Check `chrome.storage.local` permissions

### Issue: Message not received by extension

**Solution:**
- Verify `externally_connectable` in `manifest.json`
- Ensure website URL matches the pattern
- Check Extension ID is correct
- Reload extension after changes

---

## 📁 Files Modified

### Extension Files:
- ✅ [index.html](index.html) - Removed login/signup modal forms
- ✅ [popup.js](popup.js) - Added website redirect and message listener
- ✅ [manifest.json](manifest.json) - Added permissions and externally_connectable

### Website Files:
- ✅ [app.js](../Webpage/app.js) - Added extension communication

---

## 🔐 How Authentication Works

```
1. User clicks "Login" in Extension
   ↓
2. New tab opens: website/login.html?source=extension
   ↓
3. User enters credentials on website
   ↓
4. Website validates & logs in user
   ↓
5. Website detects ?source=extension parameter
   ↓
6. Website sends chrome.runtime.sendMessage() to extension
   ↓
7. Extension receives auth data (tokens + user info)
   ↓
8. Extension saves to chrome.storage.local
   ↓
9. Extension updates UI to logged-in state
   ↓
10. User can close the website tab
```

---

## 🎯 What to Expect

**Extension Intro Page:**
- Login button → Opens website login page
- Sign Up button → Opens website signup page

**Website Login/Signup:**
- Same UI as normal website
- Shows success message for extension users
- Auto-closes after 2 seconds (optional)

**Extension After Login:**
- Dashboard page appears
- User name displayed
- Protection dial active
- All features unlocked

---

## 📝 Production Notes

For production deployment:

1. **Use Real Backend**: Replace demo tokens with actual JWT from backend
2. **Update URLs**: Change localhost URLs to production URLs
3. **HTTPS Only**: Use HTTPS for security
4. **Update Extension ID**: Production extension will have different ID
5. **Update externally_connectable**: Add production domain

Example for production:

```javascript
// popup.js
const WEBSITE_URL = 'https://phishnet.com';

// app.js  
const PHISHNET_EXTENSION_ID = 'production_extension_id_here';

// manifest.json
{
  "externally_connectable": {
    "matches": [
      "https://phishnet.com/*"
    ]
  }
}
```

---

## ✨ Status: Ready to Test!

Everything is configured! Just:
1. ✅ Get Extension ID
2. ✅ Update `PHISHNET_EXTENSION_ID` in app.js
3. ✅ Start website on port 3000
4. ✅ Test login/signup flow

---

**Need Help?**
- Check browser console for errors
- Verify all URLs match
- Ensure extension is loaded
- Check permissions in manifest.json

*Setup Guide - January 14, 2026*
