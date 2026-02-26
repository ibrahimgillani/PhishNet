const User = require('../models/User');
const Analytics = require('../models/Analytics');
const { generateTokens } = require('../utils/jwt');

// @desc    Register new user
// @route   POST /api/v1/auth/signup
// @access  Public
exports.signup = async (req, res, next) => {
  const requestId = `SIGNUP-${Date.now()}`;
  
  console.log('\n=================================================');
  console.log(`[${requestId}] 📝 SIGNUP REQUEST RECEIVED`);
  console.log('=================================================');
  console.log(`[${requestId}] Timestamp: ${new Date().toISOString()}`);
  
  try {
    const { firstName, lastName, email, password, confirmPassword } = req.body;
    
    // Step 1: Validate all required fields
    console.log(`[${requestId}] 📋 Step 1: Validating required fields...`);
    
    if (!firstName || !lastName || !email || !password || !confirmPassword) {
      console.log(`[${requestId}] ❌ VALIDATION FAILED: Missing required fields`);
      if (!firstName) console.log(`[${requestId}]   - firstName is missing`);
      if (!lastName) console.log(`[${requestId}]   - lastName is missing`);
      if (!email) console.log(`[${requestId}]   - email is missing`);
      if (!password) console.log(`[${requestId}]   - password is missing`);
      if (!confirmPassword) console.log(`[${requestId}]   - confirmPassword is missing`);
      
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }
    
    console.log(`[${requestId}] ✓ All required fields present`);
    console.log(`[${requestId}] firstName: ${firstName}`);
    console.log(`[${requestId}] lastName: ${lastName}`);
    console.log(`[${requestId}] email: ${email}`);

    // Step 2: Validate email format
    console.log(`[${requestId}] 📧 Step 2: Validating email format...`);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log(`[${requestId}] ❌ VALIDATION FAILED: Invalid email format`);
      console.log(`[${requestId}] Email: ${email}`);
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }
    console.log(`[${requestId}] ✓ Email format is valid`);

    // Step 3: Validate password match
    console.log(`[${requestId}] 🔐 Step 3: Validating password confirmation...`);
    if (password !== confirmPassword) {
      console.log(`[${requestId}] ❌ VALIDATION FAILED: Passwords do not match`);
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }
    console.log(`[${requestId}] ✓ Passwords match`);
    console.log(`[${requestId}] Password length: ${password.length} characters`);

    // Step 4: Validate password strength
    console.log(`[${requestId}] 💪 Step 4: Validating password strength...`);
    if (password.length < 8) {
      console.log(`[${requestId}] ❌ VALIDATION FAILED: Password too short (${password.length} < 8)`);
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters'
      });
    }
    console.log(`[${requestId}] ✓ Password meets minimum length requirements`);

    // Step 5: Normalize email
    console.log(`[${requestId}] 🔤 Step 5: Normalizing email...`);
    const normalizedEmail = email.toLowerCase().trim();
    console.log(`[${requestId}] Normalized email: ${normalizedEmail}`);

    // Step 6: Check if user already exists
    console.log(`[${requestId}] 🔍 Step 6: Checking for existing user...`);
    console.log(`[${requestId}] Querying database for email: ${normalizedEmail}`);
    
    const existingUser = await User.findOne({ email: normalizedEmail });
    
    if (existingUser) {
      console.log(`[${requestId}] ❌ USER ALREADY EXISTS`);
      console.log(`[${requestId}] User with email ${normalizedEmail} already registered`);
      console.log(`[${requestId}] User ID: ${existingUser._id}`);
      return res.status(409).json({
        success: false,
        message: 'Email already registered. Please login instead.'
      });
    }
    console.log(`[${requestId}] ✓ Email is not registered`);

    // Step 7: Create new user
    console.log(`[${requestId}] 👤 Step 7: Creating new user in database...`);
    
    const newUser = new User({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: normalizedEmail,
      passwordHash: password, // Will be hashed by pre-save middleware
      isVerified: true, // Auto-verify for extension signup (can login immediately)
      extensionEnabled: true,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    console.log(`[${requestId}] New user object created`);
    console.log(`[${requestId}] User firstName: ${newUser.firstName}`);
    console.log(`[${requestId}] User lastName: ${newUser.lastName}`);
    console.log(`[${requestId}] User email: ${newUser.email}`);
    console.log(`[${requestId}] isVerified: true (auto-verified for extension)`);

    // Save user to database
    console.log(`[${requestId}] 💾 Saving user to MongoDB...`);
    console.log(`[${requestId}] Before save - User object:`, {
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      email: newUser.email,
      isVerified: newUser.isVerified,
      hasPasswordHash: !!newUser.passwordHash,
      extensionEnabled: newUser.extensionEnabled
    });
    
    try {
      await newUser.save();
      console.log(`[${requestId}] ✓ User successfully saved to database`);
      console.log(`[${requestId}] User ID: ${newUser._id}`);
      console.log(`[${requestId}] Account created at: ${newUser.createdAt}`);
    } catch (saveError) {
      console.log(`[${requestId}] ❌ SAVE FAILED - ${saveError.message}`);
      console.log(`[${requestId}] Save error details:`, saveError);
      return res.status(500).json({
        success: false,
        message: 'Failed to save user to database: ' + saveError.message
      });
    }

    // Step 8: Generate tokens
    console.log(`[${requestId}] 🎫 Step 8: Generating authentication tokens...`);
    const { accessToken, refreshToken } = generateTokens(newUser._id);
    
    if (!accessToken || !refreshToken) {
      console.log(`[${requestId}] ❌ TOKEN GENERATION FAILED`);
      return res.status(500).json({
        success: false,
        message: 'Failed to generate authentication tokens'
      });
    }
    
    console.log(`[${requestId}] ✓ Tokens generated successfully`);
    console.log(`[${requestId}] Access token length: ${accessToken.length}`);
    console.log(`[${requestId}] Refresh token length: ${refreshToken.length}`);

    // Step 9: Verify user was saved to database
    console.log(`[${requestId}] 🔍 Step 9: Verifying user was saved...`);
    const verifyUser = await User.findById(newUser._id);
    if (!verifyUser) {
      console.log(`[${requestId}] ❌ VERIFICATION FAILED: User not found after save!`);
      return res.status(500).json({
        success: false,
        message: 'User was not properly saved to database'
      });
    }
    console.log(`[${requestId}] ✓ User verified in database`);
    console.log(`[${requestId}] Verified user email: ${verifyUser.email}`);

    // Step 10: Prepare response
    console.log(`[${requestId}] 📦 Step 10: Preparing response data...`);
    const userResponse = {
      _id: newUser._id,
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      email: newUser.email,
      isVerified: newUser.isVerified,
      createdAt: newUser.createdAt
    };

    console.log(`[${requestId}] ✅ SIGNUP SUCCESSFUL`);
    console.log(`[${requestId}] New user: ${newUser.firstName} ${newUser.lastName} (${newUser.email})`);
    console.log(`[${requestId}] Response status: 201`);
    console.log('=================================================\n');

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      data: {
        user: userResponse,
        accessToken,
        refreshToken
      }
    });

  } catch (error) {
    console.log(`[${requestId}] ❌ CRITICAL ERROR OCCURRED`);
    console.log(`[${requestId}] Error type: ${error.name}`);
    console.log(`[${requestId}] Error message: ${error.message}`);
    console.log(`[${requestId}] Error code: ${error.code}`);
    
    // Handle specific MongoDB errors
    if (error.code === 11000) {
      console.log(`[${requestId}] ❌ Duplicate key error - email already exists`);
      console.log(`[${requestId}] Duplicate field details:`, error.keyPattern);
      return res.status(409).json({
        success: false,
        message: 'Email already registered'
      });
    }
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      console.log(`[${requestId}] ❌ Validation Error - Failed fields:`);
      messages.forEach(msg => console.log(`[${requestId}]   - ${msg}`));
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: messages
      });
    }
    
    if (error.name === 'MongoNetworkError') {
      console.log(`[${requestId}] ❌ Database Connection Error`);
      console.log(`[${requestId}] Cannot connect to MongoDB`);
      return res.status(500).json({
        success: false,
        message: 'Database connection error. Please try again.'
      });
    }
    
    console.error(`[${requestId}] Full error stack:`, error);
    console.log('=================================================\n');
    
    res.status(500).json({
      success: false,
      message: 'An unexpected error occurred during signup. Please try again.'
    });
  }
};

// @desc    Login user
// @route   POST /api/v1/auth/login
// @access  Public
exports.login = async (req, res, next) => {
  const requestId = `LOGIN-${Date.now()}`;
  
  console.log('\n=================================================');
  console.log(`[${requestId}] 🔐 LOGIN REQUEST RECEIVED`);
  console.log('=================================================');
  console.log(`[${requestId}] Timestamp: ${new Date().toISOString()}`);
  
  try {
    const { email, password } = req.body;
    
    // Step 1: Validate input
    console.log(`[${requestId}] 📝 Step 1: Validating input...`);
    
    if (!email) {
      console.log(`[${requestId}] ❌ VALIDATION FAILED: Email is missing`);
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    if (!password) {
      console.log(`[${requestId}] ❌ VALIDATION FAILED: Password is missing`);
      return res.status(400).json({
        success: false,
        message: 'Password is required'
      });
    }
    
    console.log(`[${requestId}] ✓ Input validation passed`);
    console.log(`[${requestId}] Email provided: ${email}`);
    console.log(`[${requestId}] Password length: ${password.length} characters`);

    // Step 2: Email format validation
    console.log(`[${requestId}] 📧 Step 2: Validating email format...`);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log(`[${requestId}] ❌ VALIDATION FAILED: Invalid email format`);
      console.log(`[${requestId}] Email: ${email}`);
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }
    console.log(`[${requestId}] ✓ Email format is valid`);

    // Step 3: Find user in database
    console.log(`[${requestId}] 🔍 Step 3: Searching for user in database...`);
    const normalizedEmail = email.toLowerCase().trim();
    console.log(`[${requestId}] Normalized email: ${normalizedEmail}`);
    console.log(`[${requestId}] Querying database for email: ${normalizedEmail}`);
    
    // Debug: (redacted) show only user count for diagnostics without listing PII
    const totalUsers = await User.countDocuments();
    console.log(`[${requestId}] Total users in database: ${totalUsers}`);
    
    // FIXED: Use .select('+passwordHash') to get the password field
    const user = await User.findOne({ email: normalizedEmail }).select('+passwordHash');

    if (!user) {
      console.log(`[${requestId}] ❌ USER NOT FOUND`);
      console.log(`[${requestId}] No account exists with email: ${normalizedEmail}`);
      console.log(`[${requestId}] Login attempt failed - user does not exist`);
      console.log(`[${requestId}] Searched for exact email: "${normalizedEmail}"`);
      return res.status(401).json({
        success: false,
        message: 'No account found with this email. Please sign up first.'
      });
    }

    console.log(`[${requestId}] ✓ User found in database`);
    console.log(`[${requestId}] User ID: ${user._id}`);
    console.log(`[${requestId}] User Name: ${user.getFullName ? user.getFullName() : user.firstName + ' ' + user.lastName}`);
    console.log(`[${requestId}] User Email: ${user.email}`);
    console.log(`[${requestId}] Account created: ${user.createdAt}`);

    // Step 4: Verify password
    console.log(`[${requestId}] 🔑 Step 4: Verifying password...`);
    console.log(`[${requestId}] Comparing provided password with stored hash`);
    
    const isPasswordValid = await user.matchPassword(password);
    
    if (!isPasswordValid) {
      console.log(`[${requestId}] ❌ PASSWORD MISMATCH`);
      console.log(`[${requestId}] The password provided does not match our records`);
      console.log(`[${requestId}] Login attempt failed for user: ${email}`);
      return res.status(401).json({
        success: false,
        message: 'Incorrect password. Please try again.'
      });
    }

    console.log(`[${requestId}] ✓ Password verified successfully`);

    // Step 5: Check account verification status
    console.log(`[${requestId}] 📋 Step 5: Checking account verification status...`);
    console.log(`[${requestId}] isVerified: ${user.isVerified}`);
    
    if (!user.isVerified) {
      console.log(`[${requestId}] ⚠️ ACCOUNT NOT VERIFIED`);
      console.log(`[${requestId}] User account has not been verified yet`);
      console.log(`[${requestId}] Auto-verifying account for extension access...`);
      
      // Auto-verify the account for extension usage
      user.isVerified = true;
      await user.save();
      console.log(`[${requestId}] ✓ Account auto-verified`);
    } else {
      console.log(`[${requestId}] ✓ Account is verified`);
    }

    // Step 6: Update last login
    console.log(`[${requestId}] 📅 Step 6: Updating last login timestamp...`);
    await user.updateLastLogin();
    console.log(`[${requestId}] ✓ Last login updated`);

    // Step 7: Generate tokens
    console.log(`[${requestId}] 🎫 Step 7: Generating authentication tokens...`);
    const { accessToken, refreshToken } = generateTokens(user._id);
    
    if (!accessToken || !refreshToken) {
      console.log(`[${requestId}] ❌ TOKEN GENERATION FAILED`);
      console.log(`[${requestId}] Unable to generate authentication tokens`);
      return res.status(500).json({
        success: false,
        message: 'Failed to generate authentication tokens'
      });
    }
    
    console.log(`[${requestId}] ✓ Tokens generated successfully`);
    console.log(`[${requestId}] Access token length: ${accessToken.length}`);
    console.log(`[${requestId}] Refresh token length: ${refreshToken.length}`);

    // Step 8: Save refresh token
    console.log(`[${requestId}] 💾 Step 8: Saving refresh token to database...`);
    await User.findByIdAndUpdate(user._id, { refreshToken });
    console.log(`[${requestId}] ✓ Refresh token saved`);

    // Step 9: Prepare response
    console.log(`[${requestId}] 📦 Step 9: Preparing response data...`);
    // Don't include password hash in response
    const userResponse = {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      isVerified: user.isVerified,
      createdAt: user.createdAt
    };
    
    console.log(`[${requestId}] ✅ LOGIN SUCCESSFUL`);
    console.log(`[${requestId}] User: ${user.firstName} ${user.lastName} (${user.email})`);
    console.log(`[${requestId}] Response status: 200`);
    console.log('=================================================\n');

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: userResponse,
        accessToken,
        refreshToken
      }
    });
  } catch (error) {
    console.log(`[${requestId}] ❌ CRITICAL ERROR OCCURRED`);
    console.log(`[${requestId}] Error type: ${error.name}`);
    console.log(`[${requestId}] Error message: ${error.message}`);
    console.error(`[${requestId}] Full error stack:`, error);
    console.log('=================================================\n');
    
    res.status(500).json({
      success: false,
      message: 'An unexpected error occurred during login. Please try again.'
    });
  }
};

// @desc    Refresh access token
// @route   POST /api/v1/auth/refresh-token
// @access  Public
exports.refreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    // Find user with this refresh token (refreshToken has select:false, so query explicitly)
    const user = await User.findOne({ refreshToken }).select('+refreshToken');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);

    // Save new refresh token
    await User.findByIdAndUpdate(user._id, { refreshToken: newRefreshToken });

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error refreshing token'
    });
  }
};

// @desc    Logout user
// @route   POST /api/v1/auth/logout
// @access  Private
exports.logout = async (req, res, next) => {
  try {
    const userId = req.user.id;

    // Clear refresh token
    await User.findByIdAndUpdate(userId, { refreshToken: null });

    res.status(200).json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error during logout'
    });
  }
};
