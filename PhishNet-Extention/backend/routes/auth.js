const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const {
  validateLogin,
  handleValidationErrors
} = require('../utils/validators');
const {
  signup,
  login,
  refreshToken,
  logout
} = require('../controllers/authController');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// @route   POST /api/v1/auth/signup
// @desc    Register a new user
// @access  Public
// NOTE: Validation is done in the controller for better error handling
router.post('/signup', signup);

// @route   POST /api/v1/auth/login
// @desc    Login user
// @access  Public
router.post('/login', validateLogin, handleValidationErrors, login);

// @route   POST /api/v1/auth/refresh-token
// @desc    Refresh access token
// @access  Public
router.post('/refresh-token', refreshToken);

// @route   POST /api/v1/auth/logout
// @desc    Logout user
// @access  Private
router.post('/logout', authenticate, logout);

// ============================================================
// PASSWORD RESET ENDPOINTS
// ============================================================

// @route   POST /api/v1/auth/forgot-password
// @desc    Generate a 6-digit reset code and store it (simulates sending email)
// @access  Public
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail })
      .select('+passwordResetToken +passwordResetExpiry');

    if (!user) {
      // Don't reveal whether email exists — return success anyway
      console.log(`[ForgotPassword] No account found for: ${normalizedEmail}`);
      return res.json({
        success: true,
        message: 'If an account with that email exists, a reset code has been sent.'
      });
    }

    // Generate 6-digit code
    const resetCode = crypto.randomInt(100000, 999999).toString();

    // Hash the code before storing (security best practice)
    const hashedCode = crypto.createHash('sha256').update(resetCode).digest('hex');

    // Store in DB — expires in 10 minutes
    user.passwordResetToken = hashedCode;
    user.passwordResetExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save({ validateBeforeSave: false });

    // Log the code to console (simulating email delivery for local dev)
    console.log('\n══════════════════════════════════════════════');
    console.log('📧 PASSWORD RESET CODE');
    console.log('══════════════════════════════════════════════');
    console.log(`   Email: ${normalizedEmail}`);
    console.log(`   Code:  ${resetCode}`);
    console.log(`   Expires in 10 minutes`);
    console.log('══════════════════════════════════════════════\n');

    res.json({
      success: true,
      message: 'If an account with that email exists, a reset code has been sent.',
      // In development, include the code in the response so the UI can show it
      ...(process.env.NODE_ENV !== 'production' && { devCode: resetCode })
    });

  } catch (error) {
    console.error('[ForgotPassword] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
});

// @route   POST /api/v1/auth/reset-password
// @desc    Verify reset code and update password
// @access  Public
router.post('/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword, confirmPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Email, reset code, and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters'
      });
    }

    if (confirmPassword && newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Hash the provided code to compare with stored hash
    const hashedCode = crypto.createHash('sha256').update(code.toString().trim()).digest('hex');

    // Find user with matching email, reset token, and non-expired token
    const user = await User.findOne({
      email: normalizedEmail,
      passwordResetToken: hashedCode,
      passwordResetExpiry: { $gt: new Date() }
    }).select('+passwordResetToken +passwordResetExpiry +passwordHash');

    if (!user) {
      console.log(`[ResetPassword] Invalid or expired code for: ${normalizedEmail}`);
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset code. Please request a new one.'
      });
    }

    // Update password (pre-save hook will hash it)
    user.passwordHash = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpiry = undefined;
    await user.save();

    console.log(`[ResetPassword] ✅ Password reset successful for: ${normalizedEmail}`);

    res.json({
      success: true,
      message: 'Password has been reset successfully. You can now log in with your new password.'
    });

  } catch (error) {
    console.error('[ResetPassword] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password. Please try again.'
    });
  }
});

module.exports = router;
