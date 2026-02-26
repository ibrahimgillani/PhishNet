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

module.exports = router;
