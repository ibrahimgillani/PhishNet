const { body, validationResult } = require('express-validator');

// Validation middleware wrapper
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map((error) => ({
        field: error.param,
        message: error.msg
      }))
    });
  }
  next();
};

// Signup validation rules
const validateSignup = [
  body('firstName')
    .trim()
    .notEmpty()
    .withMessage('First name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('First name must be between 2 and 100 characters'),
  body('lastName')
    .trim()
    .notEmpty()
    .withMessage('Last name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Last name must be between 2 and 100 characters'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number'),
  body('confirmPassword')
    .notEmpty()
    .withMessage('Please confirm your password'),
  // Custom validation to check if passwords match
  body().custom((value, { req }) => {
    if (req.body.password !== req.body.confirmPassword) {
      throw new Error('Passwords do not match');
    }
    return true;
  })
];

// Login validation rules
const validateLogin = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// Email validation rule
const validateEmail = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail()
];

// URL validation rule — also accepts email addresses for email-type scans
const validateUrl = [
  body('url')
    .trim()
    .notEmpty()
    .withMessage('URL is required')
    .custom((value, { req }) => {
      // Allow email addresses when scanType is 'email' or value contains @
      const scanType = (req.body.scanType || '').toLowerCase();
      if (scanType === 'email' || value.includes('@')) {
        return true;
      }
      // For URL scans, validate as URL
      try {
        new URL(value.startsWith('http') ? value : `https://${value}`);
        return true;
      } catch (e) {
        throw new Error('Please provide a valid URL');
      }
    })
];

// URL status validation
const validateUrlStatus = [
  body('status')
    .isIn(['safe', 'unsafe', 'phishing', 'threat', 'unknown'])
    .withMessage('Invalid status. Must be one of: safe, unsafe, phishing, threat, unknown'),
  body('url')
    .trim()
    .notEmpty()
    .withMessage('URL is required')
];

module.exports = {
  handleValidationErrors,
  validateSignup,
  validateLogin,
  validateEmail,
  validateUrl,
  validateUrlStatus
};
