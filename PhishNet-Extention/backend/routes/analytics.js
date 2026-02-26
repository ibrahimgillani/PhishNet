const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const {
  getAnalytics,
  updateAnalytics
} = require('../controllers/analyticsController');

// @route   GET /api/v1/analytics
// @desc    Get platform analytics
// @access  Public
router.get('/', getAnalytics);

// @route   POST /api/v1/analytics/update
// @desc    Update analytics (manual trigger)
// @access  Private
router.post('/update', authenticate, updateAnalytics);

module.exports = router;
