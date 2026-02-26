const Analytics = require('../models/Analytics');
const URLCheckHistory = require('../models/URLCheckHistory');
const User = require('../models/User');

// @desc    Get platform analytics (real-time computed from DB)
// @route   GET /api/v1/analytics
// @access  Public
exports.getAnalytics = async (req, res, next) => {
  try {
    // --- Compute real-time stats from URLCheckHistory ---

    // Total URLs scanned (all time)
    const totalScans = await URLCheckHistory.countDocuments();

    // Scans today (since midnight UTC)
    const todayStart = new Date();
    todayStart.setUTCHours(0, 0, 0, 0);
    const scansToday = await URLCheckHistory.countDocuments({
      createdAt: { $gte: todayStart }
    });

    // Threats detected (unsafe + phishing + threat)
    const threatsDetected = await URLCheckHistory.countDocuments({
      status: { $in: ['unsafe', 'phishing', 'threat'] }
    });

    // Safe scans
    const safeScans = await URLCheckHistory.countDocuments({
      status: 'safe'
    });

    // Active users (users who have scanned at least once)
    const activeUserIds = await URLCheckHistory.distinct('userId');
    const activeUsers = activeUserIds.length;

    // Registered users
    const registeredUsers = await User.countDocuments();

    // Detection rate = threats / total * 100
    const detectionRate = totalScans > 0
      ? parseFloat(((threatsDetected / totalScans) * 100).toFixed(1))
      : 0;

    // Protection rate = safe / total * 100
    const protectionRate = totalScans > 0
      ? parseFloat(((safeScans / totalScans) * 100).toFixed(1))
      : 0;

    // Also try to update the legacy Analytics doc for backward compatibility
    try {
      let analytics = await Analytics.findOne();
      if (!analytics) analytics = new Analytics();
      analytics.totalRegisteredUsers = registeredUsers;
      analytics.totalUnsafeUrlsDetected = threatsDetected;
      analytics.totalPhishingUrlsDetected = threatsDetected;
      analytics.totalSafeWebsitesVisited = safeScans;
      analytics.totalProtectionEvents = totalScans;
      analytics.lastUpdatedAt = new Date();
      await analytics.save();
    } catch (e) {
      // Non-critical
    }

    res.status(200).json({
      success: true,
      data: {
        totalScans,
        scansToday,
        threatsDetected,
        safeScans,
        activeUsers,
        registeredUsers,
        detectionRate,
        protectionRate,
        lastUpdated: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Get analytics error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error fetching analytics'
    });
  }
};

// @desc    Update analytics (manual trigger)
// @route   POST /api/v1/analytics/update
// @access  Private (should be admin only in production)
exports.updateAnalytics = async (req, res, next) => {
  try {
    // Trigger the same real-time computation
    const totalScans = await URLCheckHistory.countDocuments();
    const threatsDetected = await URLCheckHistory.countDocuments({
      status: { $in: ['unsafe', 'phishing', 'threat'] }
    });
    const safeScans = await URLCheckHistory.countDocuments({ status: 'safe' });
    const registeredUsers = await User.countDocuments();

    let analytics = await Analytics.findOne();
    if (!analytics) analytics = new Analytics();
    analytics.totalRegisteredUsers = registeredUsers;
    analytics.totalUnsafeUrlsDetected = threatsDetected;
    analytics.totalSafeWebsitesVisited = safeScans;
    analytics.totalProtectionEvents = totalScans;
    analytics.lastUpdatedAt = new Date();
    await analytics.save();

    res.status(200).json({
      success: true,
      message: 'Analytics updated successfully',
      data: analytics
    });
  } catch (error) {
    console.error('Update analytics error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error updating analytics'
    });
  }
};
