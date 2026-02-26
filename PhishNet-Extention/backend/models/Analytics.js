const mongoose = require('mongoose');

const analyticsSchema = new mongoose.Schema(
  {
    // Platform-wide statistics
    totalRegisteredUsers: {
      type: Number,
      default: 0,
      min: 0
    },
    totalPhishingUrlsDetected: {
      type: Number,
      default: 0,
      min: 0
    },
    totalUnsafeUrlsDetected: {
      type: Number,
      default: 0,
      min: 0
    },
    totalProtectionEvents: {
      type: Number,
      default: 0,
      min: 0
    },
    totalSafeWebsitesVisited: {
      type: Number,
      default: 0,
      min: 0
    },
    // Aggregated statistics
    averageUnsafeUrlsPerUser: {
      type: Number,
      default: 0,
      min: 0
    },
    averageProtectionEventsPerUser: {
      type: Number,
      default: 0,
      min: 0
    },
    // Safe vs unsafe ratio
    safeToUnsafeRatio: {
      type: Number,
      default: 0
    },
    // Date of last update
    lastUpdatedAt: {
      type: Date,
      default: Date.now
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

// Method to update analytics from all users
analyticsSchema.statics.updateAnalytics = async function () {
  try {
    const User = mongoose.model('User');
    const users = await User.find();

    const totalUsers = users.length;
    const totalUnsafe = users.reduce((sum, user) => sum + user.unsafeUrlsDetectedCount, 0);
    const totalProtection = users.reduce((sum, user) => sum + user.protectionEventsCount, 0);
    const totalSafe = users.reduce((sum, user) => sum + user.safeWebsitesVisitedCount, 0);

    const avgUnsafe = totalUsers > 0 ? totalUnsafe / totalUsers : 0;
    const avgProtection = totalUsers > 0 ? totalProtection / totalUsers : 0;
    const safeToUnsafeRatio = totalUnsafe > 0 ? totalSafe / totalUnsafe : 0;

    let analytics = await this.findOne();
    if (!analytics) {
      analytics = new this();
    }

    analytics.totalRegisteredUsers = totalUsers;
    analytics.totalPhishingUrlsDetected = totalUnsafe;
    analytics.totalUnsafeUrlsDetected = totalUnsafe;
    analytics.totalProtectionEvents = totalProtection;
    analytics.totalSafeWebsitesVisited = totalSafe;
    analytics.averageUnsafeUrlsPerUser = avgUnsafe;
    analytics.averageProtectionEventsPerUser = avgProtection;
    analytics.safeToUnsafeRatio = safeToUnsafeRatio;
    analytics.lastUpdatedAt = new Date();

    return await analytics.save();
  } catch (error) {
    console.error('Error updating analytics:', error);
    throw error;
  }
};

// Method to get current analytics
analyticsSchema.statics.getAnalytics = async function () {
  try {
    let analytics = await this.findOne();
    if (!analytics) {
      analytics = new this();
      await analytics.save();
    }
    return analytics;
  } catch (error) {
    console.error('Error getting analytics:', error);
    throw error;
  }
};

module.exports = mongoose.model('Analytics', analyticsSchema);
