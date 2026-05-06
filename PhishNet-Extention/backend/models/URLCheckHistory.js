const mongoose = require('mongoose');

const urlCheckHistorySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required']
    },
    url: {
      type: String,
      required: [true, 'URL is required'],
      trim: true,
      lowercase: true
    },
    status: {
      type: String,
      enum: ['safe', 'unsafe', 'phishing', 'threat', 'unknown'],
      default: 'unknown'
    },
    // Reason for warning (can have multiple reasons)
    reasons: {
      type: [String],
      default: []
    },
    // User action taken
    userAction: {
      type: String,
      enum: ['visited', 'avoided', 'reported', 'ignored'],
      default: 'ignored'
    },
    // Whether the user was warned
    wasWarned: {
      type: Boolean,
      default: false
    },
    // Threat intelligence score (0-100 from multi-source scan)
    threatScore: {
      type: Number,
      default: null
    },
    // Confidence percentage (0-100)
    confidence: {
      type: Number,
      default: null
    },
    // Threat classification
    threatLevel: {
      type: String,
      default: null
    },
    threatType: {
      type: String,
      default: null
    },
    isSafe: {
      type: Boolean,
      default: null
    },
    scanType: {
      type: String,
      default: 'url'
    },
    summary: {
      type: String,
      default: null
    },
    indicators: {
      type: [String],
      default: []
    },
    issues: {
      type: [String],
      default: []
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    senderEmail: {
      type: String,
      default: null
    },
    // Additional metadata
    domain: {
      type: String,
      trim: true,
      lowercase: true
    },
    timestamp: {
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

// Index for efficient querying
urlCheckHistorySchema.index({ userId: 1, timestamp: -1 });
urlCheckHistorySchema.index({ status: 1 });
urlCheckHistorySchema.index({ url: 1 });

// Method to get user's URL history
urlCheckHistorySchema.statics.getUserHistory = async function (userId, limit = 500, skip = 0) {
  try {
    return await this.find({ userId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .skip(skip)
      .lean();
  } catch (error) {
    console.error('Error fetching user history:', error);
    throw error;
  }
};

// Method to get unsafe URLs for a user
urlCheckHistorySchema.statics.getUserUnsafeUrls = async function (userId) {
  try {
    return await this.find({
      userId,
      status: { $in: ['unsafe', 'phishing', 'threat'] }
    }).sort({ timestamp: -1 });
  } catch (error) {
    console.error('Error fetching unsafe URLs:', error);
    throw error;
  }
};

// Method to check if URL was previously checked
urlCheckHistorySchema.statics.checkUrlHistory = async function (userId, url) {
  try {
    return await this.findOne({ userId, url });
  } catch (error) {
    console.error('Error checking URL history:', error);
    throw error;
  }
};

module.exports = mongoose.model('URLCheckHistory', urlCheckHistorySchema);
