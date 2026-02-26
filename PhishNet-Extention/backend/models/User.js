const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// MATCHED WITH WEBSITE USER SCHEMA - DO NOT MODIFY
// This schema must be compatible with Webpage/phishnet-website-backend/models/User.js
const userSchema = new mongoose.Schema(
  {
    // Basic user information
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      minlength: [2, 'First name must be at least 2 characters'],
      maxlength: [50, 'First name cannot exceed 50 characters'],
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      minlength: [2, 'Last name must be at least 2 characters'],
      maxlength: [50, 'Last name cannot exceed 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,})+$/,
        'Please provide a valid email address',
      ],
      index: true,
    },

    // Password stored as hash (MUST USE THIS FIELD NAME)
    passwordHash: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },

    // JWT token fields
    jwtTokens: [
      {
        token: {
          type: String,
          required: true,
        },
        createdAt: {
          type: Date,
          default: Date.now,
          expires: 7 * 24 * 60 * 60,
        },
      },
    ],

    // Account status
    isVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: {
      type: String,
      select: false,
    },
    verificationTokenExpiry: {
      type: Date,
      select: false,
    },

    // Password reset
    passwordResetToken: {
      type: String,
      select: false,
    },
    passwordResetExpiry: {
      type: Date,
      select: false,
    },

    // User settings
    notificationsEnabled: {
      type: Boolean,
      default: true,
    },
    securityLevel: {
      type: String,
      enum: ['low', 'medium', 'high'],
      default: 'high',
    },
    theme: {
      type: String,
      enum: ['light', 'dark'],
      default: 'dark',
    },

    // Refresh token for token renewal (single active session)
    refreshToken: {
      type: String,
      default: null,
      select: false,
    },

    // Extension specific fields
    extensionEnabled: {
      type: Boolean,
      default: true,
    },
    lastLoginDate: {
      type: Date,
      default: null,
    },

    // Timestamps
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

// Hash password before saving (only if modified)
userSchema.pre('save', async function (next) {
  if (!this.isModified('passwordHash')) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(10);
    this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password (matches website implementation)
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.passwordHash);
};

// Method to update lastLoginDate
userSchema.methods.updateLastLogin = function () {
  this.lastLoginDate = new Date();
  this.updatedAt = new Date();
  return this.save();
};

// Method to get full name
userSchema.methods.getFullName = function () {
  return `${this.firstName} ${this.lastName}`;
};

// Static method to find by email (case insensitive)
userSchema.statics.findByEmail = function (email) {
  return this.findOne({ email: email.toLowerCase().trim() });
};

module.exports = mongoose.model('User', userSchema);
