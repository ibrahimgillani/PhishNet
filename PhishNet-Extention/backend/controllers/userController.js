const User = require('../models/User');
const UserSettings = require('../models/UserSettings');

// @desc    Get current user profile
// @route   GET /api/v1/users/me
// @access  Private
exports.getCurrentUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error fetching user'
    });
  }
};

// @desc    Get user settings (including profile picture)
// @route   GET /api/v1/users/settings
// @access  Private
exports.getSettings = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const settingsDoc = await UserSettings.findOne({ userId });

    res.status(200).json({
      success: true,
      data: settingsDoc
        ? { settings: settingsDoc.settings || {}, profilePicture: settingsDoc.profilePicture || null }
        : { settings: {}, profilePicture: null }
    });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error fetching settings'
    });
  }
};

// @desc    Upsert user settings and optional profile picture
// @route   POST /api/v1/users/settings
// @access  Private
exports.saveSettings = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { settings = {}, profilePicture } = req.body;

    const upserted = await UserSettings.findOneAndUpdate(
      { userId },
      {
        userId,
        settings,
        ...(profilePicture !== undefined ? { profilePicture } : {}),
        updatedAt: new Date()
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    // Optionally mirror profile picture onto User if provided
    if (profilePicture !== undefined) {
      await User.findByIdAndUpdate(userId, { updatedAt: new Date() });
    }

    res.status(200).json({
      success: true,
      message: 'Settings saved successfully',
      data: {
        settings: upserted.settings,
        profilePicture: upserted.profilePicture
      }
    });
  } catch (error) {
    console.error('Save settings error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error saving settings'
    });
  }
};

// @desc    Get user profile (merges avatar from UserSettings)
// @route   GET /api/v1/users/profile
// @access  Private
exports.getProfile = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Merge avatar from UserSettings so frontend gets it in one call
    const settingsDoc = await UserSettings.findOne({ userId });
    const userObj = user.toObject();
    userObj.avatar = settingsDoc?.profilePicture || null;
    userObj.avatarFit = 'cover';

    res.status(200).json({
      success: true,
      data: { user: userObj }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ success: false, message: error.message || 'Error fetching profile' });
  }
};

// @desc    Update user profile (name fields)
// @route   PUT /api/v1/users/profile
// @access  Private
exports.updateProfile = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { firstName, lastName } = req.body;

    const updates = {
      updatedAt: new Date()
    };

    if (firstName) updates.firstName = firstName.trim();
    if (lastName) updates.lastName = lastName.trim();

    const user = await User.findByIdAndUpdate(
      userId,
      updates,
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Merge avatar from UserSettings
    const settingsDoc = await UserSettings.findOne({ userId });
    const userObj = user.toObject();
    userObj.avatar = settingsDoc?.profilePicture || null;
    userObj.avatarFit = 'cover';

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: { user: userObj }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error updating profile'
    });
  }
};

// @desc    Update or remove user avatar (profile picture)
// @route   PUT /api/v1/users/profile/avatar
// @access  Private
exports.updateAvatar = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { avatar, fitMode, remove } = req.body;

    let profilePicture = null;
    if (!remove && avatar) {
      profilePicture = avatar;
    }

    // Upsert into UserSettings
    const upserted = await UserSettings.findOneAndUpdate(
      { userId },
      { userId, profilePicture, updatedAt: new Date() },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    // Build response with full user data + avatar
    const user = await User.findById(userId);
    const userObj = user ? user.toObject() : {};
    userObj.avatar = upserted.profilePicture || null;
    userObj.avatarFit = fitMode || 'cover';

    res.status(200).json({
      success: true,
      message: remove ? 'Avatar removed successfully' : 'Avatar updated successfully',
      data: { user: userObj }
    });
  } catch (error) {
    console.error('Update avatar error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error updating avatar'
    });
  }
};

// @desc    Change user password
// @route   PUT /api/v1/users/password
// @access  Private
exports.changePassword = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'All password fields are required' });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'New passwords do not match' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'New password must be at least 8 characters' });
    }

    // Get user with password hash
    const user = await User.findById(userId).select('+passwordHash');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Verify current password
    const isMatch = await user.matchPassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    // Update password (pre-save hook will hash it)
    user.passwordHash = newPassword;
    user.updatedAt = new Date();
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Password updated successfully'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error changing password'
    });
  }
};

// @desc    Get user statistics
// @route   GET /api/v1/users/stats
// @access  Private
exports.getUserStats = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const stats = {
      safeWebsitesVisitedCount: user.safeWebsitesVisitedCount,
      unsafeUrlsDetectedCount: user.unsafeUrlsDetectedCount,
      protectionEventsCount: user.protectionEventsCount,
      lastLogin: user.lastLogin
    };

    res.status(200).json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error fetching statistics'
    });
  }
};

// @desc    Increment safe websites count
// @route   POST /api/v1/users/increment-safe-visits
// @access  Private
exports.incrementSafeVisits = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    await user.incrementSafeVisits();

    res.status(200).json({
      success: true,
      message: 'Safe visit count incremented',
      data: {
        safeWebsitesVisitedCount: user.safeWebsitesVisitedCount
      }
    });
  } catch (error) {
    console.error('Increment safe visits error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error incrementing safe visits'
    });
  }
};

// @desc    Increment unsafe URLs detected count
// @route   POST /api/v1/users/increment-unsafe-detected
// @access  Private
exports.incrementUnsafeDetected = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    await user.incrementUnsafeDetected();

    res.status(200).json({
      success: true,
      message: 'Unsafe URLs detected count incremented',
      data: {
        unsafeUrlsDetectedCount: user.unsafeUrlsDetectedCount
      }
    });
  } catch (error) {
    console.error('Increment unsafe detected error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error incrementing unsafe detected count'
    });
  }
};

// @desc    Increment protection events count
// @route   POST /api/v1/users/increment-protection-events
// @access  Private
exports.incrementProtectionEvents = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    await user.incrementProtectionEvents();

    res.status(200).json({
      success: true,
      message: 'Protection events count incremented',
      data: {
        protectionEventsCount: user.protectionEventsCount
      }
    });
  } catch (error) {
    console.error('Increment protection events error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error incrementing protection events'
    });
  }
};
