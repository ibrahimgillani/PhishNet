const URLCheckHistory = require('../models/URLCheckHistory');

// @desc    Add URL check to history
// @route   POST /api/v1/urls/check
// @access  Private
exports.checkUrl = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { url, status, reasons, userAction, wasWarned,
            confidence, threatScore, threatLevel, threatType,
            isSafe, scanType, summary, indicators, issues,
            details, senderEmail } = req.body;

    // Extract domain from URL or email address
    let domain;
    try {
      if (url && url.includes('@')) {
        // Email address — extract domain part after @
        domain = url.split('@').pop().toLowerCase();
      } else {
        const urlObj = new URL(url);
        domain = urlObj.hostname;
      }
    } catch (e) {
      domain = req.body.domain || url;
    }

    const urlCheck = await URLCheckHistory.create({
      userId,
      url: url.toLowerCase(),
      domain,
      status: status || 'unknown',
      reasons: reasons || [],
      userAction: userAction || 'ignored',
      wasWarned: wasWarned || false,
      confidence: confidence != null ? parseFloat(confidence) : null,
      threatScore: threatScore != null ? parseFloat(threatScore) : null,
      threatLevel: threatLevel || null,
      threatType: threatType || null,
      isSafe: isSafe != null ? isSafe : null,
      scanType: scanType || 'url',
      summary: summary || null,
      indicators: indicators || [],
      issues: issues || [],
      details: details || null,
      senderEmail: senderEmail || null
    });

    res.status(201).json({
      success: true,
      message: 'URL check recorded',
      data: urlCheck
    });
  } catch (error) {
    console.error('Check URL error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error checking URL'
    });
  }
};

// @desc    Get user's URL history
// @route   GET /api/v1/urls/history
// @access  Private
exports.getUrlHistory = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const limit = parseInt(req.query.limit) || 500;
    const skip = parseInt(req.query.skip) || 0;

    const history = await URLCheckHistory.getUserHistory(userId, limit, skip);
    const total = await URLCheckHistory.countDocuments({ userId });

    res.status(200).json({
      success: true,
      data: {
        history,
        total,
        limit,
        skip
      }
    });
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error fetching URL history'
    });
  }
};

// @desc    Get user's unsafe URLs
// @route   GET /api/v1/urls/unsafe
// @access  Private
exports.getUnsafeUrls = async (req, res, next) => {
  try {
    const userId = req.user.id;

    const unsafeUrls = await URLCheckHistory.getUserUnsafeUrls(userId);

    res.status(200).json({
      success: true,
      data: unsafeUrls
    });
  } catch (error) {
    console.error('Get unsafe URLs error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error fetching unsafe URLs'
    });
  }
};

// @desc    Check if URL was previously checked
// @route   GET /api/v1/urls/check-history/:url
// @access  Private
exports.checkUrlHistory = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { url } = req.params;

    const history = await URLCheckHistory.checkUrlHistory(userId, url.toLowerCase());

    if (!history) {
      return res.status(404).json({
        success: false,
        message: 'URL not found in history'
      });
    }

    res.status(200).json({
      success: true,
      data: history
    });
  } catch (error) {
    console.error('Check history error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error checking URL history'
    });
  }
};

// @desc    Update URL check status
// @route   PUT /api/v1/urls/:id
// @access  Private
exports.updateUrlStatus = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { status, userAction } = req.body;

    // Ensure the record belongs to the requesting user
    const urlCheck = await URLCheckHistory.findOneAndUpdate(
      { _id: id, userId: req.user.id },
      { status, userAction, updatedAt: new Date() },
      { new: true, runValidators: true }
    );

    if (!urlCheck) {
      return res.status(404).json({
        success: false,
        message: 'URL check record not found or does not belong to the user'
      });
    }

    res.status(200).json({
      success: true,
      message: 'URL status updated',
      data: urlCheck
    });
  } catch (error) {
    console.error('Update URL status error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error updating URL status'
    });
  }
};

// @desc    Delete URL from history
// @route   DELETE /api/v1/urls/:id
// @access  Private
exports.deleteUrlRecord = async (req, res, next) => {
  try {
    const { id } = req.params;

    // Ensure deletion only removes records owned by the requester
    const urlCheck = await URLCheckHistory.findOneAndDelete({ _id: id, userId: req.user.id });

    if (!urlCheck) {
      return res.status(404).json({
        success: false,
        message: 'URL check record not found or does not belong to the user'
      });
    }

    res.status(200).json({
      success: true,
      message: 'URL record deleted successfully'
    });
  } catch (error) {
    console.error('Delete URL error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error deleting URL record'
    });
  }
};
