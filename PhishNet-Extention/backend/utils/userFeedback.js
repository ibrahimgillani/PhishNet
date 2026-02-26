/**
 * PhishNet User Feedback & Online Learning Module
 * 
 * Logs every user override (mark safe / mark phishing) as ground truth.
 * Periodically retrains model weight calibration using this feedback data.
 * 
 * Architecture:
 * 1. Feedback is stored in MongoDB (UserFeedback collection)
 * 2. A calibration layer learns source-specific weight adjustments
 * 3. Weights are applied on top of the base scoring in scanUrlMultiSource
 * 4. Export to CSV/JSON for offline model retraining
 */

const mongoose = require('mongoose');

// ─────────────────────────────────────────────
// MongoDB Schema for User Feedback
// ─────────────────────────────────────────────

const userFeedbackSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  url: {
    type: String,
    required: true,
    trim: true,
  },
  domain: {
    type: String,
    trim: true,
  },
  // What the model predicted
  modelVerdict: {
    type: String,
    enum: ['safe', 'suspicious', 'malicious'],
    required: true,
  },
  modelScore: {
    type: Number,
    min: 0,
    max: 1,
    required: true,
  },
  modelContributions: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  modelExplanation: {
    type: String,
    default: '',
  },
  // What the user says it actually is
  userVerdict: {
    type: String,
    enum: ['safe', 'phishing'],
    required: true,
  },
  // Whether this was a correction (model was wrong)
  isCorrection: {
    type: Boolean,
    default: false,
  },
  // Type of correction
  correctionType: {
    type: String,
    enum: ['false_positive', 'false_negative', 'confirmed_correct', null],
    default: null,
  },
  // Optional user note
  note: {
    type: String,
    maxlength: 500,
    default: '',
  },
  // Snapshot of sources at scan time (for retraining)
  sourceResults: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

userFeedbackSchema.index({ userId: 1, createdAt: -1 });
userFeedbackSchema.index({ url: 1 });
userFeedbackSchema.index({ isCorrection: 1, createdAt: -1 });
userFeedbackSchema.index({ correctionType: 1 });

let UserFeedback;
try {
  UserFeedback = mongoose.model('UserFeedback');
} catch (_) {
  UserFeedback = mongoose.model('UserFeedback', userFeedbackSchema);
}


// ─────────────────────────────────────────────
// Calibration Weights (learned from feedback)
// ─────────────────────────────────────────────

// In-memory calibration — loaded from DB on startup, updated periodically
let _calibrationWeights = {
  gsb: 1.0,
  virustotal: 1.0,
  urlhaus: 1.0,
  abuseipdb: 1.0,
  shodan: 1.0,
  ml_model: 1.0,
  domain_age: 1.0,
  redirect: 1.0,
  heuristics_typosquat: 1.0,
  heuristics_structure: 1.0,
  heuristics_ssl: 1.0,
  heuristics_entropy: 1.0,
  headless_browser: 1.0,
  lastUpdated: null,
  totalFeedback: 0,
};

const calibrationWeightsSchema = new mongoose.Schema({
  key: { type: String, default: 'global', unique: true },
  weights: { type: mongoose.Schema.Types.Mixed, required: true },
  totalFeedback: { type: Number, default: 0 },
  lastRetrained: { type: Date, default: null },
  history: [{
    weights: mongoose.Schema.Types.Mixed,
    totalFeedback: Number,
    retrainedAt: Date,
  }],
});

let CalibrationWeights;
try {
  CalibrationWeights = mongoose.model('CalibrationWeights');
} catch (_) {
  CalibrationWeights = mongoose.model('CalibrationWeights', calibrationWeightsSchema);
}


// ─────────────────────────────────────────────
// Core Functions
// ─────────────────────────────────────────────

/**
 * Record user feedback on a scan result.
 * 
 * @param {object} params
 * @param {string} params.userId - User ID
 * @param {string} params.url - Scanned URL
 * @param {string} params.modelVerdict - What the model said (safe/suspicious/malicious)
 * @param {number} params.modelScore - Model risk score (0-1)
 * @param {object} params.modelContributions - Per-source contributions
 * @param {string} params.modelExplanation - Human-readable explanation
 * @param {string} params.userVerdict - User's correction (safe/phishing)
 * @param {string} [params.note] - Optional user note
 * @param {object} [params.sourceResults] - Raw source results snapshot
 * @returns {object} Saved feedback document
 */
async function recordFeedback(params) {
  const {
    userId, url, modelVerdict, modelScore, modelContributions,
    modelExplanation, userVerdict, note, sourceResults
  } = params;

  // Determine correction type
  const modelSafe = modelVerdict === 'safe';
  const userSafe = userVerdict === 'safe';
  let correctionType = 'confirmed_correct';
  let isCorrection = false;

  if (modelSafe && !userSafe) {
    correctionType = 'false_negative'; // Model said safe, user says phishing
    isCorrection = true;
  } else if (!modelSafe && userSafe) {
    correctionType = 'false_positive'; // Model said phishing, user says safe
    isCorrection = true;
  }

  // Extract domain
  let domain = '';
  try { domain = new URL(url).hostname; } catch (_) { domain = url; }

  const feedback = await UserFeedback.create({
    userId,
    url,
    domain,
    modelVerdict,
    modelScore,
    modelContributions: modelContributions || {},
    modelExplanation: modelExplanation || '',
    userVerdict,
    isCorrection,
    correctionType,
    note: note || '',
    sourceResults: sourceResults || {},
  });

  console.log(`[Feedback] Recorded: ${correctionType} for ${url} (model: ${modelVerdict}, user: ${userVerdict})`);

  // Check if we have enough new feedback to trigger recalibration
  const recentCount = await UserFeedback.countDocuments({
    createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
  });
  if (recentCount > 0 && recentCount % 10 === 0) {
    // Auto-recalibrate every 10 feedback entries
    recalibrateWeights().catch(err => {
      console.warn('[Feedback] Auto-recalibration failed:', err.message);
    });
  }

  return feedback;
}


/**
 * Recalibrate source weights based on accumulated feedback.
 * 
 * Algorithm:
 * For each source, compute:
 *   - falsePositiveRate: how often this source flagged a URL that users confirmed safe
 *   - falseNegativeRate: how often this source missed a URL that users flagged as phishing
 *   - adjustment = 1 - (FP_rate × 0.5) + (detection_rate × 0.3) - (FN_rate × 0.4)
 *   - Clamp to [0.3, 2.0] to prevent degenerate weights
 */
async function recalibrateWeights() {
  const corrections = await UserFeedback.find({ isCorrection: true })
    .sort({ createdAt: -1 })
    .limit(500) // Use last 500 corrections
    .lean();

  if (corrections.length < 5) {
    console.log('[Feedback] Not enough corrections for recalibration:', corrections.length);
    return _calibrationWeights;
  }

  const sourceKeys = Object.keys(_calibrationWeights).filter(k => k !== 'lastUpdated' && k !== 'totalFeedback');
  const sourceStats = {};
  for (const key of sourceKeys) {
    sourceStats[key] = { truePositive: 0, falsePositive: 0, falseNegative: 0, total: 0 };
  }

  for (const fb of corrections) {
    const contribs = fb.modelContributions || {};

    for (const key of sourceKeys) {
      // Determine if this source contributed to the score
      let sourceContrib = 0;
      if (key.startsWith('heuristics_')) {
        const subKey = key.replace('heuristics_', '');
        sourceContrib = contribs.heuristics?.[subKey] || 0;
      } else {
        sourceContrib = contribs[key] || 0;
      }

      const sourceActive = sourceContrib > 0.01;

      if (fb.correctionType === 'false_positive') {
        // Model flagged, user says safe
        if (sourceActive) sourceStats[key].falsePositive++;
        sourceStats[key].total++;
      } else if (fb.correctionType === 'false_negative') {
        // Model missed, user says phishing
        if (!sourceActive) sourceStats[key].falseNegative++;
        else sourceStats[key].truePositive++;
        sourceStats[key].total++;
      }
    }
  }

  // Compute adjusted weights
  const newWeights = { ...structuredClone(_calibrationWeights) };
  for (const key of sourceKeys) {
    const stats = sourceStats[key];
    if (stats.total === 0) continue;

    const fpRate = stats.falsePositive / stats.total;
    const fnRate = stats.falseNegative / stats.total;
    const detectionRate = stats.truePositive / Math.max(1, stats.truePositive + stats.falseNegative);

    // Weight adjustment formula
    let adjustment = 1.0 - (fpRate * 0.5) + (detectionRate * 0.3) - (fnRate * 0.4);
    adjustment = Math.max(0.3, Math.min(2.0, adjustment)); // Clamp

    newWeights[key] = parseFloat(adjustment.toFixed(3));
  }

  newWeights.lastUpdated = new Date();
  newWeights.totalFeedback = corrections.length;

  // Save to DB
  await CalibrationWeights.findOneAndUpdate(
    { key: 'global' },
    {
      weights: newWeights,
      totalFeedback: corrections.length,
      lastRetrained: new Date(),
      $push: {
        history: {
          $each: [{ weights: { ...newWeights }, totalFeedback: corrections.length, retrainedAt: new Date() }],
          $slice: -20, // Keep last 20 calibrations
        }
      }
    },
    { upsert: true, new: true }
  );

  _calibrationWeights = newWeights;
  console.log('[Feedback] Recalibrated weights from', corrections.length, 'corrections:', JSON.stringify(newWeights));

  return newWeights;
}


/**
 * Load calibration weights from DB on startup.
 */
async function loadCalibrationWeights() {
  try {
    const doc = await CalibrationWeights.findOne({ key: 'global' }).lean();
    if (doc && doc.weights) {
      _calibrationWeights = { ..._calibrationWeights, ...doc.weights };
      console.log('[Feedback] Loaded calibration weights (', doc.totalFeedback, 'feedback samples)');
    }
  } catch (err) {
    console.warn('[Feedback] Could not load calibration weights:', err.message);
  }
  return _calibrationWeights;
}


/**
 * Get current calibration weights (for applying in risk engine).
 */
function getCalibrationWeights() {
  return { ..._calibrationWeights };
}


/**
 * Apply calibration weights to raw contributions.
 * Called from scanUrlMultiSource after computing raw contributions.
 * 
 * @param {object} contributions - Raw per-source contributions
 * @returns {object} Calibrated contributions
 */
function applyCalibration(contributions) {
  const w = _calibrationWeights;
  const calibrated = JSON.parse(JSON.stringify(contributions)); // deep clone

  calibrated.gsb = (calibrated.gsb || 0) * (w.gsb || 1);
  calibrated.virustotal = (calibrated.virustotal || 0) * (w.virustotal || 1);
  calibrated.urlhaus = (calibrated.urlhaus || 0) * (w.urlhaus || 1);
  calibrated.abuseipdb = (calibrated.abuseipdb || 0) * (w.abuseipdb || 1);
  calibrated.shodan = (calibrated.shodan || 0) * (w.shodan || 1);
  calibrated.ml_model = (calibrated.ml_model || 0) * (w.ml_model || 1);
  calibrated.domain_age = (calibrated.domain_age || 0) * (w.domain_age || 1);
  calibrated.redirect = (calibrated.redirect || 0) * (w.redirect || 1);

  if (calibrated.heuristics) {
    calibrated.heuristics.typosquat = (calibrated.heuristics.typosquat || 0) * (w.heuristics_typosquat || 1);
    calibrated.heuristics.structure = (calibrated.heuristics.structure || 0) * (w.heuristics_structure || 1);
    calibrated.heuristics.ssl = (calibrated.heuristics.ssl || 0) * (w.heuristics_ssl || 1);
    calibrated.heuristics.entropy = (calibrated.heuristics.entropy || 0) * (w.heuristics_entropy || 1);
  }

  return calibrated;
}


/**
 * Get feedback statistics for dashboard display.
 */
async function getFeedbackStats() {
  const [total, corrections, fpCount, fnCount, recent] = await Promise.all([
    UserFeedback.countDocuments(),
    UserFeedback.countDocuments({ isCorrection: true }),
    UserFeedback.countDocuments({ correctionType: 'false_positive' }),
    UserFeedback.countDocuments({ correctionType: 'false_negative' }),
    UserFeedback.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    }),
  ]);

  return {
    totalFeedback: total,
    totalCorrections: corrections,
    falsePositives: fpCount,
    falseNegatives: fnCount,
    recentWeek: recent,
    accuracy: total > 0 ? (((total - corrections) / total) * 100).toFixed(1) + '%' : 'N/A',
    calibrationWeights: _calibrationWeights,
  };
}


/**
 * Export feedback data for offline model retraining.
 * 
 * @param {object} [options]
 * @param {string} [options.format='json'] - 'json' or 'csv'
 * @param {number} [options.limit=1000]
 * @returns {string} Formatted data
 */
async function exportFeedbackData(options = {}) {
  const format = options.format || 'json';
  const limit = options.limit || 1000;

  const data = await UserFeedback.find()
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();

  if (format === 'csv') {
    const headers = ['url', 'domain', 'modelVerdict', 'modelScore', 'userVerdict', 'correctionType', 'createdAt'];
    const rows = data.map(d =>
      headers.map(h => {
        const val = d[h];
        if (val instanceof Date) return val.toISOString();
        if (typeof val === 'string') return `"${val.replace(/"/g, '""')}"`;
        return val;
      }).join(',')
    );
    return headers.join(',') + '\n' + rows.join('\n');
  }

  return JSON.stringify(data, null, 2);
}


module.exports = {
  UserFeedback,
  CalibrationWeights,
  recordFeedback,
  recalibrateWeights,
  loadCalibrationWeights,
  getCalibrationWeights,
  applyCalibration,
  getFeedbackStats,
  exportFeedbackData,
};
