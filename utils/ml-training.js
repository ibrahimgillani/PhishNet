/**
 * ML Model Fine-Tuning System
 * Provides utilities for training and fine-tuning the phishing detection model
 * 
 * Features:
 * - Training data collection and management
 * - Data preprocessing and augmentation
 * - Model training interface
 * - Performance evaluation
 * - Export training data for external tools
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class PhishingDataset {
  constructor() {
    this.dataDir = path.join(__dirname, '..', 'training_data');
    this.phishingFile = path.join(this.dataDir, 'phishing_samples.jsonl');
    this.legitimateFile = path.join(this.dataDir, 'legitimate_samples.jsonl');
    this.urlDataFile = path.join(this.dataDir, 'url_samples.jsonl');
    this.feedbackFile = path.join(this.dataDir, 'user_feedback.jsonl');
    
    this.ensureDataDir();
  }

  /**
   * Ensure training data directory exists
   */
  ensureDataDir() {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
      console.log('📁 Created training data directory:', this.dataDir);
    }
  }

  /**
   * Add a phishing email sample
   */
  addPhishingSample(text, metadata = {}) {
    const sample = {
      text,
      label: 'phishing',
      timestamp: new Date().toISOString(),
      source: metadata.source || 'manual',
      confidence: metadata.confidence || 1.0,
      features: this.extractFeatures(text),
      ...metadata
    };

    this.appendToFile(this.phishingFile, sample);
    return sample;
  }

  /**
   * Add a legitimate email sample
   */
  addLegitimateSample(text, metadata = {}) {
    const sample = {
      text,
      label: 'legitimate',
      timestamp: new Date().toISOString(),
      source: metadata.source || 'manual',
      confidence: metadata.confidence || 1.0,
      features: this.extractFeatures(text),
      ...metadata
    };

    this.appendToFile(this.legitimateFile, sample);
    return sample;
  }

  /**
   * Add a URL sample with label
   */
  addURLSample(url, isPhishing, metadata = {}) {
    const sample = {
      url,
      isPhishing,
      timestamp: new Date().toISOString(),
      source: metadata.source || 'manual',
      riskFactors: metadata.riskFactors || [],
      ...metadata
    };

    this.appendToFile(this.urlDataFile, sample);
    return sample;
  }

  /**
   * Record user feedback for model improvement
   */
  addFeedback(input, predictedLabel, correctLabel, inputType = 'email') {
    const feedback = {
      input,
      inputType,
      predictedLabel,
      correctLabel,
      isCorrect: predictedLabel === correctLabel,
      timestamp: new Date().toISOString()
    };

    this.appendToFile(this.feedbackFile, feedback);
    return feedback;
  }

  /**
   * Extract features from text for analysis
   */
  extractFeatures(text) {
    const features = {
      length: text.length,
      wordCount: text.split(/\s+/).length,
      
      // URL features
      hasURL: /https?:\/\/\S+/i.test(text),
      urlCount: (text.match(/https?:\/\/\S+/gi) || []).length,
      
      // Urgency indicators
      hasUrgency: /urgent|immediate|action required|act now|expires|limited time/i.test(text),
      urgencyCount: (text.match(/urgent|immediate|action required|act now|expires|limited time/gi) || []).length,
      
      // Credential keywords
      hasCredentialRequest: /password|login|signin|account|verify|confirm|update|secure/i.test(text),
      
      // Money/financial
      hasFinancialTerms: /bank|credit|debit|payment|billing|invoice|transfer|wire/i.test(text),
      
      // Threat indicators
      hasThreat: /suspend|terminate|close|lock|fraud|unauthorized|unusual activity/i.test(text),
      
      // Reward/prize
      hasReward: /winner|won|prize|lottery|gift|reward|congratulations|selected/i.test(text),
      
      // Contact requests
      hasContactRequest: /call|phone|contact|click|reply|respond/i.test(text),
      
      // Personal info requests
      hasPersonalInfoRequest: /social security|ssn|dob|date of birth|mother.*maiden|personal information/i.test(text),
      
      // Spelling/grammar issues
      hasSpellingIssues: /recieve|verifiy|acccount|secur1ty|paypa1|amaz0n|g00gle/i.test(text),
      
      // ALL CAPS words
      capsWordsCount: (text.match(/\b[A-Z]{4,}\b/g) || []).length,
      
      // Excessive punctuation
      excessivePunctuation: (text.match(/[!?]{2,}/g) || []).length,
      
      // HTML presence
      hasHTML: /<[^>]+>/i.test(text)
    };

    return features;
  }

  /**
   * Append data to JSONL file
   */
  appendToFile(filePath, data) {
    fs.appendFileSync(filePath, JSON.stringify(data) + '\n');
  }

  /**
   * Read all samples from a JSONL file
   */
  readSamples(filePath) {
    if (!fs.existsSync(filePath)) {
      return [];
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    return content.trim().split('\n')
      .filter(line => line.trim())
      .map(line => JSON.parse(line));
  }

  /**
   * Get all training data
   */
  getAllTrainingData() {
    const phishing = this.readSamples(this.phishingFile);
    const legitimate = this.readSamples(this.legitimateFile);
    const urls = this.readSamples(this.urlDataFile);
    const feedback = this.readSamples(this.feedbackFile);

    return {
      phishing,
      legitimate,
      urls,
      feedback,
      stats: {
        phishingSamples: phishing.length,
        legitimateSamples: legitimate.length,
        urlSamples: urls.length,
        feedbackEntries: feedback.length,
        totalEmailSamples: phishing.length + legitimate.length
      }
    };
  }

  /**
   * Export training data in various formats
   */
  exportTrainingData(format = 'csv') {
    const data = this.getAllTrainingData();
    const exportDir = path.join(this.dataDir, 'exports');
    
    if (!fs.existsSync(exportDir)) {
      fs.mkdirSync(exportDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    switch (format.toLowerCase()) {
      case 'csv':
        return this.exportToCSV(data, exportDir, timestamp);
      case 'json':
        return this.exportToJSON(data, exportDir, timestamp);
      case 'huggingface':
        return this.exportForHuggingFace(data, exportDir, timestamp);
      default:
        throw new Error(`Unknown export format: ${format}`);
    }
  }

  /**
   * Export to CSV format
   */
  exportToCSV(data, exportDir, timestamp) {
    // Email samples
    const emailCSV = ['text,label,features'];
    
    [...data.phishing, ...data.legitimate].forEach(sample => {
      const text = sample.text.replace(/"/g, '""').replace(/\n/g, ' ');
      emailCSV.push(`"${text}","${sample.label}","${JSON.stringify(sample.features).replace(/"/g, '""')}"`);
    });

    const emailFile = path.join(exportDir, `email_training_${timestamp}.csv`);
    fs.writeFileSync(emailFile, emailCSV.join('\n'));

    // URL samples
    const urlCSV = ['url,is_phishing,risk_factors'];
    data.urls.forEach(sample => {
      const url = sample.url.replace(/"/g, '""');
      const factors = (sample.riskFactors || []).join(';');
      urlCSV.push(`"${url}",${sample.isPhishing},"${factors}"`);
    });

    const urlFile = path.join(exportDir, `url_training_${timestamp}.csv`);
    fs.writeFileSync(urlFile, urlCSV.join('\n'));

    return { emailFile, urlFile };
  }

  /**
   * Export to JSON format
   */
  exportToJSON(data, exportDir, timestamp) {
    const file = path.join(exportDir, `training_data_${timestamp}.json`);
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
    return { file };
  }

  /**
   * Export in HuggingFace datasets format
   */
  exportForHuggingFace(data, exportDir, timestamp) {
    const hfData = {
      info: {
        description: 'PhishNet training dataset',
        features: {
          text: { dtype: 'string' },
          label: { dtype: 'string' }
        }
      },
      data: []
    };

    [...data.phishing, ...data.legitimate].forEach(sample => {
      hfData.data.push({
        text: sample.text,
        label: sample.label
      });
    });

    const file = path.join(exportDir, `huggingface_dataset_${timestamp}.json`);
    fs.writeFileSync(file, JSON.stringify(hfData, null, 2));
    return { file, sampleCount: hfData.data.length };
  }

  /**
   * Get model improvement suggestions based on feedback
   */
  getImprovementSuggestions() {
    const feedback = this.readSamples(this.feedbackFile);
    
    if (feedback.length === 0) {
      return { message: 'No feedback data available' };
    }

    const incorrect = feedback.filter(f => !f.isCorrect);
    const accuracy = ((feedback.length - incorrect.length) / feedback.length * 100).toFixed(2);

    const suggestions = [];

    // Analyze false positives (predicted phishing, was legitimate)
    const falsePositives = incorrect.filter(f => 
      f.predictedLabel === 'phishing' && f.correctLabel === 'legitimate'
    );

    // Analyze false negatives (predicted legitimate, was phishing)
    const falseNegatives = incorrect.filter(f => 
      f.predictedLabel === 'legitimate' && f.correctLabel === 'phishing'
    );

    if (falsePositives.length > falseNegatives.length) {
      suggestions.push('Model is too aggressive - consider adding more legitimate samples');
    }

    if (falseNegatives.length > falsePositives.length) {
      suggestions.push('Model is missing phishing - consider adding more phishing samples');
    }

    return {
      totalFeedback: feedback.length,
      correctPredictions: feedback.length - incorrect.length,
      incorrectPredictions: incorrect.length,
      accuracy: `${accuracy}%`,
      falsePositives: falsePositives.length,
      falseNegatives: falseNegatives.length,
      suggestions
    };
  }

  /**
   * Clear all training data (use with caution)
   */
  clearAllData() {
    const files = [this.phishingFile, this.legitimateFile, this.urlDataFile, this.feedbackFile];
    
    files.forEach(file => {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    });

    return { message: 'All training data cleared' };
  }
}

// Pre-built phishing templates for augmentation
const phishingTemplates = [
  {
    subject: "Urgent: Your account has been compromised",
    body: "Dear Customer,\n\nWe have detected suspicious activity on your account. Your account access has been temporarily limited. Please verify your identity immediately by clicking the link below:\n\n{link}\n\nFailure to verify within 24 hours will result in permanent account suspension.\n\nSecurity Team"
  },
  {
    subject: "Action Required: Verify Your Payment Information",
    body: "Your payment method needs to be updated. We were unable to process your recent transaction.\n\nClick here to update your billing information: {link}\n\nIf you do not update within 48 hours, your account will be closed.\n\nBilling Department"
  },
  {
    subject: "You've Won! Claim Your Prize Now",
    body: "CONGRATULATIONS!\n\nYou have been selected as the winner of our monthly lottery! You have won $1,000,000!\n\nTo claim your prize, click here: {link}\n\nAct now - this offer expires in 24 hours!\n\nLottery Commission"
  },
  {
    subject: "Password Expiration Notice",
    body: "Your password will expire in 24 hours. To avoid being locked out of your account, please reset your password immediately.\n\nReset Password: {link}\n\nThis is an automated security message.\n\nIT Security"
  },
  {
    subject: "Important: Tax Refund Available",
    body: "Dear Taxpayer,\n\nAfter review of your tax documents, we have determined you are eligible for a refund of $3,247.00.\n\nTo receive your refund, please verify your information: {link}\n\nIRS Department"
  }
];

const legitimateTemplates = [
  {
    subject: "Your order has shipped",
    body: "Hi,\n\nGreat news! Your order #12345 has shipped and is on its way.\n\nTracking number: ABC123456789\n\nYou can track your package on our website.\n\nThank you for your purchase!\n\nCustomer Service Team"
  },
  {
    subject: "Weekly Newsletter",
    body: "Hello,\n\nHere's what's new this week:\n\n- New feature announcement\n- Tips and tricks\n- Community highlights\n\nAs always, thank you for being part of our community.\n\nBest regards,\nThe Team"
  },
  {
    subject: "Meeting reminder",
    body: "Hi,\n\nThis is a reminder that we have a meeting scheduled for tomorrow at 2pm.\n\nAgenda:\n1. Project updates\n2. Q&A session\n3. Next steps\n\nPlease let me know if you have any questions.\n\nBest,\nJohn"
  },
  {
    subject: "Your receipt from Store",
    body: "Thank you for your purchase!\n\nOrder Details:\n- Product: Widget\n- Price: $29.99\n- Tax: $2.40\n- Total: $32.39\n\nYour card ending in 1234 was charged.\n\nThank you for shopping with us!"
  }
];

export default new PhishingDataset();
export { PhishingDataset, phishingTemplates, legitimateTemplates };
