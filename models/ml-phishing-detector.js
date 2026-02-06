/**
 * ML-Based Phishing Detection using ONNX Runtime
 * Uses Transformers.js with pre-trained phishing detection models
 */

import { pipeline, env } from '@xenova/transformers';

// Configure transformers.js
env.allowLocalModels = true;
env.useBrowserCache = false;

class MLPhishingDetector {
  constructor() {
    this.classifier = null;
    this.isLoaded = false;
    // Primary: ONNX phishing detection model (specifically trained for phishing)
    this.phishingModelName = 'onnx-community/phishing-email-detection-distilbert_v2.4.1-ONNX';
    // Backup: Another ONNX phishing model
    this.backupPhishingModel = 'onnx-community/bert-finetuned-phishing-ONNX';
    // Final fallback: Sentiment model (less accurate for phishing)
    this.sentimentModelName = 'Xenova/distilbert-base-uncased-finetuned-sst-2-english';
    this.usePhishingModel = false;
    this.currentModel = null;
    this.loadingPromise = null;
  }

  /**
   * Initialize the ML model
   */
  async initialize() {
    if (this.isLoaded) return true;
    if (this.loadingPromise) return this.loadingPromise;

    this.loadingPromise = this._loadModel();
    return this.loadingPromise;
  }

  async _loadModel() {
    console.log('🧠 Loading ML Phishing Detection Model...');
    console.log('📦 This may take a moment on first run (downloading model)...');

    // Try models in order of preference
    const modelsToTry = [
      { name: this.phishingModelName, label: 'Primary Phishing ONNX Model', isPhishingModel: true },
      { name: this.backupPhishingModel, label: 'Backup Phishing ONNX Model', isPhishingModel: true },
      { name: this.sentimentModelName, label: 'Sentiment Fallback Model', isPhishingModel: false }
    ];

    for (const model of modelsToTry) {
      try {
        console.log(`🔄 Attempting to load ${model.label}...`);
        console.log(`   Model: ${model.name}`);
        
        this.classifier = await pipeline('text-classification', model.name, {
          quantized: true, // Use quantized model for faster inference
        });
        
        this.usePhishingModel = model.isPhishingModel;
        this.currentModel = model.name;
        this.isLoaded = true;
        console.log(`✅ ${model.label} loaded successfully!`);
        console.log(`📊 Model: ${model.name}`);
        return true;
      } catch (error) {
        console.warn(`⚠️ Could not load ${model.label}: ${error.message}`);
      }
    }

    console.error('❌ Failed to load any ML model');
    this.isLoaded = false;
    return false;
  }

  /**
   * Preprocess email text for the model
   */
  preprocessText(subject, body) {
    // Combine subject and body
    let text = '';
    if (subject) text += `Subject: ${subject} `;
    if (body) text += body;

    // Clean the text
    text = text
      .replace(/https?:\/\/[^\s]+/g, '[URL]') // Replace URLs with token
      .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[EMAIL]') // Replace emails
      .replace(/\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/g, '[PHONE]') // Replace phone numbers
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim();

    // Truncate to max length (512 tokens ~ 2000 chars for safety)
    if (text.length > 2000) {
      text = text.substring(0, 2000);
    }

    return text;
  }

  /**
   * Classify email using ML model
   */
  async classifyWithML(subject, body) {
    if (!this.isLoaded) {
      await this.initialize();
    }

    if (!this.classifier) {
      throw new Error('ML model not available');
    }

    const text = this.preprocessText(subject, body);
    
    if (!text || text.length < 10) {
      return {
        isPhishing: false,
        confidence: 0.5,
        label: 'unknown',
        method: 'ml-insufficient-text'
      };
    }

    try {
      const startTime = Date.now();
      const results = await this.classifier(text);
      const inferenceTime = Date.now() - startTime;

      console.log(`🔍 ML inference completed in ${inferenceTime}ms`);
      console.log('📊 Raw ML results:', results);

      // Process results based on model type
      if (this.usePhishingModel) {
        // ONNX Phishing models typically return:
        // - LABEL_0/safe/legitimate vs LABEL_1/phishing/unsafe
        // - Or "phishing"/"legitimate" directly
        const result = results[0];
        const labelLower = result.label.toLowerCase();
        
        // Detect phishing label (handles various naming conventions)
        const isPhishing = labelLower === 'label_1' || 
                          labelLower === 'phishing' || 
                          labelLower === 'unsafe' ||
                          labelLower.includes('phish') ||
                          labelLower.includes('malicious');
        
        const confidence = result.score;

        return {
          isPhishing,
          confidence,
          label: isPhishing ? 'phishing' : 'legitimate',
          rawLabel: result.label,
          method: `ml-phishing-onnx`,
          modelUsed: this.currentModel,
          inferenceTime
        };
      } else {
        // Fallback model (sentiment) - NEGATIVE could indicate phishing-like content
        const result = results[0];
        // Use NEGATIVE sentiment as a proxy for suspicious content
        const isNegative = result.label === 'NEGATIVE';
        const confidence = result.score;

        return {
          isPhishing: isNegative && confidence > 0.7,
          confidence: isNegative ? confidence : 1 - confidence,
          label: isNegative && confidence > 0.7 ? 'suspicious' : 'likely-safe',
          rawLabel: result.label,
          method: 'ml-sentiment-fallback',
          modelUsed: this.currentModel,
          inferenceTime
        };
      }

    } catch (error) {
      console.error('ML classification error:', error);
      throw error;
    }
  }

  /**
   * Get model information
   */
  getModelInfo() {
    return {
      isLoaded: this.isLoaded,
      modelType: this.usePhishingModel ? 'Phishing-ONNX' : 'Sentiment-Fallback',
      modelName: this.currentModel,
      quantized: true,
      runtime: 'ONNX Runtime (via Transformers.js)'
    };
  }
}

// Export singleton instance
const mlDetector = new MLPhishingDetector();
export default mlDetector;
export { MLPhishingDetector };
