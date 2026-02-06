/**
 * Simple test script to verify model integration
 * Run with: node test-model.js
 */

import phishingDetector from './models/phishing-detector.js';
import dotenv from 'dotenv';

dotenv.config();

async function runTests() {
  console.log('\n🧪 PhishNet Model Integration Test\n');
  console.log('=' .repeat(50));

  try {
    // Test 1: Initialize model
    console.log('\n📌 Test 1: Initializing model...');
    const modelPath = process.env.LOCAL_MODEL_PATH;
    await phishingDetector.initialize(modelPath);
    console.log('✅ Model initialized successfully');

    // Test 2: Get model info
    console.log('\n📌 Test 2: Getting model info...');
    const modelInfo = phishingDetector.getModelInfo();
    console.log('✅ Model Info:');
    console.log(JSON.stringify(modelInfo, null, 2));

    // Test 3: Classify legitimate email
    console.log('\n📌 Test 3: Classifying LEGITIMATE email...');
    const legitEmail = await phishingDetector.classifyEmail(
      'Invoice #12345',
      'Please review the attached invoice for your order.'
    );
    console.log('✅ Result:');
    console.log(`   Classification: ${legitEmail.classification}`);
    console.log(`   Confidence: ${legitEmail.confidence}`);
    console.log(`   Risk Level: ${legitEmail.riskLevel}`);

    // Test 4: Classify phishing email
    console.log('\n📌 Test 4: Classifying PHISHING email...');
    const phishingEmail = await phishingDetector.classifyEmail(
      'URGENT: Verify Your Account Immediately',
      'Dear User, your account has been compromised. Click [LINK] to verify your credentials now.'
    );
    console.log('✅ Result:');
    console.log(`   Classification: ${phishingEmail.classification}`);
    console.log(`   Confidence: ${phishingEmail.confidence}`);
    console.log(`   Risk Level: ${phishingEmail.riskLevel}`);

    // Test 5: Batch classification
    console.log('\n📌 Test 5: Batch classification...');
    const emails = [
      { subject: 'Meeting Scheduled', body: 'Your meeting is scheduled for tomorrow at 2pm' },
      { subject: 'URGENT: Action Required', body: 'Click [LINK] to verify your account or it will be closed' }
    ];
    const batchResults = await phishingDetector.classifyBatch(emails);
    console.log('✅ Batch Results:');
    batchResults.forEach((result, idx) => {
      console.log(`   Email ${idx + 1}: ${result.classification} (${result.confidence})`);
    });

    // Test 6: Text preprocessing
    console.log('\n📌 Test 6: Text preprocessing...');
    const rawText = 'Visit https://bank.com or call +1-800-555-1234 for help';
    const processed = phishingDetector.preprocessText(rawText);
    console.log(`   Original: ${rawText}`);
    console.log(`   Processed: ${processed}`);

    console.log('\n' + '='.repeat(50));
    console.log('\n✅ All tests passed! Model is working correctly.\n');
    process.exit(0);

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error('\nMake sure:');
    console.error('  1. npm install has been run');
    console.error('  2. .env file exists with MODEL_PATH configured');
    console.error('  3. Internet connection available for model download');
    process.exit(1);
  }
}

// Run tests
runTests();
