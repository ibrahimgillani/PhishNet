const axios = require('axios');
require('dotenv').config({ path: './PhishNet-Extention/backend/.env' });

async function testML() {
  const url = 'http://google.com';
  const apiToken = process.env.HUGGINGFACE_API_TOKEN;
  const modelId = process.env.HUGGINGFACE_MODEL_ID || 'mrm8488/bert-tiny-finetuned-phishing';
  const endpoint = `https://api-inference.huggingface.co/models/${modelId}`;

  console.log('Testing ML Model:', modelId);
  console.log('Endpoint:', endpoint);
  console.log('Token starts with:', apiToken?.substring(0, 10));

  try {
    const response = await axios.post(
      endpoint,
      { inputs: url },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiToken?.trim()}`
        },
        timeout: 15000
      }
    );
    console.log('Success!', JSON.stringify(response.data, null, 2));
  } catch (err) {
    console.error('Error Status:', err.response?.status);
    console.error('Error Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Error Message:', err.message);
  }
}

testML();
