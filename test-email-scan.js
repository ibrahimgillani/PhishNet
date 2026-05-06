const http = require('http');

const data = JSON.stringify({
  subject: "Test",
  emailContent: "This is a test email body with no links."
});

const options = {
  hostname: 'localhost',
  port: 5000,
  path: '/api/v1/emails/scan',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data)
  }
};

const req = http.request(options, (res) => {
  console.log(`STATUS: ${res.statusCode}`);
  res.setEncoding('utf8');
  res.on('data', (chunk) => {
    console.log(`BODY: ${chunk}`);
  });
});

req.on('error', (e) => {
  console.error(`problem with request: ${e.message}`);
});

req.write(data);
req.end();
