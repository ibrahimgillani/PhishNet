const http = require('http');

const data = JSON.stringify({ url: process.argv[2] || 'https://google.com' });

const req = http.request({
  hostname: 'localhost',
  port: 5000,
  path: '/api/v1/urls/scan',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer test',
    'Content-Length': data.length
  }
}, (res) => {
  let body = '';
  res.on('data', c => body += c);
  res.on('end', () => {
    const r = JSON.parse(body);
    if (!r.success) { console.log('Error:', r.message); return; }
    console.log(`\n=== Scan: ${r.meta?.url || process.argv[2]} ===`);
    console.log(`Status: ${r.status} | Score: ${r.score} | Confidence: ${r.confidence}% | Sources: ${(r.sources || []).length}/7`);
    console.log('\nSource Details:');
    for (const s of r.sourceDetails || []) {
      console.log(`  ${s.source}: safe=${s.safe}`);
      if (s.source === 'URL Heuristics') {
        console.log('    Details keys:', Object.keys(s.details || {}));
        const det = s.details || {};
        if (det.ssl) {
          const ssl = det.ssl;
          console.log('    --- SSL Certificate Analysis ---');
          console.log(`    Valid: ${ssl.valid} | Authorized: ${ssl.authorized}`);
          console.log(`    Self-signed: ${ssl.selfSigned} | Hostname match: ${ssl.hostnameMatch}`);
          console.log(`    Days until expiry: ${ssl.daysUntilExpiry}`);
          console.log(`    Cert age (days): ${ssl.certAgeDays}`);
          console.log(`    Validity period (days): ${ssl.validityDays}`);
          console.log(`    Issuer: ${ssl.issuer} | Subject: ${ssl.subject}`);
          console.log(`    Free CA: ${ssl.isFreeCert} | TLS: ${ssl.tlsVersion} | Weak TLS: ${ssl.weakTLS}`);
          console.log(`    Wildcard: ${ssl.hasWildcard} | SAN count: ${ssl.sanCount}`);
          console.log(`    Anomalies: ${(ssl.anomalies || []).join(', ') || 'none'}`);
          if (ssl.ct) {
            console.log(`    CT Logs: ${ssl.ct.totalCerts} certs, newest ${ssl.ct.newestCertDays}d ago, first seen ${ssl.ct.domainFirstSeen}d ago`);
          }
        }
      }
    }
    console.log('\nThreats:');
    if (!r.threats || r.threats.length === 0) console.log('  (none)');
    for (const t of r.threats || []) {
      console.log(`  [${t.source}] ${t.type}: ${t.detail || t.details || ''}`);
    }
  });
});
req.on('error', e => console.error('Connection error:', e.message));
req.write(data);
req.end();
