const fs = require('fs');
let content = fs.readFileSync('public/js/scanning-system.js', 'utf8');

// Replace the status block
const statusRegex = /\/\/ Convert backend response to UI format[\s\S]*?(?=\/\/ Build indicators from backend findings)/;
const newStatus = // Convert backend response to UI format
    // Backend returns: { verdict: 'SAFE'|'SUSPICIOUS'|'MALICIOUS'|'CAUTION', score: 0-100 }
    const verdictUpper = (data.verdict || '').toUpperCase();
    const isPhishing = verdictUpper === 'MALICIOUS' || verdictUpper === 'SUSPICIOUS' || verdictUpper === 'CAUTION';
    const scoreVal = data.score || 0;
    const confidencePercent = scoreVal;
    const status = verdictUpper === 'MALICIOUS' ? 'malicious' : (verdictUpper === 'SUSPICIOUS' || verdictUpper === 'CAUTION') ? 'suspicious' : 'safe';

    ;
content = content.replace(statusRegex, newStatus);

// Replace the findings mapping block
const findingsRegex = /\/\/ Build indicators from backend findings[\s\S]*?(?=\/\/ Extract sender email from content)/;
const newFindings = // Build indicators from backend findings (headerAnalysis + bodyAnalysis)
    const allFindings = [
      ...(data.headerAnalysis?.findings || []),
      ...(data.bodyAnalysis?.findings || [])
    ];
    
    const findingIndicators = allFindings.map(f => '?? ' + (f.detail || f.type));
    
    // Build issues list from findings
    const issues = isPhishing 
      ? [\Phishing detected (Score: \/100)\, ...findingIndicators.filter(i => i.startsWith('??') || i.startsWith('?'))]
      : findingIndicators.length > 0 
        ? findingIndicators
        : ['? No phishing indicators detected', '? Email appears safe'];

    // Build indicators (include positive markers too)
    const indicators = findingIndicators.length > 0 
      ? findingIndicators 
      : (isPhishing 
        ? ['?? Phishing patterns detected', '?? Suspicious content'] 
        : ['? No phishing patterns', '? Safe content']);

    ;
content = content.replace(findingsRegex, newFindings);

// Replace the summary block
const summaryRegex = /const summary = isPhishing[\s\S]*?(?=\n\n    return \{)/;
const newSummary = const summary = isPhishing
      ? \WARNING: This email has been identified as a potential phishing attempt (Score: \/100). \. Exercise extreme caution — do not click links or download attachments.\
      : \This email appears to be legitimate. Our PhishNet analysis found no phishing indicators. The content does not match known phishing patterns.\;;
content = content.replace(summaryRegex, newSummary);

// Replace the return block to ensure correct properties
const returnRegex = /return \{[\s\S]*?(?=\n  \})/
const newReturn = eturn {
      status,
      threat: status,
      riskLevel: status === 'safe' ? 'Low' : status === 'suspicious' ? 'Medium' : 'High',
      riskPercent: scoreVal,
      issues,
      indicators,
      summary,
      confidence: confidencePercent,
      isSafe: !isPhishing,
      isVerifiedLegitimate: data.headerAnalysis?.isVerifiedLegit || false,
      senderEmail,
      subject: parsedSubject || data.bodyAnalysis?.subject || '',
      detectionMethod: 'hybrid-ml-heuristic',
      model: 'PhishNet Hybrid Engine',
      heuristicScore: data.bodyAnalysis?.score || 0,
      headerScore: data.headerAnalysis?.score || 0,
      mlResult: null,
      riskFactors: []
    };
content = content.replace(returnRegex, newReturn);

fs.writeFileSync('public/js/scanning-system.js', content, 'utf8');
console.log('Fixed file');
