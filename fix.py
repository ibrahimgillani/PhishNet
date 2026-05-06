import re

with open('public/js/scanning-system.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace from `// Build indicators from backend findings` down to the end of the function
pattern = re.compile(r'// Build indicators from backend findings.*?\}\n  \}', re.DOTALL)

replacement = """// Build indicators from backend findings (headerAnalysis + bodyAnalysis)
    const allFindings = [
      ...(data.headerAnalysis?.findings || []),
      ...(data.bodyAnalysis?.findings || [])
    ];
    
    const findingIndicators = allFindings.map(f => '?? ' + (f.detail || f.type));
    
    // Build issues list from findings
    const issues = isPhishing 
      ? [`Phishing detected (Score: ${scoreVal}/100)`, ...findingIndicators.filter(i => i.startsWith('??') || i.startsWith('?'))]
      : findingIndicators.length > 0 
        ? findingIndicators
        : ['? No phishing indicators detected', '? Email appears safe'];

    // Build indicators (include positive markers too)
    const indicators = findingIndicators.length > 0 
      ? findingIndicators 
      : (isPhishing 
        ? ['?? Phishing patterns detected', '?? Suspicious content'] 
        : ['? No phishing patterns', '? Safe content']);

    // Extract sender email from backend response
    const senderEmail = data.headerAnalysis?.sender?.from || null;

    // Build summary
    const summary = isPhishing
      ? `WARNING: This email has been identified as a potential phishing attempt (Score: ${scoreVal}/100). ${findingIndicators.slice(0, 3).join('. ')}. Exercise extreme caution — do not click links or download attachments.`
      : `This email appears to be legitimate. Our PhishNet analysis found no phishing indicators. The content does not match known phishing patterns.`;

    return {
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
  }"""

content = pattern.sub(replacement, content)

with open('public/js/scanning-system.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done")
