/**
 * PhishNet Adversarial Mutation Testing Module
 * 
 * Generates mutations of known phishing domains to stress-test detection:
 * 1. Insert random benign words
 * 2. Change TLD
 * 3. Add long subdomain chains
 * 4. Replace characters with Unicode homoglyphs
 * 5. Keyboard-adjacent typos
 * 6. Character doubling/removal
 * 7. Hyphen insertion (combo-squatting)
 * 
 * Also measures explainability consistency:
 * - For identical risk scores, explanations should be stable
 * - Semantic equivalence should produce similar scores
 */

// Unicode homoglyphs for adversarial testing
const HOMOGLYPH_MAP = {
  'a': ['\u0430', '\u03b1', '@'],       // Cyrillic а, Greek α
  'b': ['\u0432', '\u13cf'],             // Cyrillic в
  'c': ['\u0441', '\u03f2'],             // Cyrillic с, Greek ϲ
  'd': ['\u0501', '\u13e7'],             // Cyrillic ԁ
  'e': ['\u0435', '\u03b5', '3'],        // Cyrillic е, Greek ε
  'g': ['\u0261', '9'],                  // Latin g variant
  'h': ['\u04bb', '\u0570'],             // Cyrillic һ
  'i': ['\u0456', '1', 'l', '|'],        // Cyrillic і
  'k': ['\u043a'],                       // Cyrillic к
  'l': ['\u04cf', '1', 'I'],             // Cyrillic ӏ
  'm': ['\u043c'],                       // Cyrillic м
  'n': ['\u043f'],                       // Cyrillic п
  'o': ['\u043e', '\u03bf', '0'],        // Cyrillic о, Greek ο
  'p': ['\u0440', '\u03c1'],             // Cyrillic р, Greek ρ
  'r': ['\u0433'],                       // Cyrillic г
  's': ['\u0455', '$', '5'],             // Cyrillic ѕ
  't': ['\u0442', '\u03c4'],             // Cyrillic т, Greek τ
  'u': ['\u03bc'],                       // Greek μ
  'v': ['\u0475'],                       // Cyrillic ѵ
  'w': ['\u0461'],                       // Cyrillic ѡ
  'x': ['\u0445'],                       // Cyrillic х
  'y': ['\u0443'],                       // Cyrillic у
  'z': ['\u0437'],                       // Cyrillic з
};

const BENIGN_WORDS = [
  'secure', 'login', 'verify', 'account', 'update', 'confirm',
  'service', 'support', 'help', 'online', 'web', 'my', 'official',
  'real', 'auth', 'portal', 'access', 'billing', 'payment',
];

const ALT_TLDS = [
  '.xyz', '.top', '.click', '.link', '.site', '.online', '.live',
  '.club', '.icu', '.vip', '.buzz', '.net', '.org', '.info', '.co',
  '.io', '.app', '.dev', '.tech', '.space', '.fun', '.lol',
];

const KEYBOARD_ADJACENT = {
  'a': ['s','q','z'],  'b': ['v','n','g'],  'c': ['x','v','d'],
  'd': ['s','f','e'],  'e': ['w','r','d'],  'f': ['d','g','r'],
  'g': ['f','h','t'],  'h': ['g','j','y'],  'i': ['u','o','k'],
  'j': ['h','k','u'],  'k': ['j','l','i'],  'l': ['k','o','p'],
  'm': ['n','j','k'],  'n': ['b','m','h'],  'o': ['i','p','l'],
  'p': ['o','l'],      'q': ['w','a'],      'r': ['e','t','f'],
  's': ['a','d','w'],  't': ['r','y','g'],  'u': ['y','i','j'],
  'v': ['c','b','f'],  'w': ['q','e','s'],  'x': ['z','c','s'],
  'y': ['t','u','h'],  'z': ['x','a','s'],
};

/**
 * Generate all mutation variants of a known phishing domain.
 * 
 * @param {string} domain - Base domain to mutate (e.g., 'paypal.com')
 * @param {object} [options] - Generation options
 * @param {number} [options.maxPerType=3] - Max mutations per type
 * @returns {Array<{url: string, mutation: string, type: string}>}
 */
function generateMutations(domain, options = {}) {
  const maxPerType = options.maxPerType || 3;
  const mutations = [];
  
  // Parse domain
  const parts = domain.split('.');
  if (parts.length < 2) return mutations;
  const baseName = parts.slice(0, -1).join('.');
  const tld = '.' + parts[parts.length - 1];

  // ── 1. Insert benign words (combo-squatting) ──
  const wordSample = shuffle(BENIGN_WORDS).slice(0, maxPerType);
  for (const word of wordSample) {
    mutations.push({
      url: `https://${baseName}-${word}${tld}`,
      mutation: `${baseName}-${word}${tld}`,
      type: 'combo_squat_suffix',
      description: `Added "${word}" suffix with hyphen`,
    });
    mutations.push({
      url: `https://${word}-${baseName}${tld}`,
      mutation: `${word}-${baseName}${tld}`,
      type: 'combo_squat_prefix',
      description: `Added "${word}" prefix with hyphen`,
    });
  }

  // ── 2. Change TLD ──
  const tldSample = shuffle(ALT_TLDS.filter(t => t !== tld)).slice(0, maxPerType);
  for (const newTld of tldSample) {
    mutations.push({
      url: `https://${baseName}${newTld}`,
      mutation: `${baseName}${newTld}`,
      type: 'tld_swap',
      description: `Changed TLD from ${tld} to ${newTld}`,
    });
  }

  // ── 3. Add long subdomain chains ──
  const subdomains = ['secure', 'login', 'www', 'mail', 'account', 'auth'];
  for (let depth = 2; depth <= Math.min(4, maxPerType + 1); depth++) {
    const chain = shuffle(subdomains).slice(0, depth).join('.');
    mutations.push({
      url: `https://${chain}.${baseName}.evilsite.xyz`,
      mutation: `${chain}.${baseName}.evilsite.xyz`,
      type: 'subdomain_chain',
      description: `${depth}-level subdomain chain with brand in subdomain`,
    });
  }

  // ── 4. Unicode homoglyph replacement ──
  const baseChars = baseName.toLowerCase().split('');
  let homoglyphCount = 0;
  for (let i = 0; i < baseChars.length && homoglyphCount < maxPerType; i++) {
    const ch = baseChars[i];
    if (HOMOGLYPH_MAP[ch]) {
      const replacement = HOMOGLYPH_MAP[ch][0]; // Use first homoglyph
      const mutated = baseChars.slice();
      mutated[i] = replacement;
      const mutatedDomain = mutated.join('') + tld;
      mutations.push({
        url: `https://${mutatedDomain}`,
        mutation: mutatedDomain,
        type: 'homoglyph',
        description: `Replaced '${ch}' at position ${i} with homoglyph '${replacement}' (U+${replacement.charCodeAt(0).toString(16).padStart(4, '0')})`,
      });
      homoglyphCount++;
    }
  }

  // ── 5. Keyboard-adjacent typos ──
  let typoCount = 0;
  for (let i = 0; i < baseChars.length && typoCount < maxPerType; i++) {
    const ch = baseChars[i];
    if (KEYBOARD_ADJACENT[ch]) {
      const adj = KEYBOARD_ADJACENT[ch][0];
      const mutated = baseChars.slice();
      mutated[i] = adj;
      const mutatedDomain = mutated.join('') + tld;
      mutations.push({
        url: `https://${mutatedDomain}`,
        mutation: mutatedDomain,
        type: 'keyboard_typo',
        description: `Swapped '${ch}' for adjacent key '${adj}' at position ${i}`,
      });
      typoCount++;
    }
  }

  // ── 6. Character doubling ──
  for (let i = 0; i < baseChars.length && i < maxPerType; i++) {
    const mutated = baseChars.slice();
    mutated.splice(i, 0, baseChars[i]); // double the char
    const mutatedDomain = mutated.join('') + tld;
    mutations.push({
      url: `https://${mutatedDomain}`,
      mutation: mutatedDomain,
      type: 'char_doubling',
      description: `Doubled character '${baseChars[i]}' at position ${i}`,
    });
  }

  // ── 7. Character removal ──
  for (let i = 0; i < baseChars.length && i < maxPerType; i++) {
    if (baseChars.length <= 3) break; // don't remove from very short names
    const mutated = baseChars.slice();
    mutated.splice(i, 1);
    const mutatedDomain = mutated.join('') + tld;
    mutations.push({
      url: `https://${mutatedDomain}`,
      mutation: mutatedDomain,
      type: 'char_removal',
      description: `Removed character '${baseChars[i]}' at position ${i}`,
    });
  }

  // ── 8. Number substitution ──
  const numSubs = { 'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 'l': '1', 'g': '9' };
  let numSubCount = 0;
  for (let i = 0; i < baseChars.length && numSubCount < maxPerType; i++) {
    const ch = baseChars[i];
    if (numSubs[ch]) {
      const mutated = baseChars.slice();
      mutated[i] = numSubs[ch];
      const mutatedDomain = mutated.join('') + tld;
      mutations.push({
        url: `https://${mutatedDomain}`,
        mutation: mutatedDomain,
        type: 'number_substitution',
        description: `Substituted '${ch}' with '${numSubs[ch]}'`,
      });
      numSubCount++;
    }
  }

  return mutations;
}


/**
 * Run stress test: generate mutations and scan each one.
 * Returns pass/fail results for each mutation.
 * 
 * @param {string} domain - Known phishing target domain (e.g., 'paypal.com')
 * @param {function} scanFunction - async (url) => { risk_score, status, explanation, contributions }
 * @param {object} [options]
 * @param {number} [options.minExpectedScore=0.30] - Minimum risk score mutations should achieve
 * @param {number} [options.maxPerType=2] - Max mutations per type
 * @returns {object} Test report
 */
async function stressTestDomain(domain, scanFunction, options = {}) {
  const minScore = options.minExpectedScore || 0.30;
  const mutations = generateMutations(domain, { maxPerType: options.maxPerType || 2 });
  
  const results = [];
  let passed = 0;
  let failed = 0;
  const failedMutations = [];

  for (const mutation of mutations) {
    try {
      const scanResult = await scanFunction(mutation.url);
      const score = scanResult.risk_score || (scanResult.score / 100) || 0;
      const status = scanResult.status || 'UNKNOWN';
      const isPass = score >= minScore || status === 'MALICIOUS' || status === 'SUSPICIOUS';

      const entry = {
        mutation: mutation.mutation,
        type: mutation.type,
        description: mutation.description,
        score,
        status,
        pass: isPass,
      };

      results.push(entry);
      if (isPass) passed++;
      else {
        failed++;
        failedMutations.push(entry);
      }
    } catch (err) {
      results.push({
        mutation: mutation.mutation,
        type: mutation.type,
        description: mutation.description,
        error: err.message,
        pass: false,
      });
      failed++;
    }
  }

  return {
    domain,
    totalMutations: mutations.length,
    passed,
    failed,
    passRate: mutations.length > 0 ? ((passed / mutations.length) * 100).toFixed(1) + '%' : 'N/A',
    failedMutations,
    results,
  };
}


/**
 * Measure explainability consistency across similar-scoring URLs.
 * Groups results by score buckets and checks if explanations within
 * each bucket mention the same risk factors.
 * 
 * @param {Array<{url: string, score: number, explanation: string, contributions: object}>} scanResults
 * @returns {object} Consistency report
 */
function measureExplainabilityConsistency(scanResults) {
  if (!scanResults || scanResults.length < 2) {
    return { consistent: true, buckets: [], message: 'Not enough results to measure consistency' };
  }

  // Group into score buckets (0.1 wide)
  const buckets = {};
  for (const result of scanResults) {
    const score = result.score || result.risk_score || 0;
    const bucketKey = (Math.floor(score * 10) / 10).toFixed(1);
    if (!buckets[bucketKey]) buckets[bucketKey] = [];
    buckets[bucketKey].push(result);
  }

  const inconsistencies = [];

  for (const [bucketKey, items] of Object.entries(buckets)) {
    if (items.length < 2) continue;

    // Extract risk factor mentions from explanations
    const riskFactorSets = items.map(item => {
      const explanation = item.explanation || '';
      const factors = new Set();

      // Extract mentioned risk categories
      const categories = [
        'Google Safe Browsing', 'VirusTotal', 'URLhaus', 'AbuseIPDB', 'Shodan',
        'ML', 'BERT', 'Typosquatting', 'Structure', 'SSL', 'Entropy',
        'Domain Age', 'Redirect', 'corroboration',
      ];
      for (const cat of categories) {
        if (explanation.toLowerCase().includes(cat.toLowerCase())) {
          factors.add(cat);
        }
      }
      return factors;
    });

    // Check pairwise consistency
    for (let i = 0; i < riskFactorSets.length; i++) {
      for (let j = i + 1; j < riskFactorSets.length; j++) {
        const setA = riskFactorSets[i];
        const setB = riskFactorSets[j];
        const union = new Set([...setA, ...setB]);
        const intersection = new Set([...setA].filter(x => setB.has(x)));
        const jaccardSimilarity = union.size > 0 ? intersection.size / union.size : 1;

        if (jaccardSimilarity < 0.5) {
          inconsistencies.push({
            bucket: bucketKey,
            urlA: items[i].url,
            urlB: items[j].url,
            scoreA: items[i].score || items[i].risk_score,
            scoreB: items[j].score || items[j].risk_score,
            factorsA: [...setA],
            factorsB: [...setB],
            jaccardSimilarity: jaccardSimilarity.toFixed(2),
          });
        }
      }
    }
  }

  return {
    consistent: inconsistencies.length === 0,
    totalResults: scanResults.length,
    bucketCount: Object.keys(buckets).length,
    inconsistencies,
    message: inconsistencies.length === 0
      ? 'All similar-scored URLs have consistent explanations.'
      : `Found ${inconsistencies.length} inconsistency(ies) where similar scores have different explanations.`,
  };
}


// Fisher-Yates shuffle
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}


module.exports = {
  generateMutations,
  stressTestDomain,
  measureExplainabilityConsistency,
};
