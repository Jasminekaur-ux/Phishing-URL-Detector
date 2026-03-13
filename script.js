// ──────────────────────────────────────────────
//  🔑 REPLACE THESE WITH YOUR OWN KEYS
// ──────────────────────────────────────────────
const VT_API_KEY        = "YOUR_VIRUSTOTAL_API_KEY_HERE";            // ← VirusTotal v3
const GOOGLE_SB_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY_HERE";  // ← Google Safe Browsing v4

// ── DOM references ────────────────────────────
const form       = document.getElementById('urlForm');
const urlInput   = document.getElementById('urlInput');
const checkBtn   = document.getElementById('checkBtn');
const resultDiv  = document.getElementById('result');
const loadingDiv = document.getElementById('loading');

// ── Data ──────────────────────────────────────
// Popular brands for typosquatting detection (expand as needed)
const trustedBrands = [
  "paypal", "amazon", "netflix", "google", "microsoft", "apple",
  "facebook", "instagram", "twitter", "youtube", "linkedin",
  "bankofamerica", "chase", "wellsfargo", "ebay", "aliexpress"
];

const suspiciousTLDs = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
  ".club", ".online", ".site", ".buzz", ".loan", ".win"
];

// ── Levenshtein Distance ──────────────────────
function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = Array(b.length + 1).fill(null).map(() => Array(a.length + 1).fill(0));

  for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j++) matrix[j][0] = j;

  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      const indicator = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,           // deletion
        matrix[j - 1][i] + 1,           // insertion
        matrix[j - 1][i - 1] + indicator // substitution
      );
    }
  }
  return matrix[b.length][a.length];
}

// ── Shannon Entropy ───────────────────────────
function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const char of str) freq[char] = (freq[char] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ── Heuristic Analysis ────────────────────────
function heuristicAnalysis(urlStr) {
  try {
    const url = new URL(urlStr.trim());
    let score = 0;
    const reasons = [];

    // 1. Protocol check
    if (url.protocol !== 'https:') {
      score += 40;
      reasons.push("HTTP instead of HTTPS");
    }

    // 2. IP address used instead of domain
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname) || url.hostname.includes('[')) {
      score += 45;
      reasons.push("IP address instead of domain name");
    }

    // 3. Suspicious TLD
    const tld = url.hostname.split('.').pop().toLowerCase();
    if (suspiciousTLDs.some(s => tld === s.slice(1))) {
      score += 30;
      reasons.push(`Suspicious TLD (.${tld})`);
    }

    // 4. Excessive subdomains
    const dotCount = (url.hostname.match(/\./g) || []).length;
    if (dotCount > 4) {
      score += 25;
      reasons.push("Many subdomains (possible obfuscation)");
    }

    // 5. Very long URL
    if (urlStr.length > 90) {
      score += 20;
      reasons.push("Very long URL");
    }

    // 6. Too many special characters
    const specialChars = (urlStr.match(/[%@#?&=]/g) || []).length;
    if (specialChars > 6) {
      score += 15;
      reasons.push("Too many special characters");
    }

    // 7. Typosquatting via Levenshtein distance
    const domainLower = url.hostname.toLowerCase().replace(/^www\./, '');
    for (const brand of trustedBrands) {
      const dist = levenshteinDistance(domainLower, brand);
      if (dist <= 2 && domainLower !== brand && dist !== 0) {
        score += 35;
        reasons.push(`Possible typosquatting of "${brand}" (edit distance ${dist})`);
        break; // one strong match is enough
      }
    }

    // 8. High Shannon entropy (randomized-looking domain)
    const domainEntropy = shannonEntropy(url.hostname);
    if (domainEntropy > 3.8) {
      score += 28;
      reasons.push(`High domain entropy (${domainEntropy.toFixed(2)}) – looks randomized`);
    }

    score = Math.min(100, score);
    return { score, reasons, entropy: domainEntropy.toFixed(2) };
  } catch (err) {
    return { score: 0, reasons: ["Invalid URL format"], entropy: "N/A" };
  }
}

// ── VirusTotal Check ──────────────────────────
async function checkVirusTotal(url) {
  if (!VT_API_KEY || VT_API_KEY === "YOUR_VIRUSTOTAL_API_KEY_HERE") {
    return { success: false, message: "VirusTotal API key missing" };
  }

  try {
    const urlId = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": VT_API_KEY }
    });

    if (res.status === 429) return { success: false, message: "VirusTotal rate limit exceeded" };
    if (!res.ok) return { success: false, message: `VirusTotal error (${res.status})` };

    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0) || 70;

    let verdict = "clean";
    if (malicious >= 3) verdict = "malicious";
    else if (malicious >= 1 || suspicious >= 3) verdict = "suspicious";

    return {
      success: true,
      malicious, suspicious, total, verdict,
      link: `https://www.virustotal.com/gui/url/${urlId}`
    };
  } catch (err) {
    return { success: false, message: "VirusTotal fetch failed" };
  }
}

// ── Google Safe Browsing Check ────────────────
async function checkGoogleSafeBrowsing(url) {
  if (!GOOGLE_SB_API_KEY || GOOGLE_SB_API_KEY === "YOUR_GOOGLE_SAFE_BROWSING_API_KEY_HERE") {
    return { success: false, message: "Google Safe Browsing API key missing" };
  }

  try {
    const body = {
      client: { clientId: "phish-detector", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };

    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SB_API_KEY}`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    );

    if (!res.ok) return { success: false, message: `Google SB error (${res.status})` };

    const data = await res.json();
    const matches = data.matches || [];

    if (matches.length > 0) {
      const threats = matches.map(m => m.threatType).join(", ");
      return { success: true, safe: false, threats };
    }
    return { success: true, safe: true };
  } catch (err) {
    return { success: false, message: "Google Safe Browsing fetch failed" };
  }
}

// ── Main Form Handler ─────────────────────────
form.addEventListener('submit', async e => {
  e.preventDefault();
  const inputUrl = urlInput.value.trim();
  if (!inputUrl) return;

  resultDiv.style.display = 'none';
  loadingDiv.style.display = 'block';
  checkBtn.disabled = true;
  urlInput.style.borderColor = '#e2e8f0';

  let html = '';
  let finalClass = 'safe';
  let finalScore = 0;

  // 1. Heuristics (50% weight)
  const heur = heuristicAnalysis(inputUrl);
  finalScore += heur.score / 2;

  html += `<strong>Heuristic Risk Score:</strong> ${heur.score}/100<br>`;
  if (heur.reasons.length) {
    html += `<ul>${heur.reasons.map(r => `<li>${r}</li>`).join('')}</ul>`;
  }
  html += `<p>Domain entropy: ${heur.entropy} bits</p><hr>`;

  // 2. VirusTotal
  const vt = await checkVirusTotal(inputUrl);
  html += `<strong>VirusTotal:</strong> `;
  if (vt.success) {
    if (vt.verdict === "malicious") {
      finalScore += 40;
      finalClass = 'danger';
      html += `<span style="color:#991b1b">MALICIOUS (${vt.malicious} / ${vt.total} engines)</span>`;
    } else if (vt.verdict === "suspicious") {
      finalScore += 20;
      if (finalClass !== 'danger') finalClass = 'suspicious';
      html += `<span style="color:#92400e">SUSPICIOUS (${vt.suspicious + vt.malicious} flags)</span>`;
    } else {
      html += `Clean / low detections`;
    }
    html += ` <a href="${vt.link}" target="_blank">[view report]</a>`;
  } else {
    html += `<em>${vt.message}</em>`;
  }
  html += `<br><hr>`;

  // 3. Google Safe Browsing
  const gsb = await checkGoogleSafeBrowsing(inputUrl);
  html += `<strong>Google Safe Browsing:</strong> `;
  if (gsb.success) {
    if (!gsb.safe) {
      finalScore += 45;
      finalClass = 'danger';
      html += `<span style="color:#991b1b">UNSAFE – ${gsb.threats}</span>`;
    } else {
      html += `No threats found`;
    }
  } else {
    html += `<em>${gsb.message}</em>`;
  }
  html += `<br><hr>`;

  // Final verdict
  finalScore = Math.min(100, Math.round(finalScore));

  const verdictText =
    finalScore >= 65 ? "HIGH RISK – PHISHING LIKELY" :
    finalScore >= 35 ? "SUSPICIOUS – Use caution" :
    "APPEARS SAFE";

  let verdictClass =
    finalScore >= 65 ? "danger" :
    finalScore >= 35 ? "suspicious" : "safe";

  if (finalClass === 'danger') verdictClass = 'danger';

  const barColor =
    finalScore >= 65 ? '#f87171' :
    finalScore >= 35 ? '#fbbf24' : '#34d399';

  resultDiv.innerHTML = `
    <h3>${verdictText}</h3>
    <div class="score-bar">
      <div class="score-fill" style="width:${finalScore}%; background:${barColor}"></div>
    </div>
    <p><strong>Combined Risk:</strong> ${finalScore}/100</p>
    ${html}
  `;

  resultDiv.className = verdictClass;
  resultDiv.style.display = 'block';
  loadingDiv.style.display = 'none';
  checkBtn.disabled = false;

  urlInput.style.borderColor =
    verdictClass === 'danger'     ? '#f87171' :
    verdictClass === 'suspicious' ? '#fbbf24' : '#34d399';
});

// Clear result on new input
urlInput.addEventListener('input', () => {
  resultDiv.style.display = 'none';
  urlInput.style.borderColor = '#e2e8f0';
});
