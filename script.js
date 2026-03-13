const form = document.getElementById('urlForm');
const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const resultDiv = document.getElementById('result');
const loadingDiv = document.getElementById('loading');

// Common phishing patterns (you can expand this list)
const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online', '.site', '.buzz'];
const commonBrands = ['paypal', 'amazon', 'netflix', 'google', 'microsoft', 'apple', 'facebook', 'instagram', 'bank', 'login'];

function analyzeURL(urlString) {
  try {
    const url = new URL(urlString.trim());
    let score = 0;
    let reasons = [];

    // 1. No HTTPS → high risk
    if (url.protocol !== 'https:') {
      score += 35;
      reasons.push("⚠️ Uses HTTP (not secure)");
    }

    // 2. Very long URL
    if (urlString.length > 80) {
      score += 20;
      reasons.push("Long URL (possible obfuscation)");
    }

    // 3. Uses IP address instead of domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname) ||
        url.hostname.includes('[')) { // IPv6
      score += 40;
      reasons.push("Uses IP address (common in phishing)");
    }

    // 4. Suspicious TLDs
    const tld = url.hostname.split('.').pop().toLowerCase();
    if (suspiciousTLDs.includes('.' + tld)) {
      score += 25;
      reasons.push("Suspicious top-level domain (." + tld + ")");
    }

    // 5. Contains common brand names + suspicious patterns
    const hostnameLower = url.hostname.toLowerCase();
    commonBrands.forEach(brand => {
      if (hostnameLower.includes(brand) &&
          !hostnameLower.includes(brand + '.com') &&
          !hostnameLower.includes(brand + '.net') &&
          !hostnameLower.endsWith(brand + '.org')) {
        score += 30;
        reasons.push(`Looks like fake ${brand} domain`);
      }
    });

    // 6. Too many special characters / encoding
    const specialChars = (urlString.match(/[%@#?&=]/g) || []).length;
    if (specialChars > 6) {
      score += 15;
      reasons.push("Too many special characters");
    }

    // 7. Subdomain abuse (many dots)
    const dotCount = (url.hostname.match(/\./g) || []).length;
    if (dotCount > 4) {
      score += 20;
      reasons.push("Excessive subdomains");
    }

    // Final classification
    let status, message, className;

    if (score >= 60) {
      status = "DANGER";
      message = "High probability of phishing!";
      className = "danger";
    } else if (score >= 30) {
      status = "SUSPICIOUS";
      message = "This URL looks suspicious. Be careful!";
      className = "suspicious";
    } else {
      status = "SAFE";
      message = "No obvious phishing signs detected.";
      className = "safe";
    }

    return { status, message, score, reasons, className };
  } catch (e) {
    return {
      status: "ERROR",
      message: "Invalid URL format. Please enter a valid URL.",
      className: "danger",
      reasons: []
    };
  }
}

form.addEventListener('submit', (e) => {
  e.preventDefault();

  const url = urlInput.value.trim();
  if (!url) return;

  resultDiv.style.display = 'none';
  loadingDiv.style.display = 'block';
  checkBtn.disabled = true;

  // Small delay to show loading (real API would be async)
  setTimeout(() => {
    const analysis = analyzeURL(url);

    resultDiv.innerHTML = `
      <strong style="font-size: 1.4rem; display: block; margin-bottom: 0.8rem;">
        ${analysis.status}
      </strong>
      <p>${analysis.message}</p>
      ${analysis.reasons.length > 0 ? `
        <ul style="margin-top: 1rem; padding-left: 1.2rem;">
          ${analysis.reasons.map(r => `<li>${r}</li>`).join('')}
        </ul>
      ` : ''}
      ${analysis.score !== undefined ? `
        <p style="margin-top: 1rem; font-size: 0.95rem; opacity: 0.8;">
          Risk score: ${analysis.score}/100
        </p>
      ` : ''}
    `;

    resultDiv.className = analysis.className;
    resultDiv.style.display = 'block';
    loadingDiv.style.display = 'none';
    checkBtn.disabled = false;

    // Highlight input border based on result
    urlInput.style.borderColor =
      analysis.className === 'danger' ? '#f87171' :
      analysis.className === 'suspicious' ? '#fbbf24' : '#34d399';
  }, 800);
});

// Clear result when user starts typing again
urlInput.addEventListener('input', () => {
  resultDiv.style.display = 'none';
  urlInput.style.borderColor = '#e2e8f0';
});
