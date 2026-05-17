// Analyzer UI: live local feedback, breach check only on explicit request.

const analyzerEls = {};
let localAnalyzeTimer = null;
let latestLocalResult = null;
let breachRequestId = 0;

function setText(el, value) {
  if (el) el.textContent = value;
}

function debounce(fn, delay) {
  return (...args) => {
    clearTimeout(localAnalyzeTimer);
    localAnalyzeTimer = setTimeout(() => fn(...args), delay);
  };
}

function getPatternSummary(pattern) {
  const labels = {
    common_password: 'Common password or blocklist match',
    keyboard_walk: 'Keyboard pattern detected',
    repeated_chars: 'Repeated characters detected',
    sequential_digits: 'Sequential digits detected',
    sequential_letters: 'Sequential letters detected',
    date_pattern: 'Date-like pattern detected',
    leet_speak: 'Leet-speak version of a common password',
    common_suffix: 'Word plus number or symbol pattern',
  };
  return labels[pattern.type] || pattern.desc || 'Predictable pattern detected';
}

function getIssues(result) {
  const issues = [];
  if (result.length < 15) issues.push({ severity: 'High', text: 'Shorter than 15 characters' });
  result.patterns.forEach(pattern => {
    const severity = pattern.type === 'common_password' ? 'High' : 'Medium';
    issues.push({ severity, text: getPatternSummary(pattern) });
  });
  if (result.nistIssues.some(issue => issue.toLowerCase().includes('blocklist'))) {
    issues.push({ severity: 'High', text: 'Found in local common-password screening' });
  }

  const seen = new Set();
  return issues.filter(issue => {
    const key = issue.text.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function getMainReason(result) {
  const issues = getIssues(result);
  if (issues.length >= 2) {
    return `Main issue: ${issues[0].text} and ${issues[1].text.charAt(0).toLowerCase()}${issues[1].text.slice(1)}.`;
  }
  if (issues.length === 1) return `Main issue: ${issues[0].text}.`;
  return 'Main issue: No major local weakness patterns detected.';
}

function splitRecommendation(text) {
  const trimmed = String(text || '').trim().replace(/\s+/g, ' ');
  if (!trimmed) {
    return {
      title: 'Use a unique password',
      detail: 'Avoid reusing passwords across accounts.',
    };
  }

  const sentence = trimmed.length > 92 ? `${trimmed.slice(0, 89).trim()}...` : trimmed;
  if (/15|longer|length|characters/i.test(sentence)) {
    return { title: 'Use more length', detail: sentence };
  }
  if (/manager|generate|random|personalized/i.test(sentence)) {
    return { title: 'Generate a safer password', detail: sentence };
  }
  if (/reuse|unique/i.test(sentence)) {
    return { title: 'Keep it unique', detail: sentence };
  }
  return { title: 'Reduce predictability', detail: sentence };
}

function getRecommendations(result) {
  const source = result.suggestions.length > 0
    ? result.suggestions
    : ['Use a unique password for every account.', 'Store it in a password manager.'];
  return source.slice(0, 2).map(splitRecommendation);
}

function renderIssues(result) {
  const issues = getIssues(result).slice(0, 3);
  analyzerEls.issuesList.replaceChildren();

  if (issues.length === 0) {
    const card = document.createElement('div');
    card.className = 'issue-card';
    const text = document.createElement('span');
    text.textContent = 'No major issues found';
    card.appendChild(text);
    analyzerEls.issuesList.appendChild(card);
    return;
  }

  issues.forEach(issue => {
    const card = document.createElement('div');
    card.className = 'issue-card';

    const severity = document.createElement('span');
    severity.className = `severity severity-${issue.severity.toLowerCase()}`;
    severity.textContent = issue.severity;

    const text = document.createElement('span');
    text.textContent = issue.text;

    card.append(severity, text);
    analyzerEls.issuesList.appendChild(card);
  });
}

function renderRecommendations(result) {
  const recommendations = getRecommendations(result);
  analyzerEls.recommendationsList.replaceChildren();

  recommendations.forEach((recommendation, index) => {
    const card = document.createElement('div');
    card.className = 'action-card';

    const title = document.createElement('strong');
    title.textContent = `Action ${index + 1}: ${recommendation.title}`;

    const detail = document.createElement('span');
    detail.textContent = recommendation.detail;

    card.append(title, detail);
    analyzerEls.recommendationsList.appendChild(card);
  });
}

function renderBreachStatus(state = 'not_checked', count = 0) {
  const safeCount = Number.isFinite(count) ? Math.max(0, count) : 0;
  const states = {
    not_checked: {
      icon: 'i',
      status: 'Not checked',
      message: 'Click Check Breach to see whether this password appears in known breach datasets.',
      live: 'polite',
    },
    checking: {
      icon: '...',
      status: 'Checking breach data...',
      message: 'Checking HIBP k-anonymity breach data.',
      live: 'polite',
    },
    not_found: {
      icon: 'OK',
      status: 'Not found in known breach data',
      message: 'This password was not found in the checked HIBP dataset. This does not guarantee it is safe, but it is a good sign.',
      live: 'polite',
    },
    found: {
      icon: '!',
      status: 'Found in breach data',
      message: 'Do not use or reuse this password. Choose a fresh unique password.',
      live: 'assertive',
    },
    error: {
      icon: '!',
      status: 'Could not check breach data',
      message: 'Local analysis completed, but the breach database could not be reached.',
      live: 'polite',
    },
  };

  const view = states[state] || states.not_checked;
  analyzerEls.breachCard.dataset.state = states[state] ? state : 'not_checked';
  analyzerEls.breachCard.setAttribute('aria-live', view.live);
  setText(analyzerEls.breachIcon, view.icon);
  setText(analyzerEls.breachStatus, view.status);
  setText(analyzerEls.breachMessage, view.message);

  if (state === 'found') {
    setText(analyzerEls.breachCount, `Found ${safeCount.toLocaleString()} times`);
    analyzerEls.breachCount.hidden = false;
  } else {
    setText(analyzerEls.breachCount, '');
    analyzerEls.breachCount.hidden = true;
  }
}

function resetResult() {
  latestLocalResult = null;
  setText(analyzerEls.strengthLabel, '-');
  analyzerEls.strengthLabel.style.color = '';
  setText(analyzerEls.scoreValue, '-');
  setText(analyzerEls.crackTimeValue, '-');
  setText(analyzerEls.mainReason, 'Start typing to see local analysis.');
  analyzerEls.issuesList.replaceChildren();
  analyzerEls.recommendationsList.replaceChildren();
  analyzerEls.strengthBar.style.width = '0%';
  renderBreachStatus('not_checked');
}

function renderLocalResult(result) {
  const color = STRENGTH_COLORS[result.label] || '#8b949e';
  latestLocalResult = result;

  setText(analyzerEls.strengthLabel, result.label);
  analyzerEls.strengthLabel.style.color = color;
  setText(analyzerEls.scoreValue, `${result.score}/100`);
  setText(analyzerEls.crackTimeValue, result.crackTimes.offline_fast_hash);
  setText(analyzerEls.mainReason, getMainReason(result));
  renderIssues(result);
  renderRecommendations(result);

  analyzerEls.strengthBar.style.width = `${Math.max(6, result.score)}%`;
  analyzerEls.strengthBar.style.background = color;
}

function runLocalAnalysis() {
  const password = analyzerEls.passwordInput.value;
  const result = analyzePassword(password);
  if (!result) {
    resetResult();
    return;
  }

  renderLocalResult(result);
  renderBreachStatus('not_checked');
}

const runLocalAnalysisDebounced = debounce(runLocalAnalysis, 150);

async function checkHibpBreach(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuf = await crypto.subtle.digest('SHA-1', data);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  const sha1 = hashArr.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' },
  });
  if (!resp.ok) throw new Error(`HIBP HTTP ${resp.status}`);

  const body = await resp.text();
  for (const line of body.split('\n')) {
    const [hashSuffix, count] = line.trim().split(':');
    if (hashSuffix === suffix) return parseInt(count, 10);
  }
  return 0;
}

async function checkBreachData() {
  const password = analyzerEls.passwordInput.value;
  if (!password) {
    resetResult();
    return;
  }

  const requestId = ++breachRequestId;
  runLocalAnalysis();
  renderBreachStatus('checking');
  analyzerEls.analyzeBtn.disabled = true;
  analyzerEls.analyzeBtn.textContent = 'Checking...';

  try {
    const breachCount = await checkHibpBreach(password);
    if (requestId !== breachRequestId) return;
    if (breachCount > 0) {
      renderBreachStatus('found', breachCount);
    } else {
      renderBreachStatus('not_found');
    }
  } catch (err) {
    if (requestId !== breachRequestId) return;
    renderBreachStatus('error');
  } finally {
    if (requestId === breachRequestId) {
      analyzerEls.analyzeBtn.disabled = false;
      analyzerEls.analyzeBtn.textContent = 'Check Breach';
    }
  }
}

function handlePasswordInput() {
  breachRequestId += 1;
  analyzerEls.analyzeBtn.disabled = false;
  analyzerEls.analyzeBtn.textContent = 'Check Breach';
  runLocalAnalysisDebounced();
}

function toggleVisibility() {
  const input = analyzerEls.passwordInput;
  input.type = input.type === 'password' ? 'text' : 'password';
  analyzerEls.toggleVisibility.textContent = input.type === 'password' ? 'Show' : 'Hide';
}

document.addEventListener('DOMContentLoaded', () => {
  Object.assign(analyzerEls, {
    passwordInput: document.getElementById('passwordInput'),
    toggleVisibility: document.getElementById('toggleVisibility'),
    analyzeBtn: document.getElementById('analyzeBtn'),
    strengthBar: document.getElementById('strengthBar'),
    strengthLabel: document.getElementById('strengthLabel'),
    scoreValue: document.getElementById('scoreValue'),
    crackTimeValue: document.getElementById('crackTimeValue'),
    breachCard: document.getElementById('breachCard'),
    breachIcon: document.getElementById('breachIcon'),
    breachStatus: document.getElementById('breachStatus'),
    breachCount: document.getElementById('breachCount'),
    breachMessage: document.getElementById('breachMessage'),
    mainReason: document.getElementById('mainReason'),
    issuesList: document.getElementById('issuesList'),
    recommendationsList: document.getElementById('recommendationsList'),
  });

  analyzerEls.passwordInput.addEventListener('input', handlePasswordInput);
  analyzerEls.passwordInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') checkBreachData();
  });
  analyzerEls.toggleVisibility.addEventListener('click', toggleVisibility);
  analyzerEls.analyzeBtn.addEventListener('click', checkBreachData);
  resetResult();
});
