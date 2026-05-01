/**
 * PassAudit — Password Strength Calculator
 * script.js
 *
 * Architecture:
 *   1. Constants & Data  — static lists, config values
 *   2. Utility Functions — pure helpers
 *   3. Analysis Engine   — scoring and rule evaluation
 *   4. UI Renderer       — DOM update functions
 *   5. Event Handlers    — user interaction bindings
 *   6. Initialisation    — boot
 */

'use strict';

/* =========================================================
   1. CONSTANTS & DATA
   ========================================================= */

/**
 * Hundreds of the most commonly used passwords.
 * Checking against this list is one of the most realistic
 * signals of a weak password.
 */
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '123456', '1234567', '12345678',
  '123456789', '1234567890', 'qwerty', 'qwerty123', 'qwertyuiop', 'abc123',
  'iloveyou', 'admin', 'letmein', 'monkey', 'dragon', 'master', 'sunshine',
  'princess', 'welcome', 'shadow', 'superman', 'michael', 'football',
  'baseball', 'soccer', 'hockey', 'basketball', 'starwars', 'login',
  'hello', 'charlie', 'donald', 'aa123456', 'zxcvbnm', 'trustno1', 'batman',
  'passw0rd', 'pass123', 'test', 'test123', 'guest', 'root', 'toor',
  'changeme', 'default', 'admin123', 'adminadmin', '000000', '111111',
  '222222', '333333', '444444', '555555', '666666', '777777', '888888',
  '999999', '121212', '112233', '123123', '987654321', '654321', 'asdfgh',
  'asdfghjkl', 'zxcvbn', 'passpass', 'qazwsx', 'qweasd', '1q2w3e4r',
  'abcdef', 'abcdefg', 'abcdefgh', '1qaz2wsx', 'letmein1', 'password2',
  'summer', 'winter', 'spring', 'autumn', 'secret', 'cheese', 'butter',
  'chicken', 'coffee', 'cookie', 'flower', 'guitar', 'hunter', 'killer',
  'maggie', 'bailey', 'thunder', 'ranger', 'silver', 'jordan', 'matrix',
  'jessica', 'joshua', 'amanda', 'andrew', 'thomas', 'robert', 'george',
  'jennifer', 'joseph', 'daniel', 'david', 'richard', 'william', 'charles',
  'february', 'january', 'december', 'november', 'october', 'september',
  'password!', 'hello123', 'iloveyou1', 'sunshine1', 'princess1', 'welcome1',
  'ninja', 'samurai', 'wizard', 'dragon1', 'monkey1', 'shadow1', 'master1',
  'batman1', 'superman1', 'charlie1', 'password12', 'qwerty1', 'abc1234',
  'mustang', 'harley', 'corvette', 'porsche', 'ferrari', 'lamborghini',
  'a123456', 'pass', 'pass1', 'user', 'user123', 'mypassword', 'newpass',
]);

/**
 * Common keyboard row patterns. We check if the password
 * contains any of these substrings (case-insensitive).
 */
const KEYBOARD_PATTERNS = [
  'qwerty', 'qwertyu', 'qwertyui', 'asdfgh', 'asdfghjkl',
  'zxcvbn', 'zxcvbnm', '1qaz', '2wsx', '3edc', 'qazwsx',
  'qweasd', '!qaz', '!qaz@wsx', 'qazwsxedc', '1qazxsw2',
  'poiuyt', 'lkjhgf', 'mnbvcxz',
];

/** Configuration for scoring */
const SCORING_CONFIG = {
  maxScore: 100,

  // Points awarded for character set variety
  charsets: {
    lowercase: 10,
    uppercase: 10,
    number: 10,
    special: 15,
  },

  // Length bonus: points per character tier
  length: {
    thresholds: [4, 8, 10, 12, 16, 20],
    bonuses:    [0, 10, 15, 20, 25, 30],
  },

  // Penalties
  penalties: {
    isCommon:       -50,
    hasKeyboard:    -15,
    hasSequential:  -10,
    excessiveRepeat:-10,
  },
};

/** Labels and score ranges for each tier */
const STRENGTH_TIERS = [
  { label: 'Very Weak', min: 0,  max: 19, cls: 'very-weak' },
  { label: 'Weak',      min: 20, max: 39, cls: 'weak'      },
  { label: 'Fair',      min: 40, max: 59, cls: 'fair'      },
  { label: 'Good',      min: 60, max: 79, cls: 'good'      },
  { label: 'Strong',    min: 80, max: 100, cls: 'strong'   },
];

/** Characters used when generating a random strong password */
const GENERATOR_CHARSET = {
  lowercase: 'abcdefghijkmnopqrstuvwxyz',  // omit l for readability
  uppercase: 'ABCDEFGHJKLMNPQRSTUVWXYZ',   // omit I, O
  numbers:   '23456789',                   // omit 0, 1
  special:   '!@#$%^&*-_=+?',
};

/* =========================================================
   2. UTILITY FUNCTIONS
   ========================================================= */

/**
 * Clamp a number between min and max (inclusive).
 * @param {number} val
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function clamp(val, min, max) {
  return Math.min(max, Math.max(min, val));
}

/**
 * Shuffle an array in-place using Fisher-Yates algorithm.
 * @param {Array} arr
 * @returns {Array} The same array, shuffled
 */
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Pick a random character from a string.
 * @param {string} str
 * @returns {string}
 */
function pickRandom(str) {
  return str[Math.floor(Math.random() * str.length)];
}

/**
 * Detect if the password contains any sequential character run
 * of a given minimum length (e.g. '1234', 'abcd', 'dcba').
 * @param {string} password
 * @param {number} [minLen=3]
 * @returns {boolean}
 */
function hasSequentialPattern(password, minLen = 3) {
  const lower = password.toLowerCase();
  let ascRun = 1, descRun = 1;

  for (let i = 1; i < lower.length; i++) {
    const delta = lower.charCodeAt(i) - lower.charCodeAt(i - 1);

    // Ascending sequence: abc, 123
    ascRun  = delta === 1  ? ascRun + 1  : 1;
    // Descending sequence: cba, 321
    descRun = delta === -1 ? descRun + 1 : 1;

    if (ascRun >= minLen || descRun >= minLen) return true;
  }
  return false;
}

/**
 * Check if the password contains a keyboard walk pattern.
 * @param {string} password
 * @returns {boolean}
 */
function hasKeyboardPattern(password) {
  const lower = password.toLowerCase();
  return KEYBOARD_PATTERNS.some(pattern => lower.includes(pattern));
}

/**
 * Check if any character repeats more than 3 times in a row,
 * or if more than 40% of the password is a single character.
 * @param {string} password
 * @returns {boolean}
 */
function hasExcessiveRepeat(password) {
  // Check for 4+ identical consecutive characters
  if (/(.)\1{3,}/.test(password)) return true;

  // Check if any character accounts for > 40% of the password
  const counts = {};
  for (const ch of password) {
    counts[ch] = (counts[ch] || 0) + 1;
  }
  const maxCount = Math.max(...Object.values(counts));
  return maxCount / password.length > 0.4;
}

/**
 * Estimate the crack time string based on the password score.
 * Uses a rough logarithmic approximation for presentation.
 * @param {number} score  0–100
 * @param {number} length  password length
 * @returns {string}
 */
function estimateCrackTime(score, length) {
  if (score === 0 || length === 0) return '—';

  // Approximate character pool size from score
  const poolMap = [
    [0,  10,  10],   // digits only
    [11, 25,  36],   // digits + lower
    [26, 45,  62],   // + upper
    [46, 65,  90],   // + special (small set)
    [66, 100, 130],  // full extended set
  ];

  let pool = 10;
  for (const [min, max, p] of poolMap) {
    if (score >= min && score <= max) { pool = p; break; }
  }

  // Estimated guesses = pool ^ length
  // Using logarithms: log10(pool^length) = length * log10(pool)
  const log10Guesses = length * Math.log10(pool);

  // Assume 10 billion guesses per second (fast offline attack)
  const log10GuessesPerSec = 10; // 10^10
  const log10Seconds = log10Guesses - log10GuessesPerSec;

  // Convert to human-readable
  if (log10Seconds < 0)   return 'Instantly';
  if (log10Seconds < 1)   return 'A few seconds';
  if (log10Seconds < 2)   return 'A few minutes';
  if (log10Seconds < 3.6) return 'Hours';
  if (log10Seconds < 4.9) return 'Days';
  if (log10Seconds < 7.5) return 'Months';
  if (log10Seconds < 9.5) return 'Years';
  if (log10Seconds < 12)  return 'Decades';
  if (log10Seconds < 15)  return 'Centuries';
  return 'Millions of years';
}

/* =========================================================
   3. ANALYSIS ENGINE
   ========================================================= */

/**
 * @typedef {Object} CheckResults
 * @property {boolean} hasMinLength   At least 8 chars
 * @property {boolean} hasGoodLength  At least 12 chars
 * @property {boolean} hasUppercase
 * @property {boolean} hasLowercase
 * @property {boolean} hasNumbers
 * @property {boolean} hasSpecial
 * @property {boolean} noExcessiveRepeat
 * @property {boolean} notCommon
 * @property {boolean} noSequential
 * @property {boolean} noKeyboard
 */

/**
 * Run all individual rule checks on the password.
 * @param {string} password
 * @returns {CheckResults}
 */
function runChecks(password) {
  const lower = password.toLowerCase();

  return {
    hasMinLength:       password.length >= 8,
    hasGoodLength:      password.length >= 12,
    hasUppercase:       /[A-Z]/.test(password),
    hasLowercase:       /[a-z]/.test(password),
    hasNumbers:         /[0-9]/.test(password),
    hasSpecial:         /[^A-Za-z0-9]/.test(password),
    noExcessiveRepeat:  !hasExcessiveRepeat(password),
    notCommon:          !COMMON_PASSWORDS.has(lower),
    noSequential:       !hasSequentialPattern(password),
    noKeyboard:         !hasKeyboardPattern(password),
  };
}

/**
 * Calculate a composite strength score (0–100).
 *
 * Scoring breakdown:
 *   - Length bonus:         up to 30 pts
 *   - Character diversity:  up to 45 pts  (10+10+10+15)
 *   - Penalties applied:    variable
 *
 * @param {string} password
 * @param {CheckResults} checks
 * @returns {number} Integer 0–100
 */
function calculateScore(password, checks) {
  if (password.length === 0) return 0;

  let score = 0;
  const { length, charsets, penalties } = SCORING_CONFIG;

  // -- Length bonus --
  let lengthBonus = 0;
  for (let i = length.thresholds.length - 1; i >= 0; i--) {
    if (password.length >= length.thresholds[i]) {
      lengthBonus = length.bonuses[i];
      break;
    }
  }
  score += lengthBonus;

  // -- Character set diversity --
  if (checks.hasLowercase) score += charsets.lowercase;
  if (checks.hasUppercase) score += charsets.uppercase;
  if (checks.hasNumbers)   score += charsets.number;
  if (checks.hasSpecial)   score += charsets.special;

  // -- Variety bonus: extra reward for 3+ different character types --
  const typesUsed = [
    checks.hasLowercase, checks.hasUppercase,
    checks.hasNumbers, checks.hasSpecial,
  ].filter(Boolean).length;

  if (typesUsed >= 3) score += 5;
  if (typesUsed === 4) score += 5;

  // -- Penalties --
  if (!checks.notCommon)         score += penalties.isCommon;
  if (!checks.noKeyboard)        score += penalties.hasKeyboard;
  if (!checks.noSequential)      score += penalties.hasSequential;
  if (!checks.noExcessiveRepeat) score += penalties.excessiveRepeat;

  // Safety: if very short, cap the score
  if (password.length < 6)  score = Math.min(score, 15);
  if (password.length < 8)  score = Math.min(score, 30);
  if (password.length < 10) score = Math.min(score, 55);

  return clamp(Math.round(score), 0, 100);
}

/**
 * Resolve the strength tier object for a given score.
 * @param {number} score
 * @returns {{ label: string, cls: string }}
 */
function getTier(score) {
  return STRENGTH_TIERS.find(t => score >= t.min && score <= t.max)
      || STRENGTH_TIERS[0];
}

/**
 * Build an array of feedback messages based on checks and score.
 * Each item: { type: 'positive'|'negative'|'warning', text: string }
 *
 * @param {string} password
 * @param {CheckResults} checks
 * @param {number} score
 * @returns {Array<{type: string, icon: string, text: string}>}
 */
function buildFeedback(password, checks, score) {
  const messages = [];

  const add = (type, icon, text) => messages.push({ type, icon, text });

  // --- Positive feedback ---
  if (checks.hasGoodLength)      add('positive', '✓', `Good length (${password.length} characters).`);
  else if (checks.hasMinLength)  add('warning',  '→', `Length is acceptable but 12+ characters is recommended.`);

  if (checks.hasUppercase && checks.hasLowercase) add('positive', '✓', 'Mixes uppercase and lowercase letters.');
  if (checks.hasNumbers)   add('positive', '✓', 'Contains numbers.');
  if (checks.hasSpecial)   add('positive', '✓', 'Contains special characters — great!');
  if (checks.noSequential && checks.noKeyboard && password.length > 0)
    add('positive', '✓', 'No obvious sequential or keyboard patterns detected.');
  if (checks.noExcessiveRepeat && password.length > 0)
    add('positive', '✓', 'No excessive character repetition.');

  // --- Negative / warning feedback ---
  if (!checks.hasMinLength)
    add('negative', '✗', `Too short — add at least ${8 - password.length} more character(s). Minimum is 8.`);
  else if (!checks.hasGoodLength)
    add('warning', '→', `Consider making it longer. ${12 - password.length} more character(s) to reach the recommended 12.`);

  if (!checks.notCommon)
    add('negative', '✗', 'This is one of the most commonly used passwords. Please choose something unique.');
  if (!checks.hasUppercase)
    add('negative', '✗', 'Add uppercase letters (A–Z) to increase character variety.');
  if (!checks.hasLowercase)
    add('negative', '✗', 'Add lowercase letters (a–z).');
  if (!checks.hasNumbers)
    add('warning', '→', 'Adding numbers would improve the score.');
  if (!checks.hasSpecial)
    add('warning', '→', 'Adding special characters (!@#$%) gives a significant boost.');
  if (!checks.noSequential)
    add('negative', '✗', 'Contains sequential characters (e.g. 1234 or abcd) — avoid these patterns.');
  if (!checks.noKeyboard)
    add('negative', '✗', 'Contains a keyboard pattern (e.g. qwerty, asdf) — these are easy to guess.');
  if (!checks.noExcessiveRepeat)
    add('negative', '✗', 'Too many repeated characters — diversify your character usage.');

  // Top-level summary tip
  if (score >= 80)
    add('positive', '🔐', 'Excellent! This password would take a long time to crack.');
  else if (score < 40)
    add('negative', '⚠', 'This password is considered weak. Consider using a passphrase or a password manager.');

  return messages;
}

/**
 * Master analysis function — runs all checks and returns a full result.
 * @param {string} password
 * @returns {{ score: number, tier: Object, checks: CheckResults, feedback: Array, crackTime: string }}
 */
function analyzePassword(password) {
  const checks    = runChecks(password);
  const score     = calculateScore(password, checks);
  const tier      = getTier(score);
  const feedback  = buildFeedback(password, checks, score);
  const crackTime = estimateCrackTime(score, password.length);

  return { score, tier, checks, feedback, crackTime };
}

/* =========================================================
   4. PASSWORD GENERATOR
   ========================================================= */

/**
 * Generate a cryptographically reasonable random password.
 * Guarantees at least one character from each character set,
 * then fills the rest randomly and shuffles the result.
 *
 * @param {number} [length=18]
 * @returns {string}
 */
function generatePassword(length = 18) {
  const { lowercase, uppercase, numbers, special } = GENERATOR_CHARSET;
  const allChars = lowercase + uppercase + numbers + special;

  // Guarantee at least 2 of each type for a balanced password
  const guaranteed = [
    pickRandom(lowercase), pickRandom(lowercase),
    pickRandom(uppercase), pickRandom(uppercase),
    pickRandom(numbers),   pickRandom(numbers),
    pickRandom(special),   pickRandom(special),
  ];

  // Fill remaining slots with random characters from the full charset
  const remaining = Array.from(
    { length: length - guaranteed.length },
    () => pickRandom(allChars)
  );

  return shuffle([...guaranteed, ...remaining]).join('');
}

/* =========================================================
   5. UI RENDERER
   ========================================================= */

/** Cache DOM references to avoid repeated querySelector calls */
const DOM = {
  input:           document.getElementById('password-input'),
  toggleBtn:       document.getElementById('toggle-visibility'),
  eyeShow:         document.querySelector('.eye-show'),
  eyeHide:         document.querySelector('.eye-hide'),
  generateBtn:     document.getElementById('generate-btn'),

  meterEmpty:      document.getElementById('meter-empty'),
  meterActive:     document.getElementById('meter-active'),
  progressTrack:   document.getElementById('progress-track'),
  progressBar:     document.getElementById('progress-bar'),
  scoreNumber:     document.getElementById('score-number'),
  strengthLabel:   document.getElementById('strength-label'),
  strengthDot:     document.getElementById('strength-dot'),
  crackTime:       document.getElementById('crack-time'),

  checklist:       document.getElementById('checklist'),
  feedbackEmpty:   document.getElementById('feedback-empty'),
  feedbackList:    document.getElementById('feedback-list'),
};

/** Last known strength class (used to remove it before applying new one) */
let currentStrengthClass = '';

/**
 * Update the strength meter UI.
 * @param {number} score
 * @param {{ label: string, cls: string }} tier
 * @param {string} crackTime
 */
function renderMeter(score, tier, crackTime) {
  // Show active state, hide empty state
  DOM.meterEmpty.classList.add('hidden');
  DOM.meterActive.classList.remove('hidden');

  // Flash animation on score number
  DOM.scoreNumber.classList.remove('score-flash');
  void DOM.scoreNumber.offsetWidth; // Trigger reflow to restart animation
  DOM.scoreNumber.classList.add('score-flash');

  // Update text values
  DOM.scoreNumber.textContent = score;
  DOM.strengthLabel.textContent = tier.label;
  DOM.crackTime.textContent = crackTime;

  // Update progress bar width
  DOM.progressBar.style.width = `${score}%`;
  DOM.progressTrack.setAttribute('aria-valuenow', score);

  // Swap strength class on the meter active element
  if (currentStrengthClass) {
    DOM.meterActive.classList.remove(`strength--${currentStrengthClass}`);
  }
  DOM.meterActive.classList.add(`strength--${tier.cls}`);
  currentStrengthClass = tier.cls;
}

/**
 * Reset the meter to its empty / default state.
 */
function resetMeter() {
  DOM.meterEmpty.classList.remove('hidden');
  DOM.meterActive.classList.add('hidden');

  DOM.progressBar.style.width = '0%';
  DOM.scoreNumber.textContent = '0';
  DOM.strengthLabel.textContent = '—';
  DOM.crackTime.textContent = '—';
  DOM.progressTrack.setAttribute('aria-valuenow', 0);

  if (currentStrengthClass) {
    DOM.meterActive.classList.remove(`strength--${currentStrengthClass}`);
    currentStrengthClass = '';
  }
}

/**
 * Update every checklist item based on the check results.
 * @param {CheckResults} checks
 * @param {boolean} hasPassword  Whether any password is entered
 */
function renderChecklist(checks, hasPassword) {
  const checkMap = {
    'check-length':      checks.hasMinLength,
    'check-length-good': checks.hasGoodLength,
    'check-upper':       checks.hasUppercase,
    'check-lower':       checks.hasLowercase,
    'check-number':      checks.hasNumbers,
    'check-special':     checks.hasSpecial,
    'check-no-repeat':   checks.noExcessiveRepeat,
    'check-no-common':   checks.notCommon,
    'check-no-sequential': checks.noSequential,
    'check-no-keyboard': checks.noKeyboard,
  };

  for (const [id, passed] of Object.entries(checkMap)) {
    const el = document.getElementById(id);
    if (!el) continue;

    el.classList.remove('passed', 'failed', 'neutral');

    if (!hasPassword) {
      el.classList.add('neutral');
    } else if (passed) {
      el.classList.add('passed');
    } else {
      el.classList.add('failed');
    }
  }
}

/**
 * Render the feedback list section.
 * @param {Array<{type: string, icon: string, text: string}>} feedbackItems
 */
function renderFeedback(feedbackItems) {
  if (feedbackItems.length === 0) {
    DOM.feedbackEmpty.classList.remove('hidden');
    DOM.feedbackList.classList.add('hidden');
    DOM.feedbackList.innerHTML = '';
    return;
  }

  DOM.feedbackEmpty.classList.add('hidden');
  DOM.feedbackList.classList.remove('hidden');

  // Build list items
  const fragment = document.createDocumentFragment();
  feedbackItems.forEach(item => {
    const li = document.createElement('li');
    li.className = `feedback-item ${item.type}`;

    const iconSpan  = document.createElement('span');
    iconSpan.className   = 'feedback-icon';
    iconSpan.textContent = item.icon;
    iconSpan.setAttribute('aria-hidden', 'true');

    const textSpan  = document.createElement('span');
    textSpan.textContent = item.text;

    li.appendChild(iconSpan);
    li.appendChild(textSpan);
    fragment.appendChild(li);
  });

  DOM.feedbackList.innerHTML = '';
  DOM.feedbackList.appendChild(fragment);
}

/**
 * Main render function — updates all UI components from an analysis result.
 * @param {string} password
 */
function renderAll(password) {
  if (password.length === 0) {
    // Reset everything to the default / empty state
    resetMeter();
    renderChecklist({
      hasMinLength: false, hasGoodLength: false,
      hasUppercase: false, hasLowercase: false,
      hasNumbers: false, hasSpecial: false,
      noExcessiveRepeat: true, notCommon: true,
      noSequential: true, noKeyboard: true,
    }, false);
    renderFeedback([]);
    return;
  }

  const result = analyzePassword(password);
  renderMeter(result.score, result.tier, result.crackTime);
  renderChecklist(result.checks, true);
  renderFeedback(result.feedback);
}

/* =========================================================
   6. EVENT HANDLERS
   ========================================================= */

/**
 * Handle password input (live analysis).
 */
function onPasswordInput() {
  renderAll(DOM.input.value);
}

/**
 * Toggle password field between text and password type.
 */
function onToggleVisibility() {
  const isHidden = DOM.input.type === 'password';
  DOM.input.type = isHidden ? 'text' : 'password';

  // Swap eye icons
  DOM.eyeShow.classList.toggle('hidden', isHidden);
  DOM.eyeHide.classList.toggle('hidden', !isHidden);

  // Update aria-label
  DOM.toggleBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');

  // Keep focus on input
  DOM.input.focus();
}

/**
 * Generate and populate a strong password, then analyze it.
 */
function onGeneratePassword() {
  const pwd = generatePassword(18);
  DOM.input.value = pwd;

  // Ensure the generated password is visible
  DOM.input.type = 'text';
  DOM.eyeShow.classList.add('hidden');
  DOM.eyeHide.classList.remove('hidden');
  DOM.toggleBtn.setAttribute('aria-label', 'Hide password');

  renderAll(pwd);
  DOM.input.focus();

  // Brief visual pulse on the generate button
  DOM.generateBtn.style.borderColor = 'var(--accent)';
  DOM.generateBtn.style.color = 'var(--accent)';
  setTimeout(() => {
    DOM.generateBtn.style.borderColor = '';
    DOM.generateBtn.style.color = '';
  }, 600);
}

/* =========================================================
   7. INITIALISATION
   ========================================================= */

/**
 * Bootstrap the application — attach event listeners,
 * set neutral checklist state on load.
 */
function init() {
  // Attach listeners
  DOM.input.addEventListener('input', onPasswordInput);
  DOM.toggleBtn.addEventListener('click', onToggleVisibility);
  DOM.generateBtn.addEventListener('click', onGeneratePassword);

  // Set all checklist items to neutral on page load
  document.querySelectorAll('.check-item').forEach(el => {
    el.classList.add('neutral');
  });

  // Clear any browser autofill that might trigger a stale analysis
  DOM.input.value = '';
}

// Run on DOMContentLoaded to be safe
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
