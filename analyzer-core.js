// ============================================================
// PASSANALYTIQ ANALYZER CORE — shared engine
// Extracted from index.html to eliminate duplication.
// Used by both index.html (Analyzer) and generator.html (Generator).
// ============================================================

// --- Common passwords list (subset) ---
const COMMON_PASSWORDS = new Set([
    "password", "123456", "password1", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password2", "welcome",
    "1234567890", "charlie", "donald", "password123", "qwerty123", "iloveyou1",
    "admin", "login", "hello", "whatever", "qwertyuiop", "zxcvbnm", "1q2w3e4r",
    "111111", "1234", "12345", "123456789", "000000", "1111111", "11111111",
    "princess", "pass", "test", "guest", "root", "toor", "changeme", "secret",
    "letmein", "welcome1", "monkey123", "sunshine1", "password!", "p@ssword",
    "p@ssw0rd", "pa$$word", "passw0rd!", "qwerty!", "abc1234", "1234abc",
    "pass123", "pass1234", "mypassword", "mypass", "temp", "temp123", "user",
    "user123", "admin123", "administrator", "root123", "system", "default",
    "service", "access", "access1", "login1", "test123", "demo", "sample",
    "example", "internet", "computer", "windows", "linux", "apple", "google",
    "facebook", "twitter", "instagram", "amazon", "netflix", "spotify", "youtube",
    "baseball1", "basketball", "football1", "soccer", "hockey", "tennis", "golf",
    "summer", "winter", "spring", "autumn", "monday", "friday", "january",
    "february", "december", "birthday", "anniversary", "chocolate", "coffee",
    "pizza", "burger", "cookie", "batman", "superman1", "spiderman", "ironman",
    "captain", "starwars", "matrix", "avatar", "pokemon", "mario", "love",
    "love123", "lovely", "lover", "loveme", "baby", "baby123", "babe", "honey",
    "sweetheart", "killer", "hacker", "ninja", "warrior", "hunter", "thunder",
    "lightning", "storm", "fire", "water", "black", "white", "blue", "red", "green",
    "tiger", "lion", "eagle", "wolf", "bear", "michael1", "jennifer", "jessica",
    "ashley1", "amanda", "daniel", "matthew", "joshua", "andrew", "james",
    "robert", "william", "richard", "charles", "joseph", "thomas", "christopher",
    "david", "george", "edward",
]);

const KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1234567890", "0987654321", "qazwsx", "wsxedc", "edcrfv", "rfvtgb",
    "tgbyhn", "yhnujm", "qweasdzxc", "1qaz2wsx", "2wsx3edc", "abcdefgh",
];

const LEET_MAP = {
    "@": "a", "4": "a", "8": "b", "3": "e", "6": "g", "1": "i", "!": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "2": "z",
};

const ATTACK_SPEEDS = {
    online_throttled: 100 / 3600,
    online_unthrottled: 10_000,
    offline_slow_hash: 10_000_000,
    offline_fast_hash: 10_000_000_000,
    offline_gpu_cluster: 100_000_000_000_000,
};

// --- Strength colors (used by both pages) ---
const STRENGTH_COLORS = {
    "Very Weak": "#f85149",
    "Weak": "#ff7b72",
    "Fair": "#e3b341",
    "Strong": "#3fb950",
    "Very Strong": "#58a6ff",
};

const DEFAULT_PASSPHRASE_WORDLIST_SIZE = 1344;

// --- Passphrase detection (mirrors Python _detect_passphrase) ---
function detectPassphrase(password) {
    // Split on common passphrase separators used by the generator; keep tokens with >=3 chars.
    const tokens = password.split(/[\s\-._]+/).filter(t => t.length >= 3);
    return { isPassphrase: tokens.length >= 3, wordCount: tokens.length };
}

function getPassphraseWordlistSize() {
    if (
        typeof GeneratorCore !== 'undefined' &&
        GeneratorCore &&
        typeof GeneratorCore.getWordlistSize === 'function'
    ) {
        return GeneratorCore.getWordlistSize();
    }
    return DEFAULT_PASSPHRASE_WORDLIST_SIZE;
}

function passphraseEntropy(wordCount, wordlistSize = getPassphraseWordlistSize()) {
    // Entropy is based on the bundled generator wordlist size when available.
    // The fallback is the current bundled list size, not a larger external list.
    return wordCount * Math.log2(wordlistSize);
}

// --- Input sanitization: strip C0/C1 control chars (mirrors Python _sanitize_input) ---
function sanitizeInput(password) {
    // Remove Unicode categories Cc (control) and Cs (surrogates)
    const cleaned = [...password].filter(ch => {
        const cp = ch.codePointAt(0);
        if (cp <= 0x001F) return false;          // C0 controls
        if (cp >= 0x007F && cp <= 0x009F) return false; // DEL + C1 controls
        if (cp >= 0xD800 && cp <= 0xDFFF) return false; // lone surrogates (Cs)
        return true;
    }).join('');
    return cleaned;
}

function normalizePassword(password) {
    // NIST SP 800-63B-4 recommends NFC for accepted Unicode passwords.
    return typeof password.normalize === 'function' ? password.normalize('NFC') : password;
}

// --- Emoji detection helper (mirrors Python _is_emoji) ---
function isEmoji(ch) {
    const cp = ch.codePointAt(0);
    return (
        (cp >= 0x1F300 && cp <= 0x1FAFF) || // Misc symbols, emoticons, transport…
        (cp >= 0x2600 && cp <= 0x27BF) || // Misc symbols block
        (cp >= 0xFE00 && cp <= 0xFE0F)     // Variation selectors (emoji modifiers)
    );
}

function detectCharSets(p) {
    const chars = [...p]; // proper Unicode code-point split
    const hasEmoji = chars.some(c => c.codePointAt(0) > 127 && isEmoji(c));
    const hasUniExt = chars.some(c => c.codePointAt(0) > 127 && !isEmoji(c));
    return {
        lowercase: /[a-z]/.test(p),
        uppercase: /[A-Z]/.test(p),
        digits: /\d/.test(p),
        symbols: /[!@#$%^&*()\-_=+\[\]{};:'",.<>?/\\|`~]/.test(p),
        spaces: p.includes(" "),
        unicode_ext: hasUniExt,   // non-ASCII, non-emoji (+80)
        emoji: hasEmoji,    // emoji / symbol blocks (+1024)
    };
}

function calcCharSetSize(cs) {
    let s = 0;
    if (cs.lowercase) s += 26;
    if (cs.uppercase) s += 26;
    if (cs.digits) s += 10;
    if (cs.symbols) s += 32;
    if (cs.spaces) s += 10;  // word-separator pool (NIST passphrase-friendly)
    if (cs.unicode_ext) s += 80;  // conservative non-ASCII, non-emoji estimate
    if (cs.emoji) s += 1024; // realistic emoji pool (~2^10)
    return Math.max(s, 1);
}

function calcEntropy(length, charSetSize) {
    if (length === 0 || charSetSize === 0) return 0;
    return length * Math.log2(charSetSize);
}

function decodeLeet(text) {
    return [...text].map(c => LEET_MAP[c] || c).join('');
}

function detectPatterns(password) {
    const patterns = [];
    const lower = password.toLowerCase();

    if (COMMON_PASSWORDS.has(lower)) {
        patterns.push({ type: "common_password", text: password, desc: "This is one of the most commonly used passwords — will be tried first by any attacker.", penalty: 40 });
    }

    for (const kp of KEYBOARD_PATTERNS) {
        if (kp.length >= 4 && (lower.includes(kp) || lower.includes(kp.split('').reverse().join('')))) {
            const match = lower.includes(kp) ? kp : kp.split('').reverse().join('');
            patterns.push({ type: "keyboard_walk", text: match, desc: `Keyboard walk pattern '${match}' detected — easily guessable.`, penalty: Math.min(match.length * 2.5, 20) });
            break;
        }
    }

    const repeatMatch = password.match(/(.)\1{3,}/);
    if (repeatMatch) {
        patterns.push({ type: "repeated_chars", text: repeatMatch[0], desc: `Repeated character sequence '${repeatMatch[0]}' reduces entropy.`, penalty: 10 });
    }

    if (/012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210/.test(password)) {
        patterns.push({ type: "sequential_digits", text: "", desc: "Sequential digit pattern detected — predictable.", penalty: 8 });
    }

    if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/.test(lower)) {
        patterns.push({ type: "sequential_letters", text: "", desc: "Sequential letter pattern detected — predictable.", penalty: 8 });
    }

    if (/(19|20)\d{2}/.test(password) || /\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{2,4}\b/.test(password)) {
        patterns.push({ type: "date_pattern", text: "", desc: "Date-like pattern detected — attackers try birth years and common dates.", penalty: 12 });
    }

    const leetDecoded = decodeLeet(lower);
    if (leetDecoded !== lower && COMMON_PASSWORDS.has(leetDecoded)) {
        patterns.push({ type: "leet_speak", text: password, desc: `Leet-speak substitution of '${leetDecoded}' — easily cracked by modern tools.`, penalty: 20 });
    }

    if (/[a-zA-Z]{3,}(123|1234|12345|!|!!|@|#|\d{1,4})$/.test(password)) {
        patterns.push({ type: "common_suffix", text: "", desc: "Word + numbers/symbols pattern — attackers apply these transformations automatically.", penalty: 12 });
    }

    return patterns;
}

function estimateCrackTimes(entropyBits) {
    const guesses = Math.pow(2, entropyBits);
    const result = {};
    for (const [scenario, speed] of Object.entries(ATTACK_SPEEDS)) {
        const seconds = guesses / speed;
        result[scenario] = formatTime(seconds);
    }
    return result;
}

function formatTime(seconds) {
    if (seconds < 1) return "< 1 second";
    if (seconds < 60) return `${seconds.toFixed(1)} sec`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hrs`;
    if (seconds < 86400 * 30) return `${(seconds / 86400).toFixed(1)} days`;
    if (seconds < 86400 * 365) return `${(seconds / (86400 * 30)).toFixed(1)} months`;
    if (seconds < 86400 * 365 * 1000) return `${(seconds / (86400 * 365)).toFixed(1)} years`;
    if (seconds < 86400 * 365 * 1e6) return `${(seconds / (86400 * 365 * 1000)).toFixed(1)}K years`;
    if (seconds < 86400 * 365 * 1e9) return `${(seconds / (86400 * 365 * 1e6)).toFixed(1)}M years`;
    if (seconds < 86400 * 365 * 1e12) return ">1 billion years";
    return ">1 trillion years";
}

function checkNIST(password, patterns = []) {
    const issues = [];
    const lower = password.toLowerCase();
    const patternTypes = new Set(patterns.map(p => p.type));

    // NIST-inspired length check: 15 characters for single-factor password guidance;
    // 8-character minimums may apply in some MFA contexts.
    if (password.length < 15) {
        issues.push(
            `Too short: ${password.length} character(s). ` +
            'This NIST-inspired check uses 15 characters for single-factor password guidance; 8 characters may apply in MFA contexts.'
        );
    }
    if (COMMON_PASSWORDS.has(lower) || patternTypes.has("leet_speak")) {
        issues.push("This password appears in the project common-password blocklist used for NIST-inspired screening.");
    }
    if (/(.)\1{4,}/.test(password)) {
        issues.push("Contains 5+ repeated identical characters — flagged by this project's predictable-pattern checks.");
    }
    return { compliant: issues.length === 0, issues };
}

function calcScore(effectiveEntropy, length, charSets, patterns, nistCompliant) {
    // NIST-inspired allocation, mirroring password_analyzer.py:
    // Length 0–50, effective entropy after structural penalties 0–30,
    // NIST-inspired check 0–20. Character sets are display-only and do not
    // add or remove score.
    void charSets;

    const patternTypes = new Set(patterns.map(p => p.type));
    const isBlacklisted = patternTypes.has("common_password") || patternTypes.has("leet_speak");
    if (isBlacklisted) {
        return Math.max(0, Math.min(10, Math.floor((effectiveEntropy / 80) * 10)));
    }

    let lengthScore = 0;
    if (length >= 30) lengthScore = 50;
    else if (length >= 25) lengthScore = 45;
    else if (length >= 20) lengthScore = 38;
    else if (length >= 17) lengthScore = 32;
    else if (length >= 15) lengthScore = 26;
    else if (length >= 12) lengthScore = 18;
    else if (length >= 10) lengthScore = 12;
    else if (length >= 8) lengthScore = 6;

    const entropyScore = Math.min(30, (effectiveEntropy / 80) * 30);
    const nistBonus = nistCompliant ? 20 : 0;

    let score = lengthScore + entropyScore + nistBonus;

    const allSameChar = patterns.some(p => p.type === "repeated_chars" && p.text.length === length);
    const stronglySequential = (patternTypes.has("sequential_digits") || patternTypes.has("sequential_letters")) && length <= 12;
    if (allSameChar || stronglySequential) score *= 0.25;

    return Math.max(0, Math.min(100, Math.floor(score)));
}

function scoreToLabel(score, length = 0) {
    // Mirrors Python _score_to_label: "Very Strong" requires score ≥80 and length ≥15.
    if (score < 20) return "Very Weak";
    if (score < 40) return "Weak";
    if (score < 60) return "Fair";
    if (score < 80) return "Strong";
    return length >= 15 ? "Very Strong" : "Strong";
}

function generateSuggestions(password, length, charSets, patterns, nistIssues, score, isPassphrase = false) {
    const suggestions = [];
    const patternTypes = new Set(patterns.map(p => p.type));
    void password;
    void charSets;
    void nistIssues;

    if (length < 8)
        suggestions.push(`Your password is only ${length} character(s). Use at least 8 characters, and prefer 15 or more for a stronger memorized secret.`);
    else if (length < 15)
        suggestions.push(`Increase length to at least 15 characters (currently ${length}). Longer passwords are dramatically harder to crack.`);

    if (patternTypes.has("common_password") || patternTypes.has("leet_speak"))
        suggestions.push("Choose a password that is not common, reused, or known from breach lists. Modern crackers also handle leet-speak substitutions automatically.");
    if (patternTypes.has("keyboard_walk"))
        suggestions.push("Avoid keyboard-walk sequences such as qwerty, asdf, or 1234. These are among the first patterns tried by cracking tools.");
    if (patternTypes.has("date_pattern"))
        suggestions.push("Avoid embedding dates such as birth years or anniversaries; personal dates are easy to guess.");
    if (patternTypes.has("repeated_chars"))
        suggestions.push("Avoid repeated character sequences such as aaaa or 1111. Repetition provides little additional security.");
    if (patternTypes.has("sequential_digits") || patternTypes.has("sequential_letters"))
        suggestions.push("Avoid sequential strings such as 12345678 or abcdefgh. These are trivially enumerated by cracking tools.");
    if (patternTypes.has("common_suffix"))
        suggestions.push("Appending numbers or symbols to a word, such as hello123, is predictable because cracking tools apply these transformations automatically.");

    if (!isPassphrase && length < 20)
        suggestions.push("Consider a longer passphrase made from 4–6 random unrelated words separated by spaces or hyphens.");
    if (score < 40)
        suggestions.push("Use a password manager to generate and store a unique random password for each account.");

    return suggestions;
}

// --- Analyzer Core ---
function analyzePassword(password) {
    if (!password) return null;

    // 1. Sanitize input and normalize Unicode with NFC
    password = sanitizeInput(password);
    password = normalizePassword(password);
    if (!password) return null;

    const length = password.length;

    // 2. Character-set analysis (display only; not part of scoring)
    const charSets = detectCharSets(password);
    const charSetSize = calcCharSetSize(charSets);

    // 3. Entropy — display/crack-time model, upgraded to bundled wordlist entropy if passphrase
    const charsetEntropy = calcEntropy(length, charSetSize);
    const { isPassphrase, wordCount } = detectPassphrase(password);
    const rawEntropy = isPassphrase
        ? Math.max(charsetEntropy, passphraseEntropy(wordCount))
        : charsetEntropy;

    // 4. Pattern detection & effective entropy
    const patterns = detectPatterns(password);
    const penalty = patterns.reduce((s, p) => s + p.penalty, 0);
    const effectiveEntropy = Math.max(0, rawEntropy - penalty);

    // 5. Crack times, NIST, scoring, label, suggestions
    const crackTimes = estimateCrackTimes(effectiveEntropy);
    const { compliant, issues } = checkNIST(password, patterns);
    const score = calcScore(effectiveEntropy, length, charSets, patterns, compliant);
    const label = scoreToLabel(score, length);
    const suggestions = generateSuggestions(password, length, charSets, patterns, issues, score, isPassphrase);

    return {
        password, length, score, label,
        entropy: +rawEntropy.toFixed(2),
        effectiveEntropy: +effectiveEntropy.toFixed(2),
        charSets, charSetSize,
        patterns, crackTimes, compliant, nistIssues: issues, suggestions,
        entropyPerChar: length > 0 ? +(rawEntropy / length).toFixed(2) : 0,
        isPassphrase,
    };
}

// Expose for Node.js testing without affecting browser globals.
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        COMMON_PASSWORDS,
        KEYBOARD_PATTERNS,
        STRENGTH_COLORS,
        DEFAULT_PASSPHRASE_WORDLIST_SIZE,
        sanitizeInput,
        normalizePassword,
        detectCharSets,
        calcCharSetSize,
        calcEntropy,
        detectPassphrase,
        getPassphraseWordlistSize,
        passphraseEntropy,
        formatTime,
        detectPatterns,
        checkNIST,
        calcScore,
        scoreToLabel,
        generateSuggestions,
        analyzePassword,
    };
}
