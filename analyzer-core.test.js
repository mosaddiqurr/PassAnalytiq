// ===== PassAnalytiq Analyzer Core — Test Suite =====
// Run: node analyzer-core.test.js

const {
    analyzePassword,
    DEFAULT_PASSPHRASE_WORDLIST_SIZE,
    getPassphraseWordlistSize,
    passphraseEntropy,
    formatTime,
} = require('./analyzer-core.js');
const { EFF_SHORT_WORDLIST, GeneratorCore } = require('./generator.js');
const fs = require('fs');

let passed = 0;
let failed = 0;

function assert(condition, testName) {
    if (condition) {
        console.log(`✅ ${testName}`);
        passed++;
    } else {
        console.error(`❌ ${testName}`);
        failed++;
    }
}

function assertEqual(actual, expected, testName) {
    if (actual === expected) {
        console.log(`✅ ${testName}`);
        passed++;
    } else {
        console.error(`❌ ${testName}: Expected '${expected}', got '${actual}'`);
        failed++;
    }
}

function analyze(password) {
    const result = analyzePassword(password);
    assert(result !== null, `analyzePassword('${password}') returns a result`);
    return result;
}

function patternTypes(result) {
    return result.patterns.map(p => p.type);
}

function suggestionsText(result) {
    return result.suggestions.join(' ');
}

console.log("=== PassAnalytiq Analyzer Core — Tests ===\n");

// ─── 1. Common / weak passwords ───
console.log("--- Common weak passwords ---");

assertEqual(analyze('password').label, 'Very Weak', "password → Very Weak");
assertEqual(analyze('password123').label, 'Very Weak', "password123 → Very Weak");
assertEqual(analyze('p@ssw0rd').label, 'Very Weak', "p@ssw0rd → Very Weak");
assertEqual(analyze('qwerty123').label, 'Very Weak', "qwerty123 → Very Weak");

// ─── 2. NIST-inspired scoring philosophy ───
console.log("\n--- NIST-inspired scoring philosophy ---");

assertEqual(DEFAULT_PASSPHRASE_WORDLIST_SIZE, EFF_SHORT_WORDLIST.length, "JS analyzer default passphrase wordlist size matches generator wordlist length");
assertEqual(getPassphraseWordlistSize(), GeneratorCore.getWordlistSize(), "JS analyzer passphrase wordlist size uses the bundled generator size");
assertEqual(passphraseEntropy(4), 4 * Math.log2(EFF_SHORT_WORDLIST.length), "JS passphrase entropy uses actual bundled wordlist length");
assertEqual(formatTime(86400 * 365 * 1e9), ">1 billion years", "JS crack-time formatting caps billion-year estimates");
assertEqual(formatTime(86400 * 365 * 1e12), ">1 trillion years", "JS crack-time formatting caps trillion-year estimates");

const troubador = analyze('Tr0ub4dor&3');
assert(troubador.label !== 'Very Strong', "Tr0ub4dor&3 is not Very Strong just because it mixes character classes");
assert(troubador.length < 15, "Tr0ub4dor&3 is shorter than the 15-character single-factor guidance check");

const longLowercase = analyze('correcthorsebatterystaplerandom');
assert(['Strong', 'Very Strong'].includes(longLowercase.label), "Long lowercase-only random-looking password is Strong or Very Strong");
assert(!longLowercase.suggestions.some(s => /uppercase|digit|symbol/i.test(s)), "Long lowercase-only password does not get composition-rule suggestions");

const longPassphrase = analyze('correct horse battery staple');
assert(['Strong', 'Very Strong'].includes(longPassphrase.label), "Long passphrase is Strong or Very Strong");
assert(longPassphrase.isPassphrase, "Long passphrase is detected as a passphrase");
assert(analyze('correct-horse-battery-staple').isPassphrase, "Hyphen-separated passphrase is detected as a passphrase");
assert(analyze('correct.horse.battery.staple').isPassphrase, "Dot-separated passphrase is detected as a passphrase");
assert(analyze('correct_horse_battery_staple').isPassphrase, "Underscore-separated passphrase is detected as a passphrase");

const noSymbols = analyze('longlowercasepasswordwithoutsymbols');
assert(noSymbols.score >= 80, "Missing symbols does not automatically reduce score");

const noUppercase = analyze('longlowercasewithdigits12345');
assert(noUppercase.score >= 60, "Missing uppercase does not automatically reduce score");

// ─── 3. Pattern detection ───
console.log("\n--- Pattern detection ---");

assert(patternTypes(analyze('aaaaaaaaaaaaaaaa')).includes('repeated_chars'), "Repeated characters are detected");
assert(patternTypes(analyze('qwertySafePassphrase')).includes('keyboard_walk'), "Keyboard walk is detected");
assert(patternTypes(analyze('summer2024vacationplan')).includes('date_pattern'), "Date pattern is detected");

// ─── 4. Suggestion wording ───
console.log("\n--- Suggestion wording ---");

const suggestionSamples = [
    analyze('password'),
    analyze('Tr0ub4dor&3'),
    analyze('longlowercasepasswordwithoutsymbols'),
    analyze('correct horse battery staple'),
];
const allSuggestions = suggestionSamples.map(suggestionsText).join(' ');

assert(!allSuggestions.includes('Add uppercase'), "Suggestions do not include old advice: Add uppercase");
assert(!allSuggestions.includes('Include digits'), "Suggestions do not include old advice: Include digits");
assert(!allSuggestions.includes('Add special symbols'), "Suggestions do not include old advice: Add special symbols");

console.log("\n--- HIBP privacy guard ---");
const analyzerUiSource = fs.readFileSync('./analyzer-ui.js', 'utf8');
assert(analyzerUiSource.includes('sha1.slice(0, 5)'), "HIBP browser code sends only SHA-1 prefix");
assert(analyzerUiSource.includes('sha1.slice(5)'), "HIBP browser code keeps suffix local for comparison");
assert(!analyzerUiSource.includes('console.log(password'), "Analyzer UI does not log passwords");

// â”€â”€â”€ 5. Old rules vs modern guidance helper â”€â”€â”€
// ─── Summary ───
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
