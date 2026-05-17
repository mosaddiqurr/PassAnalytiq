// PassAnalytiq generator tests

const { GeneratorCore, EFF_SHORT_WORDLIST } = require('./generator.js');
const fs = require('fs');

let passed = 0;
let failed = 0;

function assert(condition, testName) {
    if (condition) {
        console.log(`PASS ${testName}`);
        passed++;
    } else {
        console.error(`FAIL ${testName}`);
        failed++;
    }
}

function assertEqual(actual, expected, testName) {
    assert(actual === expected, `${testName}${actual === expected ? '' : `: expected ${expected}, got ${actual}`}`);
}

async function main() {
console.log("=== PassAnalytiq Generator Tests ===\n");

console.log("--- secureRandomInt ---");
const r1 = GeneratorCore.secureRandomInt(10);
assert(r1 >= 0 && r1 < 10, "secureRandomInt(10) returns value in [0, 10)");
assertEqual(GeneratorCore.secureRandomInt(1), 0, "secureRandomInt(1) always returns 0");

const seen = new Set();
for (let i = 0; i < 1000; i++) seen.add(GeneratorCore.secureRandomInt(100));
assert(seen.size > 50, "secureRandomInt distribution covers >50 of 100 values in 1000 samples");

console.log("\n--- secureShuffle ---");
const arr = [1, 2, 3, 4, 5];
const original = [...arr];
GeneratorCore.secureShuffle(arr);
assert(arr.length === original.length, "secureShuffle preserves array length");
assert(original.every(v => arr.includes(v)), "secureShuffle preserves all elements");

console.log("\n--- generateCharPassword ---");
const p20 = GeneratorCore.generateCharPassword(20, { upper: true, lower: true, numbers: true, symbols: true });
assertEqual(p20.length, 20, "Character password length = 20");
assert(/[A-Z]/.test(p20), "Character password contains uppercase");
assert(/[a-z]/.test(p20), "Character password contains lowercase");
assert(/[0-9]/.test(p20), "Character password contains digit");
assert(/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(p20), "Character password contains symbol");

const fallback = GeneratorCore.generateCharPassword(10, { upper: false, lower: false, numbers: false, symbols: false });
assert(/^[a-z]+$/.test(fallback), "No toggles enabled falls back to lowercase");

console.log("\n--- generatePassphrase core utility ---");
const pp4 = GeneratorCore.generatePassphrase(4, "-");
const words4 = pp4.split("-");
assertEqual(words4.length, 4, "Passphrase utility has 4 words");
assert(words4.every(w => EFF_SHORT_WORDLIST.includes(w)), "Passphrase utility uses bundled wordlist");
assertEqual(GeneratorCore.getWordlistSize(), EFF_SHORT_WORDLIST.length, "getWordlistSize returns bundled wordlist length");

console.log("\n--- sanitizeCustomWord ---");
assertEqual(GeneratorCore.sanitizeCustomWord('<img src=x onerror=alert(1)>'), '', "Sanitize rejects img HTML payload");
assertEqual(GeneratorCore.sanitizeCustomWord('<script>alert(1)</script>'), '', "Sanitize rejects script HTML payload");
assertEqual(GeneratorCore.sanitizeCustomWord('hello<world>'), '', "Sanitize rejects mixed angle-bracket text");
assertEqual(GeneratorCore.sanitizeCustomWord('  HelloWorld  '), 'HelloWorld', "Sanitize trims normal words");
assertEqual(GeneratorCore.sanitizeCustomWord('abcdefghijklmnopqrstuvwxyz'), 'abcdefghijklmnopqrst', "Sanitize truncates to 20 code points");

function recognizable(value) {
    return value
        .toLowerCase()
        .replace(/@/g, 'a')
        .replace(/4/g, 'a')
        .replace(/3/g, 'e')
        .replace(/[1!]/g, 'i')
        .replace(/0/g, 'o')
        .replace(/8/g, 'b')
        .replace(/7/g, 't')
        .replace(/9/g, 'g')
        .replace(/2/g, 'z')
        .replace(/\$/g, 's')
        .replace(/[^a-z0-9]/g, '');
}

function includesReadableAnchor(password, anchor) {
    return recognizable(password).includes(anchor);
}

console.log("\n--- personalized helpers ---");
const transformedApple = GeneratorCore.transformMemoryWord('apple', 'balanced');
assert(recognizable(transformedApple).includes('apple'), "transformMemoryWord preserves recognizability");
assert(transformedApple.length >= 5, "transformMemoryWord does not collapse the word");

for (let i = 0; i < 100; i++) {
    const transformedStudent = GeneratorCore.transformMemoryWord('student', 'stronger');
    assert(!/^[A-Za-z][.-][A-Za-z]/.test(transformedStudent), "transformMemoryWord does not split after one letter");
    assert(!/[.-].*[.-]/.test(transformedStudent), "transformMemoryWord uses at most one internal separator");
    assert(recognizable(transformedStudent).includes('student'), "transformMemoryWord keeps longer words recognizable");
}

const secret = GeneratorCore.generateSecretChunk('balanced');
assert(secret.length >= 6, "Balanced generateSecretChunk creates a memorable random code");
assert(/^[A-Z][a-z]{3,5}[0-9]+[!@#$%&?]$/.test(secret), "Balanced secret chunk uses a readable random code word");
assert(/[A-Z]/.test(secret), "Secret chunk contains uppercase");
assert(/[a-z]/.test(secret), "Secret chunk contains lowercase");
assert(/[0-9]/.test(secret), "Secret chunk contains digit");
assert(/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(secret), "Secret chunk contains symbol");
const strongSecret = GeneratorCore.generateSecretChunk('stronger');
assert(strongSecret.length >= 12, "Stronger generateSecretChunk creates a longer memorable random code");
assert(/^[A-Z][a-z]{3,5}[0-9][\-._][A-Z][a-z]{3,5}[0-9]+[!@#$%&?]$/.test(strongSecret), "Stronger secret chunk uses two readable random code words");
assert(/[A-Z]/.test(strongSecret) && /[a-z]/.test(strongSecret) && /[0-9]/.test(strongSecret), "Stronger secret chunk contains mixed alphanumeric characters");
assert(/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(strongSecret), "Stronger secret chunk contains symbol");

console.log("\n--- generatePersonalizedPassword ---");
const skyBlueNoon = GeneratorCore.generatePersonalizedPassword(['sky', 'blue', 'noon']);
assert(['sky', 'blue', 'noon'].every(anchor => includesReadableAnchor(skyBlueNoon.password, anchor)), "sky blue noon output includes recognizable versions of all three words");
assert(/[()[\]{}]/.test(skyBlueNoon.password), "Personalized output uses bracket structure");
assert(/[!@#$%&?._#-]/.test(skyBlueNoon.password), "Personalized output uses strong separators or symbols");
assert(/[0-9!@$]/.test(skyBlueNoon.password), "Personalized output mixes numbers or symbolic substitutions into words");

const personalized = GeneratorCore.generatePersonalizedPassword(['cyber', 'xmum']);
assert(personalized.password.length >= 16, "Personalized password length is reasonable");
assert(personalized.words.includes('cyber') && personalized.words.includes('xmum'), "Personalized password keeps sanitized words");
assertEqual(personalized.transformedWords.length, 2, "Personalized password includes all provided word anchors");
assert(personalized.transformedWords.every((word, index) => recognizable(word).includes(personalized.words[index])), "Personalized password keeps all anchors recognizable");
assertEqual(personalized.secretChunk, '', "Personalized mode no longer appends a separate secret chunk");
assertEqual(personalized.targetLength, null, "Personalized mode does not use a manual target length");
assert(/[A-Z]/.test(personalized.password), "Personalized output contains uppercase");
assert(/[a-z]/.test(personalized.password), "Personalized output contains lowercase");
assert(/[0-9]/.test(personalized.password) || /[!@$]/.test(personalized.password), "Personalized output contains numeric or symbolic word substitutions");
assert(/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(personalized.password), "Personalized output contains symbols or brackets");
assert(personalized.words.every(anchor => includesReadableAnchor(personalized.password, anchor)), "Personalized output includes all custom words");
assert(personalized.password !== personalized.words.join(''), "Personalized password does not just join custom words");
assert(personalized.password !== personalized.words.join('-'), "Personalized password is not only separated custom words");
assertEqual(personalized.randomChunk, personalized.secretChunk, "randomChunk alias matches secretChunk");

const limitedPersonalized = GeneratorCore.generatePersonalizedPassword(['one', 'two', 'three', 'four', 'five']);
assertEqual(limitedPersonalized.words.length, 4, "Personalized password uses at most 4 custom words");
assert(limitedPersonalized.warnings.includes('Using first 4 words.'), "Personalized password reports first-4 word limit");
assert(limitedPersonalized.transformedWords.every((word, index) => recognizable(word).includes(limitedPersonalized.words[index])), "Personalized password preserves all first 4 words");
assertEqual(GeneratorCore.generatePersonalizedPassword(['<script>']).password, '', "Personalized password rejects invalid custom words");

const singleWord = GeneratorCore.generatePersonalizedPassword(['bat']);
assert(singleWord.password.length >= 18, "Single short word is expanded to a safer memorized structure");
assert(includesReadableAnchor(singleWord.password, 'bat'), "Single-word output keeps the original anchor recognizable");
assert(/[()[\]{}]/.test(singleWord.password), "Single-word output uses brackets");
assert(/[0-9!@$]/.test(singleWord.password), "Single-word output includes numeric or symbolic transformations");

const risky = GeneratorCore.generatePersonalizedPassword(['password']);
assertEqual(risky.password, '', "Risky common password word does not generate output by itself");
assert(risky.warnings.some(warning => warning.includes('This word is too common')), "Risky common password word returns warning");
assert(GeneratorCore.isCommonRiskyWord('admin'), "Common risky word detector flags admin");
assert(GeneratorCore.isCommonRiskyWord('qwerty'), "Common risky word detector flags qwerty");

console.log("\n--- generateMemorySeedPassword ---");
const seedFacebookA = await GeneratorCore.generateMemorySeedPassword({
    seedWord: 'Apple',
    accountLabel: 'Facebook',
    length: 24,
});
const seedFacebookB = await GeneratorCore.generateMemorySeedPassword({
    seedWord: '  Apple  ',
    accountLabel: 'facebook',
    length: 24,
});
const seedGmail = await GeneratorCore.generateMemorySeedPassword({
    seedWord: 'Apple',
    accountLabel: 'Gmail',
    length: 24,
});
const seedOrangeFacebook = await GeneratorCore.generateMemorySeedPassword({
    seedWord: 'Orange',
    accountLabel: 'Facebook',
    length: 24,
});
const seedLength32 = await GeneratorCore.generateMemorySeedPassword({
    seedWord: 'Apple',
    accountLabel: 'Facebook',
    length: 32,
});
assertEqual(seedFacebookA.password, seedFacebookB.password, "Same seed word + same account label produces same password");
assert(seedFacebookA.password !== seedGmail.password, "Same seed word + different account label produces different password");
assert(seedFacebookA.password !== seedOrangeFacebook.password, "Different seed word + same account label produces different password");
assertEqual(seedLength32.password.length, 32, "Memory seed output length matches requested length");
assert(/[A-Z]/.test(seedFacebookA.password), "Memory seed output includes uppercase");
assert(/[a-z]/.test(seedFacebookA.password), "Memory seed output includes lowercase");
assert(/[0-9]/.test(seedFacebookA.password), "Memory seed output includes number");
assert(/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(seedFacebookA.password), "Memory seed output includes symbol");
['password', 'apple', 'admin', 'love'].forEach(word => {
    assert(GeneratorCore.isWeakSeedWord(word), `Weak seed word warning detects ${word}`);
});
const emptySeed = await GeneratorCore.generateMemorySeedPassword({ seedWord: '', accountLabel: 'Gmail', length: 24 });
assertEqual(emptySeed.password, '', "Memory seed mode does not generate without seed word");
assertEqual(emptySeed.warnings.length, 0, "Memory seed mode does not show extra warning text for empty seed");
const noAccount = await GeneratorCore.generateMemorySeedPassword({ seedWord: 'RiverStone', accountLabel: '', length: 24 });
assertEqual(noAccount.warnings.length, 0, "Memory seed mode does not warn when account is empty");

console.log("\n--- Security check ---");
const source = fs.readFileSync('./generator.js', 'utf-8');
const codeOnly = source.split('\n').filter(line => !line.trim().startsWith('//') && !line.trim().startsWith('*')).join('\n');
assert(!codeOnly.includes('Math.random('), "generator.js does not call Math.random()");
assert(/generateSecretChunk[\s\S]*secureRandomInt/.test(source), "generateSecretChunk uses crypto-secure random selection");
assert(/generateMemorySeedPassword[\s\S]*deterministicByteStream/.test(source) && /deterministicByteStream[\s\S]*sha256Bytes/.test(source), "Memory seed deterministic function uses SHA-256 bytes");
assert(!/generateMemorySeedPassword[\s\S]*getRandomValues/.test(source), "Deterministic function does not use crypto.getRandomValues() for final output");
assert(!source.includes('innerHTML'), "generator.js does not use innerHTML");

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});
