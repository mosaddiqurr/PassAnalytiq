"""
Test suite for the PassAnalytiq Analyzer.
Covers a wide range of password types to validate scoring, entropy,
pattern detection, crack time estimation, and NIST-inspired guidance checks.
"""

import json
import sys
import io
import math

# Ensure UTF-8 output on Windows (avoids charmap UnicodeEncodeError)
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from password_analyzer import PasswordStrengthAnalyzer, batch_analyze, DICEWARE_WORDLIST

analyzer = PasswordStrengthAnalyzer()

STRICT_FAILURES = []

def record_strict(condition, test_name, detail=""):
    if condition:
        print(f"OK  {test_name}")
    else:
        suffix = f" — {detail}" if detail else ""
        print(f"FAIL {test_name}{suffix}")
        STRICT_FAILURES.append(f"{test_name}{suffix}")

def assert_label(password, expected_label):
    result = analyzer.analyze(password)
    record_strict(
        result.strength_label == expected_label,
        f"{password!r} label is exactly {expected_label}",
        f"got {result.strength_label} (score {result.score})",
    )

def assert_pattern(password, expected_pattern):
    result = analyzer.analyze(password)
    patterns = [p.pattern_type for p in result.patterns_found]
    record_strict(
        expected_pattern in patterns,
        f"{password!r} detects {expected_pattern}",
        f"got {patterns}",
    )

def run_strict_regression_tests():
    print("\n" + "=" * 80)
    print("  STRICT REGRESSION TESTS")
    print("=" * 80)

    # Exact labels for important weak-password cases.
    for password in ["password", "123456", "password123", "p@ssw0rd", "qwerty123"]:
        assert_label(password, "Very Weak")

    # NIST-inspired guidance checks.
    record_strict(
        not analyzer.analyze("ShortPass1").nist_compliant,
        "Password shorter than 15 chars is not guidance-compliant",
    )
    record_strict(
        not analyzer.analyze("password").nist_compliant,
        "Common password is not guidance-compliant",
    )
    record_strict(
        analyzer.analyze("correct horse battery staple").nist_compliant,
        "Long clean passphrase is guidance-compliant",
    )
    record_strict(
        analyzer.analyze("correcthorsebatterystaplerandom").nist_compliant,
        "Long lowercase-only password can be guidance-compliant",
    )

    # Composition rules are not enforced.
    no_upper = analyzer.analyze("correcthorsebatterystaplerandom")
    record_strict(
        no_upper.nist_compliant and not no_upper.character_sets["uppercase"],
        "No uppercase requirement is enforced",
    )
    no_digit = analyzer.analyze("correct horse battery staple")
    record_strict(
        no_digit.nist_compliant and not no_digit.character_sets["digits"],
        "No digit requirement is enforced",
    )
    no_symbol = analyzer.analyze("correcthorsebatterystaplerandom")
    record_strict(
        no_symbol.nist_compliant and not no_symbol.character_sets["symbols"],
        "No symbol requirement is enforced",
    )

    # Unicode support.
    accented = analyzer.analyze("Café sécurité très longue")
    record_strict(
        accented.length > 0 and accented.character_sets["unicode_ext"],
        "Accented characters do not crash and are detected",
    )
    emoji = analyzer.analyze("safe passphrase words \U0001f510")
    record_strict(
        emoji.length > 0 and emoji.character_sets["emoji"],
        "Emoji do not crash and are detected",
    )
    spaced = analyzer.analyze("correct horse battery staple")
    record_strict(
        spaced.character_sets["spaces"] and spaced.is_passphrase,
        "Spaces in passphrases are allowed",
    )
    dotted = analyzer.analyze("correct.horse.battery.staple")
    record_strict(
        dotted.is_passphrase,
        "Dots in generated passphrases are detected",
    )
    underscored = analyzer.analyze("correct_horse_battery_staple")
    record_strict(
        underscored.is_passphrase,
        "Underscores in generated passphrases are detected",
    )

    # Bundled passphrase wordlist entropy consistency.
    record_strict(
        DICEWARE_WORDLIST == 1344,
        "Python bundled passphrase wordlist size matches generator.js",
        f"got {DICEWARE_WORDLIST}",
    )
    record_strict(
        math.isclose(analyzer._passphrase_entropy(4), 4 * math.log2(DICEWARE_WORDLIST), rel_tol=0, abs_tol=1e-12),
        "Python passphrase entropy uses the bundled wordlist size",
    )
    record_strict(
        analyzer._format_time(86400 * 365 * 1_000_000_000) == ">1 billion years",
        "Python crack-time formatting caps billion-year estimates",
    )
    record_strict(
        analyzer._format_time(86400 * 365 * 1_000_000_000_000) == ">1 trillion years",
        "Python crack-time formatting caps trillion-year estimates",
    )

    # Pattern detection.
    assert_pattern("qwertySafePassphrase", "keyboard_walk")
    assert_pattern("summer2024vacationplan", "date_pattern")
    assert_pattern("aaaaaaaaaaaaaaaa", "repeated_chars")
    assert_pattern("abc123456789", "sequential_digits")

# Test passwords: (password, expected_strength_category)
TEST_CASES = [
    # Very weak
    ("123456",          "Very Weak"),
    ("password",        "Very Weak"),
    ("qwerty",          "Very Weak"),
    ("aaa",             "Very Weak"),
    ("abc",             "Very Weak"),

    # Weak
    ("password123",     "Very Weak"),
    ("p@ssw0rd",        "Very Weak"),
    ("hello123",        "Weak"),
    ("qwerty123",       "Very Weak"),
    ("abc12345",        "Weak"),

    # Fair
    ("Summer2024!",     "Fair"),
    ("MyDog$Fluffy7",   "Strong"),
    ("Tr0ub4dor&3",     "Weak"),
    ("Blue#Sky99",      "Fair"),

    # Strong
    ("G7#mK9!pLx2@",   "Strong"),
    ("Correct-Horse-Battery-Staple", "Strong"),
    ("xK8$mP2#nQ5!",   "Fair"),

    # Very Strong
    ("X9#kL2$mP7@nQ4!wR", "Very Strong"),
    ("j8K#mN2$pL9@xQ5!wR3", "Very Strong"),
    ("Th3!Qu1ck#Br0wn$F0x@Jumps", "Very Strong"),
]

run_strict_regression_tests()

print("\n" + "=" * 80)
print("  PASSANALYTIQ ANALYZER — TEST RESULTS")
print("=" * 80)
print(f"{'Password':<35} {'Score':>5} {'Label':<15} {'Entropy':>8} {'Eff.Entropy':>12} {'Patterns':>8}")
print("-" * 80)

results_data = []
all_pass = True

for password, expected_category in TEST_CASES:
    result = analyzer.analyze(password)
    display_pw = password if len(password) <= 32 else password[:29] + "..."

    # Loose category check (allow one tier off)
    category_order = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    expected_idx = category_order.index(expected_category)
    actual_idx = category_order.index(result.strength_label)
    close_enough = abs(expected_idx - actual_idx) <= 1

    status = "OK " if close_enough else "FAIL"
    if not close_enough:
        all_pass = False

    print(f"{status} {display_pw:<33} {result.score:>5} {result.strength_label:<15} "
          f"{result.entropy_bits:>7.1f}b {result.effective_entropy:>11.1f}b "
          f"{len(result.patterns_found):>7} patterns")

    results_data.append({
        "password": password,
        "score": result.score,
        "strength_label": result.strength_label,
        "entropy_bits": result.entropy_bits,
        "effective_entropy": result.effective_entropy,
        "character_set_size": result.character_set_size,
        "length": result.length,
        "patterns": [p.pattern_type for p in result.patterns_found],
        "crack_times": result.crack_times,
        "nist_compliant": result.nist_compliant,
        "nist_issues": result.nist_issues,
        "suggestions": result.suggestions,
        "character_sets": result.character_sets,
    })

print("-" * 80)
all_pass = all_pass and not STRICT_FAILURES
print(f"\nAll tests passed: {all_pass}")
if STRICT_FAILURES:
    print("\nStrict regression failures:")
    for failure in STRICT_FAILURES:
        print(f"  - {failure}")

# Save results to JSON for the webpage
with open("test_results.json", "w", encoding="utf-8") as f:
    json.dump(results_data, f, indent=2)

print("\nTest results saved to test_results.json")

# Print detailed report for a few interesting cases
print("\n\n" + "=" * 80)
print("  DETAILED REPORTS FOR SELECTED PASSWORDS")
print("=" * 80)

selected = ["password", "p@ssw0rd", "Tr0ub4dor&3", "X9#kL2$mP7@nQ4!wR"]
for pw in selected:
    r = analyzer.analyze(pw)
    print(r.detailed_feedback)
    print()

if not all_pass:
    sys.exit(1)
