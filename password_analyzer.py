"""
PassAnalytiq Analyzer — NIST-Inspired Edition
==============================================================
Aligned with key password guidance principles from NIST SP 800-63B-4
(Digital Identity Guidelines: Authentication and Authenticator Management).

Key NIST-inspired principles implemented
----------------------------------------
1. LENGTH IS THE PRIMARY STRENGTH SIGNAL.
   This project uses 15 characters for single-factor password guidance.
   Eight-character minimums may apply in MFA contexts; support up to 128+
   characters.

2. NO COMPOSITION RULES.
   We do NOT require uppercase, lowercase, digits, or special characters.
   We do NOT penalise passwords for *lacking* any character category.
   NIST explicitly discourages composition rules because they encourage
   predictable patterns (Password1!, Tr0ub4dor&3, etc.) without materially
   increasing security.

3. UNICODE NFC NORMALISATION applied before every check, following
   SP 800-63B-4 guidance for accepted Unicode passwords.

4. PROJECT BLOCKLIST / PATTERN CHECKS — passwords are screened against:
   • A hardcoded common-password set (top ~150 passwords).
   • Repetitive, sequential, and context-specific patterns are flagged as
     project checks inspired by NIST blocklist guidance.
   A production deployment MUST also integrate a breached-password corpus
   (e.g. HIBP SHA-1 range API or an offline Bloom filter) at this step.

5. STRENGTH SCORING is based on:
   (a) Length   — the single biggest driver.
   (b) Blacklist status — immediate failure / heavy penalty.
   (c) Pattern penalties — repetition, keyboard walks, dates, etc.
   (d) Passphrase bonus — bundled wordlist-chain model (§5.1.1.2).
   Shannon / character-class entropy is deliberately NOT used as the
   primary metric (see NIST note: "complexity requirements … offer little …
   benefit").  Charset entropy is still computed and exposed as
   `entropy_bits` for display purposes only (some UIs expect it).

6. FEEDBACK focuses on actionable, non-prescriptive advice:
   "Use a longer passphrase" rather than "Add a special character".

Production-readiness notes (out of scope for this module)
----------------------------------------------------------
• Rate-limit authentication endpoints (§5.2.2).
• Hash passwords with a memory-hard KDF: Argon2id (preferred), bcrypt,
  scrypt, or PBKDF2-SHA256 (min 310 000 iterations for PBKDF2).
• Use a per-password unique random salt (≥ 32 bytes).
• NEVER store passwords in plaintext; NEVER log them.
• Integrate a breached-password corpus (HIBP Pwned Passwords dataset,
  currently 900 M+ hashes) for comprehensive blacklist coverage.
• Re-prompt users to change passwords discovered in future breaches.

Author: Cybersecurity Student Project
"""

from __future__ import annotations

import re
import math
import hashlib
import hmac
import time
import string
import unicodedata
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional


# ---------------------------------------------------------------------------
# Common / breached password blacklist
# ---------------------------------------------------------------------------
# In production: replace / augment this set with an offline Bloom filter
# loaded from the HIBP SHA-1 dataset (see https://haveibeenpwned.com/Passwords).
COMMON_PASSWORDS: frozenset[str] = frozenset({
    # Top 200 most-used passwords (lower-cased; checked case-insensitively)
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password2", "welcome", "1234567890", "charlie", "donald",
    "password123", "qwerty123", "iloveyou1", "admin", "login", "hello",
    "whatever", "qwertyuiop", "654321", "zxcvbnm", "1q2w3e4r", "111111",
    "1234", "12345", "123456789", "000000", "1111111", "11111111",
    "princess", "dragon", "master", "pass", "test", "guest", "root",
    "toor", "changeme", "secret", "letmein", "welcome1", "monkey123",
    "sunshine1", "password!", "p@ssword", "p@ssw0rd", "pa$$word",
    "passw0rd!", "qwerty!", "abc1234", "1234abc", "pass123", "pass1234",
    "mypassword", "mypass", "temp", "temp123", "user", "user123",
    "admin123", "administrator", "root123", "system", "default",
    "service", "access", "access1", "login1", "test123", "demo",
    "sample", "example", "internet", "computer", "windows", "linux",
    "apple", "google", "facebook", "twitter", "instagram", "amazon",
    "netflix", "spotify", "youtube", "github", "stackoverflow",
    "baseball1", "basketball", "football1", "soccer", "hockey",
    "tennis", "golf", "swimming", "running", "fitness",
    "summer", "winter", "spring", "autumn", "monday", "friday",
    "january", "february", "december", "birthday", "anniversary",
    "chocolate", "coffee", "pizza", "burger", "cookie",
    "batman", "superman1", "spiderman", "ironman", "captain",
    "starwars", "matrix", "avatar", "pokemon", "mario",
    "love", "love123", "lovely", "lover", "loveme",
    "baby", "baby123", "babe", "honey", "sweetheart",
    "killer", "hacker", "ninja", "warrior", "hunter",
    "thunder", "lightning", "storm", "fire", "water",
    "black", "white", "blue", "red", "green",
    "tiger", "lion", "eagle", "wolf", "bear",
    "michael1", "jennifer", "jessica", "ashley1", "amanda",
    "daniel", "matthew", "joshua", "andrew", "james",
    "robert", "william", "richard", "charles", "joseph",
    "thomas", "christopher", "david", "george", "edward",
    # Common sequential / repetitive strings flagged by this project.
    "abcdefgh", "abcdefghij", "abcdefghijklmnop",
    "12345678", "123456789", "1234567890",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "aaaaaaaa", "aaaaaaaaa", "aaaaaaaaaa",
    "0000000", "00000000",
})

# ---------------------------------------------------------------------------
# Keyboard adjacency patterns (walk detection)
# ---------------------------------------------------------------------------
KEYBOARD_WALKS: List[str] = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1234567890", "0987654321", "qazwsx", "wsxedc", "edcrfv", "rfvtgb",
    "tgbyhn", "yhnujm", "qweasdzxc", "1qaz2wsx", "2wsx3edc",
    "!@#$%^&*()", "!qaz@wsx", "abcdefgh", "abcdefghij",
]

# ---------------------------------------------------------------------------
# Leet-speak substitution map (for decoding before blacklist check)
# ---------------------------------------------------------------------------
LEET_MAP: Dict[str, str] = {
    "@": "a", "4": "a", "8": "b", "3": "e", "6": "g",
    "1": "i", "!": "i", "0": "o", "5": "s", "$": "s",
    "7": "t", "+": "t", "2": "z",
}

# ---------------------------------------------------------------------------
# Attack-speed table (guesses / second) — for crack-time display only
# ---------------------------------------------------------------------------
ATTACK_SPEEDS: Dict[str, float] = {
    "online_throttled":    100 / 3600,       # 100 attempts/hour (rate-limited)
    "online_unthrottled":  10_000,
    "offline_slow_hash":   10_000_000,       # bcrypt / scrypt
    "offline_fast_hash":   10_000_000_000,   # MD5/SHA-1 GPU
    "offline_gpu_cluster": 100_000_000_000_000,  # High-end GPU cluster
}

# Project guidance thresholds inspired by NIST SP 800-63B-4.
NIST_MIN_LENGTH: int = 15  # Single-factor password guidance
NIST_ABS_MIN: int = 8      # May apply in MFA contexts
NIST_MAX_ALLOW: int = 128  # We allow up to 128 characters (NIST: ≥ 64)

# Bundled generator wordlist size used for passphrase entropy.
# Keep this in sync with len(EFF_SHORT_WORDLIST) in generator.js.
DICEWARE_WORDLIST: int = 1344


# ---------------------------------------------------------------------------
# Data classes — API unchanged so test_analyzer.py needs zero edits
# ---------------------------------------------------------------------------
@dataclass
class PatternMatch:
    """Represents a detected weakness pattern and its entropy penalty."""
    pattern_type: str
    matched_text: str
    start: int
    end: int
    description: str
    penalty: float  # bits subtracted from effective entropy


@dataclass
class AnalysisResult:
    """
    Full analysis result.  Field names are preserved for backward compatibility
    with test_analyzer.py and the index.html front-end.

    Alignment notes
    ---------------
    • `character_sets`     — presence flags only; NOT used for scoring.
    • `character_set_size` — charset alphabet size; exposed for display / UI.
    • `entropy_bits`       — character-set OR bundled-wordlist entropy (display only).
    • `effective_entropy`  — entropy after pattern penalties.
    • `score`              — 0-100; driven primarily by length.
    • `nist_compliant`     — True when the project's NIST-inspired checks pass.
    """
    password: str
    length: int
    score: int
    strength_label: str
    entropy_bits: float
    effective_entropy: float
    character_sets: Dict[str, bool]
    character_set_size: int
    patterns_found: List[PatternMatch]
    crack_times: Dict[str, str]
    nist_compliant: bool
    nist_issues: List[str]
    suggestions: List[str]
    detailed_feedback: str
    is_passphrase: bool = False
    hibp_pwned_count: int = 0


# ---------------------------------------------------------------------------
# Core Analyzer
# ---------------------------------------------------------------------------
class PasswordStrengthAnalyzer:
    """
    NIST-inspired password strength analyzer.

    Design philosophy (§5.1.1)
    --------------------------
    • Length is the PRIMARY quality signal.
    • Composition rules (must have uppercase / symbol / digit) are REMOVED —
      NIST explicitly discourages them.
    • A project blocklist / pattern check (common passwords, breached
      passwords if supplied, repetitive / sequential strings, and
      context-specific values) is applied BEFORE any scoring.
    • Strength feedback is non-prescriptive: we encourage long passphrases
      rather than mandating specific character categories.
    • Unicode passwords are supported via NFC normalisation.

    Production requirements (not implemented here — see module docstring)
    -------------------------------------------------------------------
    • Server-side rate limiting on authentication endpoints.
    • Memory-hard password hashing (Argon2id / bcrypt / scrypt / PBKDF2).
    • Salted, one-way storage — never plaintext.
    • Breached-password corpus integration (HIBP dataset or equivalent).
    """

    def __init__(
        self,
        *,
        app_name: str = "",
        org_name: str = "",
        username: str = "",
        extra_blacklist: Optional[frozenset[str]] = None,
    ) -> None:
        """
        Parameters
        ----------
        app_name, org_name, username
            Context-specific values used for §5.1.1 context-specific blacklist
            checks.  Provide these when integrating into a real application.
        extra_blacklist
            Additional lower-cased tokens to treat as blacklisted (e.g. loaded
            from a breached-password corpus).
        """
        self._common = COMMON_PASSWORDS
        self._extra = extra_blacklist or frozenset()
        self._context_tokens: List[str] = [
            t.lower() for t in [app_name, org_name, username] if t
        ]
        self._keyboard_walks = KEYBOARD_WALKS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze(
        self,
        password: str,
        *,
        username: str = "",
        check_hibp: bool = False,
    ) -> AnalysisResult:
        """
        Perform a NIST-inspired analysis.

        Parameters
        ----------
        password   : The candidate password string.
        username   : If provided, the password is checked for username
                     as a project context-specific pattern check.
        check_hibp : When True, perform an opt-in HIBP k-Anonymity lookup.
                     Requires internet access; safe to leave False offline.
        """
        # ── Step 1: Sanitize & normalise (NFC — SP 800-63B-4 guidance) ────
        password = self._sanitize_input(password)
        password = unicodedata.normalize("NFC", password)
        length = len(password)

        # ── Step 2: Character-set detection (display only; NOT scored) ────
        char_sets = self._detect_character_sets(password)
        char_set_size = self._calculate_charset_size(char_sets)
        charset_entropy = self._charset_entropy(length, char_set_size)

        # ── Step 3: Passphrase detection & bundled-wordlist entropy upgrade ─
        is_passphrase, word_count = self._detect_passphrase(password)
        if is_passphrase:
            diceware_e = self._passphrase_entropy(word_count)
            entropy = max(charset_entropy, diceware_e)
        else:
            entropy = charset_entropy

        # ── Step 4: Blacklist & context checks ────────────────────────────
        #    NIST §5.1.1.2: "verifiers SHALL compare … against a list …"
        blacklist_patterns = self._check_blacklist(password, username=username)

        # ── Step 5: Structural pattern detection (keyboard walks, repeats…)
        structural_patterns = self._detect_structural_patterns(password)
        all_patterns = blacklist_patterns + structural_patterns

        # ── Step 6: Effective entropy after penalties ──────────────────────
        penalty = sum(p.penalty for p in all_patterns)
        effective_entropy = max(0.0, entropy - penalty)

        # ── Step 7: Crack times, guidance check, score, label, feedback ──
        crack_times  = self._estimate_crack_times(effective_entropy)
        is_blacklisted = any(
            p.pattern_type in ("blacklisted", "context_specific")
            for p in blacklist_patterns
        )
        nist_compliant, nist_issues = self._check_nist_compliance(
            password, length, is_blacklisted, all_patterns
        )
        score = self._calculate_score(
            effective_entropy, length, all_patterns, nist_compliant, is_blacklisted
        )
        strength_label  = self._score_to_label(score, length)
        suggestions     = self._generate_suggestions(
            password, length, char_sets, all_patterns, nist_issues, score, is_passphrase
        )
        detailed_feedback = self._generate_detailed_feedback(
            password, length, char_sets, entropy, effective_entropy,
            all_patterns, crack_times, score, strength_label, nist_issues,
            is_passphrase=is_passphrase,
        )

        # ── Step 8: Optional HIBP lookup ─────────────────────────────────
        hibp_count = 0
        if check_hibp:
            hibp_count = self.check_hibp_breach(password)

        return AnalysisResult(
            password=password,
            length=length,
            score=score,
            strength_label=strength_label,
            entropy_bits=round(entropy, 2),
            effective_entropy=round(effective_entropy, 2),
            character_sets=char_sets,
            character_set_size=char_set_size,
            patterns_found=all_patterns,
            crack_times=crack_times,
            nist_compliant=nist_compliant,
            nist_issues=nist_issues,
            suggestions=suggestions,
            detailed_feedback=detailed_feedback,
            is_passphrase=is_passphrase,
            hibp_pwned_count=hibp_count,
        )

    # ------------------------------------------------------------------
    # HIBP k-Anonymity breach check (opt-in)
    # ------------------------------------------------------------------
    def check_hibp_breach(self, password: str) -> int:
        """
        Query the Have I Been Pwned API using the k-Anonymity model.

        Only the first 5 hex characters of the SHA-1 hash are transmitted;
        the remaining suffix is compared locally using constant-time compare.

        Returns
        -------
        > 0   — number of occurrences in breach data.
          0   — not found.
         -1   — network / API error (treat as unknown).
        """
        sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url    = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "PasswordStrengthAnalyzer/2.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.URLError:
            return -1
        for line in body.splitlines():
            hash_suffix, _, count_str = line.partition(":")
            if hmac.compare_digest(hash_suffix.strip(), suffix):
                return int(count_str.strip())
        return 0

    # ------------------------------------------------------------------
    # Input sanitization (C0/C1 control-character stripping)
    # ------------------------------------------------------------------
    @staticmethod
    def _sanitize_input(password: str) -> str:
        """
        Strip C0 (U+0000–U+001F) and C1 (U+007F–U+009F) control characters
        plus lone surrogates (Unicode category Cs).  Printable characters,
        spaces, accented letters, and emoji are ALL preserved.

        Raises ValueError if nothing remains after stripping.
        """
        cleaned = "".join(
            ch for ch in password
            if unicodedata.category(ch) not in ("Cc", "Cs")
        )
        if not cleaned:
            raise ValueError(
                "Password is empty after removing control characters. "
                "Please enter printable characters."
            )
        return cleaned

    # ------------------------------------------------------------------
    # Character-set detection (display / UI purposes only — not scored)
    # ------------------------------------------------------------------
    @staticmethod
    def _detect_character_sets(password: str) -> Dict[str, bool]:
        """
        Detect which character pools are represented.

        IMPORTANT: These flags are exposed for display only.  Per NIST §5.1.1,
        the presence / absence of any category MUST NOT penalise or reward the
        password during scoring.

        Buckets match the JavaScript front-end:
          lowercase, uppercase, digits, symbols, spaces, unicode_ext, emoji
        """
        def _is_emoji(ch: str) -> bool:
            cp = ord(ch)
            cat = unicodedata.category(ch)
            return (
                cat in ("So", "Sm")
                or 0x1F300 <= cp <= 0x1FAFF
                or 0x2600  <= cp <= 0x27BF
                or 0xFE00  <= cp <= 0xFE0F
            )

        has_emoji   = any(_is_emoji(c) for c in password if ord(c) > 127)
        has_uni_ext = any(ord(c) > 127 and not _is_emoji(c) for c in password)

        return {
            "lowercase":   bool(re.search(r"[a-z]", password)),
            "uppercase":   bool(re.search(r"[A-Z]", password)),
            "digits":      bool(re.search(r"\d",    password)),
            "symbols":     bool(re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password)),
            "spaces":      " " in password,
            "unicode_ext": has_uni_ext,
            "emoji":       has_emoji,
        }

    @staticmethod
    def _calculate_charset_size(char_sets: Dict[str, bool]) -> int:
        """
        Return the effective alphabet size for *display-only* charset entropy.

        This number is NOT used in the NIST scoring path.  It is retained
        solely so UI elements (entropy gauge, charset size display) continue
        to function, and so test_analyzer.py field access works unchanged.
        """
        size = 0
        if char_sets["lowercase"]:           size += 26
        if char_sets["uppercase"]:           size += 26
        if char_sets["digits"]:              size += 10
        if char_sets["symbols"]:             size += 32
        if char_sets["spaces"]:              size += 10
        if char_sets.get("unicode_ext"):     size += 80
        if char_sets.get("emoji"):           size += 1024
        return max(size, 1)

    # ------------------------------------------------------------------
    # Entropy helpers (display / crack-time only)
    # ------------------------------------------------------------------
    @staticmethod
    def _charset_entropy(length: int, charset_size: int) -> float:
        """H = L × log₂(N).  Kept for display / crack-time purposes only."""
        if length == 0 or charset_size == 0:
            return 0.0
        return length * math.log2(charset_size)

    # ------------------------------------------------------------------
    # Passphrase / bundled wordlist model (NIST §5.1.1.2)
    # ------------------------------------------------------------------
    @staticmethod
    def _detect_passphrase(password: str) -> Tuple[bool, int]:
        """
        Detect a random-word style passphrase.

        A passphrase is identified when ≥ 3 tokens separated by common
        generator separators each have ≥ 3 characters. NIST §5.1.1.2
        explicitly permits and encourages long passphrases; spaces must be
        allowed.

        Returns (is_passphrase, word_count).
        """
        tokens = [t for t in re.split(r"[\s\-._]+", password) if len(t) >= 3]
        return len(tokens) >= 3, len(tokens)

    @staticmethod
    def _passphrase_entropy(word_count: int, wordlist_size: int = DICEWARE_WORDLIST) -> float:
        """Bundled wordlist entropy: word_count × log₂(wordlist_size)."""
        return word_count * math.log2(wordlist_size)

    # ------------------------------------------------------------------
    # Blocklist / pattern checking inspired by NIST guidance
    # ------------------------------------------------------------------
    def _check_blacklist(
        self, password: str, *, username: str = ""
    ) -> List[PatternMatch]:
        """
        Screen the password against this project's blocklist and pattern checks.

        Checks (all case-insensitive after NFC normalisation):
          1. Common / widely-used passwords.
          2. Extra breached-password tokens supplied at construction time.
          3. Leet-speak variant of a common password.
          4. Context-specific values: username, app-name, org-name,
             reversed username, username as substring.
          5. Purely repetitive strings (e.g. "aaaaaaa").
          6. Sequential digit / letter runs (e.g. "1234567890", "abcdef").
        """
        found: List[PatternMatch] = []
        lower = password.lower()

        # Gather context tokens — include per-call username too
        context = list(self._context_tokens)
        if username:
            u = username.lower()
            context.extend([u, u[::-1]])  # also check reversed username

        # 1 & 2 — common + extra blacklist (constant-time iteration)
        is_common = self._ct_in_set(self._common, lower)
        is_extra  = self._ct_in_set(self._extra,  lower) if self._extra else False
        if is_common or is_extra:
            found.append(PatternMatch(
                pattern_type="blacklisted",
                matched_text=password,
                start=0, end=len(password),
                description=(
                    "This password appears in known common or breached password lists. "
                    "NIST-inspired guidance calls for screening passwords against blocklists."
                ),
                penalty=60.0,
            ))

        # 3 — Leet-speak variant of a common password
        leet_decoded = self._decode_leet(lower)
        if leet_decoded != lower and self._ct_in_set(self._common, leet_decoded):
            found.append(PatternMatch(
                pattern_type="blacklisted",
                matched_text=password,
                start=0, end=len(password),
                description=(
                    f"Leet-speak variant maps to common password '{leet_decoded}'. "
                    "Modern cracking tools apply these substitutions automatically."
                ),
                penalty=40.0,
            ))

        # 4 — Context-specific values
        for token in context:
            if len(token) >= 3 and token in lower:
                found.append(PatternMatch(
                    pattern_type="context_specific",
                    matched_text=token,
                    start=lower.find(token),
                    end=lower.find(token) + len(token),
                    description=(
                        f"Password contains a context-specific value ('{token}'). "
                        "This project treats context-specific values as predictable patterns."
                    ),
                    penalty=30.0,
                ))
                break  # one match is sufficient

        # 5 — Repetitive strings  (e.g. "aaaaaaa", "1111111")
        #     Project predictable-pattern check.
        if re.fullmatch(r"(.)\1+", password) and len(password) >= 3:
            found.append(PatternMatch(
                pattern_type="repetitive_string",
                matched_text=password,
                start=0, end=len(password),
                description=(
                    "Password is entirely a repeated single character. "
                    "This project flags repetitive strings as predictable."
                ),
                penalty=60.0,
            ))

        # 6 — Sequential strings (e.g. "12345678", "abcdefg")
        #     Detect runs of ≥ 6 consecutive ascending/descending chars
        if self._is_sequential(lower, min_run=6):
            found.append(PatternMatch(
                pattern_type="sequential_string",
                matched_text=password,
                start=0, end=len(password),
                description=(
                    "Password consists primarily of sequential characters "
                    "(e.g. 12345678, abcdefgh). This project flags sequential strings as predictable."
                ),
                penalty=50.0,
            ))

        return found

    @staticmethod
    def _is_sequential(text: str, min_run: int = 6) -> bool:
        """Return True when `text` contains a sequential ASCII run of `min_run`+ chars."""
        if len(text) < min_run:
            return False
        run = 1
        for i in range(1, len(text)):
            diff = ord(text[i]) - ord(text[i - 1])
            if diff in (1, -1):
                run += 1
                if run >= min_run:
                    return True
            else:
                run = 1
        return False

    # ------------------------------------------------------------------
    # Structural pattern detection (penalties, NOT composition rules)
    # ------------------------------------------------------------------
    def _detect_structural_patterns(self, password: str) -> List[PatternMatch]:
        """
        Detect weakness patterns that reduce effective entropy.

        NOTE: We detect these not to enforce composition rules, but because
        they reduce the true guessing difficulty of a password regardless of
        its length or character variety.

        Patterns detected:
          1. Keyboard walks (qwerty, asdf…)
          2. Repeated sub-sequences (aaaa, 1111)
          3. Sequential digit runs (123, 987)
          4. Sequential letter runs (abc, xyz)
          5. Date-like patterns (year, MMDD)
          6. Word + common suffix (hello123, pass!)
        """
        patterns: List[PatternMatch] = []
        lower = password.lower()

        # 1. Keyboard walks
        for kp in self._keyboard_walks:
            if len(kp) >= 4:
                rev = kp[::-1]
                for match in (kp, rev):
                    if match in lower:
                        idx = lower.find(match)
                        patterns.append(PatternMatch(
                            pattern_type="keyboard_walk",
                            matched_text=password[idx: idx + len(match)],
                            start=idx, end=idx + len(match),
                            description=(
                                f"Keyboard walk pattern '{match}' detected — "
                                "trivially enumerated by crack dictionaries."
                            ),
                            penalty=min(len(match) * 2.5, 20.0),
                        ))
                        break

        # 2. Repeated sub-sequences (≥ 4 of same char)
        m = re.search(r"(.)\1{3,}", password)
        if m:
            patterns.append(PatternMatch(
                pattern_type="repeated_chars",
                matched_text=m.group(),
                start=m.start(), end=m.end(),
                description=f"Repeated character sequence '{m.group()}' significantly reduces entropy.",
                penalty=10.0,
            ))

        # 3. Sequential digits
        if re.search(
            r"012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210",
            password,
        ):
            patterns.append(PatternMatch(
                pattern_type="sequential_digits",
                matched_text="", start=0, end=0,
                description="Sequential digit run detected — predictable and easily guessed.",
                penalty=8.0,
            ))

        # 4. Sequential letters
        if re.search(
            r"abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|"
            r"pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|zyx|yxw|xwv|wvu|vut|uts|"
            r"tsr|srq|rqp|qpo|pon|onm|nml|mlk|lkj|kji|jih|ihg|hgf|gfe|fed|"
            r"edc|dcb|cba",
            lower,
        ):
            patterns.append(PatternMatch(
                pattern_type="sequential_letters",
                matched_text="", start=0, end=0,
                description="Sequential letter run detected — predictable.",
                penalty=8.0,
            ))

        # 5. Date patterns (years, MMDD, delimited dates)
        if re.search(
            r"(19|20)\d{2}|"
            r"\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{2,4}\b|"
            r"\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
            password,
        ):
            patterns.append(PatternMatch(
                pattern_type="date_pattern",
                matched_text="", start=0, end=0,
                description=(
                    "Date-like pattern detected. Attackers routinely try birth years "
                    "and common dates via targeted dictionaries."
                ),
                penalty=12.0,
            ))

        # 6. Word + trivial suffix (word123, word!)
        if re.search(r"[a-zA-Z]{3,}(123|1234|12345|!|!!|@|#|\d{1,4})$", password):
            patterns.append(PatternMatch(
                pattern_type="common_suffix",
                matched_text="", start=0, end=0,
                description=(
                    "Common word + numbers/symbols suffix pattern. "
                    "Cracking tools apply these transforms automatically."
                ),
                penalty=12.0,
            ))

        return patterns

    # ------------------------------------------------------------------
    # Crack time estimation
    # ------------------------------------------------------------------
    def _estimate_crack_times(self, entropy_bits: float) -> Dict[str, str]:
        guesses = 2 ** entropy_bits
        return {
            scenario: self._format_time(guesses / speed)
            for scenario, speed in ATTACK_SPEEDS.items()
        }

    @staticmethod
    def _format_time(seconds: float) -> str:
        if seconds < 1:                      return "less than a second"
        if seconds < 60:                     return f"{seconds:.1f} seconds"
        if seconds < 3600:                   return f"{seconds / 60:.1f} minutes"
        if seconds < 86400:                  return f"{seconds / 3600:.1f} hours"
        if seconds < 86400 * 30:             return f"{seconds / 86400:.1f} days"
        if seconds < 86400 * 365:            return f"{seconds / (86400 * 30):.1f} months"
        if seconds < 86400 * 365 * 1_000:    return f"{seconds / (86400 * 365):.1f} years"
        if seconds < 86400 * 365 * 1_000_000: return f"{seconds / (86400 * 365 * 1_000):.1f} thousand years"
        if seconds < 86400 * 365 * 1_000_000_000: return f"{seconds / (86400 * 365 * 1_000_000):.1f} million years"
        if seconds < 86400 * 365 * 1_000_000_000_000: return ">1 billion years"
        return ">1 trillion years"

    # ------------------------------------------------------------------
    # NIST-inspired guidance check
    # ------------------------------------------------------------------
    def _check_nist_compliance(
        self,
        password: str,
        length: int,
        is_blacklisted: bool,
        patterns: List[PatternMatch],
    ) -> Tuple[bool, List[str]]:
        """
        Return (passes_project_guidance, issues_list).

        Project criteria inspired by NIST SP 800-63B-4:
          1. Length ≥ NIST_MIN_LENGTH. We use 15 for single-factor password
             guidance; 8 characters may apply in MFA contexts.
          2. Not in the blacklist (common / breached passwords).
          3. Not context-specific according to project integration inputs.
          4. Not purely repetitive (already caught by project pattern checks).
          5. No 5+-char repeated run.

        Notably absent, following modern NIST-inspired guidance:
          • Uppercase requirement.
          • Lowercase requirement.
          • Digit requirement.
          • Symbol requirement.
          • Password expiry hints.
          • Knowledge-based authentication hints.
        """
        issues: List[str] = []

        if length < NIST_MIN_LENGTH:
            issues.append(
                f"Too short: {length} character(s). "
                f"This NIST-inspired check uses {NIST_MIN_LENGTH} characters for "
                "single-factor password guidance; 8 characters may apply in MFA contexts."
            )

        if is_blacklisted:
            issues.append(
                "Password appears in common or breached password lists used by "
                "this project's NIST-inspired screening."
            )

        ctx_types = {"context_specific"}
        if any(p.pattern_type in ctx_types for p in patterns):
            issues.append(
                "Contains a context-specific value (username / app name / org name). "
                "This project flags context-specific values as predictable."
            )

        if re.search(r"(.)\1{4,}", password):
            issues.append(
                "Contains 5 or more consecutive identical characters. "
                "This project flags repeated runs as predictable."
            )

        return len(issues) == 0, issues

    # ------------------------------------------------------------------
    # Scoring — LENGTH DOMINANT, no composition rules
    # ------------------------------------------------------------------
    def _calculate_score(
        self,
        effective_entropy: float,
        length: int,
        patterns: List[PatternMatch],
        nist_compliant: bool,
        is_blacklisted: bool,
    ) -> int:
        """
        Score 0–100.

        Allocation (NIST-inspired philosophy)
        ----------------------------------------
        Length           0–50 pts  ← the primary quality signal
        Effective entropy 0–30 pts ← structural diversity after penalties
        NIST-inspired check  0–20 pts ← length + blocklist gate together

        DELIBERATELY EXCLUDED:
        • Bonus for having uppercase / lowercase / digits / symbols.
        • Penalty for lacking any character category.
        These would re-introduce composition rules that modern guidance avoids.
        """
        # Hard failure for blacklisted passwords — no meaningful score
        if is_blacklisted:
            return max(0, min(10, int((effective_entropy / 80) * 10)))

        # ── Length score (0–50) ────────────────────────────────────────────
        # Calibrated so that a 15-char password reaches ≥ 35 pts on length
        # alone, and a 25+ char password maxes out this component.
        if length >= 30:        length_score = 50
        elif length >= 25:      length_score = 45
        elif length >= 20:      length_score = 38
        elif length >= 17:      length_score = 32
        elif length >= 15:      length_score = 26
        elif length >= 12:      length_score = 18
        elif length >= 10:      length_score = 12
        elif length >= 8:       length_score = 6
        else:                   length_score = 0

        # ── Entropy score (0–30) ──────────────────────────────────────────
        entropy_score = min(30, (effective_entropy / 80) * 30)

        # ── NIST-inspired guidance bonus (0–20) ───────────────────────────
        nist_bonus = 20 if nist_compliant else 0

        raw = length_score + entropy_score + nist_bonus

        # ── Critical pattern hard penalties ──────────────────────────────
        critical = {"repetitive_string", "sequential_string"}
        for p in patterns:
            if p.pattern_type in critical:
                raw *= 0.25   # severe downgrade

        return max(0, min(100, int(raw)))

    def _score_to_label(self, score: int, length: int = 0) -> str:
        """
        Map numeric score to a human-readable label.

        Project gate: "Very Strong" additionally requires length ≥ NIST_MIN_LENGTH
        (15 chars) — a very short password cannot be "Very Strong" regardless
        of complexity, following the length-first project philosophy.
        """
        if score < 20:  return "Very Weak"
        if score < 40:  return "Weak"
        if score < 60:  return "Fair"
        if score < 80:  return "Strong"
        return "Very Strong" if length >= NIST_MIN_LENGTH else "Strong"

    # ------------------------------------------------------------------
    # Feedback — non-prescriptive, inspired by modern NIST guidance
    # ------------------------------------------------------------------
    def _generate_suggestions(
        self,
        password: str,
        length: int,
        char_sets: Dict[str, bool],
        patterns: List[PatternMatch],
        nist_issues: List[str],
        score: int,
        is_passphrase: bool,
    ) -> List[str]:
        """
        Generate ordered, actionable, NIST-inspired suggestions.

        This project avoids prescriptive composition and rotation advice that
        modern NIST-inspired guidance discourages.

        We SHOULD encourage:
          • Longer passphrases.
          • Avoiding common/predictable phrases.
          • Using a password manager.
        """
        suggestions: List[str] = []
        pattern_types = {p.pattern_type for p in patterns}

        # ── 1. Length (highest priority) ──────────────────────────────────
        if length < NIST_ABS_MIN:
            suggestions.append(
                f"Your password is only {length} character(s). "
                f"Use at least {NIST_ABS_MIN} characters; {NIST_MIN_LENGTH} is used "
                "here for single-factor password guidance."
            )
        elif length < NIST_MIN_LENGTH:
            suggestions.append(
                f"Increase your password to at least {NIST_MIN_LENGTH} characters "
                f"(currently {length}). Longer passwords are dramatically harder to crack — "
                "each extra character multiplies the search space."
            )

        # ── 2. Passphrase encouragement ──────────────────────────────────
        if not is_passphrase and length < 20:
            suggestions.append(
                "Consider a passphrase: chain 4–6 random unrelated words separated by "
                "spaces or hyphens (e.g., 'purple-lemur-rocket-fern'). "
                "Spaces are fully allowed and make long passwords much easier to remember."
            )

        # ── 3. Blacklist / breach warnings ───────────────────────────────
        if "blacklisted" in pattern_types:
            suggestions.append(
                "Choose a password that is not commonly used or that has not appeared "
                "in known data breaches. Use a password manager to generate a truly "
                "random, unique password for each account."
            )

        if "context_specific" in pattern_types:
            suggestions.append(
                "Avoid passwords that include your username, application name, or "
                "organisation name — attackers target these patterns specifically."
            )

        # ── 4. Structural pattern warnings ───────────────────────────────
        if "keyboard_walk" in pattern_types:
            suggestions.append(
                "Avoid keyboard-walk sequences (e.g., qwerty, asdf, 1234). "
                "These are among the first patterns tried by cracking tools."
            )

        if "date_pattern" in pattern_types:
            suggestions.append(
                "Avoid embedding dates such as birth years or anniversaries — "
                "personal dates are easily guessed through social engineering."
            )

        if "repeated_chars" in pattern_types or "repetitive_string" in pattern_types:
            suggestions.append(
                "Avoid repeated character sequences (e.g., aaaa, 1111). "
                "Repetition provides almost no additional security."
            )

        if "sequential_string" in pattern_types or "sequential_digits" in pattern_types:
            suggestions.append(
                "Avoid sequential strings such as '12345678' or 'abcdefgh'. "
                "These are trivially enumerated by cracking tools."
            )

        if "common_suffix" in pattern_types:
            suggestions.append(
                "Appending numbers or symbols to a word (e.g., 'hello123') does not "
                "significantly improve security — cracking tools apply these "
                "transformations automatically."
            )

        # ── 5. General recommendation for very weak passwords ─────────────
        if score < 40:
            suggestions.append(
                "Use a password manager (e.g., Bitwarden, 1Password) to generate and "
                "store a truly random, high-entropy credential. You should never need "
                "to memorise a randomly-generated password."
            )

        return suggestions

    # ------------------------------------------------------------------
    # Detailed feedback report
    # ------------------------------------------------------------------
    def _generate_detailed_feedback(
        self,
        password: str,
        length: int,
        char_sets: Dict[str, bool],
        entropy: float,
        effective_entropy: float,
        patterns: List[PatternMatch],
        crack_times: Dict[str, str],
        score: int,
        strength_label: str,
        nist_issues: List[str],
        *,
        is_passphrase: bool = False,
    ) -> str:
        lines = [
            "=== Password Strength Analysis Report (NIST-Inspired) ===",
            f"Strength : {strength_label}  (Score: {score}/100)",
            f"Length   : {length} characters",
        ]
        if is_passphrase:
            lines.append(f"Entropy  : {entropy:.2f} bits  ✦ bundled wordlist passphrase model")
        else:
            lines.append(f"Entropy  : {entropy:.2f} bits  (charset model, display only)")
        lines.append(f"Effective: {effective_entropy:.2f} bits  (after pattern penalties)")
        lines.append("")

        lines.append("--- Character Sets Detected (display only — not scored) ---")
        for cs_name, present in char_sets.items():
            lines.append(f"  {'✓' if present else '✗'} {cs_name.replace('_', ' ').capitalize()}")
        lines.append("")
        lines.append(
            "  ℹ Character-class composition is not required or scored. "
            "Length and blocklist status are the primary signals."
        )
        lines.append("")

        if patterns:
            lines.append("--- Patterns Detected (Weaknesses) ---")
            for p in patterns:
                lines.append(
                    f"  [{p.pattern_type}] {p.description} "
                    f"(entropy penalty: −{p.penalty:.1f} bits)"
                )
            lines.append("")

        lines.append("--- Estimated Crack Times ---")
        lines.append(
            "  Crack-time estimates are educational approximations. They assume "
            "brute-force search over the estimated keyspace. Real attackers often "
            "use dictionaries, leaked passwords, masks and targeted guesses first."
        )
        labels = {
            "online_throttled":    "Online (throttled,  100/hr)",
            "online_unthrottled":  "Online (unthrottled, 10K/s)",
            "offline_slow_hash":   "Offline slow hash  (bcrypt, 10M/s)",
            "offline_fast_hash":   "Offline fast hash  (MD5/SHA1, 10B/s)",
            "offline_gpu_cluster": "High-end GPU cluster (100T/s)",
        }
        for key, label in labels.items():
            lines.append(f"  {label}: {crack_times[key]}")
        lines.append("")

        if nist_issues:
            lines.append("--- NIST-Inspired Guidance Check Issues ---")
            for issue in nist_issues:
                lines.append(f"  ⚠ {issue}")
            lines.append("")
        else:
            lines.append("--- NIST-Inspired Guidance Check: PASSED ✓ ---")
            lines.append("")

        lines.append("--- Production Requirements (out of scope here) ---")
        lines.append("  • Rate-limit authentication endpoints (NIST §5.2.2).")
        lines.append("  • Hash with Argon2id / bcrypt / scrypt / PBKDF2 — never store plaintext.")
        lines.append("  • Use a unique random salt (≥ 32 bytes) per password.")
        lines.append("  • Screen against the full HIBP SHA-1 breach dataset (900M+ hashes).")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Constant-time helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _ct_in_set(collection: frozenset, value: str) -> bool:
        """
        Timing-attack-resistant membership test.
        Iterates the entire collection to avoid early-exit timing leaks.
        """
        found = False
        for item in collection:
            try:
                if hmac.compare_digest(item, value):
                    found = True
            except TypeError:
                pass
        return found

    @staticmethod
    def _decode_leet(text: str) -> str:
        return "".join(LEET_MAP.get(ch, ch) for ch in text)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
def print_result(result: AnalysisResult) -> None:
    """Pretty-print an AnalysisResult to stdout with ANSI colour."""
    colors = {
        "Very Weak":   "\033[91m",
        "Weak":        "\033[93m",
        "Fair":        "\033[33m",
        "Strong":      "\033[92m",
        "Very Strong": "\033[96m",
    }
    reset = "\033[0m"
    color = colors.get(result.strength_label, "")

    print("\n" + "=" * 65)
    print("  PassAnalytiq Analyzer — NIST-Inspired")
    print("=" * 65)
    print(f"  Password : {'*' * min(result.length, 40)}")
    print(f"  Length   : {result.length} characters")
    print(f"  Strength : {color}{result.strength_label}{reset}")
    print(f"  Score    : {color}{result.score}/100{reset}")
    print(f"  Entropy  : {result.entropy_bits:.1f} bits  "
          f"(effective: {result.effective_entropy:.1f} bits)")
    print()

    filled = int(result.score / 5)
    bar    = "█" * filled + "░" * (20 - filled)
    print(f"  [{bar}] {result.score}%")
    print()

    print("  Character Sets (display only — not scored):")
    for cs, present in result.character_sets.items():
        icon = "✓" if present else "✗"
        clr  = "\033[92m" if present else "\033[91m"
        print(f"    {clr}{icon}{reset} {cs.capitalize()}")
    print()

    if result.patterns_found:
        print(f"  ⚠  Weaknesses Detected ({len(result.patterns_found)}):")
        for p in result.patterns_found:
            print(f"    • [{p.pattern_type}] {p.description}")
        print()

    print("  Estimated Crack Times:")
    print("    Crack-time estimates are educational approximations. They assume")
    print("    brute-force search over the estimated keyspace. Real attackers often")
    print("    use dictionaries, leaked passwords, masks and targeted guesses first.")
    scenario_labels = {
        "online_throttled":    "Online (throttled)   ",
        "online_unthrottled":  "Online (unthrottled) ",
        "offline_slow_hash":   "Offline slow hash    ",
        "offline_fast_hash":   "Offline fast hash    ",
        "offline_gpu_cluster": "High-end GPU cluster",
    }
    for key, label in scenario_labels.items():
        print(f"    {label}: {result.crack_times[key]}")
    print()

    nist_color  = "\033[92m" if result.nist_compliant else "\033[91m"
    nist_status = "PASSED" if result.nist_compliant else "NEEDS REVIEW"
    print(f"  NIST-inspired check: {nist_color}{nist_status}{reset}")
    if result.nist_issues:
        for issue in result.nist_issues:
            print(f"    ⚠ {issue}")
    print()

    if result.suggestions:
        print("  Recommendations:")
        for i, s in enumerate(result.suggestions, 1):
            print(f"    {i}. {s}")
    print("=" * 65)


def batch_analyze(passwords: List[str]) -> List[AnalysisResult]:
    """Analyze a list of passwords and return their results."""
    analyzer = PasswordStrengthAnalyzer()
    return [analyzer.analyze(p) for p in passwords]


def interactive_mode() -> None:
    """
    Interactive CLI mode with progressive delay (anti-brute-force demo).

    Note: Real rate-limiting belongs at the authentication layer, not here.
    This is a *simulation* only.
    """
    import getpass

    analyzer = PasswordStrengthAnalyzer()
    print("\n" + "=" * 65)
    print("  PassAnalytiq Analyzer — NIST-Inspired — Interactive")
    print("  Type 'quit' to exit")
    print("=" * 65)

    consecutive_weak = 0

    while True:
        try:
            password = getpass.getpass("\nEnter password to analyze (hidden): ")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if password.lower() == "quit":
            print("Goodbye!")
            break
        if not password:
            print("Please enter a password.")
            continue

        try:
            result = analyzer.analyze(password)
        except ValueError as exc:
            print(f"  ✗ Input error: {exc}")
            continue

        print_result(result)

        if result.score < 40:
            consecutive_weak += 1
            if consecutive_weak >= 2:
                delay = min(2 ** (consecutive_weak - 2), 8)
                print(
                    f"  ⚠  Rate-limit [demo]: {delay}s cooldown after "
                    f"{consecutive_weak} consecutive weak attempts."
                )
                time.sleep(delay)
        else:
            consecutive_weak = 0


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        analyzer = PasswordStrengthAnalyzer()
        result   = analyzer.analyze(sys.argv[1])
        print_result(result)
    else:
        interactive_mode()
