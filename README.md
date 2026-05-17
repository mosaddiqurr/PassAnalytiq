# PassAnalytiq

PassAnalytiq is a browser-based password risk analyzer and password generator. It provides real-time feedback, estimates password risk, checks breach exposure through Have I Been Pwned k-anonymity, and includes multiple generation modes including a deterministic Memory Seed mode.

The project is designed as a clean, static web application with no build step required.

## Features

- Real-time password analysis in the browser
- NIST-inspired guidance focused on length, blocklist checks, predictable patterns and usability
- Detection for common passwords, keyboard walks, repeated characters, date-like patterns, sequential strings, leet substitutions and predictable suffixes
- Educational crack-time estimate for password risk interpretation
- Breach exposure check using the Have I Been Pwned k-anonymity model
- Strong random password generation using cryptographically secure randomness
- Personalized password generation using memorable words plus random hardening
- Memory Seed mode for deterministic password recreation from the same memory word and website/app name
- JavaScript and Python test coverage for analyzer and generator behavior

## Pages

| Page | File | Purpose |
|---|---|---|
| Analyzer | `index.html` | Analyze password strength, risk factors, crack-time estimate and breach exposure |
| Generator | `generator.html` | Generate strong random, personalized and deterministic Memory Seed passwords |

## Memory Seed Mode

Memory Seed mode generates the same password again when the same inputs are used.

Example:

```text
Memory word: Apple
Website / App name: Gmail
Length: 24
```

Using the same memory word, website/app name, length and character settings will recreate the same password. Changing the website/app name creates a different password, which helps avoid reusing one generated password across multiple accounts.

Memory Seed is useful as an educational deterministic generation pattern, but it is not a replacement for a full password manager. Weak or common memory words are risky, so PassAnalytiq warns against seed words such as `password`, `admin`, `love`, `apple` and `qwerty`.

## Security Model

- Password analysis runs locally in the browser.
- Generated passwords are created locally.
- Strong random and personalized generator modes use `crypto.getRandomValues()` in the browser.
- Memory Seed mode is deterministic and uses SHA-256-derived bytes so the same inputs recreate the same output.
- Memory Seed mode does not use random values for its final deterministic output.
- Seed words, website/app names, generated passwords and raw analyzer inputs are not stored or logged.
- The breach check never sends the raw password.
- The breach check sends only the first 5 characters of the SHA-1 hash prefix to the Have I Been Pwned API, and suffix comparison happens locally.
- Character categories may be shown as feedback, but composition rules are not required for scoring.

## Limitations

- Crack-time estimates are educational approximations, not guarantees.
- Real attackers may use leaked password lists, dictionaries, masks, targeted guesses and service-specific context.
- The local common-password blocklist is intentionally small for a portfolio-scale project.
- Breach checking depends on network access and the availability of the Have I Been Pwned API.
- Personalized passwords still depend on safe word choices.
- Memory Seed passwords depend heavily on the secrecy and uniqueness of the memory word and website/app name.
- This project is NIST-inspired. It is not a formal claim of NIST compliance.

## Tech Stack

- HTML
- CSS
- Vanilla JavaScript
- Web Crypto API
- Node.js tests for JavaScript logic
- Python regression and cross-language consistency checks

## Project Structure

```text
PassAnalytiq/
├── index.html
├── generator.html
├── analyzer.css
├── generator.css
├── analyzer-core.js
├── analyzer-ui.js
├── generator.js
├── analyzer-core.test.js
├── generator.test.js
├── password_analyzer.py
├── test_analyzer.py
├── consistency_check.py
├── package.json
├── README.md
├── LICENSE
└── _headers
```

## How To Run

No build step is required.

### Option 1: Open directly

Open the analyzer page:

```text
index.html
```

Open the generator page:

```text
generator.html
```

### Option 2: Run with a local server

From the project folder, run:

```bash
python -m http.server 8000
```

Then open:

```text
http://localhost:8000
```

Analyzer:

```text
http://localhost:8000/index.html
```

Generator:

```text
http://localhost:8000/generator.html
```

The project can be hosted as static files on GitHub Pages, Netlify or Vercel.

## How To Test

Run the full test suite:

```bash
npm test
```

Run individual test groups:

```bash
npm run test:generator
npm run test:analyzer
npm run test:python
npm run test:consistency
```

Equivalent direct commands:

```bash
node generator.test.js
node analyzer-core.test.js
python test_analyzer.py
python consistency_check.py
```

```

## Future Improvements

- Add screenshots and a hosted demo link
- Add a larger offline blocklist or Bloom filter demo
- Add GitHub Actions for automated tests
- Add more accessibility checks
- Add optional exportable password-risk reports

