# PassAnalytiq

PassAnalytiq is a browser-based password risk analyzer and password generator. It gives practical strength feedback, checks breach exposure on request and includes multiple generation modes, including a deterministic **Memory Seed** mode for recreating passwords from the same inputs.

The project is built as a lightweight cybersecurity portfolio project using HTML, CSS, vanilla JavaScript and Python tests.

## Features

- Real-time password strength analysis in the browser
- NIST-inspired guidance focused on length, blocklist screening and usability
- Pattern detection for common passwords, keyboard walks, repeated characters, dates, sequential strings, leet substitutions and predictable suffixes
- Educational crack-time estimates
- Have I Been Pwned breach lookup using k-anonymity on explicit request
- Cryptographically secure random password generation
- Personalized password generation using transformed memorable words
- Memory Seed mode for deterministic password recreation from a memory word and optional website/app name
- JavaScript tests, Python regression tests and cross-language consistency checks
- GitHub Actions workflow for automated testing

## Memory Seed Mode

Memory Seed generates the same password again when the same memory word, website/app name, length and character settings are used.

Example:

```text
Memory word: Apple
Website / App name: Gmail
```

Using the same inputs recreates the same password. Changing the website/app name creates a different password, which helps reduce password reuse across accounts.

Common memory words are risky because attackers can guess them. PassAnalytiq warns on weak seeds such as `password`, `admin`, `love`, `apple` and `qwerty`.

Memory Seed is deterministic. It is included as an educational deterministic generation pattern and is not a replacement for a full password manager.

## Security Model

- Password analysis runs locally in the browser.
- Generated passwords are created locally.
- Strong Random Password and Personalized Password modes use `crypto.getRandomValues()` in the browser.
- Memory Seed mode uses deterministic SHA-256-derived bytes so the same inputs recreate the same output.
- Memory Seed mode does not use random values for the final deterministic output.
- Seed words, website/app names, generated passwords and raw analyzer inputs are not stored or logged.
- Breach checking never sends the raw password.
- Breach checking sends only the first 5 characters of the SHA-1 hash prefix to the HIBP API; suffix comparison stays local.
- Character categories may be shown for feedback, but composition rules are not required for scoring.

## Limitations

- Crack-time estimates are educational approximations, not guarantees.
- Real attackers may use leaked password lists, dictionaries, masks, targeted guesses and service-specific context.
- The local common-password blocklist is intentionally small for a portfolio-scale project.
- HIBP availability depends on the third-party API and network access.
- Personalized passwords still depend on safe word choices.
- Memory Seed passwords depend heavily on the secrecy and uniqueness of the memory word and website/app name.
- This project is NIST-inspired; it is not a claim of formal NIST compliance.
- This tool is educational and should not be treated as a complete replacement for a password manager.

## Tech Stack

- HTML
- CSS
- Vanilla JavaScript
- Web Crypto API
- Node.js tests
- Python regression and consistency tests
- GitHub Actions

## Project Structure

```text
PassAnalytiq/
├── .github/workflows/test.yml
├── _headers
├── analyzer-core.js
├── analyzer-core.test.js
├── analyzer-ui.js
├── analyzer.css
├── consistency_check.py
├── favicon.svg
├── generator.css
├── generator.html
├── generator.js
├── generator.test.js
├── index.html
├── LICENSE
├── package.json
├── password_analyzer.py
├── README.md
└── test_analyzer.py
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

The project can also be hosted as static files on GitHub Pages, Netlify or Vercel.

## How To Test

Run the full test suite:

```bash
npm test
```

Run individual checks:

```bash
npm run test:generator
npm run test:analyzer
npm run test:python
npm run test:consistency
```

Underlying commands:

```bash
node generator.test.js
node analyzer-core.test.js
python test_analyzer.py
python consistency_check.py
```

## Deployment Notes

This is a static web project. It can be deployed without a backend.

If deploying to Netlify, the `_headers` file can be used for security headers.

## Future Improvements

- Add screenshots and a hosted demo link
- Add a larger offline blocklist or Bloom filter demo
- Expand GitHub Actions with browser-based UI checks
- Add more accessibility checks
- Add optional exportable password-risk reports
- Add more realistic password policy comparison examples

## License

This project is licensed under the MIT License.
