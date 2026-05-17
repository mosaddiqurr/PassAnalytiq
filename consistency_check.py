"""
Cross-language consistency check for PassAnalytiq analyzers.

Run:
    python consistency_check.py

The Python analyzer is treated as the reference model. JavaScript labels should
match Python labels for these important regression cases, and guidance/check
booleans should agree.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from password_analyzer import PasswordStrengthAnalyzer


PASSWORDS = [
    "password",
    "password123",
    "p@ssw0rd",
    "qwerty123",
    "Tr0ub4dor&3",
    "Correct-Horse-Battery-Staple",
    "correcthorsebatterystaplerandom",
]

CATEGORY_ORDER = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


def python_results() -> dict[str, dict[str, object]]:
    analyzer = PasswordStrengthAnalyzer()
    results: dict[str, dict[str, object]] = {}
    for password in PASSWORDS:
        result = analyzer.analyze(password)
        results[password] = {
            "label": result.strength_label,
            "score": result.score,
            "compliant": result.nist_compliant,
        }
    return results


def javascript_results(project_dir: Path) -> dict[str, dict[str, object]]:
    js = r"""
const { analyzePassword } = require('./analyzer-core.js');
const passwords = JSON.parse(process.argv[1]);
const results = {};
for (const password of passwords) {
  const result = analyzePassword(password);
  results[password] = {
    label: result.label,
    score: result.score,
    compliant: result.compliant,
  };
}
process.stdout.write(JSON.stringify(results));
"""
    completed = subprocess.run(
        ["node", "-e", js, json.dumps(PASSWORDS)],
        cwd=project_dir,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Node.js consistency check failed:\n"
            f"{completed.stderr or completed.stdout}"
        )
    return json.loads(completed.stdout)


def label_distance(left: str, right: str) -> int:
    return abs(CATEGORY_ORDER.index(left) - CATEGORY_ORDER.index(right))


def status_for(py: dict[str, object], js: dict[str, object]) -> str:
    label_match = py["label"] == js["label"]
    compliance_match = py["compliant"] == js["compliant"]
    if label_match and compliance_match:
        return "OK"
    if label_distance(str(py["label"]), str(js["label"])) > 1:
        return "FAIL: major label mismatch"
    if not compliance_match:
        return "FAIL: guidance check mismatch"
    return "WARN: label differs by one tier"


def main() -> int:
    project_dir = Path(__file__).resolve().parent
    py_results = python_results()
    js_results = javascript_results(project_dir)

    rows = []
    failures = []
    for password in PASSWORDS:
        py = py_results[password]
        js = js_results[password]
        status = status_for(py, js)
        if status.startswith("FAIL"):
            failures.append(password)
        rows.append((password, py["label"], js["label"], status))

    print("password | Python label | JS label | status")
    print("-" * 72)
    for password, py_label, js_label, status in rows:
        print(f"{password:<36} | {py_label:<12} | {js_label:<12} | {status}")

    if failures:
        print("\nPython is the reference model. Review JS mismatches above.")
        return 1

    print("\nConsistency check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
