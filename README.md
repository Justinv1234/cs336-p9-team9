# cs336-p9-team9
## Privacy Leakage via "Taint Lite" — CS 336 Project 9

> **Documentation website:** open `docs/index.html` in a browser for the full interactive guide.

---

## Team Members

| Name | Student ID | Email | Role |
|---|---|---|---|
| Justin Veltri | s1357059 | s1357059@monmouth.edu | Project Lead & Taint Engine |
| Flavia Daniels | s1365459 | s1365459@monmouth.edu | Parser & AST Design |
| Arnav Vasa | s1364337 | s1364337@monmouth.edu | Documentation |
| Garrett Boag | s1353729 | s1353729@monmouth.edu | Lexer & Test Suite |
| Jonathan Veltri | s1357058 | s1357058@monmouth.edu | Integration, Reporter & Examples |

---

## Project Overview

A taint analysis tool that tracks PII (names, emails, SSNs, etc.) through variable assignments and reports when tainted data reaches a dangerous sink such as `log`, `send_analytics`, or `send_to_api`.

Now supports:
- **IMP-Core** (`.imp`) — the original toy language
- **Python** (`.py`) — real-world Python source files via the built-in `ast` module
- **External policy files** — define your own sources and sinks in JSON without editing source code

---

## Prerequisites

- Python 3.9 or later (tested on 3.11)
- No external runtime dependencies — uses only the Python standard library

To run the tests you also need `pytest`:

```bash
pip3 install pytest
```

---

## Repository Structure

```
cs336-p9-team9/
├── src/
│   ├── ast_nodes.py        # AST dataclasses (IMP)
│   ├── lexer.py            # Tokenizer (IMP)
│   ├── parser.py           # Recursive-descent parser (IMP)
│   ├── taint.py            # Taint propagation engine (IMP)
│   ├── python_analyzer.py  # Taint frontend for Python source files
│   ├── policy.py           # External policy loader
│   ├── reporter.py         # Output formatter
│   └── main.py             # CLI entry point
├── tests/
│   ├── test_lexer.py
│   ├── test_parser.py
│   ├── test_taint.py
│   ├── test_policy.py
│   └── test_python_analyzer.py
├── examples/
│   ├── basic.imp               # Spec example (email + name → log + analytics)
│   ├── multi_sink.imp          # SSN/phone/address across three sinks
│   ├── no_leak.imp             # Clean program — no leaks expected
│   ├── chained.imp             # PII propagated through a 3-variable chain
│   ├── webapp_leak.py          # Python example — 3 leaks
│   ├── webapp_clean.py         # Python example — no leaks
│   ├── custom_policy_demo.py   # Demonstrates custom policy sources/sinks
│   └── custom_policy.json      # Example JSON policy file
├── docs/
│   └── index.html          # User-friendly documentation website
└── README.md
```

---

## How to Run the Tool

```bash
python3 src/main.py <program.imp|program.py> [--policy policy.json]
```

The tool exits with code `0` if no leaks are found, or `1` if any leaks are detected.

---

## How to Run Tests

```bash
pip3 install pytest          # one-time install
python3 -m pytest tests/ -v
```

Expected output:

```
collected 50 items

tests/test_lexer.py::...              6 passed
tests/test_parser.py::...             7 passed
tests/test_policy.py::...             8 passed
tests/test_python_analyzer.py::...   19 passed
tests/test_taint.py::...             10 passed

50 passed in 0.08s
```

---

## Example Commands with Expected Output

### Example 1 — Spec example (`examples/basic.imp`)

```bash
python3 src/main.py examples/basic.imp
```

```
PII LEAK at line 4
  Sink: log
  PII types exposed: {email, name}
  Recommendation: Redact PII before logging

PII LEAK at line 5
  Sink: send_analytics
  PII types exposed: {name}
  Recommendation: Anonymize before sending to analytics
```

### Example 2 — Python webapp with leaks

```bash
python3 src/main.py examples/webapp_leak.py
```

```
PII LEAK at line 22
  Sink: info
  PII types exposed: {email}
  Recommendation: Redact PII before logging

PII LEAK at line 25
  Sink: send_analytics
  PII types exposed: {name}
  Recommendation: Anonymize before sending to analytics

PII LEAK at line 29
  Sink: send_to_api
  PII types exposed: {ssn}
  Recommendation: Remove PII before sending to external sink
```

### Example 3 — No leak

```bash
python3 src/main.py examples/no_leak.imp
# → No PII leaks detected.

python3 src/main.py examples/webapp_clean.py
# → No PII leaks detected.
```

### Example 4 — Custom policy

```bash
# Without policy: kafka_publish and s3_upload are unknown → no leaks
python3 src/main.py examples/custom_policy_demo.py

# With policy: 2 leaks detected
python3 src/main.py examples/custom_policy_demo.py --policy examples/custom_policy.json
```

---

## External Policy Files

Define your own sources and sinks in a JSON file and pass it with `--policy`.  
The file **merges** with built-in defaults — only list what you want to add or override.

```json
{
  "sources": {
    "fetch_credit_card":   "credit_card",
    "get_passport_number": "passport",
    "load_biometric":      ["biometric", "sensitive"]
  },
  "sinks": {
    "kafka_publish": "Remove PII before publishing to Kafka",
    "s3_upload":     "Encrypt PII before uploading to S3"
  },
  "sink_patterns": ["log", "analytics", "api", "publish", "upload"]
}
```

---

## PII Sources Recognized (built-in)

| Function | PII Tag |
|---|---|
| `get_email()` | `email` |
| `get_name()` | `name` |
| `get_ssn()` | `ssn` |
| `get_phone()` | `phone` |
| `get_address()` | `address` |
| `get_dob()` | `date_of_birth` |
| `get_user_id()` | `user_id` |

## Sinks Recognized (built-in)

| Function | Recommendation |
|---|---|
| `log` | Redact PII before logging |
| `send_analytics` | Anonymize before sending to analytics |
| `send_to_api` | Remove PII before sending to external sink |
| `print_log` | Redact PII before logging |
| `write_log` | Redact PII before logging |
| `post_to_server` | Remove PII before sending to external sink |

Any function whose name contains `log`, `analytics`, `api`, `server`, `report`, `track`, or `monitor` is also treated as a sink.
