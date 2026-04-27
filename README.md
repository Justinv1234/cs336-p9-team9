# cs336-p9-team9
## Privacy Leakage via "Taint Lite" — CS 336 Project 9

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

A simplified taint analysis tool for a small IMP-Core dialect.  
The tool tracks PII (names, emails, SSNs, etc.) through variable assignments and reports when tainted data reaches a dangerous sink such as `log`, `send_analytics`, or `send_to_api`.

- **Project Number:** 9  
- **Difficulty:** Easy  
- **Language Variant:** A (IMP-Core)  
- **Privacy Focus:** Unintentional PII exposure  

---

## Prerequisites

- Python 3.9 or later (tested on 3.11)
- No external runtime dependencies — the analyzer uses only the Python standard library

To run the tests you also need `pytest`:

```bash
pip3 install pytest
```

---

## Repository Structure

```
cs336-p9-team9/
├── src/
│   ├── ast_nodes.py   # AST dataclasses
│   ├── lexer.py       # Tokenizer
│   ├── parser.py      # Recursive-descent parser
│   ├── taint.py       # Taint propagation engine
│   ├── reporter.py    # Output formatter
│   └── main.py        # CLI entry point
├── tests/
│   ├── test_lexer.py
│   ├── test_parser.py
│   └── test_taint.py
├── examples/
│   ├── basic.imp      # Spec example (email + name → log + analytics)
│   ├── multi_sink.imp # SSN/phone/address across three sinks
│   ├── no_leak.imp    # Clean program — no leaks expected
│   └── chained.imp    # PII propagated through a 3-variable chain
└── README.md
```

---

## Build Instructions

No compilation step required — pure Python.

```bash
git clone https://github.com/INSERT-YOUR-ORG/cs336-p9-team9.git
cd cs336-p9-team9
```

That's it. No build step needed.

---

## How to Run the Tool

```bash
python3 src/main.py <program.imp>
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
collected 23 items

tests/test_lexer.py::test_simple_assignment_tokens PASSED
tests/test_lexer.py::test_string_literal PASSED
tests/test_lexer.py::test_comment_skipped PASSED
tests/test_lexer.py::test_line_numbers PASSED
tests/test_lexer.py::test_plus_and_comma PASSED
tests/test_lexer.py::test_unexpected_char_raises PASSED
tests/test_parser.py::test_parse_assignment PASSED
tests/test_parser.py::test_parse_sink_call PASSED
tests/test_parser.py::test_parse_binary_op PASSED
tests/test_parser.py::test_parse_multiple_statements PASSED
tests/test_parser.py::test_parse_comment_ignored PASSED
tests/test_parser.py::test_parse_call_with_args PASSED
tests/test_parser.py::test_parse_line_numbers PASSED
tests/test_taint.py::test_spec_example PASSED
tests/test_taint.py::test_no_pii_no_leak PASSED
tests/test_taint.py::test_pii_not_at_sink_no_leak PASSED
tests/test_taint.py::test_chained_propagation PASSED
tests/test_taint.py::test_union_propagation PASSED
tests/test_taint.py::test_multiple_sinks PASSED
tests/test_taint.py::test_send_to_api_is_sink PASSED
tests/test_taint.py::test_clean_log_after_pii_assigned PASSED
tests/test_taint.py::test_recommendation_log PASSED
tests/test_taint.py::test_recommendation_analytics PASSED

23 passed in 0.03s
```

---

## Example Commands with Expected Output

### Example 1 — Spec example (`examples/basic.imp`)

**Program:**
```
email := get_email()
name := get_name()
user_info := email + " - " + name
log(user_info)          # Privacy leak!
send_analytics(name)    # Another leak!
```

**Command:**
```bash
python3 src/main.py examples/basic.imp
```

**Output:**
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

---

### Example 2 — Multiple sinks (`examples/multi_sink.imp`)

**Command:**
```bash
python3 src/main.py examples/multi_sink.imp
```

**Output:**
```
PII LEAK at line 13
  Sink: log
  PII types exposed: {name, ssn}
  Recommendation: Redact PII before logging

PII LEAK at line 14
  Sink: send_analytics
  PII types exposed: {phone}
  Recommendation: Anonymize before sending to analytics

PII LEAK at line 15
  Sink: send_to_api
  PII types exposed: {address}
  Recommendation: Remove PII before sending to external sink
```

---

### Example 3 — No leak (`examples/no_leak.imp`)

**Command:**
```bash
python3 src/main.py examples/no_leak.imp
```

**Output:**
```
No PII leaks detected.
```

---

### Example 4 — Chained propagation (`examples/chained.imp`)

**Program:**
```
email := get_email()
a := email
b := a
c := b + " extra"
log(c)
```

**Command:**
```bash
python3 src/main.py examples/chained.imp
```

**Output:**
```
PII LEAK at line 6
  Sink: log
  PII types exposed: {email}
  Recommendation: Redact PII before logging
```

---

## PII Sources Recognized

| Function | PII Tag |
|---|---|
| `get_email()` | `email` |
| `get_name()` | `name` |
| `get_ssn()` | `ssn` |
| `get_phone()` | `phone` |
| `get_address()` | `address` |
| `get_dob()` | `date_of_birth` |
| `get_user_id()` | `user_id` |

## Sinks Recognized

| Function | Recommendation |
|---|---|
| `log` | Redact PII before logging |
| `send_analytics` | Anonymize before sending to analytics |
| `send_to_api` | Remove PII before sending to external sink |
| `print_log` | Redact PII before logging |
| `write_log` | Redact PII before logging |
| `post_to_server` | Remove PII before sending to external sink |

Any function whose name contains `log`, `analytics`, `api`, `server`, `report`, `track`, or `monitor` is also treated as a sink.
