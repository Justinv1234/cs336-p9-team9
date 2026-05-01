"""Tests for the Python-language taint analysis frontend."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from python_analyzer import analyze_python
from policy import Policy


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def leaks_from(source: str, policy=None):
    return analyze_python(source, policy or Policy.default())


# ---------------------------------------------------------------------------
# Basic source detection
# ---------------------------------------------------------------------------

def test_direct_assignment_to_sink():
    src = """\
email = get_email(1)
log(email)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "email" in leaks[0].pii_types
    assert leaks[0].sink == "log"


def test_attribute_call_sink():
    src = """\
email = get_email(1)
logging.info(email)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "email" in leaks[0].pii_types
    assert leaks[0].sink == "logging.info"


def test_name_variable_propagation():
    src = """\
name = get_name(1)
x = name
send_analytics(x)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "name" in leaks[0].pii_types


def test_no_pii_no_leak():
    src = """\
msg = "hello world"
log(msg)
"""
    leaks = leaks_from(src)
    assert leaks == []


def test_pii_not_reaching_sink_no_leak():
    src = """\
email = get_email(1)
x = "safe value"
log(x)
"""
    leaks = leaks_from(src)
    assert leaks == []


# ---------------------------------------------------------------------------
# Propagation patterns
# ---------------------------------------------------------------------------

def test_string_concatenation_propagates_taint():
    src = """\
email = get_email(1)
msg = "User: " + email
log(msg)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "email" in leaks[0].pii_types


def test_fstring_propagates_taint():
    src = """\
name = get_name(1)
msg = f"Hello {name}"
log(msg)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "name" in leaks[0].pii_types


def test_union_of_multiple_pii_types():
    src = """\
email = get_email(1)
name = get_name(1)
data = email + " " + name
log(data)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "email" in leaks[0].pii_types
    assert "name" in leaks[0].pii_types


def test_dict_value_propagates_taint():
    src = """\
ssn = get_ssn(1)
payload = {"ssn": ssn, "action": "verify"}
send_to_api(payload)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "ssn" in leaks[0].pii_types


def test_chained_assignment_propagates():
    src = """\
email = get_email(1)
a = email
b = a
c = b
log(c)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "email" in leaks[0].pii_types


def test_augmented_assignment_propagates():
    src = """\
name = get_name(1)
msg = "Dear "
msg += name
log(msg)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "name" in leaks[0].pii_types


# ---------------------------------------------------------------------------
# Multiple sinks
# ---------------------------------------------------------------------------

def test_multiple_leaks_reported():
    src = """\
email = get_email(1)
name = get_name(1)
log(email)
send_analytics(name)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 2
    sinks = {lk.sink for lk in leaks}
    assert "log" in sinks
    assert "send_analytics" in sinks


# ---------------------------------------------------------------------------
# Control flow
# ---------------------------------------------------------------------------

def test_taint_inside_if_branch():
    src = """\
email = get_email(1)
if True:
    log(email)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1


def test_taint_inside_function_body():
    src = """\
def handle():
    name = get_name(1)
    send_analytics(name)
"""
    leaks = leaks_from(src)
    assert len(leaks) == 1
    assert "name" in leaks[0].pii_types


# ---------------------------------------------------------------------------
# Custom policy
# ---------------------------------------------------------------------------

def test_custom_source_detected():
    import json, tempfile, os
    policy_data = {"sources": {"fetch_passport": "passport"}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(policy_data, f)
        fname = f.name
    try:
        policy = Policy.load(fname)
        src = """\
p = fetch_passport(1)
log(p)
"""
        leaks = analyze_python(src, policy)
        assert len(leaks) == 1
        assert "passport" in leaks[0].pii_types
    finally:
        os.unlink(fname)


def test_custom_sink_detected():
    import json, tempfile, os
    policy_data = {"sinks": {"kafka_publish": "Remove PII before Kafka"}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(policy_data, f)
        fname = f.name
    try:
        policy = Policy.load(fname)
        src = """\
email = get_email(1)
kafka_publish(email)
"""
        leaks = analyze_python(src, policy)
        assert len(leaks) == 1
        assert leaks[0].sink == "kafka_publish"
        assert "Kafka" in leaks[0].recommendation
    finally:
        os.unlink(fname)


def test_unknown_sink_without_policy():
    src = """\
email = get_email(1)
kafka_publish(email)
"""
    leaks = leaks_from(src)
    assert leaks == []


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

def test_recommendation_for_log_sink():
    src = """\
email = get_email(1)
log(email)
"""
    leaks = leaks_from(src)
    assert "Redact" in leaks[0].recommendation


def test_recommendation_for_analytics_sink():
    src = """\
name = get_name(1)
send_analytics(name)
"""
    leaks = leaks_from(src)
    assert "Anonymize" in leaks[0].recommendation
