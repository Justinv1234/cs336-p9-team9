import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

import pytest
from parser import parse
from taint import analyze


def leaks_for(source):
    return analyze(parse(source))


def test_spec_example():
    src = (
        "email := get_email()\n"
        "name := get_name()\n"
        'user_info := email + " - " + name\n'
        "log(user_info)\n"
        "send_analytics(name)\n"
    )
    leaks = leaks_for(src)
    assert len(leaks) == 2

    log_leak = leaks[0]
    assert log_leak.line == 4
    assert log_leak.sink == "log"
    assert "email" in log_leak.pii_types
    assert "name" in log_leak.pii_types

    analytics_leak = leaks[1]
    assert analytics_leak.line == 5
    assert analytics_leak.sink == "send_analytics"
    assert analytics_leak.pii_types == frozenset({"name"})


def test_no_pii_no_leak():
    src = 'log("hello")\n'
    assert leaks_for(src) == []


def test_pii_not_at_sink_no_leak():
    src = "name := get_name()\nlog(\"safe string\")\n"
    assert leaks_for(src) == []


def test_chained_propagation():
    src = "a := get_ssn()\nb := a\nc := b\nlog(c)\n"
    leaks = leaks_for(src)
    assert len(leaks) == 1
    assert "ssn" in leaks[0].pii_types


def test_union_propagation():
    src = "e := get_email()\nn := get_name()\ncombined := e + n\nlog(combined)\n"
    leaks = leaks_for(src)
    assert len(leaks) == 1
    assert leaks[0].pii_types == frozenset({"email", "name"})


def test_multiple_sinks():
    src = (
        "ssn := get_ssn()\n"
        "phone := get_phone()\n"
        "log(ssn)\n"
        "send_analytics(phone)\n"
    )
    leaks = leaks_for(src)
    assert len(leaks) == 2
    assert leaks[0].sink == "log"
    assert "ssn" in leaks[0].pii_types
    assert leaks[1].sink == "send_analytics"
    assert "phone" in leaks[1].pii_types


def test_send_to_api_is_sink():
    src = "addr := get_address()\nsend_to_api(addr)\n"
    leaks = leaks_for(src)
    assert len(leaks) == 1
    assert "address" in leaks[0].pii_types


def test_clean_log_after_pii_assigned():
    src = "name := get_name()\ngreeting := \"Hello!\"\nlog(greeting)\n"
    assert leaks_for(src) == []


def test_recommendation_log():
    src = "e := get_email()\nlog(e)\n"
    leaks = leaks_for(src)
    assert "Redact" in leaks[0].recommendation


def test_recommendation_analytics():
    src = "n := get_name()\nsend_analytics(n)\n"
    leaks = leaks_for(src)
    assert "Anonymize" in leaks[0].recommendation
