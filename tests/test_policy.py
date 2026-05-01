"""Tests for the external policy loading system."""
import json
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from policy import Policy


def test_default_policy_has_builtin_sources():
    p = Policy.default()
    assert "get_email" in p.sources
    assert "get_name" in p.sources
    assert "get_ssn" in p.sources
    assert "email" in p.sources["get_email"]


def test_default_policy_has_builtin_sinks():
    p = Policy.default()
    assert "log" in p.sinks
    assert "send_analytics" in p.sinks


def test_default_policy_has_sink_patterns():
    p = Policy.default()
    assert "log" in p.sink_patterns
    assert "analytics" in p.sink_patterns


def test_load_adds_custom_source_single_tag(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({
        "sources": {"fetch_credit_card": "credit_card"}
    }))
    p = Policy.load(str(policy_file))
    assert "fetch_credit_card" in p.sources
    assert "credit_card" in p.sources["fetch_credit_card"]
    # built-ins still present
    assert "get_email" in p.sources


def test_load_adds_custom_source_multi_tag(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({
        "sources": {"load_biometric": ["biometric", "sensitive"]}
    }))
    p = Policy.load(str(policy_file))
    assert "biometric" in p.sources["load_biometric"]
    assert "sensitive" in p.sources["load_biometric"]


def test_load_adds_custom_sink(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({
        "sinks": {"kafka_publish": "Remove PII before publishing to Kafka"}
    }))
    p = Policy.load(str(policy_file))
    assert "kafka_publish" in p.sinks
    assert "Kafka" in p.sinks["kafka_publish"]
    # built-ins still present
    assert "log" in p.sinks


def test_load_replaces_sink_patterns(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({
        "sink_patterns": ["kafka", "s3", "slack"]
    }))
    p = Policy.load(str(policy_file))
    assert "kafka" in p.sink_patterns
    assert "s3" in p.sink_patterns
    # old patterns replaced
    assert "analytics" not in p.sink_patterns


def test_load_merges_all_fields(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({
        "sources": {"get_passport": "passport"},
        "sinks": {"s3_upload": "Encrypt before S3"},
        "sink_patterns": ["log", "s3", "kafka"]
    }))
    p = Policy.load(str(policy_file))
    assert "get_passport" in p.sources
    assert "s3_upload" in p.sinks
    assert "s3" in p.sink_patterns
    assert "get_email" in p.sources   # default source preserved
    assert "log" in p.sinks           # default sink preserved


def test_load_file_not_found():
    with pytest.raises(FileNotFoundError):
        Policy.load("/nonexistent/path/policy.json")
