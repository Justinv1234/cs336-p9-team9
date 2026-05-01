from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List
import json

_DEFAULT_SOURCES: Dict[str, FrozenSet[str]] = {
    "get_email":   frozenset({"email"}),
    "get_name":    frozenset({"name"}),
    "get_ssn":     frozenset({"ssn"}),
    "get_phone":   frozenset({"phone"}),
    "get_address": frozenset({"address"}),
    "get_dob":     frozenset({"date_of_birth"}),
    "get_user_id": frozenset({"user_id"}),
}

_DEFAULT_SINKS: Dict[str, str] = {
    "log":            "Redact PII before logging",
    "send_analytics": "Anonymize before sending to analytics",
    "send_to_api":    "Remove PII before sending to external sink",
    "print_log":      "Redact PII before logging",
    "write_log":      "Redact PII before logging",
    "post_to_server": "Remove PII before sending to external sink",
}

_DEFAULT_SINK_PATTERNS: List[str] = [
    "log", "analytics", "api", "server", "report", "track", "monitor",
]


@dataclass
class Policy:
    """Configures which functions are PII sources and which are dangerous sinks.

    Load from a JSON file via Policy.load(path) or get built-in defaults via
    Policy.default().  JSON files are *merged* with defaults, so you only need
    to list the fields you want to add or override.

    JSON schema
    -----------
    {
      "sources": {
        "<function_name>": "<pii_tag>"          // single tag
        "<function_name>": ["<tag1>", "<tag2>"] // multiple tags
      },
      "sinks": {
        "<function_name>": "<recommendation_message>"
      },
      "sink_patterns": ["<substring>", ...]  // replaces default list when present
    }
    """

    sources: Dict[str, FrozenSet[str]] = field(default_factory=dict)
    sinks: Dict[str, str] = field(default_factory=dict)
    sink_patterns: List[str] = field(default_factory=list)

    @classmethod
    def default(cls) -> Policy:
        return cls(
            sources=dict(_DEFAULT_SOURCES),
            sinks=dict(_DEFAULT_SINKS),
            sink_patterns=list(_DEFAULT_SINK_PATTERNS),
        )

    @classmethod
    def load(cls, path: str) -> Policy:
        """Load a JSON policy file and merge its entries with the built-in defaults."""
        with open(path) as f:
            data = json.load(f)

        policy = cls.default()

        for func, tags in data.get("sources", {}).items():
            if isinstance(tags, str):
                tags = [tags]
            policy.sources[func] = frozenset(tags)

        for func, rec in data.get("sinks", {}).items():
            policy.sinks[func] = rec

        if "sink_patterns" in data:
            policy.sink_patterns = list(data["sink_patterns"])

        return policy
