from dataclasses import dataclass
from typing import Dict, FrozenSet, List
from ast_nodes import (
    Program, Assignment, SinkCall,
    Variable, StringLiteral, Call, BinaryOp, Expr,
)

# Map from source function name → PII tag(s) it introduces
PII_SOURCES: Dict[str, FrozenSet[str]] = {
    "get_email":   frozenset({"email"}),
    "get_name":    frozenset({"name"}),
    "get_ssn":     frozenset({"ssn"}),
    "get_phone":   frozenset({"phone"}),
    "get_address": frozenset({"address"}),
    "get_dob":     frozenset({"date_of_birth"}),
    "get_user_id": frozenset({"user_id"}),
}

# Sinks and their human-readable recommendations
SINK_RECOMMENDATIONS: Dict[str, str] = {
    "log":            "Redact PII before logging",
    "send_analytics": "Anonymize before sending to analytics",
    "send_to_api":    "Remove PII before sending to external sink",
    "print_log":      "Redact PII before logging",
    "write_log":      "Redact PII before logging",
    "post_to_server": "Remove PII before sending to external sink",
}

# Any function name containing these substrings is treated as a sink
_SINK_SUBSTRINGS = ("log", "analytics", "api", "server", "report", "track", "monitor")

TaintEnv = Dict[str, FrozenSet[str]]


@dataclass
class Leak:
    line: int
    sink: str
    pii_types: FrozenSet[str]
    recommendation: str


def _is_sink(func: str) -> bool:
    if func in SINK_RECOMMENDATIONS:
        return True
    lower = func.lower()
    return any(sub in lower for sub in _SINK_SUBSTRINGS)


def _recommendation(func: str) -> str:
    if func in SINK_RECOMMENDATIONS:
        return SINK_RECOMMENDATIONS[func]
    lower = func.lower()
    if "log" in lower or "print" in lower or "write" in lower:
        return "Redact PII before logging"
    if "analytic" in lower or "track" in lower or "monitor" in lower:
        return "Anonymize before sending to analytics"
    return "Remove PII before sending to external sink"


def _eval_taint(expr: Expr, env: TaintEnv) -> FrozenSet[str]:
    if isinstance(expr, StringLiteral):
        return frozenset()
    if isinstance(expr, Variable):
        return env.get(expr.name, frozenset())
    if isinstance(expr, Call):
        if expr.func in PII_SOURCES:
            return PII_SOURCES[expr.func]
        # conservative: union of argument taints
        result: FrozenSet[str] = frozenset()
        for arg in expr.args:
            result = result | _eval_taint(arg, env)
        return result
    if isinstance(expr, BinaryOp):
        return _eval_taint(expr.left, env) | _eval_taint(expr.right, env)
    return frozenset()


def analyze(program: Program) -> List[Leak]:
    env: TaintEnv = {}
    leaks: List[Leak] = []

    for stmt in program.statements:
        if isinstance(stmt, Assignment):
            taint = _eval_taint(stmt.value, env)
            env[stmt.target] = taint

        elif isinstance(stmt, SinkCall):
            if _is_sink(stmt.func):
                combined: FrozenSet[str] = frozenset()
                for arg in stmt.args:
                    combined = combined | _eval_taint(arg, env)
                if combined:
                    leaks.append(Leak(
                        line=stmt.line,
                        sink=stmt.func,
                        pii_types=combined,
                        recommendation=_recommendation(stmt.func),
                    ))

    return leaks
