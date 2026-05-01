from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional
from ast_nodes import (
    Program, Assignment, SinkCall,
    Variable, StringLiteral, Call, BinaryOp, Expr,
)
from policy import Policy

TaintEnv = Dict[str, FrozenSet[str]]


@dataclass
class Leak:
    line: int
    sink: str
    pii_types: FrozenSet[str]
    recommendation: str


def _is_sink(func: str, policy: Policy) -> bool:
    if func in policy.sinks:
        return True
    lower = func.lower()
    return any(sub in lower for sub in policy.sink_patterns)


def _recommendation(func: str, policy: Policy) -> str:
    if func in policy.sinks:
        return policy.sinks[func]
    lower = func.lower()
    if "log" in lower or "print" in lower or "write" in lower:
        return "Redact PII before logging"
    if "analytic" in lower or "track" in lower or "monitor" in lower:
        return "Anonymize before sending to analytics"
    return "Remove PII before sending to external sink"


def _eval_taint(expr: Expr, env: TaintEnv, policy: Policy) -> FrozenSet[str]:
    if isinstance(expr, StringLiteral):
        return frozenset()
    if isinstance(expr, Variable):
        return env.get(expr.name, frozenset())
    if isinstance(expr, Call):
        if expr.func in policy.sources:
            return policy.sources[expr.func]
        result: FrozenSet[str] = frozenset()
        for arg in expr.args:
            result = result | _eval_taint(arg, env, policy)
        return result
    if isinstance(expr, BinaryOp):
        return _eval_taint(expr.left, env, policy) | _eval_taint(expr.right, env, policy)
    return frozenset()


def analyze(program: Program, policy: Optional[Policy] = None) -> List[Leak]:
    if policy is None:
        policy = Policy.default()

    env: TaintEnv = {}
    leaks: List[Leak] = []

    for stmt in program.statements:
        if isinstance(stmt, Assignment):
            taint = _eval_taint(stmt.value, env, policy)
            env[stmt.target] = taint

        elif isinstance(stmt, SinkCall):
            if _is_sink(stmt.func, policy):
                combined: FrozenSet[str] = frozenset()
                for arg in stmt.args:
                    combined = combined | _eval_taint(arg, env, policy)
                if combined:
                    leaks.append(Leak(
                        line=stmt.line,
                        sink=stmt.func,
                        pii_types=combined,
                        recommendation=_recommendation(stmt.func, policy),
                    ))

    return leaks
