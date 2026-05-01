"""Taint analysis frontend for real Python source files.

Uses Python's built-in `ast` module to parse source code and performs
a forward, flow-insensitive taint analysis using the same Policy and
Leak types as the IMP-Core engine.
"""

from __future__ import annotations
import ast
from typing import Dict, FrozenSet, List, Optional

from policy import Policy
from taint import Leak

TaintEnv = Dict[str, FrozenSet[str]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call_name(node: ast.Call) -> str:
    """Return a name for the callee suitable for sink matching.

    For bare calls (log) returns the function name.
    For attribute calls (logging.info) returns the full dotted string so that
    patterns like 'log' match 'logging.info'.
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        obj = func.value
        if isinstance(obj, ast.Name):
            return f"{obj.id}.{func.attr}"
        return func.attr
    return ""


def _is_sink(name: str, policy: Policy) -> bool:
    if name in policy.sinks:
        return True
    lower = name.lower()
    return any(sub in lower for sub in policy.sink_patterns)


def _sink_recommendation(name: str, policy: Policy) -> str:
    if name in policy.sinks:
        return policy.sinks[name]
    lower = name.lower()
    if any(k in lower for k in ("log", "print", "write", "debug", "info", "warn", "error")):
        return "Redact PII before logging"
    if any(k in lower for k in ("analytic", "track", "monitor")):
        return "Anonymize before sending to analytics"
    return "Remove PII before sending to external sink"


# ---------------------------------------------------------------------------
# Taint evaluator for Python AST expressions
# ---------------------------------------------------------------------------

def _eval(node: ast.expr, env: TaintEnv, policy: Policy) -> FrozenSet[str]:
    if isinstance(node, ast.Constant):
        return frozenset()

    if isinstance(node, ast.Name):
        return env.get(node.id, frozenset())

    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name in policy.sources:
            return policy.sources[name]
        # conservative: propagate union of all argument taints
        result: FrozenSet[str] = frozenset()
        for arg in node.args:
            result = result | _eval(arg, env, policy)
        for kw in node.keywords:
            result = result | _eval(kw.value, env, policy)
        return result

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _eval(node.left, env, policy) | _eval(node.right, env, policy)

    if isinstance(node, ast.JoinedStr):  # f-string
        result: FrozenSet[str] = frozenset()
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                result = result | _eval(part.value, env, policy)
        return result

    if isinstance(node, ast.Dict):
        result: FrozenSet[str] = frozenset()
        for val in node.values:
            if val is not None:
                result = result | _eval(val, env, policy)
        return result

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        result: FrozenSet[str] = frozenset()
        for elt in node.elts:
            result = result | _eval(elt, env, policy)
        return result

    if isinstance(node, ast.IfExp):
        return _eval(node.body, env, policy) | _eval(node.orelse, env, policy)

    if isinstance(node, ast.Attribute):
        # propagate taint through attribute access (e.g. user.email)
        return _eval(node.value, env, policy)

    return frozenset()


# ---------------------------------------------------------------------------
# Statement-level traversal
# ---------------------------------------------------------------------------

def _assign_target(target: ast.expr, taint: FrozenSet[str], env: TaintEnv) -> None:
    if isinstance(target, ast.Name):
        env[target.id] = taint
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _assign_target(elt, taint, env)


def _visit_stmts(
    stmts: List[ast.stmt],
    env: TaintEnv,
    leaks: List[Leak],
    policy: Policy,
) -> None:
    for stmt in stmts:
        _visit_stmt(stmt, env, leaks, policy)


def _visit_stmt(
    stmt: ast.stmt,
    env: TaintEnv,
    leaks: List[Leak],
    policy: Policy,
) -> None:
    # --- assignments ---
    if isinstance(stmt, ast.Assign):
        taint = _eval(stmt.value, env, policy)
        for target in stmt.targets:
            _assign_target(target, taint, env)

    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        taint = _eval(stmt.value, env, policy)
        _assign_target(stmt.target, taint, env)

    elif isinstance(stmt, ast.AugAssign):
        existing = env.get(
            stmt.target.id if isinstance(stmt.target, ast.Name) else "",
            frozenset(),
        )
        new_taint = _eval(stmt.value, env, policy)
        if isinstance(stmt.target, ast.Name):
            env[stmt.target.id] = existing | new_taint

    # --- standalone call (potential sink) ---
    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call = stmt.value
        name = _call_name(call)
        if _is_sink(name, policy):
            combined: FrozenSet[str] = frozenset()
            for arg in call.args:
                combined = combined | _eval(arg, env, policy)
            for kw in call.keywords:
                combined = combined | _eval(kw.value, env, policy)
            if combined:
                leaks.append(Leak(
                    line=call.lineno,
                    sink=name,
                    pii_types=combined,
                    recommendation=_sink_recommendation(name, policy),
                ))

    # --- return statement (useful inside function bodies) ---
    elif isinstance(stmt, ast.Return) and stmt.value is not None:
        pass  # returns don't reach sinks directly; taint tracked via callers

    # --- control flow: recurse into all branches ---
    elif isinstance(stmt, (ast.If, ast.For, ast.While, ast.With)):
        _visit_stmts(getattr(stmt, "body", []), env, leaks, policy)
        _visit_stmts(getattr(stmt, "orelse", []), env, leaks, policy)

    elif isinstance(stmt, ast.Try):
        _visit_stmts(stmt.body, env, leaks, policy)
        for handler in stmt.handlers:
            _visit_stmts(handler.body, env, leaks, policy)
        _visit_stmts(stmt.orelse, env, leaks, policy)
        _visit_stmts(stmt.finalbody, env, leaks, policy)

    # --- function / class definitions: recurse to catch top-level leaks ---
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        _visit_stmts(stmt.body, env, leaks, policy)

    elif isinstance(stmt, ast.ClassDef):
        _visit_stmts(stmt.body, env, leaks, policy)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_python(source: str, policy: Optional[Policy] = None) -> List[Leak]:
    """Parse *source* as Python and return all detected PII leaks."""
    if policy is None:
        policy = Policy.default()

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise SyntaxError(f"Could not parse Python source: {exc}") from exc

    env: TaintEnv = {}
    leaks: List[Leak] = []
    _visit_stmts(tree.body, env, leaks, policy)
    return leaks
