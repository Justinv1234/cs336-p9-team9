import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

import pytest
from parser import parse
from ast_nodes import Program, Assignment, SinkCall, Variable, StringLiteral, Call, BinaryOp


def test_parse_assignment():
    prog = parse("x := get_email()\n")
    assert len(prog.statements) == 1
    stmt = prog.statements[0]
    assert isinstance(stmt, Assignment)
    assert stmt.target == "x"
    assert isinstance(stmt.value, Call)
    assert stmt.value.func == "get_email"


def test_parse_sink_call():
    prog = parse("log(x)\n")
    assert len(prog.statements) == 1
    stmt = prog.statements[0]
    assert isinstance(stmt, SinkCall)
    assert stmt.func == "log"
    assert len(stmt.args) == 1
    assert isinstance(stmt.args[0], Variable)


def test_parse_binary_op():
    prog = parse('x := a + "hello"\n')
    stmt = prog.statements[0]
    assert isinstance(stmt.value, BinaryOp)
    assert isinstance(stmt.value.left, Variable)
    assert isinstance(stmt.value.right, StringLiteral)


def test_parse_multiple_statements():
    src = "a := get_name()\nb := get_email()\nlog(a)\n"
    prog = parse(src)
    assert len(prog.statements) == 3


def test_parse_comment_ignored():
    src = "# just a comment\nx := get_name()\n"
    prog = parse(src)
    assert len(prog.statements) == 1


def test_parse_call_with_args():
    prog = parse("send_analytics(a, b)\n")
    stmt = prog.statements[0]
    assert isinstance(stmt, SinkCall)
    assert len(stmt.args) == 2


def test_parse_line_numbers():
    src = "a := get_name()\nlog(a)\n"
    prog = parse(src)
    assert prog.statements[0].line == 1
    assert prog.statements[1].line == 2
