import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

import pytest
from lexer import tokenize, IDENT, ASSIGN, LPAREN, RPAREN, COMMA, PLUS, STRING, NEWLINE, EOF


def types(source):
    return [t.type for t in tokenize(source)]


def test_simple_assignment_tokens():
    toks = tokenize("x := get_email()")
    assert toks[0].type == IDENT and toks[0].value == "x"
    assert toks[1].type == ASSIGN
    assert toks[2].type == IDENT and toks[2].value == "get_email"
    assert toks[3].type == LPAREN
    assert toks[4].type == RPAREN
    assert toks[5].type == EOF


def test_string_literal():
    toks = tokenize('"hello world"')
    assert toks[0].type == STRING
    assert toks[0].value == '"hello world"'


def test_comment_skipped():
    toks = tokenize("x := y  # this is a comment\n")
    tok_types = [t.type for t in toks]
    assert "COMMENT" not in tok_types


def test_line_numbers():
    toks = tokenize("a := b\nc := d\n")
    ident_toks = [t for t in toks if t.type == IDENT]
    assert ident_toks[0].line == 1
    assert ident_toks[2].line == 2


def test_plus_and_comma():
    toks = tokenize("f(a + b, c)")
    tok_types = [t.type for t in toks]
    assert PLUS in tok_types
    assert COMMA in tok_types


def test_unexpected_char_raises():
    with pytest.raises(SyntaxError):
        tokenize("x @ y")
