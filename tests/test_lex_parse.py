from __future__ import annotations

import pytest

from schematic_airlock.domain import SyntaxFailure
from schematic_airlock.lex import LogicalLine, logical_lines, tokenize
from schematic_airlock.parse import parse_deck


def test_logical_lines_remove_comments_and_join_continuations() -> None:
    text = """* title
R1 a b 1k ; inline
+ temp=27 $ second inline

V1 a 0 1.8
"""
    lines = logical_lines(text, "x.sp")
    assert [line.text for line in lines] == ["R1 a b 1k temp=27", "V1 a 0 1.8"]
    assert lines[0].line == 2
    assert lines[0].evidence == "R1 a b 1k ; inline\n+ temp=27 $ second inline"


def test_comment_markers_inside_braces_and_quotes_are_data() -> None:
    lines = logical_lines('B1 p n V={a;b}\n.include "a$b.lib"\n', "x.sp")
    assert lines[0].text == "B1 p n V={a;b}"
    assert lines[1].text == '.include "a$b.lib"'


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("+ orphan\n", "no predecessor"),
        ("R1 a b {1k\n", "unterminated braced"),
        ("R1 a b 1k}\n", "unexpected closing"),
        ('R1 a b "1k\n', "unterminated quoted"),
    ],
)
def test_logical_line_syntax_failures(text: str, message: str) -> None:
    with pytest.raises(SyntaxFailure, match=message):
        logical_lines(text, "bad.sp")


def test_logical_lines_enforce_line_and_file_budgets() -> None:
    with pytest.raises(SyntaxFailure, match="physical line"):
        logical_lines("R" * 20, "bad.sp", max_physical_line=10)
    with pytest.raises(SyntaxFailure, match="logical lines"):
        logical_lines("R1 a b 1\nR2 b c 2\n", "bad.sp", max_logical_lines=1)


def test_tokenize_preserves_grouped_values_and_columns() -> None:
    line = LogicalLine("x.sp", 4, "  R1  a b {base * 2} label='hello world'", "")
    tokens = tokenize(line)
    assert [token.value for token in tokens] == [
        "R1",
        "a",
        "b",
        "{base * 2}",
        "label=hello world",
    ]
    assert [token.column for token in tokens] == [3, 7, 9, 11, 22]


def test_tokenize_enforces_budget() -> None:
    line = LogicalLine("x.sp", 1, " ".join(str(index) for index in range(10)), "")
    with pytest.raises(SyntaxFailure, match="tokens"):
        tokenize(line, max_tokens=3)


def test_parser_builds_primitives_directives_and_includes() -> None:
    deck = parse_deck(
        """.include "models.lib"
.lib corner.lib tt
R1 a b 1k tc=0.1
C1 b 0 2p
L1 b c 3n
V1 a 0 DC 1.8
I1 c 0 10u
D1 c 0 diode area=2
M1 d g s b nch w=2u l=100n
Q1 c b e npn
E1 o 0 a b 10
G1 o 0 a b 1m
F1 o 0 VSENSE 2
H1 o 0 VSENSE 3
B1 p n V={V(a)}
Z1 unsupported syntax remains visible
.op
""",
        "top.sp",
    )
    assert len(deck.elements) == 14
    assert [element.kind for element in deck.elements] == [
        "R",
        "C",
        "L",
        "V",
        "I",
        "D",
        "M",
        "Q",
        "E",
        "G",
        "F",
        "H",
        "B",
        "Z",
    ]
    assert deck.elements[0].nodes == ("a", "b")
    assert deck.elements[0].value == "1k"
    assert deck.elements[0].parameters == (("tc", "0.1"),)
    assert deck.elements[3].value == "1.8"
    assert deck.elements[5].model == "diode"
    assert deck.elements[6].nodes == ("d", "g", "s", "b")
    assert [include.target for include in deck.includes] == ["models.lib", "corner.lib"]
    assert deck.includes[1].section == "tt"
    assert deck.directives[-1].name == "op"


def test_params_markers_are_not_ports_or_instance_model_names() -> None:
    deck = parse_deck(
        "X1 in out amp params: gain=3\n.subckt amp i o params: gain=2\nR1 i o {gain}\n.ends\n",
        "params.sp",
    )
    instance = deck.elements[0]
    assert instance.nodes == ("in", "out")
    assert instance.model == "amp"
    assert instance.parameters == (("gain", "3"),)
    assert deck.subcircuits[0].ports == ("i", "o")
    assert deck.subcircuits[0].parameters == (("gain", "2"),)


def test_parser_builds_subcircuit_and_call() -> None:
    deck = parse_deck(
        """X1 in out amp
.subckt amp i o gain=2
R1 i o {gain*1k}
.param local=3
.ends amp
""",
        "top.sp",
    )
    assert deck.elements[0].kind == "X"
    assert deck.elements[0].model == "amp"
    subckt = deck.subcircuits[0]
    assert subckt.name == "amp"
    assert subckt.ports == ("i", "o")
    assert subckt.parameters == (("gain", "2"),)
    assert subckt.elements[0].value == "{gain*1k}"
    assert subckt.directives[0].name == "param"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("R1 a\n", "requires"),
        (".include\n", "requires"),
        (".ends\n", "no matching"),
        (".subckt a x\n.subckt b y\n", "nested"),
        (".subckt a x\n.ends b\n", "expected"),
        (".subckt a x\nR1 x 0 1k\n", "missing .ends"),
    ],
)
def test_parser_rejects_incomplete_structure(text: str, message: str) -> None:
    with pytest.raises(SyntaxFailure, match=message):
        parse_deck(text, "bad.sp")


def test_parser_is_deterministic_and_does_not_mutate_text() -> None:
    text = "R1 a b 1k\nV1 a 0 1\n"
    first = parse_deck(text, "x.sp")
    second = parse_deck(text, "x.sp")
    assert first == second
    assert text == "R1 a b 1k\nV1 a 0 1\n"
