"""Row 6: the guard's invisible-Unicode scan (spec §7.3) and its canonical JSON (spec §0)."""

import pytest

from guard import canon, unicode
from sijill import record

FLAGGED = [  # (text, code point reported)
    ("pay\u200bnow", "U+200B"), ("a\u200cb", "U+200C"), ("a\u200db", "U+200D"), ("a\u2060b", "U+2060"),
    ("a\ufeffb", "U+FEFF"), ("a\u180eb", "U+180E"), ("f\u2062x", "U+2062"), ("pass\u00adword", "U+00AD"),
    ("ignore\U000e0041\U000e0042", "U+E0041"), ("abc\u202edcba", "U+202E"), ("x\u2067y", "U+2067"),
    ("a\ue000b", "U+E000"), ("a\U000f0000b", "U+F0000"), ("a\u0378b", "U+0378"), ("a\uffffb", "U+FFFF"),
    ("a\x00b", "U+0000"), ("a\x1bb", "U+001B"), ("a\x7fb", "U+007F"), ("a\x85b", "U+0085"),
    ("a\ud800b", "U+FFFD"),
    ("salary\u200dcertificate", "U+200D"),       # ZWJ between Latin letters is not a joiner context
]
CLEAN = [
    "plain ASCII\twith tab\nand newline\r\n", "\ufeffBOM at offset 0", "thumbs \U0001f44d\ufe0f",
    "family \U0001f468\u200d\U0001f469\u200d\U0001f467",   # emoji ZWJ sequence
    "heart on fire \u2764\ufe0f\u200d\U0001f525",          # variation selector before the joiner
    "\u0645\u200c\u0631",                                   # Arabic ZWNJ between letters
    "\u0915\u094d\u200d\u0937",                             # Devanagari ZWJ after the virama
    "\u0634\u0647\u0627\u062f\u0629 \u0631\u0627\u062a\u0628", "U+FFFD itself \ufffd is a character",
]


@pytest.mark.parametrize("text,cp", FLAGGED)
def test_each_flagged_class(text, cp):
    s = unicode.scan(text)
    assert s["found"] and cp in s["codepoints"]
    assert unicode.strip(text) == "".join(ch for i, ch in enumerate(text) if i not in unicode.flagged(text))


@pytest.mark.parametrize("text", CLEAN)
def test_allowed_text_is_not_flagged(text):
    assert unicode.scan(text) == {"found": False, "count": 0, "codepoints": []}
    assert unicode.strip(text) == text


def test_strip_keeps_everything_else_and_the_scan_is_sorted_and_capped():
    assert unicode.strip("ru\u200bn np\U000e0078x") == "run npx"
    s = unicode.scan("".join(chr(0xE000 + i) for i in range(40)) + "\u200b\u200b")
    assert s["count"] == 42 and len(s["codepoints"]) == 32
    assert s["codepoints"][:2] == ["U+200B", "U+E000"]       # by code point, distinct


def test_invalid_utf8_counts_as_replacement_character():
    text = unicode.decode(b"ok \xff\xfe done")
    assert unicode.scan(text) == {"found": True, "count": 2, "codepoints": ["U+FFFD"]}


def test_canonical_json_matches_the_ledger():
    for obj in ({"b": 1, "a": ["\u0633", {"z": True, "y": None}]}, {"caseId": "MOI-2026-004211"}, [], "\u200b"):
        assert canon.canonical_json(obj) == record.canonical_json(obj)
        assert canon.args_hash(obj) == record.sha256_hex(record.canonical_json(obj))
    assert canon.args_hash({"x": "\ud800"})          # a lone surrogate hashes instead of raising


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_canonical_json_refuses_nan_and_infinities_like_the_ledger(value):
    """§2.2: NaN and infinities are not JSON; the ledger raises, and so does the guard."""
    with pytest.raises(ValueError):
        canon.canonical_json({"x": [value]})
