"""Invisible and suspicious Unicode (spec §7.3): the detection layer for tool results and MCP tool descriptions.

Code points are scanned before any normalisation. Invalid UTF-8 and lone surrogates count as U+FFFD.
"""

import unicodedata

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E}
CONTROL_OK = {0x09, 0x0A, 0x0D}
JOINERS = {0x200C, 0x200D}
# unicodedata has neither the Script nor the Extended_Pictographic property, so block ranges stand in for both.
# ponytail: block approximations; generate exact tables from UCD files if a pilot document trips one.
JOINING_SCRIPTS = ((0x0600, 0x06FF), (0x0700, 0x074F), (0x0750, 0x077F), (0x0860, 0x08FF),    # Arabic, Syriac
                   (0x0900, 0x0AFF), (0x0B80, 0x0DFF),          # Devanagari to Gujarati, Tamil to Sinhala
                   (0x0F00, 0x0FFF), (0x1000, 0x109F), (0x1780, 0x18AF),    # Tibetan, Myanmar, Khmer, Mongolian
                   (0xFB50, 0xFDFF), (0xFE70, 0xFEFC))          # Arabic presentation forms
PICTOGRAPHIC = ((0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049), (0x2122, 0x2122),
                (0x2139, 0x2139), (0x2194, 0x21AA), (0x231A, 0x23FF), (0x24C2, 0x24C2), (0x25AA, 0x27BF),
                (0x2934, 0x2935), (0x2B05, 0x2B55), (0x3030, 0x3030), (0x303D, 0x303D), (0x3297, 0x3299),
                (0x1F000, 0x1FAFF))
EMOJI_PARTS = ((0xFE00, 0xFE0F), (0x1F3FB, 0x1F3FF))           # variation selectors, skin tones


def _in(cp, ranges) -> bool:
    return cp is not None and any(a <= cp <= b for a, b in ranges)


def _suspicious(cp: int) -> bool:
    if 0xD800 <= cp <= 0xDFFF:
        return True                       # an invalid byte or a lone surrogate
    if cp in CONTROL_OK or 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return False                      # tab, LF, CR; variation selectors (emoji)
    return (cp in ZERO_WIDTH or 0x2061 <= cp <= 0x2064 or cp == 0x00AD or 0xE0000 <= cp <= 0xE007F
            or 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069 or 0xE000 <= cp <= 0xF8FF or cp >= 0xF0000
            or cp <= 0x1F or 0x7F <= cp <= 0x9F or unicodedata.category(chr(cp)) == "Cn")


def _neighbour(text: str, i: int, step: int) -> int | None:
    """The code point beside offset i, looking past variation selectors and skin tones (the heart-on-fire
    emoji has U+FE0F before its joiner)."""
    j = i + step
    while 0 <= j < len(text) and _in(ord(text[j]), EMOJI_PARTS):
        j += step
    return ord(text[j]) if 0 <= j < len(text) else None


def _context_ok(text: str, i: int) -> bool:
    cp = ord(text[i])
    if cp == 0xFEFF and i == 0:
        return True                       # a byte order mark
    if cp not in JOINERS:
        return False
    left, right = _neighbour(text, i, -1), _neighbour(text, i, 1)
    if cp == 0x200D and _in(left, PICTOGRAPHIC) and _in(right, PICTOGRAPHIC):
        return True                       # an emoji ZWJ sequence
    # Joiner-dependent scripts; marks count with letters, since a Devanagari ZWJ follows the virama.
    return all(_in(c, JOINING_SCRIPTS) and unicodedata.category(chr(c))[0] in "LM" for c in (left, right))


def flagged(text: str) -> list[int]:
    """Offsets of the flagged code points."""
    return [i for i, ch in enumerate(text) if _suspicious(ord(ch)) and not _context_ok(text, i)]


def scan(text: str) -> dict:
    """{found, count, codepoints}: codepoints sorted, distinct, at most 32 (spec §2.4.2)."""
    hits = flagged(text)
    cps = sorted({0xFFFD if 0xD800 <= ord(text[i]) <= 0xDFFF else ord(text[i]) for i in hits})
    return {"found": bool(hits), "count": len(hits), "codepoints": [f"U+{cp:04X}" for cp in cps][:32]}


def strip(text: str) -> str:
    drop = set(flagged(text))
    return "".join(ch for i, ch in enumerate(text) if i not in drop)


def decode(data: bytes) -> str:
    """UTF-8, with each invalid byte kept as a lone surrogate so that scan() counts it as U+FFFD."""
    return data.decode("utf-8", "surrogateescape")
