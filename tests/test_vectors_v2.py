"""Golden vectors (spec §2.6, §17.8): sijill.record reproduces every published v2 record byte for byte.

tests/vectors_v2.py and tests/vectors_v2.out are copies of spec/examples/examples_v2_vectors.py and
spec/examples/vectors.out; tests/tokens/ is a copy of spec/examples/tokens/. The spec repo is the source.
"""

import json
from pathlib import Path

import pytest

import vectors_v2
from sijill import record

HERE = Path(__file__).parent


def published() -> dict[int, dict]:
    text = (HERE / "vectors_v2.out").read_text(encoding="utf-8")
    recs, dec = {}, json.JSONDecoder()
    for part in text.split("=== seq ")[1:]:
        num, rest = part.split("\n", 1)
        recs[int(num)] = dec.raw_decode(rest)[0]
    return recs


PUBLISHED = published()
GOV_HASHES = {
    70: "95c0bde7d570948ba8b4bcc6d19e8802da7c11aa71436f516e6985c9f8d819e2",
    71: "4ba6868cb3786d1c1d5136bbc84b39e278e254cc8745558610bda126d8d16df4",
    72: "5ef959b1a20f692af2ee9395e292ec49170c4b04fd2775dffb950f52e257ef53",
    73: "80c027a2ad7540b6584ab2fa08ca45b002bccb38d8e55ccf0da7c419f985b5bc",
    74: "e30bbe83009386de4ad29c5fcb604ef749403e1203d971f8ca4d48eaa6edf961",
    75: "6dbbc152da10aeb97180c105d76904bdd4bca20444490bef0ba42192c9f471d7",
    76: "f9085253a51faa5347dc288b2ea330b1a4bda22d28ddaf233ccea4553b25dbcd",
    77: "2ceb17386674b9a4ad1a105ef63b55faaa032490e6a6ef549e630b2e1731ca29",
    78: "24ae7044f57bb4af263606189f4d28f9e407835c14f8fe2c4728499bfbdcff22",
    79: "9d3e222bc2f341f90d9b594c1af3e3ee00fe2ab59a9e1c285fc1f7cfe93cbec0",
}


def test_published_set_matches_the_script():
    assert sorted(PUBLISHED) == [2, 3, 4, 5, 6, 12, 40, 41, 42, 43, 44, 45, 47, 53, 60, *range(70, 80), 120, 131, 200]
    assert PUBLISHED == vectors_v2.out


@pytest.mark.parametrize("seq", sorted(PUBLISHED))
def test_writer_reproduces_vector(seq):
    want = PUBLISHED[seq]
    body = {f: want[f] for f in record.BODY_FIELDS}
    assert record.seal(body, seq, want["prev_hash"], vectors_v2.NODE_KEY) == {f: want[f] for f in record.FIELDS}


def test_vector_script_self_check():
    assert vectors_v2.check_all() == 28


def test_gov_vector_hashes_are_pinned():
    assert {k: PUBLISHED[k]["record_hash"] for k in range(70, 80)} == GOV_HASHES


def test_fixture_token_and_jwks():
    token_hash = record.sha256_hex(vectors_v2.OFFICER_JWT.encode())
    assert (HERE / "tokens" / f"{token_hash}.jwt").read_bytes() == vectors_v2.OFFICER_JWT.encode()
    assert (HERE / "tokens" / f"{vectors_v2.JWKS_HASH}.json").read_bytes() == record.canonical_json(vectors_v2.JWKS)
    assert json.loads(PUBLISHED[70]["ext"])["principal_claims"]["token_hash"] == token_hash
