"""Minimal CESR (Composable Event Streaming Representation) primitives.

Why this exists: the strings that make KERI/ACDC recognisable -- the 44-character
`E...` identifiers, the 88-character `0B...` signatures -- are not arbitrary.
They are text-domain encodings of raw cryptographic material, where a short
prefix code declares what the material is. Getting this right is what makes
sandbox output look and behave like the real thing rather than like fake hashes.

Encoding rule for a code of length `cs` over `raw` bytes:
  1. Left-pad `raw` with `ps` zero bytes so the total is a multiple of 3,
     where ps = (3 - len(raw) % 3) % 3.
  2. Base64url-encode the padded bytes.
  3. Overwrite the first `ps` characters with the code (codes are sized so that
     cs == ps for the common cases).

Digest note: KERI's default digest is Blake3-256, CESR code 'E'. Blake3 is not
in the Python standard library, so if the `blake3` package is unavailable we use
Blake2b-256 instead, which carries the distinct and equally valid CESR code 'F'.
The sandbox stays self-consistent and spec-shaped either way; only the algorithm
behind the code changes.
"""

import base64
import hashlib

# CESR Matter codes used by this sandbox
CODE_ED25519_SEED = "A"    # Ed25519 private key seed
CODE_ED25519N = "B"        # Ed25519 non-transferable verification key
CODE_ED25519 = "D"         # Ed25519 transferable verification key
CODE_BLAKE3_256 = "E"      # Blake3-256 digest (KERI default)
CODE_BLAKE2B_256 = "F"     # Blake2b-256 digest
CODE_SALT_128 = "0A"       # 128-bit salt / nonce
CODE_ED25519_SIG = "0B"    # Ed25519 signature

try:
    import blake3 as _blake3_mod

    HAS_BLAKE3 = True
    DIGEST_CODE = CODE_BLAKE3_256
    DIGEST_NAME = "Blake3-256"

    def _digest_bytes(data):
        return _blake3_mod.blake3(data).digest(length=32)

except ImportError:
    HAS_BLAKE3 = False
    DIGEST_CODE = CODE_BLAKE2B_256
    DIGEST_NAME = "Blake2b-256"

    def _digest_bytes(data):
        return hashlib.blake2b(data, digest_size=32).digest()


# Full encoded length for each code, used for dummy placeholders during SAIDing
FULL_SIZE = {
    "A": 44, "B": 44, "D": 44, "E": 44, "F": 44,
    "0A": 24, "0B": 88,
}

DUMMY = "#"


def encode(code, raw):
    """Encode raw bytes into a CESR-qualified base64url string."""
    ps = (3 - (len(raw) % 3)) % 3
    b64 = base64.urlsafe_b64encode(bytes(ps) + raw).decode("utf-8")
    return code + b64[len(code):]


def decode(qb64):
    """Recover the raw bytes from a CESR-qualified string."""
    code = qb64[0]
    cs = 2 if code in ("0", "1", "2", "3", "4") else 1
    ps = cs
    b64 = ("A" * ps) + qb64[cs:]
    return base64.urlsafe_b64decode(b64.encode("utf-8"))[ps:]


def code_of(qb64):
    """Return the CESR code that leads a qualified string."""
    return qb64[:2] if qb64[0] in ("0", "1", "2", "3", "4") else qb64[:1]


def digest(data, code=None):
    """CESR-qualified digest of raw bytes."""
    code = code or DIGEST_CODE
    return encode(code, _digest_bytes(data))


def dumps(sad):
    """Serialise a self-addressed data structure the way KERI does: compact
    JSON, no whitespace, insertion order preserved."""
    import json

    return json.dumps(sad, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def versify(protocol="KERI", kind="JSON", size=0, major=1, minor=0):
    """Build a KERI/ACDC version string, e.g. KERI10JSON0000fa_"""
    return f"{protocol}{major}{minor}{kind}{size:06x}_"


def saidify(sad, label="d", code=None, protocol="KERI", also=()):
    """Compute and embed the self-addressing identifier of `sad`.

    The trick that makes this verifiable is that the SAID field is replaced by a
    same-length run of '#' before hashing, so the digest covers a structure of
    exactly the size it will have once the digest is written back in. Anyone can
    repeat the substitution and re-derive the same value.

    `also` names extra fields that must carry the same SAID -- KERI uses this for
    inception events, where the identifier prefix `i` equals the event SAID `d`.
    """
    code = code or DIGEST_CODE
    size = FULL_SIZE[code]
    sad = dict(sad)

    # Two-pass version string: length is stable because the SAID placeholder is
    # exactly as long as the SAID that replaces it.
    if "v" in sad:
        sad["v"] = versify(protocol, "JSON", 0)
        sad[label] = DUMMY * size
        for extra in also:
            sad[extra] = DUMMY * size
        sad["v"] = versify(protocol, "JSON", len(dumps(sad)))
    else:
        sad[label] = DUMMY * size
        for extra in also:
            sad[extra] = DUMMY * size

    said = digest(dumps(sad), code)
    sad[label] = said
    for extra in also:
        sad[extra] = said
    return said, sad


def verify_said(sad, label="d", also=()):
    """Recompute a SAID and compare it with the one embedded in the structure."""
    claimed = sad.get(label)
    if not claimed:
        return False, "no SAID field present"
    code = code_of(claimed)
    if code not in FULL_SIZE:
        return False, f"unknown digest code {code!r}"
    protocol = sad.get("v", "KERI10JSON000000_")[:4]
    recomputed, _ = saidify(sad, label=label, code=code, protocol=protocol, also=also)
    if recomputed == claimed:
        return True, claimed
    return False, f"expected {claimed}, recomputed {recomputed}"
