"""Ed25519 signing with graceful degradation.

The sandbox must run anywhere -- inside Claude Code, Codex, Gemini CLI, a bare
container, a locked-down laptop. So we try the fast native libraries first and
fall back to a dependency-free pure-Python implementation (RFC 8032 reference
style) if neither is installed. The API is identical either way.

    seed = generate_seed()              # 32 raw bytes
    pub  = public_key(seed)             # 32 raw bytes
    sig  = sign(seed, message)          # 64 raw bytes
    ok   = verify(pub, message, sig)    # bool
"""

import hashlib
import os

BACKEND = None

# ---------------------------------------------------------------- fast paths
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    BACKEND = "cryptography"

    def _pub(seed):
        return (
            Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

    def _sign(seed, msg):
        return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)

    def _verify(pub, msg, sig):
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

except ImportError:
    try:
        import nacl.signing
        import nacl.exceptions

        BACKEND = "pynacl"

        def _pub(seed):
            return bytes(nacl.signing.SigningKey(seed).verify_key)

        def _sign(seed, msg):
            return nacl.signing.SigningKey(seed).sign(msg).signature

        def _verify(pub, msg, sig):
            try:
                nacl.signing.VerifyKey(pub).verify(msg, sig)
                return True
            except Exception:
                return False

    except ImportError:
        BACKEND = "pure-python"

        # -------------------------------------------------- RFC 8032 fallback
        _q = 2**255 - 19
        _L = 2**252 + 27742317777372353535851937790883648493

        def _inv(x):
            return pow(x, _q - 2, _q)

        _d = -121665 * _inv(121666) % _q
        _I = pow(2, (_q - 1) // 4, _q)

        def _xrecover(y):
            xx = (y * y - 1) * _inv(_d * y * y + 1)
            x = pow(xx, (_q + 3) // 8, _q)
            if (x * x - xx) % _q != 0:
                x = (x * _I) % _q
            if x % 2 != 0:
                x = _q - x
            return x

        _By = 4 * _inv(5)
        _B = [_xrecover(_By) % _q, _By % _q]

        def _edwards(P, Q):
            x1, y1 = P
            x2, y2 = Q
            k = _d * x1 * x2 * y1 * y2
            x3 = (x1 * y2 + x2 * y1) * _inv(1 + k)
            y3 = (y1 * y2 + x1 * x2) * _inv(1 - k)
            return [x3 % _q, y3 % _q]

        def _scalarmult(P, e):
            # iterative double-and-add; recursion would risk the stack limit
            R = [0, 1]
            Q = P
            while e > 0:
                if e & 1:
                    R = _edwards(R, Q)
                Q = _edwards(Q, Q)
                e >>= 1
            return R

        def _encodeint(y):
            return y.to_bytes(32, "little")

        def _encodepoint(P):
            x, y = P
            n = y | ((x & 1) << 255)
            return n.to_bytes(32, "little")

        def _decodeint(s):
            return int.from_bytes(s, "little")

        def _decodepoint(s):
            n = int.from_bytes(s, "little")
            y = n & ((1 << 255) - 1)
            x = _xrecover(y)
            if (x & 1) != ((n >> 255) & 1):
                x = _q - x
            P = [x, y]
            if (-P[0] * P[0] + P[1] * P[1] - 1 - _d * P[0] * P[0] * P[1] * P[1]) % _q != 0:
                raise ValueError("point not on curve")
            return P

        def _clamp(h):
            a = 2**254 + (int.from_bytes(h[:32], "little") & ~(2**254 + 7))
            a &= ~(1 << 255)
            a |= 1 << 254
            a -= a % 8
            return a

        def _secret_scalar(seed):
            h = hashlib.sha512(seed).digest()
            a = int.from_bytes(h[:32], "little")
            a &= (1 << 254) - 8
            a |= 1 << 254
            return a, h

        def _pub(seed):
            a, _ = _secret_scalar(seed)
            return _encodepoint(_scalarmult(_B, a))

        def _sign(seed, msg):
            a, h = _secret_scalar(seed)
            A = _encodepoint(_scalarmult(_B, a))
            r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % _L
            R = _encodepoint(_scalarmult(_B, r))
            k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % _L
            S = (r + k * a) % _L
            return R + _encodeint(S)

        def _verify(pub, msg, sig):
            try:
                if len(sig) != 64 or len(pub) != 32:
                    return False
                R = _decodepoint(sig[:32])
                A = _decodepoint(pub)
                S = _decodeint(sig[32:])
                k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
                lhs = _scalarmult(_B, S)
                rhs = _edwards(R, _scalarmult(A, k))
                return lhs[0] % _q == rhs[0] % _q and lhs[1] % _q == rhs[1] % _q
            except Exception:
                return False


# ------------------------------------------------------------------ public API
def generate_seed():
    return os.urandom(32)


def public_key(seed):
    return _pub(seed)


def sign(seed, message):
    return _sign(seed, message)


def verify(pub, message, signature):
    return _verify(pub, message, signature)
