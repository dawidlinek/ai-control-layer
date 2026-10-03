"""Pure-Python Ed25519 *signing* (RFC 8032 section 6 reference algorithm), stdlib only.

The feed server container stays dependency-free this way. It signs one bundle per change, so the
speed of this implementation (tens of milliseconds) is irrelevant. Verification happens in the gateway
with `cryptography`; `gateway/tests/test_1d_feed.py` checks interoperability and the RFC test vector.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
assert _GX is not None
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _compress(p: tuple[int, int, int, int]) -> bytes:
    zinv = _inv(p[2])
    x = p[0] * zinv % _P
    y = p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    a, _ = _expand(seed)
    return _compress(_mul(a, _G))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _G))
    r = int.from_bytes(_sha512(prefix + message), "little") % _Q
    r_enc = _compress(_mul(r, _G))
    h = int.from_bytes(_sha512(r_enc + pub + message), "little") % _Q
    s = (r + h * a) % _Q
    return r_enc + int.to_bytes(s, 32, "little")
