"""keccak-256, written from FIPS-202 / the Keccak reference permutation.

Independent of the Go tree on purpose: E8.3 asks for a second implementation
written from the specification, and §11.3.2 fixes keccak for `nameHash` and
§11.3.3 for the skeleton, so a second implementation that imported the first
one's hash would not be second at all.

Note this is keccak-256 (padding byte 0x01), NOT SHA3-256 (0x06) — the
Ethereum variant §2 fixes for chain interop.  hashlib.sha3_256 is the other
one and would silently produce a different digest.
"""

_MASK = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# r[x][y] rotation offsets, indexed the same way the state is: A[x + 5*y].
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK


def _keccak_f1600(a):
    for rnd in range(24):
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ (
                    (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]
                )
        # iota
        a[0] ^= _RC[rnd]
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088 bits, capacity 512
    a = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)                       # keccak padding, not SHA3's 0x06
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            a[i] ^= lane
        _keccak_f1600(a)
    out = b"".join(a[i].to_bytes(8, "little") for i in range(4))  # 32 bytes
    return out[:32]


if __name__ == "__main__":
    vectors = {
        b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        b"testing": "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02",
    }
    for msg, want in vectors.items():
        got = keccak256(msg).hex()
        print(("ok  " if got == want else "FAIL"), msg, got)
        assert got == want, (msg, got, want)
    print("keccak-256 self-test passed")
