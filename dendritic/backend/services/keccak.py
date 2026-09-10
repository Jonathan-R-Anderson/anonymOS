"""keccak-256, the hash Ethereum uses.

The runtime has no keccak library, and `hashlib.sha3_256` is NOT a substitute:
SHA3 pads with 0x06 where keccak pads with 0x01, so it is a different function
that produces plausible-looking but wrong digests — wrong function selectors,
wrong node ids, wrong epoch randomness, all of which fail silently against
anything that computes them correctly.

So it is implemented here, in about sixty lines, and checked against published
vectors on import in the tests. Sixty lines of arithmetic with a known answer is
a smaller risk than a dependency the image does not have.
"""
RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
      0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
      0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
      0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
      0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
      0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
R = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
M = (1 << 64) - 1
def rol(x, n): return ((x << n) | (x >> (64 - n))) & M
def f(A):
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x-1) % 5] ^ rol(C[(x+1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5): A[x][y] ^= D[x]
        B = [[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5): B[y][(2*x + 3*y) % 5] = rol(A[x][y], R[x][y])
        for x in range(5):
            for y in range(5): A[x][y] = B[x][y] ^ ((~B[(x+1) % 5][y]) & M & B[(x+2) % 5][y])
        A[0][0] ^= RC[rnd]
    return A
def keccak256(data: bytes) -> bytes:
    rate = 136
    data = bytearray(data)
    data.append(0x01)                      # keccak padding, not 0x06
    while len(data) % rate != 0: data.append(0x00)
    data[-1] ^= 0x80
    A = [[0]*5 for _ in range(5)]
    for off in range(0, len(data), rate):
        blk = data[off:off+rate]
        for i in range(rate // 8):
            lane = int.from_bytes(blk[i*8:(i+1)*8], "little")
            A[i % 5][i // 5] ^= lane
        A = f(A)
    out = b""
    for i in range(4):
        out += A[i % 5][i // 5].to_bytes(8, "little")
    return out[:32]
def selector(sig):
    """The 4-byte function selector for a Solidity signature, as hex."""
    return keccak256(sig.encode()).hex()[:8]
def keccak_hex(*parts):
    """keccak256 over the concatenation, as a 0x-prefixed hex string."""
    return "0x" + keccak256(b"".join(parts)).hex()
