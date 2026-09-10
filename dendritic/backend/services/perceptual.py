"""Perceptual image fingerprint + Manhattan-distance matching.

The rest of the codebase only had EXACT SHA-256 media blocking. This adds a
fuzzy fingerprint so near-duplicate images (re-encoded, rescaled, lightly
edited) can be banned by distance rather than needing a byte-identical match,
and so that ban can be broadcast to NNTPChan peers who re-derive the same
fingerprint and measure the same distance.

Fingerprint = downscale to DIMS x DIMS greyscale, take the raw 0-255 value of
each cell in row-major order. Distance = Manhattan (L1) sum of |a_i - b_i| over
the DIMS*DIMS cells; the operator-facing threshold is the AVERAGE per-cell
difference (0-255), which is resolution-independent and intuitive.
"""
import io

ALGORITHM = "graygrid1"
DIMS = 16                      # 16x16 = 256 cells
_VECTOR_LEN = DIMS * DIMS
DEFAULT_THRESHOLD = 10.0       # average per-cell abs difference (0-255)


def _lanczos():
    try:
        from PIL import Image
        return Image.Resampling.LANCZOS  # Pillow >= 9.1
    except (ImportError, AttributeError):
        try:
            from PIL import Image
            return Image.LANCZOS
        except Exception:
            return None


def compute_vector(image_bytes):
    """Return the DIMS*DIMS greyscale value vector for image bytes, or None."""
    if not image_bytes:
        return None
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            image = image.convert("L")
            resample = _lanczos()
            if resample is not None:
                image = image.resize((DIMS, DIMS), resample)
            else:
                image = image.resize((DIMS, DIMS))
            vector = list(image.getdata())
    except Exception:
        return None
    if len(vector) != _VECTOR_LEN:
        return None
    return [int(v) & 0xFF for v in vector]


def encode_vector(vector):
    """Vector -> hex string (2 hex chars per cell)."""
    if not vector:
        return None
    return bytes(int(v) & 0xFF for v in vector).hex()


def decode_vector(hex_string):
    """Hex string -> vector, or None if malformed / wrong length."""
    if not hex_string:
        return None
    try:
        raw = bytes.fromhex(hex_string.strip())
    except (ValueError, AttributeError):
        return None
    if len(raw) != _VECTOR_LEN:
        return None
    return list(raw)


def manhattan(a, b):
    """L1 distance between two equal-length vectors (raw sum)."""
    if not a or not b or len(a) != len(b):
        return None
    return sum(abs(int(x) - int(y)) for x, y in zip(a, b))


def average_distance(a, b):
    """Manhattan distance normalized to average per-cell difference (0-255)."""
    total = manhattan(a, b)
    if total is None:
        return None
    return total / float(len(a))


def compute_fingerprint(image_bytes):
    """Convenience: (algorithm, dims, hex_fingerprint) for image bytes, or None."""
    vector = compute_vector(image_bytes)
    if vector is None:
        return None
    return ALGORITHM, DIMS, encode_vector(vector)
