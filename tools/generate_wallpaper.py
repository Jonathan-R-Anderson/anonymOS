#!/usr/bin/env python3
"""Convert cfwallpaper images into a D source module for the desktop wallpaper.

The script intentionally avoids external dependencies so it can run in the
build environment without pulling additional packages. It supports
non-interlaced 8-bit PNG files in RGB or RGBA format and basic GIF89a files
with a global or local palette.
"""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path
from typing import NamedTuple


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
GIF_SIGNATURES = (b"GIF87a", b"GIF89a")


class PngDecodeError(RuntimeError):
    pass


class GifDecodeError(RuntimeError):
    pass


class Frame(NamedTuple):
    duration_ms: int
    pixels: bytes  # ARGB32, row-major


def _paeth_predictor(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _read_png(path: Path) -> tuple[int, int, list[Frame]]:
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise PngDecodeError("Not a PNG file")

    offset = len(PNG_SIGNATURE)
    width = height = None
    bit_depth = color_type = None
    idat_chunks: list[bytes] = []

    while offset < len(data):
        if offset + 8 > len(data):
            raise PngDecodeError("Truncated PNG chunk header")
        length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        offset += 8
        if offset + length + 4 > len(data):
            raise PngDecodeError("Truncated PNG chunk body")
        chunk_data = data[offset : offset + length]
        offset += length + 4  # skip CRC

        if chunk_type == b"IHDR":
            if length < 13:
                raise PngDecodeError("Invalid IHDR length")
            width, height, bit_depth, color_type, comp, filt, interlace = struct.unpack(
                ">IIBBBBB", chunk_data[:13]
            )
            if comp != 0 or filt != 0 or interlace != 0:
                raise PngDecodeError("Unsupported PNG compression/filter/interlace settings")
        elif chunk_type == b"IDAT":
            idat_chunks.append(chunk_data)
        elif chunk_type == b"IEND":
            break

    if width is None or height is None or bit_depth is None or color_type is None:
        raise PngDecodeError("Missing IHDR")
    if bit_depth != 8:
        raise PngDecodeError("Only 8-bit PNG files are supported")
    if color_type not in (2, 6):
        raise PngDecodeError("Only RGB or RGBA PNG files are supported")

    decompressed = zlib.decompress(b"".join(idat_chunks))
    pixel_size = 3 if color_type == 2 else 4
    stride = width * pixel_size
    expected = (stride + 1) * height
    if len(decompressed) != expected:
        raise PngDecodeError("Unexpected decompressed data length")

    output = bytearray(width * height * 4)
    prev = bytearray(stride)
    pos = 0
    out_pos = 0

    for _ in range(height):
        filter_type = decompressed[pos]
        pos += 1
        row = bytearray(decompressed[pos : pos + stride])
        pos += stride

        if filter_type == 1:  # Sub
            for i in range(stride):
                left = row[i - pixel_size] if i >= pixel_size else 0
                row[i] = (row[i] + left) & 0xFF
        elif filter_type == 2:  # Up
            for i in range(stride):
                row[i] = (row[i] + prev[i]) & 0xFF
        elif filter_type == 3:  # Average
            for i in range(stride):
                left = row[i - pixel_size] if i >= pixel_size else 0
                up = prev[i]
                row[i] = (row[i] + ((left + up) // 2)) & 0xFF
        elif filter_type == 4:  # Paeth
            for i in range(stride):
                a = row[i - pixel_size] if i >= pixel_size else 0
                b = prev[i]
                c = prev[i - pixel_size] if i >= pixel_size else 0
                row[i] = (row[i] + _paeth_predictor(a, b, c)) & 0xFF
        elif filter_type != 0:
            raise PngDecodeError(f"Unsupported PNG filter type {filter_type}")

        for i in range(0, stride, pixel_size):
            r, g, b = row[i : i + 3]
            a = 255 if pixel_size == 3 else row[i + 3]
            output[out_pos : out_pos + 4] = bytes((a, r, g, b))
            out_pos += 4

        prev = row

    frame = Frame(100, bytes(output))  # Static PNG, arbitrary default duration
    return width, height, [frame]


def _read_subblocks(data: bytes, offset: int) -> tuple[bytes, int]:
    chunks: list[bytes] = []
    while True:
        if offset >= len(data):
            raise GifDecodeError("Unexpected end of GIF data")
        size = data[offset]
        offset += 1
        if size == 0:
            break
        if offset + size > len(data):
            raise GifDecodeError("Truncated GIF sub-block")
        chunks.append(data[offset : offset + size])
        offset += size
    return b"".join(chunks), offset


def _parse_palette(raw: bytes) -> list[tuple[int, int, int, int]]:
    if len(raw) % 3 != 0:
        raise GifDecodeError("Palette length is not a multiple of 3")
    palette = []
    for i in range(0, len(raw), 3):
        r, g, b = raw[i : i + 3]
        palette.append((r, g, b, 255))
    return palette


def _lzw_decode(min_code_size: int, data: bytes, expected_pixels: int) -> list[int]:
    clear_code = 1 << min_code_size
    end_code = clear_code + 1
    code_size = min_code_size + 1
    next_code = end_code + 1
    max_code = 1 << code_size

    dictionary = {i: bytes([i]) for i in range(clear_code)}

    output: list[int] = []
    bit_pos = 0
    data_bits = len(data) * 8
    prev_code: int | None = None

    def read_code() -> int | None:
        nonlocal bit_pos
        if bit_pos + code_size > data_bits:
            return None
        raw = 0
        for i in range(code_size):
            byte_index = (bit_pos + i) // 8
            bit_index = (bit_pos + i) % 8
            raw |= ((data[byte_index] >> bit_index) & 1) << i
        bit_pos += code_size
        return raw

    while True:
        code = read_code()
        if code is None:
            break
        if code == clear_code:
            dictionary = {i: bytes([i]) for i in range(clear_code)}
            code_size = min_code_size + 1
            next_code = end_code + 1
            max_code = 1 << code_size
            prev_code = None
            continue
        if code == end_code:
            break

        if code in dictionary:
            entry = dictionary[code]
        elif prev_code is not None and code == next_code:
            entry = dictionary[prev_code] + dictionary[prev_code][:1]
        else:
            raise GifDecodeError("Invalid LZW code encountered")

        output.extend(entry)

        if prev_code is not None:
            dictionary[next_code] = dictionary[prev_code] + entry[:1]
            next_code += 1
            if next_code >= max_code and code_size < 12:
                code_size += 1
                max_code = 1 << code_size

        prev_code = code

        if len(output) >= expected_pixels:
            break

    return output[:expected_pixels]


def _deinterlace(indexes: list[int], width: int, height: int) -> list[int]:
    out = [0] * (width * height)
    pos = 0
    for start, step in ((0, 8), (4, 8), (2, 4), (1, 2)):
        for y in range(start, height, step):
            row_start = y * width
            out[row_start : row_start + width] = indexes[pos : pos + width]
            pos += width
    return out


def _read_gif(path: Path) -> tuple[int, int, list[Frame]]:
    data = path.read_bytes()
    if data[:6] not in GIF_SIGNATURES:
        raise GifDecodeError("Not a GIF file")
    if len(data) < 13:
        raise GifDecodeError("Truncated GIF header")

    width, height, packed, bg_index, _ = struct.unpack("<HHBBB", data[6:13])
    gct_flag = bool(packed & 0x80)
    gct_size = 2 ** ((packed & 0x07) + 1) if gct_flag else 0
    offset = 13

    global_palette: list[tuple[int, int, int, int]] = []
    if gct_flag:
        palette_bytes = data[offset : offset + 3 * gct_size]
        if len(palette_bytes) < 3 * gct_size:
            raise GifDecodeError("Truncated global color table")
        global_palette = _parse_palette(palette_bytes)
        offset += 3 * gct_size

    background_color = 0xFF000000
    if global_palette and bg_index < len(global_palette):
        r, g, b, a = global_palette[bg_index]
        background_color = (a << 24) | (r << 16) | (g << 8) | b

    frames: list[Frame] = []
    canvas = [background_color] * (width * height)

    gce_delay_ms = 100
    gce_transparent: int | None = None
    gce_disposal = 0

    while offset < len(data):
        block_introducer = data[offset]
        offset += 1

        if block_introducer == 0x3B:  # Trailer
            break
        if block_introducer == 0x21:  # Extension
            if offset >= len(data):
                raise GifDecodeError("Unexpected end of GIF in extension")
            label = data[offset]
            offset += 1
            if label == 0xF9:  # Graphic Control Extension
                if offset >= len(data):
                    raise GifDecodeError("Truncated graphic control extension")
                block_size = data[offset]
                offset += 1
                if block_size != 4:
                    raise GifDecodeError("Invalid graphic control block size")
                packed, delay_cs, transparent_index = struct.unpack(
                    "<BHB", data[offset : offset + 4]
                )
                offset += 4
                if offset >= len(data) or data[offset] != 0:
                    raise GifDecodeError("Missing graphic control terminator")
                offset += 1

                gce_disposal = (packed >> 2) & 0x07
                gce_transparent = transparent_index if (packed & 0x01) else None
                delay_ms = delay_cs * 10
                gce_delay_ms = delay_ms if delay_ms > 0 else 100
            else:
                _, offset = _read_subblocks(data, offset)
            continue

        if block_introducer != 0x2C:
            raise GifDecodeError(f"Unsupported GIF block {block_introducer:#x}")

        if offset + 9 > len(data):
            raise GifDecodeError("Truncated image descriptor")
        left, top, frame_w, frame_h, packed = struct.unpack("<HHHHB", data[offset : offset + 9])
        offset += 9

        lct_flag = bool(packed & 0x80)
        interlace_flag = bool(packed & 0x40)
        lct_size = 2 ** ((packed & 0x07) + 1) if lct_flag else 0

        palette = global_palette
        if lct_flag:
            lct_bytes = data[offset : offset + 3 * lct_size]
            if len(lct_bytes) < 3 * lct_size:
                raise GifDecodeError("Truncated local color table")
            palette = _parse_palette(lct_bytes)
            offset += 3 * lct_size

        if not palette:
            raise GifDecodeError("No color table available for frame")

        if offset >= len(data):
            raise GifDecodeError("Missing LZW minimum code size")
        lzw_min = data[offset]
        offset += 1

        compressed, offset = _read_subblocks(data, offset)
        expected_pixels = frame_w * frame_h
        indexes = _lzw_decode(lzw_min, compressed, expected_pixels)
        if len(indexes) < expected_pixels:
            raise GifDecodeError("Decoded pixel data is too short")

        if interlace_flag:
            indexes = _deinterlace(indexes, frame_w, frame_h)

        prev_canvas = list(canvas)
        working = list(canvas)

        for y in range(frame_h):
            dest_y = top + y
            if dest_y >= height:
                continue
            row_offset = y * frame_w
            for x in range(frame_w):
                dest_x = left + x
                if dest_x >= width:
                    continue
                color_idx = indexes[row_offset + x]
                if gce_transparent is not None and color_idx == gce_transparent:
                    continue
                if color_idx >= len(palette):
                    raise GifDecodeError("Color index out of range")
                r, g, b, a = palette[color_idx]
                working[dest_y * width + dest_x] = (a << 24) | (r << 16) | (g << 8) | b

        # Capture the fully composited frame.
        frame_bytes = bytearray(width * height * 4)
        for i, color in enumerate(working):
            struct.pack_into(">I", frame_bytes, i * 4, color)
        frames.append(Frame(gce_delay_ms, bytes(frame_bytes)))

        # Apply disposal method for the next frame.
        if gce_disposal == 2:  # Restore to background
            for y in range(frame_h):
                dest_y = top + y
                if dest_y >= height:
                    continue
                for x in range(frame_w):
                    dest_x = left + x
                    if dest_x >= width:
                        continue
                    working[dest_y * width + dest_x] = background_color
            canvas = working
        elif gce_disposal == 3:  # Restore to previous
            canvas = prev_canvas
        else:  # None or keep
            canvas = working

    if not frames:
        raise GifDecodeError("No frames found in GIF")

    return width, height, frames


def _write_d_module(out_path: Path, width: int, height: int, frames: list[Frame]) -> None:
    if not frames:
        raise RuntimeError("No frames to write")

    duration_values = ", ".join(str(frame.duration_ms) for frame in frames)

    frame_defs: list[str] = []
    frame_names: list[str] = []
    for idx, frame in enumerate(frames):
        values = [f"0x{int.from_bytes(frame.pixels[i:i+4], 'big'):08X}" for i in range(0, len(frame.pixels), 4)]
        lines = []
        for i in range(0, len(values), 8):
            lines.append(", ".join(values[i : i + 8]))
        frame_defs.append(
            f"enum uint[] wallpaperFrame{idx} = [\n    {"\n    ".join(lines)}\n];"
        )
        frame_names.append(f"wallpaperFrame{idx}")

    content = f"""// Auto-generated by tools/generate_wallpaper.py. Do not edit by hand.
module minimal_os.display.generated_wallpaper;

import minimal_os.display.wallpaper_types;

nothrow:
@nogc:

enum uint wallpaperWidth  = {width};
enum uint wallpaperHeight = {height};

enum uint[] wallpaperFrameDurations = [{duration_values}];

{"\n\n".join(frame_defs)}

enum const(uint[])[] wallpaperFrames = [
    {"\n    ".join(frame_names)}
];
"""
    out_path.write_text(content)


def _read_image(path: Path) -> tuple[int, int, list[Frame]]:
    with path.open("rb") as handle:
        header = handle.read(6)
    if header.startswith(PNG_SIGNATURE):
        return _read_png(path)
    if header in GIF_SIGNATURES:
        return _read_gif(path)
    raise RuntimeError("Unsupported wallpaper format. Please use PNG or GIF.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Embed cfwallpaper.gif or cfwallpaper.png as D source")
    parser.add_argument(
        "--input",
        default="cfwallpaper.gif",
        type=Path,
        help="Path to the wallpaper (GIF or PNG)",
    )
    parser.add_argument(
        "--output",
        default=Path("src/minimal_os/display/generated_wallpaper.d"),
        type=Path,
        help="Destination D module",
    )
    args = parser.parse_args()

    try:
        width, height, frames = _read_image(args.input)
    except (OSError, RuntimeError, PngDecodeError, GifDecodeError) as exc:  # noqa: PERF203
        parser.error(str(exc))
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_d_module(args.output, width, height, frames)
    print(
        f"Wrote wallpaper module to {args.output} ({width}x{height}, {len(frames)} frame{'s' if len(frames) != 1 else ''})"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
