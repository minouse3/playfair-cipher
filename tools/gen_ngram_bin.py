#!/usr/bin/env python3
"""Build a dense quantized quadgram table for the standalone Playfair breaker.

Reads an n-gram text table ("QUAD count" per line) and writes a flat
16-bit-quantized binary over the full 26-letter alphabet (A=0..Z=25),
size 26^4 = 456976 entries, little-endian uint16.

Layout used by the C++ side:
    value[i] = floor + q[i] * scale      (q in 0..65535)
where floor = log10(0.01 / total) is the "unseen n-gram" penalty and
scale = (max - floor) / 65535.

Usage: python gen_ngram_bin.py <english_quadgrams.txt> <out.bin>
"""
import sys
import struct


def main():
    if len(sys.argv) != 3:
        print("usage: gen_ngram_bin.py <quadgrams.txt> <out.bin>")
        return 1
    src, dst = sys.argv[1], sys.argv[2]

    N = 26
    size = N ** 4
    counts = [0.0] * size

    pow3 = [N ** 3, N ** 2, N ** 1, 1]
    total = 0.0
    n_lines = 0
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            gram, cnt = parts[0], parts[1]
            if len(gram) != 4:
                continue
            idx = 0
            ok = True
            for i, ch in enumerate(gram):
                c = ord(ch.upper()) - 65
                if c < 0 or c >= N:
                    ok = False
                    break
                idx += c * pow3[i]
            if not ok:
                continue
            try:
                v = float(cnt)
            except ValueError:
                continue
            counts[idx] += v
            total += v
            n_lines += 1

    if total <= 0:
        print("no data read")
        return 1

    import math
    floor = math.log10(0.01 / total)
    vals = [0.0] * size
    maxv = floor
    seen = 0
    for i in range(size):
        if counts[i] > 0:
            vals[i] = math.log10(counts[i] / total)
            seen += 1
            if vals[i] > maxv:
                maxv = vals[i]
        else:
            vals[i] = floor

    span = maxv - floor
    if span <= 0:
        span = 1.0
    scale = span / 65535.0

    payload = bytearray(size * 2)
    for i in range(size):
        q = int(round((vals[i] - floor) / scale))
        if q < 0:
            q = 0
        elif q > 65535:
            q = 65535
        struct.pack_into("<H", payload, i * 2, q)

    # 16-byte header: double floor, double scale (little-endian), then the payload.
    header = struct.pack("<dd", floor, scale)
    with open(dst, "wb") as f:
        f.write(header)
        f.write(payload)

    print(f"read {n_lines} lines, {seen}/{size} cells seen")
    print(f"total={total:.1f} floor={floor:.6f} max={maxv:.6f} scale={scale:.8g}")
    print(f"wrote {dst} ({len(header) + len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())