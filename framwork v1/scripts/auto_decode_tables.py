#!/usr/bin/env python3
"""
Heuristic flag decoder for table-compare style binaries.

It scans the input binary for contiguous sequences of small integers
(<= 0x100) stored as 32-bit little-endian words or as raw bytes, and tries
simple transform inversions to recover a plausible flag string.

Transforms attempted (per element x):
- (x ^ Kx) - Ka
- ((x + Ka) & 0xff) ^ Kx
- x ^ (Kx ^ i)
- x ^ ((Kx + i) & 0xff)

If a decode yields a string that looks like a CTF flag (e.g., d3ctf{...},
flag{...}, ctf{...}), it prints it and exits with code 0.

Usage:
  python3 scripts/auto_decode_tables.py <binary>

Exit status is 0 on success (flag printed), 1 otherwise.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def find_smallint_sequences_le32(data: bytes, min_len: int = 12) -> List[List[int]]:
    seqs: List[List[int]] = []
    cur: List[int] = []
    n = len(data)
    for i in range(0, n - 3, 4):
        v = int.from_bytes(data[i : i + 4], "little", signed=False)
        if v <= 0x100:
            cur.append(v)
        else:
            if len(cur) >= min_len:
                seqs.append(cur[:])
            cur = []
    if len(cur) >= min_len:
        seqs.append(cur)
    return seqs


def find_smallbyte_sequences(data: bytes, min_len: int = 12) -> List[List[int]]:
    seqs: List[List[int]] = []
    cur: List[int] = []
    for b in data:
        if b <= 0x100:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                seqs.append(cur[:])
            cur = []
    if len(cur) >= min_len:
        seqs.append(cur)
    return seqs


def score_candidate(s: str) -> int:
    s = s.strip()
    score = 0
    if not s:
        return 0
    # printable ratio
    printable = sum(1 for ch in s if 32 <= ord(ch) <= 126)
    score += printable
    # common flag heads
    for head in ("d3ctf{", "flag{", "ctf{", "d3ctf{", "D3CTF{"):
        if s.startswith(head):
            score += 200
    # balanced braces
    score += 50 if ("{" in s and "}" in s) else 0
    return score


def try_decoders(seq: List[int]) -> Optional[str]:
    # Try window sizes to reduce false positives
    windows = [min(len(seq), L) for L in (24, 28, 32, 40, 48, 64)]
    windows = sorted(set(windows))
    best: Tuple[int, str] | None = None

    xor_keys = [0x00, 0x13, 0x21, 0x33, 0x42, 0x57, 0xAA, 0xFF]
    add_keys = [0, 1, 2, 3, 4]

    def decode_full(mode: int, kx: int, ka: int) -> str:
        out: List[int] = []
        for i, x in enumerate(seq):
            if mode == 0:
                y = ((x ^ kx) - ka) & 0xFF
            elif mode == 1:
                y = (((x + ka) & 0xFF) ^ kx) & 0xFF
            elif mode == 2:
                y = x ^ (kx ^ (i & 0xFF))
            else:
                y = x ^ ((kx + i) & 0xFF)
            out.append(y)
        try:
            return bytes(out).decode("utf-8", errors="ignore")
        except Exception:
            return bytes(out).decode("latin-1", errors="ignore")

    for W in windows:
        head = seq[:W]
        for kx in xor_keys:
            for ka in add_keys:
                # mode 0
                h0 = [((x ^ kx) - ka) & 0xFF for x in head]
                s0 = bytes(h0).decode("latin-1", errors="ignore")
                if score_candidate(s0) >= 220:
                    full = decode_full(0, kx, ka)
                    return full
                # mode 1
                h1 = [(((x + ka) & 0xFF) ^ kx) & 0xFF for x in head]
                s1 = bytes(h1).decode("latin-1", errors="ignore")
                if score_candidate(s1) >= 220:
                    full = decode_full(1, kx, ka)
                    return full
                # mode 2 and 3 use index i
                h2 = [x ^ (kx ^ (i & 0xFF)) for i, x in enumerate(head)]
                s2 = bytes(h2).decode("latin-1", errors="ignore")
                if score_candidate(s2) >= 220:
                    full = decode_full(2, kx, ka)
                    return full
                h3 = [x ^ ((kx + i) & 0xFF) for i, x in enumerate(head)]
                s3 = bytes(h3).decode("latin-1", errors="ignore")
                if score_candidate(s3) >= 220:
                    full = decode_full(3, kx, ka)
                    return full
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Auto-decode small-int tables for flags")
    ap.add_argument("binary", type=Path)
    args = ap.parse_args()

    data = read_bytes(args.binary)
    seqs = []
    seqs.extend(find_smallint_sequences_le32(data, min_len=12))
    # Also try raw byte sequences in case table stored byte-wise
    seqs.extend(find_smallbyte_sequences(data, min_len=24))

    for seq in seqs:
        decoded = try_decoders(seq)
        if not decoded:
            continue
        # Normalize to d3ctf{...} if shape looks right
        text = decoded.strip()
        if "{" in text and "}" in text and not text.lower().startswith("d3ctf{"):
            body = text.strip().strip("{}")
            text = f"d3ctf{{{body}}}"
        print(text)
        return

    raise SystemExit(1)


if __name__ == "__main__":
    main()

