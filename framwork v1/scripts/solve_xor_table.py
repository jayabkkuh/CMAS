#!/usr/bin/env python3
"""Invert the XOR/offset transformation used in jumpjump.elf."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List


def invert_table(data: List[int], xor_const: int, adjust: int, post_xor: int) -> bytes:
    result = []
    for value in data:
        mutated = ((value ^ post_xor) - adjust) & 0xFF
        original = mutated ^ xor_const
        result.append(original)
    return bytes(result)


def read_table(path: Path, offset: int, length: int) -> List[int]:
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length * 4)
        if len(data) < length * 4:
            raise ValueError("Table shorter than expected")
        return [int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Invert XOR comparison table")
    parser.add_argument("binary", type=Path, help="Path to ELF binary")
    parser.add_argument("--offset", type=lambda x: int(x, 0), default=0x4CC100)
    parser.add_argument("--length", type=int, default=0x24)
    parser.add_argument("--xor-const", type=lambda x: int(x, 0), default=0x57)
    parser.add_argument("--post-xor", type=lambda x: int(x, 0), default=0x33)
    parser.add_argument("--adjust", type=int, default=4)
    args = parser.parse_args()

    table = read_table(args.binary, args.offset, args.length)
    flag = invert_table(table, args.xor_const, args.adjust, args.post_xor)
    print(flag.decode("utf-8"))


if __name__ == "__main__":
    main()
