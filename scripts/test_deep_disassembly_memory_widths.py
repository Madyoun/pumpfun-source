"""LDX/ST/STX size suffixes in scripts/deep_disassembly.py.

BPF size field (opcode & 0x18): 0x00 = W, 0x08 = H, 0x10 = B, 0x18 = DW.
This matches scripts/deep_section_analysis.py ({0x61: 4, 0x69: 2, 0x71: 1,
0x79: 8}) and the reviewed successor in
research/deep-disassembly-memory-widths/generate.py.
"""
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deep_disassembly import decode_instruction  # noqa: E402

ELF = SimpleNamespace(funcs=[], relocations={})


def mnemonic(opcode):
    b = bytes([opcode, 0x12, 0, 0]) + struct.pack("<i", 0)
    rec, _ = decode_instruction(b, 0, ELF)
    return rec["mnemonic"].split()[0]


class TestMemoryWidths(unittest.TestCase):
    def test_ldx_sizes(self):
        self.assertEqual(mnemonic(0x61), "ldxw")
        self.assertEqual(mnemonic(0x69), "ldxh")
        self.assertEqual(mnemonic(0x71), "ldxb")
        self.assertEqual(mnemonic(0x79), "ldxdw")

    def test_stx_shares_size_map(self):
        # STX class 0x03 uses the same size_map branch as LDX.
        self.assertEqual(mnemonic(0x63), "stxw")
        self.assertEqual(mnemonic(0x7B), "stxdw")


if __name__ == "__main__":
    unittest.main()
