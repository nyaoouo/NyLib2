from __future__ import annotations

import pytest

from nylib.imguiutils.debug_view.formats import (
    AddressFormat,
    MemCellSize,
    MemFormat,
    format_address,
    format_cell,
    snap_pow2_in,
)


def test_address_format_hex_default():
    assert format_address(0x12345678ABCD, AddressFormat.HEX) == "0x000012345678ABCD"


def test_format_cell_u8_hex():
    assert format_cell(0x42, MemFormat(MemCellSize.U8, "hex")) == "42"


def test_format_cell_u32_hex():
    assert format_cell(0xDEADBEEF, MemFormat(MemCellSize.U32, "hex")) == "DEADBEEF"


def test_format_cell_u64_dec():
    assert format_cell(1234567890, MemFormat(MemCellSize.U64, "dec")) == "1234567890"


def test_format_cell_u16_dec_zero():
    assert format_cell(0, MemFormat(MemCellSize.U16, "dec")) == "0"


def test_snap_pow2_in_matches_max_fitting():
    assert snap_pow2_in({8, 16, 32, 64}, 50) == 32
    assert snap_pow2_in({8, 16, 32, 64}, 64) == 64
    assert snap_pow2_in({8, 16, 32, 64}, 3) == 8     # below min returns min
    assert snap_pow2_in({8, 16, 32, 64}, 1000) == 64 # above max returns max


from nylib.imguiutils.debug_view.formats import parse_address


def test_parse_address_hex_prefixed():
    assert parse_address("0x1234") == 0x1234


def test_parse_address_hex_plain():
    assert parse_address("1234") == 0x1234        # plain numbers always hex


def test_parse_address_garbage():
    assert parse_address("garbage") is None


def test_parse_address_empty():
    assert parse_address("") is None
    assert parse_address("   ") is None


class _FakeLdr:
    def __init__(self, name, base, size):
        self._name = name
        self.DllBase = base
        self.SizeOfImage = size
        self.BaseDllName = self

    def remote_value(self, _proc):
        return self._name


class _FakeProc:
    def __init__(self, modules):
        self._modules = modules

    def enum_ldr_data(self):
        return iter(self._modules)


def test_parse_address_module_offset():
    proc = _FakeProc([_FakeLdr("mymod.exe", 0x140000000, 0x100000)])
    assert parse_address("mymod.exe+0x1234", proc=proc) == 0x140001234


def test_parse_address_unknown_module():
    proc = _FakeProc([])
    assert parse_address("missing.exe+0x10", proc=proc) is None
