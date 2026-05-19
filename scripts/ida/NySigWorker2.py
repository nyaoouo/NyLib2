"""NySigWorker2 helpers for generating and validating AOB signatures in IDA.

Useful entry points for external scripts:
- `make_sig(target_ea, compare_exe=None, options=None, logger=print)`
    Generate candidate signatures for a target address and return `SignatureResult` objects.
- `search_sig(signature, limit=100, language=DEFAULT_LANGUAGE, logger=print)`
    Search a signature in the current IDB and return the matched addresses and captured values.
- `compile_pattern(pattern)`
    Compile the extended NySigWorker pattern syntax for reuse in custom scanners.
- `SignatureOptions`
    Configure signature generation, fallback nesting, validation, and UI language behavior.
- `RawPatternScanner` / `IdaPatternScanner`
    Reuse the extended pattern engine against raw bytes or the current IDB.
- `main()`
    Open the interactive dialog inside IDA.

The module can be imported from other IDAPython scripts or run directly as an IDA plugin.
"""

from __future__ import annotations

import functools
import io
import os
import re
import sys
import traceback
import types
import typing
from dataclasses import dataclass

try:
    try:
        from PySide6 import QtCore, QtWidgets
        QT_BINDING = "PySide6"
    except ImportError:
        from PyQt5 import QtCore, QtWidgets
        QT_BINDING = "PyQt5"
except ImportError:
    QtCore = None
    QtWidgets = None
    QT_BINDING = None

import idaapi
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import ida_ua
import ida_xref
import idc
from idautils import XrefsFrom, XrefsTo


BADADDR = ida_idaapi.BADADDR
HEX_TOKENS = [f"{i:02x}" for i in range(256)]
CODE_FLOW_XREFS = {
    ida_xref.fl_CF,
    ida_xref.fl_CN,
    ida_xref.fl_JF,
    ida_xref.fl_JN,
    ida_xref.fl_F,
}
SIGNATURE_XREFS = CODE_FLOW_XREFS | {
    ida_xref.dr_R,
    ida_xref.dr_W,
    ida_xref.dr_T,
    ida_xref.dr_O,
}

FLAG_IS_REF = 1 << 0
FLAG_IS_BYTES = 1 << 1
FLAG_STORE = 1 << 2

HEX_CHARS = set(b"0123456789abcdefABCDEF")
DEC_CHARS = set(b"0123456789")
REGEX_SPECIAL_BYTES = set(b"()[]{}?*+-|^$\\.&~# \t\n\r\v\f")
OFFSET_SUFFIX_RE = re.compile(r"\s+\+\s*(0x[0-9a-fA-F]+|\d+)\s*$")
NATIVE_UNSUPPORTED_CHARS = set("<>()[]{}^|:")

DEFAULT_LANGUAGE = "en"
TEXT = {
    "en": {
        "window_title": "NySigWorker2 ({binding})",
        "language": "Language",
        "make_aob": "Make AOB",
        "target": "Target",
        "target_placeholder": "0x140001000 or symbol_name",
        "here": "Here",
        "operand": "Operand",
        "generate": "Generate",
        "compare": "Compare",
        "compare_placeholder": "optional compare file",
        "browse": "Browse",
        "clear": "Clear",
        "options": "Options",
        "nested_refs": "Nested refs",
        "follow_refs": "Follow refs",
        "depth": "Depth",
        "sub_instr": "Sub instr",
        "workers": "Workers",
        "steps": "Steps",
        "found": "Found",
        "validate": "Validate",
        "search_aob": "Search AOB",
        "limit": "Limit",
        "search": "Search",
        "format": "Format",
        "output": "Output",
        "copy": "Copy",
        "clear_output": "Clear Output",
        "close": "Close",
        "file_dialog_title": "Select compare file",
        "file_dialog_filter": "All files (*.*)",
        "empty_address": "empty address",
        "invalid_cursor": "current cursor address is invalid",
        "invalid_address": "invalid address or name: {value}",
        "invalid_current_address": "[!] invalid current address",
        "no_operand_target": "[!] no IDB operand target at {ea:x}",
        "target_outside": "target outside IDB range: {ea:x}",
        "start_search": "[.] start search {ea:x} {name}",
        "active_workers": "[.] active workers: {count}",
        "found_candidates": "[+] found {count} candidate(s), minimum simple match count: {min_match}",
        "compare_file": "[.] compare file: {path}",
        "make_failed": "[!] failed to make signature at {ea:x}: {error}",
        "matches_for": "[+] {count} match(es) for {signature}",
        "result_limit": "[.] result output stopped at limit={limit}",
        "plugin_comment": "AOB signature finder with nested validation",
        "plugin_help": "Generate and search nested AOB signatures",
        "compare_count": "compare",
    },
    "zh": {
        "window_title": "NySigWorker2 ({binding})",
        "language": "语言",
        "make_aob": "生成 AOB",
        "target": "目标",
        "target_placeholder": "0x140001000 或 symbol_name",
        "here": "当前位置",
        "operand": "操作数",
        "generate": "生成",
        "compare": "对比",
        "compare_placeholder": "可选对比文件",
        "browse": "浏览",
        "clear": "清空",
        "options": "选项",
        "nested_refs": "嵌套引用",
        "follow_refs": "跟随引用",
        "depth": "深度",
        "sub_instr": "子指令",
        "workers": "工作器",
        "steps": "步数",
        "found": "候选",
        "validate": "验证",
        "search_aob": "搜索 AOB",
        "limit": "限制",
        "search": "搜索",
        "format": "格式",
        "output": "输出",
        "copy": "复制",
        "clear_output": "清空输出",
        "close": "关闭",
        "file_dialog_title": "选择对比文件",
        "file_dialog_filter": "所有文件 (*.*)",
        "empty_address": "地址为空",
        "invalid_cursor": "当前光标地址无效",
        "invalid_address": "无效地址或名称: {value}",
        "invalid_current_address": "[!] 当前地址无效",
        "no_operand_target": "[!] {ea:x} 处没有 IDB 内操作数目标",
        "target_outside": "目标超出 IDB 范围: {ea:x}",
        "start_search": "[.] 开始搜索 {ea:x} {name}",
        "active_workers": "[.] 活跃 worker: {count}",
        "found_candidates": "[+] 找到 {count} 个候选，最小简单匹配数: {min_match}",
        "compare_file": "[.] 对比文件: {path}",
        "make_failed": "[!] 生成签名失败 {ea:x}: {error}",
        "matches_for": "[+] {count} 个匹配: {signature}",
        "result_limit": "[.] 结果输出达到限制 limit={limit}",
        "plugin_comment": "带嵌套验证的 AOB 签名工具",
        "plugin_help": "生成和搜索多级 AOB 签名",
        "compare_count": "对比",
    },
}


def tr(language: str, key: str, **kwargs) -> str:
    table = TEXT.get(language, TEXT[DEFAULT_LANGUAGE])
    return table.get(key, TEXT[DEFAULT_LANGUAGE][key]).format(**kwargs)


def min_ea() -> int:
    return ida_ida.inf_get_min_ea()


def max_ea() -> int:
    return ida_ida.inf_get_max_ea()


def in_idb(ea: int) -> bool:
    return min_ea() <= ea < max_ea()


def format_ea(ea: int) -> str:
    return f"0x{ea:x}"


def get_exec_cache() -> types.ModuleType:
    if "__nysigworker2_cache__" not in sys.modules:
        sys.modules["__nysigworker2_cache__"] = types.ModuleType("__nysigworker2_cache__")
    return sys.modules["__nysigworker2_cache__"]


def load_bin_file(path: str) -> bytes:
    cache = get_exec_cache()
    if not hasattr(cache, "bin_file_cache"):
        cache.bin_file_cache = {}
    stat = os.stat(path)
    cache_key = (os.path.abspath(path), stat.st_mtime_ns, stat.st_size)
    if cache_key not in cache.bin_file_cache:
        with open(path, "rb") as file:
            cache.bin_file_cache.clear()
            cache.bin_file_cache[cache_key] = file.read()
    return cache.bin_file_cache[cache_key]


def split_signature_offset(signature: str) -> tuple[str, int]:
    signature = signature.strip()
    match = OFFSET_SUFFIX_RE.search(signature)
    if not match:
        return signature, 0
    return signature[:match.start()].strip(), int(match.group(1), 0)


def normalize_native_aob(pattern: str) -> str | None:
    if any(char in NATIVE_UNSUPPORTED_CHARS for char in pattern):
        return None
    return pattern.replace("*", "?")


def parse_ea(text: str, language: str = DEFAULT_LANGUAGE) -> int:
    value = text.strip()
    if not value:
        raise ValueError(tr(language, "empty_address"))
    if value.lower() in {"here", "$", "screen"}:
        ea = idc.here()
        if ea == BADADDR:
            raise ValueError(tr(language, "invalid_cursor"))
        return ea
    try:
        return int(value, 0)
    except ValueError:
        ea = ida_name.get_name_ea(BADADDR, value)
        if ea == BADADDR:
            raise ValueError(tr(language, "invalid_address", value=value))
        return ea


def first_operand_point(ea: int) -> int:
    for operand_index in range(2):
        value = idc.get_operand_value(ea, operand_index)
        if in_idb(value):
            return value
    raise StopIteration


def take_dec_number(pattern: str, index: int) -> tuple[int, int]:
    if index >= len(pattern) or ord(pattern[index]) not in DEC_CHARS:
        raise ValueError(f"Expected decimal number at {index} in {pattern!r}")
    end = index + 1
    while end < len(pattern) and ord(pattern[end]) in DEC_CHARS:
        end += 1
    return int(pattern[index:end]), end


def take_count(pattern: str, index: int, regex_pattern: bytearray) -> int:
    if index < len(pattern) and pattern[index] == "{":
        regex_pattern.append(ord("{"))
        first_count, index = take_dec_number(pattern, index + 1)
        regex_pattern.extend(str(first_count).encode("ascii"))
        if index < len(pattern) and pattern[index] == ":":
            second_count, index = take_dec_number(pattern, index + 1)
            if first_count > second_count:
                raise ValueError(f"Invalid count range {{{first_count}:{second_count}}}")
            regex_pattern.append(ord(","))
            regex_pattern.extend(str(second_count).encode("ascii"))
        if index >= len(pattern) or pattern[index] != "}":
            raise ValueError(f"Expected }} at {index} in {pattern!r}")
        regex_pattern.append(ord("}"))
        index += 1
    return index


def take_byte(pattern: str, index: int, regex_pattern: bytearray) -> int:
    if index + 2 > len(pattern):
        raise ValueError(f"Expected byte at {index} in {pattern!r}")
    token = pattern[index:index + 2]
    try:
        byte_value = int(token, 16)
    except ValueError as exc:
        raise ValueError(f"Invalid byte {token!r} at {index} in {pattern!r}") from exc
    if byte_value in REGEX_SPECIAL_BYTES:
        regex_pattern.append(ord("\\"))
    regex_pattern.append(byte_value)
    return index + 2


def take_unknown_run(pattern: str, index: int, regex_pattern: bytearray) -> tuple[str, int]:
    unknown_type = pattern[index]
    if unknown_type not in "?*^":
        raise ValueError(f"Expected wildcard at {index} in {pattern!r}")
    while index < len(pattern):
        if pattern[index] in " \t\r\n":
            index += 1
            continue
        if pattern[index] != unknown_type:
            break
        regex_pattern.append(ord("."))
        index += 1
        index = take_count(pattern, index, regex_pattern)
        while index < len(pattern) and pattern[index] in " \t\r\n":
            index += 1
    return unknown_type, index


def take_plain_group(pattern: str, index: int, close_char: str) -> tuple[bytes, int]:
    regex_pattern = bytearray()
    while index < len(pattern):
        char = pattern[index]
        if char in " \t\r\n":
            index += 1
        elif char == close_char:
            break
        elif char == "[":
            regex_pattern.append(ord("["))
            index += 1
            index = take_byte(pattern, index, regex_pattern)
            while True:
                if index >= len(pattern):
                    raise ValueError(f"Expected ] in {pattern!r}")
                char = pattern[index]
                if char in " \t\r\n":
                    index += 1
                elif char == "]":
                    regex_pattern.append(ord("]"))
                    index += 1
                    break
                elif char == "|":
                    index = take_byte(pattern, index + 1, regex_pattern)
                elif char == ":":
                    regex_pattern.append(ord("-"))
                    index = take_byte(pattern, index + 1, regex_pattern)
                else:
                    raise ValueError(f"Invalid character {char!r} in byte set at {index}")
        elif char in "?*^":
            _unknown_type, index = take_unknown_run(pattern, index, regex_pattern)
        elif ord(char) in HEX_CHARS:
            index = take_byte(pattern, index, regex_pattern)
            index = take_count(pattern, index, regex_pattern)
        else:
            raise ValueError(f"Invalid character {char!r} in group at {index}")
    return bytes(regex_pattern), index


@dataclass
class CaptureSpec:
    sub_pattern: "Pattern | None"
    flags: int


class Pattern:
    def __init__(self, regex: re.Pattern[bytes], captures: list[CaptureSpec], pattern: str):
        self.regex = regex
        self.captures = captures
        self.pattern = pattern
        self.res_is_ref: list[bool] = []
        for capture in captures:
            if capture.flags & FLAG_STORE:
                self.res_is_ref.append(bool(capture.flags & FLAG_IS_REF))
            if capture.sub_pattern is not None:
                self.res_is_ref.extend(capture.sub_pattern.res_is_ref)

    def finditer(
        self,
        data: bytes | bytearray,
        data_base: int = 0,
        resolver: typing.Callable[[int], tuple[bytes | bytearray, int] | None] | None = None,
    ) -> typing.Generator[tuple[int, list[typing.Any]], None, None]:
        for match in self.regex.finditer(data):
            result: list[typing.Any] = []
            if self._parse_match(data, data_base, match, result, resolver):
                yield data_base + match.start(0), result

    def _match(
        self,
        data: bytes | bytearray,
        data_base: int,
        start_index: int,
        result: list[typing.Any],
        resolver: typing.Callable[[int], tuple[bytes | bytearray, int] | None] | None = None,
    ) -> bool:
        match = self.regex.match(data, start_index)
        if not match:
            return False
        return self._parse_match(data, data_base, match, result, resolver)

    def _parse_match(
        self,
        data: bytes | bytearray,
        data_base: int,
        match: re.Match[bytes],
        result: list[typing.Any],
        resolver: typing.Callable[[int], tuple[bytes | bytearray, int] | None] | None = None,
    ) -> bool:
        for index, capture in enumerate(self.captures):
            group = match.group(index + 1)
            if capture.flags & FLAG_IS_BYTES:
                value: typing.Any = group
            else:
                value = int.from_bytes(group, "little", signed=True)
                if capture.flags & FLAG_IS_REF:
                    value += data_base + match.end(index + 1)

            if capture.flags & FLAG_STORE:
                result.append(value)

            if capture.sub_pattern is None:
                continue

            target_ea = value
            if not isinstance(target_ea, int):
                return False
            if resolver is not None:
                resolved = resolver(target_ea)
                if resolved is None:
                    return False
                sub_data, sub_base = resolved
            else:
                sub_data, sub_base = data, data_base
            start_index = target_ea - sub_base
            if start_index < 0 or start_index >= len(sub_data):
                return False
            if not capture.sub_pattern._match(sub_data, sub_base, start_index, result, resolver):
                return False
        return True

    def fmt(self, indent: str | int = " ", _level: int = 0) -> str:
        if isinstance(indent, int):
            indent = " " * indent
        output = io.StringIO()
        output.write(indent * _level)
        output.write(fmt_bytes_regex_pattern(self.regex.pattern))
        output.write("\n")
        output.write(indent * _level)
        output.write("res is ref:")
        for flag in self.res_is_ref:
            output.write(" ref" if flag else " val")
        output.write("\n")
        for index, capture in enumerate(self.captures):
            output.write(indent * _level)
            output.write(f"{index}:")
            output.write("ref" if capture.flags & FLAG_IS_REF else "val")
            if capture.flags & FLAG_IS_BYTES:
                output.write(" bytes")
            if capture.flags & FLAG_STORE:
                output.write(" store")
            output.write("\n")
            if capture.sub_pattern is not None:
                output.write(capture.sub_pattern.fmt(indent, _level + 1))
                output.write("\n")
        return output.getvalue().rstrip()


def fmt_bytes_regex_pattern(pattern: bytes) -> str:
    result = ""
    is_escape = False
    is_in_count = 0
    for byte_value in pattern:
        if is_escape:
            is_escape = False
            result += f"\\x{byte_value:02x}"
        elif byte_value == ord("\\"):
            is_escape = True
        elif byte_value in REGEX_SPECIAL_BYTES:
            if byte_value == ord("{"):
                is_in_count += 1
            elif byte_value == ord("}"):
                is_in_count -= 1
            result += chr(byte_value)
        elif is_in_count:
            result += chr(byte_value)
        else:
            result += f"\\x{byte_value:02x}"
    return result


def _compile_pattern(pattern: str, index: int = 0, ret_at: str | None = None) -> tuple[Pattern, int]:
    start_index = index
    regex_pattern = bytearray()
    captures: list[CaptureSpec] = []
    while index < len(pattern):
        char = pattern[index]
        if char in " \t\r\n":
            index += 1
        elif char == "[":
            regex_pattern.append(ord("["))
            index += 1
            index = take_byte(pattern, index, regex_pattern)
            while True:
                if index >= len(pattern):
                    raise ValueError(f"Expected ] in {pattern!r}")
                char = pattern[index]
                if char in " \t\r\n":
                    index += 1
                elif char == "]":
                    regex_pattern.append(ord("]"))
                    index += 1
                    break
                elif char == "|":
                    index = take_byte(pattern, index + 1, regex_pattern)
                elif char == ":":
                    regex_pattern.append(ord("-"))
                    index = take_byte(pattern, index + 1, regex_pattern)
                else:
                    raise ValueError(f"Invalid character {char!r} in byte set at {index}")
        elif char in "(<":
            close_char = ")" if char == "(" else ">"
            store = char == "<"
            regex_pattern.append(ord("("))
            index += 1
            while index < len(pattern) and pattern[index] in " \t\r\n":
                index += 1
            base_flag = FLAG_STORE if store else 0
            sub_pattern = None
            if index < len(pattern) and pattern[index] in "?*^":
                unknown_type, index = take_unknown_run(pattern, index, regex_pattern)
                if unknown_type == "*":
                    base_flag |= FLAG_IS_REF
                elif unknown_type == "^":
                    base_flag |= FLAG_IS_BYTES
                while index < len(pattern) and pattern[index] in " \t\r\n":
                    index += 1
                if index < len(pattern) and pattern[index] == ":":
                    sub_pattern, index = _compile_pattern(pattern, index + 1, ret_at=close_char)
                    while index < len(pattern) and pattern[index] in " \t\r\n":
                        index += 1
            else:
                group_regex, index = take_plain_group(pattern, index, close_char)
                regex_pattern.extend(group_regex)
                base_flag |= FLAG_IS_BYTES
            if index >= len(pattern) or pattern[index] != close_char:
                raise ValueError(f"Expected {close_char} at {index} in {pattern!r}")
            regex_pattern.append(ord(")"))
            captures.append(CaptureSpec(sub_pattern, base_flag))
            index += 1
        elif char in "?*^":
            regex_pattern.append(ord("("))
            unknown_type, index = take_unknown_run(pattern, index, regex_pattern)
            regex_pattern.append(ord(")"))
            if unknown_type == "?":
                flags = 0
            elif unknown_type == "*":
                flags = FLAG_IS_REF | FLAG_STORE
            else:
                flags = FLAG_IS_BYTES | FLAG_STORE
            captures.append(CaptureSpec(None, flags))
        elif ord(char) in HEX_CHARS:
            index = take_byte(pattern, index, regex_pattern)
            index = take_count(pattern, index, regex_pattern)
        elif char == ret_at:
            break
        else:
            formatted = pattern[:index] + "_" + pattern[index] + "_" + pattern[index + 1:]
            raise ValueError(f"Invalid character {char!r} in pattern {formatted!r} at {index}")
    try:
        regex = re.compile(bytes(regex_pattern), re.DOTALL)
    except re.error as exc:
        raise ValueError(f"{exc}: ({pattern!r}, {start_index}, {ret_at!r}) -> {bytes(regex_pattern)!r}") from exc
    return Pattern(regex, captures, pattern), index


@functools.lru_cache(maxsize=2048)
def compile_pattern(pattern: str) -> Pattern:
    compiled, index = _compile_pattern(pattern.strip())
    if index != len(pattern.strip()):
        raise ValueError(f"Trailing pattern data at {index} in {pattern!r}")
    return compiled


@dataclass
class ImageChunk:
    start_ea: int
    data: bytes

    @property
    def end_ea(self) -> int:
        return self.start_ea + len(self.data)


class MemoryImage:
    def __init__(self, chunks: list[ImageChunk]):
        self.chunks = sorted((chunk for chunk in chunks if chunk.data), key=lambda chunk: chunk.start_ea)
        self.starts = [chunk.start_ea for chunk in self.chunks]

    def resolve(self, ea: int) -> tuple[bytes, int] | None:
        low = 0
        high = len(self.chunks) - 1
        while low <= high:
            mid = (low + high) // 2
            chunk = self.chunks[mid]
            if ea < chunk.start_ea:
                high = mid - 1
            elif ea >= chunk.end_ea:
                low = mid + 1
            else:
                return chunk.data, chunk.start_ea
        return None


def get_idb_image() -> MemoryImage:
    cache = get_exec_cache()
    segment_key = []
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if segment:
            segment_key.append((segment.start_ea, segment.end_ea))
    cache_key = (idc.get_input_file_path(), tuple(segment_key))
    if getattr(cache, "idb_image_key", None) != cache_key:
        chunks: list[ImageChunk] = []
        for start_ea, end_ea in segment_key:
            data = ida_bytes.get_bytes(start_ea, end_ea - start_ea)
            if data:
                chunks.append(ImageChunk(start_ea, bytes(data)))
        cache.idb_image = MemoryImage(chunks)
        cache.idb_image_key = cache_key
    return cache.idb_image


class IPatternScanner:
    def search(
        self,
        pattern: str | Pattern,
        limit: int = 0,
    ) -> typing.Generator[tuple[int, list[typing.Any]], None, None]:
        raise NotImplementedError

    def count(self, pattern: str | Pattern, limit: int = 0) -> int:
        count = 0
        for _address, _args in self.search(pattern, limit):
            count += 1
            if limit and count >= limit:
                break
        return count

    def search_unique(self, pattern: str | Pattern) -> tuple[int, list[typing.Any]]:
        iterator = self.search(pattern, 2)
        try:
            result = next(iterator)
        except StopIteration as exc:
            raise KeyError("pattern not found") from exc
        try:
            next(iterator)
        except StopIteration:
            return result
        raise KeyError("pattern is not unique, at least 2 matches were found")

    def find_addresses(self, pattern: str | Pattern, limit: int = 0) -> typing.Generator[int, None, None]:
        for address, _args in self.search(pattern, limit):
            yield address


class RawPatternScanner(IPatternScanner):
    def __init__(self, data: bytes):
        self.image = MemoryImage([ImageChunk(0, data)])

    def search(
        self,
        pattern: str | Pattern,
        limit: int = 0,
    ) -> typing.Generator[tuple[int, list[typing.Any]], None, None]:
        if isinstance(pattern, str):
            pattern = compile_pattern(pattern)
        yielded = 0
        for chunk in self.image.chunks:
            for address, args in pattern.finditer(chunk.data, chunk.start_ea, self.image.resolve):
                yield address, args
                yielded += 1
                if limit and yielded >= limit:
                    return


class IdaPatternScanner(IPatternScanner):
    def __init__(self):
        self.image = get_idb_image()

    def search(
        self,
        pattern: str | Pattern,
        limit: int = 0,
    ) -> typing.Generator[tuple[int, list[typing.Any]], None, None]:
        if isinstance(pattern, str):
            pattern = compile_pattern(pattern)
        yielded = 0
        for chunk in self.image.chunks:
            for address, args in pattern.finditer(chunk.data, chunk.start_ea, self.image.resolve):
                yield address, args
                yielded += 1
                if limit and yielded >= limit:
                    return


class NativeAobSearcher:
    def __init__(self):
        self.start_ea = min_ea()
        self.end_ea = max_ea()
        self.encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)

    @functools.lru_cache(maxsize=2048)
    def compile(self, pattern: str) -> ida_bytes.compiled_binpat_vec_t:
        native_pattern = normalize_native_aob(pattern)
        if native_pattern is None:
            raise ValueError("pattern requires extended scanner")
        patterns = ida_bytes.compiled_binpat_vec_t()
        parse_result = ida_bytes.parse_binpat_str(patterns, self.start_ea, native_pattern, 16, self.encoding)
        if parse_result is False or (isinstance(parse_result, str) and parse_result):
            raise ValueError(f"Could not parse native AOB: {parse_result or 'unknown error'}")
        return patterns

    def search(self, pattern: str, limit: int = 0) -> typing.Generator[int, None, None]:
        patterns = self.compile(pattern)
        address = self.start_ea
        yielded = 0
        flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
        while address < self.end_ea:
            address, _index = ida_bytes.bin_search(address, self.end_ea, patterns, flags)
            if address == BADADDR:
                break
            yield address
            yielded += 1
            if limit and yielded >= limit:
                break
            address += 1

    def count(self, pattern: str, limit: int = 0) -> int:
        return sum(1 for _address in self.search(pattern, limit))


@dataclass
class SignatureOptions:
    max_workers: int = 500
    max_found: int = 10
    max_steps: int = 50
    max_match_count: int = 10
    nested_enabled: bool = True
    nested_depth: int = 2
    nested_max_instructions: int = 8
    follow_nested_refs: bool = True
    validate_limit: int = 20
    language: str = DEFAULT_LANGUAGE


class BuildContext:
    def __init__(self, options: SignatureOptions):
        self.options = options
        self.native_searcher = NativeAobSearcher()
        self.ida_scanner: IdaPatternScanner | None = None
        self.native_count_cache: dict[tuple[str, int], int] = {}
        self.extended_count_cache: dict[tuple[str, int], int] = {}
        self.nested_cache: dict[tuple[int, int], str | None] = {}

    def count_simple(self, signature: str, limit: int | None = None) -> int:
        pattern, _offset = split_signature_offset(signature)
        if limit is None:
            limit = self.options.max_match_count
        key = (pattern, limit)
        if key not in self.native_count_cache:
            self.native_count_cache[key] = self.native_searcher.count(pattern, limit)
        return self.native_count_cache[key]

    def count_extended(self, signature: str, limit: int | None = None) -> int:
        pattern, _offset = split_signature_offset(signature)
        if limit is None:
            limit = self.options.validate_limit
        native_pattern = normalize_native_aob(pattern)
        if native_pattern is not None and "*" not in pattern:
            return self.count_simple(pattern, limit)
        key = (pattern, limit)
        if key not in self.extended_count_cache:
            if self.ida_scanner is None:
                self.ida_scanner = IdaPatternScanner()
            self.extended_count_cache[key] = self.ida_scanner.count(pattern, limit)
        return self.extended_count_cache[key]


@dataclass
class RefOperand:
    index: int
    target_ea: int
    start: int
    end: int
    is_relative: bool


def decode_instruction(ea: int) -> ida_ua.insn_t:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0 or insn.size <= 0:
        raise ValueError(f"failed to decode instruction at {ea:x}")
    return insn


def instruction_ops(insn: ida_ua.insn_t) -> list[typing.Any]:
    return [op for op in insn.ops if op.type != ida_ua.o_void]


def operand_end(insn: ida_ua.insn_t, ops: list[typing.Any], op_index: int, start: int) -> int:
    for next_op in ops[op_index + 1:]:
        if next_op.offb and next_op.offb > start:
            return min(next_op.offb, insn.size)
    return insn.size


@functools.lru_cache(maxsize=4096)
def find_ref_operands(ea: int, preferred_target: int | None = None) -> tuple[RefOperand, ...]:
    try:
        insn = decode_instruction(ea)
    except Exception:
        return ()
    data = ida_bytes.get_bytes(ea, insn.size)
    if not data:
        return ()
    ops = instruction_ops(insn)
    refs: list[RefOperand] = []
    for op_index, op in enumerate(ops):
        target = idc.get_operand_value(ea, op_index)
        if preferred_target is not None and target != preferred_target:
            continue
        if not in_idb(target):
            continue
        start = op.offb or 0
        if start <= 0 or start >= insn.size:
            continue
        end = operand_end(insn, ops, op_index, start)
        if end <= start:
            continue
        raw_value = bytes(data[start:end])
        relative_target = int.from_bytes(raw_value, "little", signed=True) + ea + end
        refs.append(RefOperand(op_index, target, start, end, relative_target == target))
    return tuple(refs)


def choose_ref_operand(ea: int, preferred_target: int | None = None) -> RefOperand | None:
    refs = find_ref_operands(ea, preferred_target)
    if refs:
        return refs[0]
    if preferred_target is None:
        refs = find_ref_operands(ea, None)
        if refs:
            return refs[0]
    return None


def make_line_signature(
    ea: int,
    context: BuildContext | None = None,
    nested_depth: int = 0,
    preferred_target: int | None = None,
    force_ref_mask: bool = False,
    visited: frozenset[int] = frozenset(),
) -> str:
    insn = decode_instruction(ea)
    data = ida_bytes.get_bytes(ea, insn.size)
    if not data:
        raise ValueError(f"failed to read instruction bytes at {ea:x}")
    ops = instruction_ops(insn)
    offset_op = next((max(op.offb, 1) for op in ops), len(data))
    ref_operand = None
    if force_ref_mask or preferred_target is not None or (context and context.options.follow_nested_refs):
        ref_operand = choose_ref_operand(ea, preferred_target)

    nested_subpattern = None
    if (
        context is not None
        and context.options.nested_enabled
        and nested_depth > 0
        and ref_operand is not None
        and ref_operand.is_relative
        and ref_operand.target_ea not in visited
    ):
        nested_subpattern = make_nested_subpattern(
            ref_operand.target_ea,
            nested_depth - 1,
            context,
            visited | {ea},
        )

    tokens: list[str] = []
    index = 0
    while index < len(data):
        if ref_operand is not None and ref_operand.start == index and index >= offset_op:
            width = ref_operand.end - ref_operand.start
            if nested_subpattern:
                open_group, close_group = ("<", ">") if force_ref_mask else ("(", ")")
                tokens.append(f"{open_group}{' '.join('*' for _ in range(width))}: {nested_subpattern}{close_group}")
            elif ref_operand.is_relative and force_ref_mask:
                tokens.extend("*" for _ in range(width))
            else:
                tokens.extend("?" for _ in range(width))
            index = ref_operand.end
        elif index < offset_op:
            tokens.append(HEX_TOKENS[data[index]])
            index += 1
        else:
            tokens.append("?")
            index += 1
    return " ".join(tokens)


def is_only_ref_from(from_ea: int, to_ea: int) -> bool:
    found = False
    for xref in XrefsTo(to_ea, 0):
        if xref.frm == from_ea:
            found = True
        elif xref.type in CODE_FLOW_XREFS:
            return False
    return found


def is_only_ref_to(from_ea: int, to_ea: int) -> bool:
    found = False
    for xref in XrefsFrom(from_ea, 0):
        if xref.to == to_ea:
            found = True
        elif xref.type in CODE_FLOW_XREFS:
            return False
    return found


class SigSearch:
    SUCCESS = 0
    FAIL = -1
    FORWARD = 1
    BACKWARD = 2

    def __init__(self, start_ea: int, context: BuildContext):
        self.context = context
        self.start_ea = start_ea
        self.current_ea = start_ea
        func = ida_funcs.get_func(start_ea)
        if not func:
            raise ValueError(f"no function at {start_ea:x}")
        self.func_start = func.start_ea
        self.func_end = func.end_ea
        self.state = SigSearch.FORWARD
        self.eaddrs = [self.current_ea]
        self.sigs = [make_line_signature(self.current_ea)]
        self.offset = 0
        self.inst_offset = 0

    @property
    def sig(self) -> str:
        return " ".join(part for part in self.sigs if part)

    def walk(self) -> None:
        if self.state == SigSearch.FORWARD:
            self.walk_forward()
        if self.state == SigSearch.BACKWARD:
            self.walk_backward()
        self.test()

    def walk_forward(self) -> None:
        next_ea = idc.next_head(self.current_ea, self.func_end)
        if next_ea < self.func_start or next_ea >= self.func_end or not is_only_ref_from(self.current_ea, next_ea):
            self.state = SigSearch.BACKWARD
            self.current_ea = self.start_ea
            return
        self.eaddrs.append(next_ea)
        self.sigs.append(make_line_signature(next_ea))
        self.current_ea = next_ea

    def walk_backward(self) -> None:
        next_ea = idc.prev_head(self.current_ea, self.func_start)
        if next_ea < self.func_start or next_ea >= self.func_end or not is_only_ref_from(next_ea, self.current_ea):
            self.state = SigSearch.FAIL
            return
        self.eaddrs.insert(0, next_ea)
        self.sigs.insert(0, make_line_signature(next_ea))
        self.offset += self.current_ea - next_ea
        self.inst_offset += 1
        self.current_ea = next_ea

    def test(self) -> None:
        if self.state in (SigSearch.FAIL, SigSearch.SUCCESS):
            return
        match_count = self.count_match(2)
        if match_count == 1:
            self.state = SigSearch.SUCCESS
        elif match_count == 0:
            self.state = SigSearch.FAIL

    def count_match(self, limit: int | None = None) -> int:
        return self.context.count_simple(self.sig, limit)

    def make(
        self,
        target_ea: int,
        nested_depth: int,
        visited: frozenset[int] = frozenset(),
    ) -> str:
        eaddrs = list(self.eaddrs)
        sigs = list(self.sigs)
        inst_offset = self.inst_offset

        def keep_index_for(current_eaddrs: list[int]) -> int:
            if target_ea in current_eaddrs:
                return current_eaddrs.index(target_ea)
            return min(inst_offset, len(current_eaddrs) - 1)

        def render_result(current_eaddrs: list[int], current_sigs: list[str]) -> str:
            result = " ".join(part for part in current_sigs if part)
            target_offset = 0
            if current_eaddrs and target_ea in current_eaddrs:
                target_offset = target_ea - current_eaddrs[0]
            elif self.start_ea == target_ea:
                target_offset = self.offset
            if target_offset:
                result += f" +0x{target_offset:x}"
            return result

        def trim_tail_if_unique(current_eaddrs: list[int], current_sigs: list[str]) -> None:
            keep_index = keep_index_for(current_eaddrs)
            while len(current_sigs) - 1 > keep_index:
                candidate = " ".join(current_sigs[:-1])
                if self.context.count_extended(candidate, 2) == 1:
                    current_sigs.pop()
                    current_eaddrs.pop()
                    keep_index = keep_index_for(current_eaddrs)
                else:
                    break

        base_match_count = self.count_match(self.context.options.max_match_count)
        if base_match_count < self.context.options.max_match_count:
            while len(sigs) - 1 > inst_offset:
                candidate = " ".join(sigs[:-1])
                if self.context.count_simple(candidate, base_match_count + 1) == base_match_count:
                    sigs.pop()
                    eaddrs.pop()
                else:
                    break

        simple_eaddrs = list(eaddrs)
        simple_sigs = list(sigs)
        if self.start_ea != target_ea and self.start_ea in simple_eaddrs:
            start_index = simple_eaddrs.index(self.start_ea)
            simple_sigs[start_index] = make_line_signature(
                self.start_ea,
                self.context,
                0,
                target_ea,
                True,
                visited | {self.start_ea},
            )
        trim_tail_if_unique(simple_eaddrs, simple_sigs)
        simple_result = render_result(simple_eaddrs, simple_sigs)
        simple_pattern, _simple_offset = split_signature_offset(simple_result)
        if not self.context.options.nested_enabled or self.context.count_extended(simple_pattern, 2) == 1:
            return simple_result

        nested_eaddrs = list(eaddrs)
        nested_sigs = list(sigs)
        for index, ea in enumerate(nested_eaddrs):
            preferred_target = target_ea if ea == self.start_ea and self.start_ea != target_ea else None
            force_ref_mask = preferred_target is not None
            if force_ref_mask or self.context.options.follow_nested_refs:
                nested_sigs[index] = make_line_signature(
                    ea,
                    self.context,
                    nested_depth,
                    preferred_target,
                    force_ref_mask,
                    visited | {ea},
                )
        trim_tail_if_unique(nested_eaddrs, nested_sigs)
        return render_result(nested_eaddrs, nested_sigs)


class SigSearcher:
    def __init__(self, target_ea: int, context: BuildContext):
        self.target_ea = target_ea
        self.context = context
        self.workers: list[SigSearch] = []
        self.found: list[SigSearch] = []
        self.failed: list[SigSearch] = []
        self._add_worker(target_ea)
        for xref in XrefsTo(target_ea, 0):
            if xref.type not in SIGNATURE_XREFS:
                continue
            if not self._add_worker(xref.frm):
                break

    def _add_worker(self, ea: int) -> bool:
        if len(self.workers) >= self.context.options.max_workers:
            return False
        try:
            worker = SigSearch(ea, self.context)
        except Exception:
            return True
        self.workers.append(worker)
        return True

    def walk(self) -> None:
        active_workers: list[SigSearch] = []
        for worker in self.workers:
            if worker.state > 0:
                worker.walk()
            if worker.state == SigSearch.SUCCESS:
                self.found.append(worker)
            elif worker.state == SigSearch.FAIL:
                self.failed.append(worker)
            else:
                active_workers.append(worker)
        self.workers = active_workers

    def auto_walk(self) -> tuple[int, list[SigSearch]]:
        if not self.workers:
            raise ValueError("no workers")
        for _step in range(self.context.options.max_steps):
            self.walk()
            if not self.workers or len(self.found) >= self.context.options.max_found:
                break
        if self.found:
            return 1, self.found[:self.context.options.max_found]

        workers = self.failed + self.workers
        if not workers:
            raise ValueError("no viable workers")
        scored = [(worker.count_match(self.context.options.max_match_count), worker) for worker in workers]
        scored.sort(key=lambda item: item[0])
        min_match = scored[0][0]
        return min_match, [worker for count, worker in scored if count == min_match][:self.context.options.max_found]


def make_nested_subpattern(
    target_ea: int,
    depth: int,
    context: BuildContext,
    visited: frozenset[int],
) -> str | None:
    if depth < 0 or target_ea in visited:
        return None
    cache_key = (target_ea, depth)
    if cache_key in context.nested_cache:
        return context.nested_cache[cache_key]
    context.nested_cache[cache_key] = None
    try:
        pattern = make_forward_subpattern(target_ea, depth, context, visited | {target_ea})
    except Exception:
        pattern = None
    context.nested_cache[cache_key] = pattern
    return pattern


def make_forward_subpattern(
    target_ea: int,
    depth: int,
    context: BuildContext,
    visited: frozenset[int],
) -> str | None:
    func = ida_funcs.get_func(target_ea)
    if not func:
        return None
    current_ea = target_ea
    parts: list[str] = []
    for _index in range(context.options.nested_max_instructions):
        if current_ea < func.start_ea or current_ea >= func.end_ea:
            break
        parts.append(make_line_signature(current_ea, context, depth, None, False, visited))
        candidate = " ".join(parts)
        if context.count_extended(candidate, 2) == 1:
            return candidate
        next_ea = idc.next_head(current_ea, func.end_ea)
        if next_ea < func.start_ea or next_ea >= func.end_ea or not is_only_ref_from(current_ea, next_ea):
            break
        current_ea = next_ea
    return " ".join(parts) if parts else None


@dataclass
class SignatureResult:
    worker_ea: int
    signature: str
    idb_count: int
    compare_count: int | None


def format_match_args(args: list[typing.Any]) -> str:
    formatted = []
    for arg in args:
        if isinstance(arg, bytes):
            formatted.append(arg.hex(" "))
        elif isinstance(arg, int):
            formatted.append(format_ea(arg) if arg >= 0 else f"-{format_ea(-arg)}")
        else:
            formatted.append(repr(arg))
    return ", ".join(formatted)


def make_sig(
    target_ea: int,
    compare_exe: str | None = None,
    options: SignatureOptions | None = None,
    logger: typing.Callable[[str], None] = print,
) -> list[SignatureResult]:
    if options is None:
        options = SignatureOptions()
    context = BuildContext(options)
    logger(tr(options.language, "start_search", ea=target_ea, name=idc.get_name(target_ea)))
    searcher = SigSearcher(target_ea, context)
    logger(tr(options.language, "active_workers", count=len(searcher.workers)))
    min_match, workers = searcher.auto_walk()
    logger(tr(options.language, "found_candidates", count=len(workers), min_match=min_match))

    compare_scanner = None
    if compare_exe:
        logger(tr(options.language, "compare_file", path=compare_exe))
        compare_scanner = RawPatternScanner(load_bin_file(compare_exe))

    results: list[SignatureResult] = []
    for worker in workers:
        try:
            signature = worker.make(target_ea, options.nested_depth, frozenset())
            pattern, _offset = split_signature_offset(signature)
            idb_count = context.count_extended(pattern, options.validate_limit)
            compare_count = None
            if compare_scanner is not None:
                compare_count = compare_scanner.count(pattern, options.validate_limit)
            results.append(SignatureResult(worker.start_ea, signature, idb_count, compare_count))
            compare_label = tr(options.language, "compare_count")
            compare_text = "" if compare_count is None else f", {compare_label}={compare_count}"
            status = "+" if idb_count == 1 and (compare_count is None or compare_count > 0) else "!"
            logger(f"[{status}] {worker.start_ea:x}: idb={idb_count}{compare_text} :: {signature}")
        except Exception as exc:
            logger(tr(options.language, "make_failed", ea=worker.start_ea, error=exc))
            logger(traceback.format_exc())
    return results


def search_sig(
    signature: str,
    limit: int = 100,
    language: str = DEFAULT_LANGUAGE,
    logger: typing.Callable[[str], None] = print,
) -> list[tuple[int, list[typing.Any]]]:
    pattern, offset = split_signature_offset(signature)
    scanner = IdaPatternScanner()
    results = list(scanner.search(pattern, limit))
    logger(tr(language, "matches_for", count=len(results), signature=signature))
    for address, args in results:
        effective_address = address + offset
        args_text = format_match_args(args)
        if offset:
            prefix = f"[+] {format_ea(effective_address)} <= {format_ea(address)} +0x{offset:x}"
        else:
            prefix = f"[+] {format_ea(address)}"
        logger(prefix + (f": {args_text}" if args_text else ""))
    if limit and len(results) >= limit:
        logger(tr(language, "result_limit", limit=limit))
    return results

if QT_BINDING is not None:
    class NySigWorkerDialog(QtWidgets.QDialog):
        def __init__(self, parent: QtWidgets.QWidget | None = None):
            super().__init__(parent)
            self.setMinimumWidth(900)
            self.translated_labels: dict[str, QtWidgets.QLabel] = {}
            self._setup_ui()
            self._load_defaults()

        def _setup_ui(self) -> None:
            root_layout = QtWidgets.QVBoxLayout(self)

            language_layout = QtWidgets.QHBoxLayout()
            self.language_combo = QtWidgets.QComboBox()
            self.language_combo.addItem("English", "en")
            self.language_combo.addItem("中文", "zh")
            language_layout.addStretch(1)
            language_layout.addWidget(self._label("language"))
            language_layout.addWidget(self.language_combo)

            self.target_group = QtWidgets.QGroupBox()
            target_layout = QtWidgets.QGridLayout(self.target_group)
            self.target_edit = QtWidgets.QLineEdit()
            self.here_button = QtWidgets.QPushButton()
            self.operand_button = QtWidgets.QPushButton()
            self.make_button = QtWidgets.QPushButton()
            target_layout.addWidget(self._label("target"), 0, 0)
            target_layout.addWidget(self.target_edit, 0, 1)
            target_layout.addWidget(self.here_button, 0, 2)
            target_layout.addWidget(self.operand_button, 0, 3)
            target_layout.addWidget(self.make_button, 0, 4)

            self.compare_edit = QtWidgets.QLineEdit()
            self.compare_button = QtWidgets.QPushButton()
            self.compare_clear_button = QtWidgets.QPushButton()
            target_layout.addWidget(self._label("compare"), 1, 0)
            target_layout.addWidget(self.compare_edit, 1, 1, 1, 2)
            target_layout.addWidget(self.compare_button, 1, 3)
            target_layout.addWidget(self.compare_clear_button, 1, 4)

            self.options_group = QtWidgets.QGroupBox()
            options_layout = QtWidgets.QGridLayout(self.options_group)
            self.nested_check = QtWidgets.QCheckBox()
            self.nested_check.setChecked(True)
            self.follow_refs_check = QtWidgets.QCheckBox()
            self.follow_refs_check.setChecked(True)
            self.depth_spin = self._make_spin(0, 8, 2)
            self.sub_instr_spin = self._make_spin(1, 64, 8)
            self.workers_spin = self._make_spin(1, 5000, 500)
            self.steps_spin = self._make_spin(1, 500, 50)
            self.found_spin = self._make_spin(1, 100, 10)
            self.validate_spin = self._make_spin(1, 10000, 20)
            options_layout.addWidget(self.nested_check, 0, 0)
            options_layout.addWidget(self.follow_refs_check, 0, 1)
            options_layout.addWidget(self._label("depth"), 0, 2)
            options_layout.addWidget(self.depth_spin, 0, 3)
            options_layout.addWidget(self._label("sub_instr"), 0, 4)
            options_layout.addWidget(self.sub_instr_spin, 0, 5)
            options_layout.addWidget(self._label("workers"), 1, 0)
            options_layout.addWidget(self.workers_spin, 1, 1)
            options_layout.addWidget(self._label("steps"), 1, 2)
            options_layout.addWidget(self.steps_spin, 1, 3)
            options_layout.addWidget(self._label("found"), 1, 4)
            options_layout.addWidget(self.found_spin, 1, 5)
            options_layout.addWidget(self._label("validate"), 1, 6)
            options_layout.addWidget(self.validate_spin, 1, 7)

            self.search_group = QtWidgets.QGroupBox()
            search_layout = QtWidgets.QGridLayout(self.search_group)
            self.search_edit = QtWidgets.QPlainTextEdit()
            self.search_edit.setMaximumHeight(90)
            self.search_button = QtWidgets.QPushButton()
            self.format_button = QtWidgets.QPushButton()
            self.search_limit_spin = self._make_spin(1, 10000, 100)
            search_layout.addWidget(self.search_edit, 0, 0, 1, 5)
            search_layout.addWidget(self._label("limit"), 1, 0)
            search_layout.addWidget(self.search_limit_spin, 1, 1)
            search_layout.addWidget(self.search_button, 1, 3)
            search_layout.addWidget(self.format_button, 1, 4)

            self.output_group = QtWidgets.QGroupBox()
            output_layout = QtWidgets.QVBoxLayout(self.output_group)
            self.output_edit = QtWidgets.QPlainTextEdit()
            self.output_edit.setReadOnly(True)
            output_layout.addWidget(self.output_edit)

            button_layout = QtWidgets.QHBoxLayout()
            self.copy_button = QtWidgets.QPushButton()
            self.clear_output_button = QtWidgets.QPushButton()
            self.close_button = QtWidgets.QPushButton()
            button_layout.addWidget(self.copy_button)
            button_layout.addWidget(self.clear_output_button)
            button_layout.addStretch(1)
            button_layout.addWidget(self.close_button)

            root_layout.addLayout(language_layout)
            root_layout.addWidget(self.target_group)
            root_layout.addWidget(self.options_group)
            root_layout.addWidget(self.search_group)
            root_layout.addWidget(self.output_group, 1)
            root_layout.addLayout(button_layout)

            self.language_combo.currentIndexChanged.connect(self._apply_language)
            self.here_button.clicked.connect(self._set_here)
            self.operand_button.clicked.connect(self._set_operand)
            self.compare_button.clicked.connect(self._browse_compare)
            self.compare_clear_button.clicked.connect(self._clear_compare)
            self.make_button.clicked.connect(self._run_make)
            self.search_button.clicked.connect(self._run_search)
            self.format_button.clicked.connect(self._format_pattern)
            self.copy_button.clicked.connect(self._copy_output)
            self.clear_output_button.clicked.connect(self.output_edit.clear)
            self.close_button.clicked.connect(self.accept)
            self._apply_language()

        def _label(self, key: str) -> QtWidgets.QLabel:
            label = QtWidgets.QLabel()
            self.translated_labels[key] = label
            return label

        def _language(self) -> str:
            if not hasattr(self, "language_combo"):
                return DEFAULT_LANGUAGE
            return self.language_combo.currentData() or DEFAULT_LANGUAGE

        def _apply_language(self) -> None:
            language = self._language()
            self.setWindowTitle(tr(language, "window_title", binding=QT_BINDING))
            self.target_group.setTitle(tr(language, "make_aob"))
            self.options_group.setTitle(tr(language, "options"))
            self.search_group.setTitle(tr(language, "search_aob"))
            self.output_group.setTitle(tr(language, "output"))
            self.target_edit.setPlaceholderText(tr(language, "target_placeholder"))
            self.compare_edit.setPlaceholderText(tr(language, "compare_placeholder"))
            self.here_button.setText(tr(language, "here"))
            self.operand_button.setText(tr(language, "operand"))
            self.make_button.setText(tr(language, "generate"))
            self.compare_button.setText(tr(language, "browse"))
            self.compare_clear_button.setText(tr(language, "clear"))
            self.nested_check.setText(tr(language, "nested_refs"))
            self.follow_refs_check.setText(tr(language, "follow_refs"))
            self.search_button.setText(tr(language, "search"))
            self.format_button.setText(tr(language, "format"))
            self.copy_button.setText(tr(language, "copy"))
            self.clear_output_button.setText(tr(language, "clear_output"))
            self.close_button.setText(tr(language, "close"))
            for key, label in self.translated_labels.items():
                label.setText(tr(language, key))

        @staticmethod
        def _make_spin(minimum: int, maximum: int, value: int) -> QtWidgets.QSpinBox:
            spin = QtWidgets.QSpinBox()
            spin.setRange(minimum, maximum)
            spin.setValue(value)
            return spin

        def _load_defaults(self) -> None:
            current = idc.here()
            if current != BADADDR:
                self.target_edit.setText(format_ea(current))
            cache = get_exec_cache()
            compare_exe = getattr(cache, "compare_exe", "")
            if compare_exe:
                self.compare_edit.setText(compare_exe)

        def _options(self) -> SignatureOptions:
            return SignatureOptions(
                max_workers=self.workers_spin.value(),
                max_found=self.found_spin.value(),
                max_steps=self.steps_spin.value(),
                nested_enabled=self.nested_check.isChecked(),
                nested_depth=self.depth_spin.value(),
                nested_max_instructions=self.sub_instr_spin.value(),
                follow_nested_refs=self.follow_refs_check.isChecked(),
                validate_limit=self.validate_spin.value(),
                language=self._language(),
            )

        def _log(self, message: str) -> None:
            print(message)
            self.output_edit.appendPlainText(message)
            self.output_edit.verticalScrollBar().setValue(self.output_edit.verticalScrollBar().maximum())
            app = QtWidgets.QApplication.instance()
            if app is not None:
                app.processEvents()

        def _set_here(self) -> None:
            current = idc.here()
            if current == BADADDR:
                self._log(tr(self._language(), "invalid_current_address"))
                return
            self.target_edit.setText(format_ea(current))

        def _set_operand(self) -> None:
            current = idc.here()
            try:
                self.target_edit.setText(format_ea(first_operand_point(current)))
            except StopIteration:
                self._log(tr(self._language(), "no_operand_target", ea=current))

        def _browse_compare(self) -> None:
            language = self._language()
            path, _filter = QtWidgets.QFileDialog.getOpenFileName(
                self,
                tr(language, "file_dialog_title"),
                "",
                tr(language, "file_dialog_filter"),
            )
            if path:
                self.compare_edit.setText(path)
                get_exec_cache().compare_exe = path

        def _clear_compare(self) -> None:
            self.compare_edit.clear()
            get_exec_cache().compare_exe = ""

        def _run_make(self) -> None:
            try:
                language = self._language()
                target = parse_ea(self.target_edit.text(), language)
                if not in_idb(target):
                    raise ValueError(tr(language, "target_outside", ea=target))
                compare = self.compare_edit.text().strip() or None
                if compare:
                    get_exec_cache().compare_exe = compare
                self._with_busy_cursor(lambda: make_sig(target, compare, self._options(), self._log))
            except Exception as exc:
                self._log(f"[!] {exc}")
                self._log(traceback.format_exc())
                QtWidgets.QMessageBox.critical(self, "NySigWorker2", str(exc))

        def _run_search(self) -> None:
            signature = self.search_edit.toPlainText().strip()
            if not signature:
                return
            try:
                language = self._language()
                self._with_busy_cursor(lambda: search_sig(signature, self.search_limit_spin.value(), language, self._log))
            except Exception as exc:
                self._log(f"[!] {exc}")
                self._log(traceback.format_exc())
                QtWidgets.QMessageBox.critical(self, "NySigWorker2", str(exc))

        def _format_pattern(self) -> None:
            signature = self.search_edit.toPlainText().strip()
            if not signature:
                return
            try:
                pattern, _offset = split_signature_offset(signature)
                self._log(compile_pattern(pattern).fmt(2))
            except Exception as exc:
                self._log(f"[!] {exc}")

        def _copy_output(self) -> None:
            text = self.output_edit.textCursor().selectedText().replace("\u2029", "\n")
            if not text:
                text = self.output_edit.toPlainText()
            QtWidgets.QApplication.clipboard().setText(text)

        @staticmethod
        def _with_busy_cursor(callback: typing.Callable[[], typing.Any]) -> typing.Any:
            wait_cursor = getattr(QtCore.Qt, "WaitCursor", None)
            if wait_cursor is None:
                wait_cursor = QtCore.Qt.CursorShape.WaitCursor
            QtWidgets.QApplication.setOverrideCursor(wait_cursor)
            try:
                with ida_kernwin.disabled_script_timeout_t():
                    return callback()
            finally:
                QtWidgets.QApplication.restoreOverrideCursor()


    def exec_dialog(dialog: QtWidgets.QDialog) -> int:
        if hasattr(dialog, "exec"):
            return dialog.exec()
        return dialog.exec_()

else:
    class NySigWorkerDialog:
        def __init__(self):
            raise NotImplementedError("Qt bindings not available")
    
    def exec_dialog(dialog) -> int:
        raise NotImplementedError("Qt bindings not available")

def main() -> None:
    dialog = NySigWorkerDialog()
    with ida_kernwin.disabled_script_timeout_t():
        exec_dialog(dialog)


class NySigFinder2(idaapi.plugin_t):
    flags = 0
    wanted_name = "NySigFinder2"
    wanted_hotkey = "Ctrl-Alt-Shift-S"
    comment = TEXT[DEFAULT_LANGUAGE]["plugin_comment"]
    help = TEXT[DEFAULT_LANGUAGE]["plugin_help"]

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        main()


def PLUGIN_ENTRY():
    return NySigFinder2()


if __name__ == "__main__":
    NySigFinder2().run(0)