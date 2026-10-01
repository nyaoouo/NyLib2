"""Oracle parsers and sweep helpers for stage 9's capture checks (## Verification, O9.1-O9.5, G9.10):
Dumper-7's CppSDK/Assertions.inl (alignof/sizeof/offsetof per C++ name) and Dumpspace/EnumsInfo.json
(enum member names), plus a floor+fail-rate accumulator the sweep and the layout check share."""
import dataclasses
import json
import keyword
import os
import re

from ..names import make_name_valid

_DEFINE_RE = re.compile(r'^#define\s+DUMPER7_ASSERTS_(\S+)')
_ALIGNOF_RE = re.compile(r'static_assert\(alignof\((\S+)\)\s*==\s*(0[xX][0-9A-Fa-f]+)\s*,')
_SIZEOF_RE = re.compile(r'static_assert\(sizeof\((\S+)\)\s*==\s*(0[xX][0-9A-Fa-f]+)\s*,')
_OFFSETOF_RE = re.compile(r'static_assert\(offsetof\((\S+?),\s*(\S+?)\)\s*==\s*(0[xX][0-9A-Fa-f]+)\s*,')
_ENUM_RESERVED = ('name', 'value', 'mro')


@dataclasses.dataclass(frozen=True)
class AssertionRecord:
    cpp_name: str
    alignof: int | None
    sizeof: int | None
    offsets: dict  # raw member name -> int offset, in file order


def parse_assertions(path) -> dict:
    """Parse a Dumper-7 CppSDK/Assertions.inl: one AssertionRecord per `#define DUMPER7_ASSERTS_<name>`
    block, keyed by its C++ name. A name defined twice keeps the later block (last wins)."""
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f'path must be str or os.PathLike, got {type(path).__name__}')
    records: dict[str, AssertionRecord] = {}
    cur_name = None
    cur_align = cur_size = None
    cur_offsets: dict[str, int] = {}

    def flush():
        nonlocal cur_name, cur_align, cur_size, cur_offsets
        if cur_name is not None:
            records[cur_name] = AssertionRecord(cpp_name=cur_name, alignof=cur_align, sizeof=cur_size, offsets=cur_offsets)
        cur_name, cur_align, cur_size, cur_offsets = None, None, None, {}

    with open(path, encoding='utf-8-sig') as f:
        for line in f:
            m = _DEFINE_RE.match(line)
            if m:
                flush()
                cur_name = m.group(1)
                continue
            if cur_name is None:
                continue
            if not line.strip():
                flush()
                continue
            if m := _ALIGNOF_RE.search(line):
                if m.group(1) == cur_name:
                    cur_align = int(m.group(2), 16)
                continue
            if m := _SIZEOF_RE.search(line):
                if m.group(1) == cur_name:
                    cur_size = int(m.group(2), 16)
                continue
            if m := _OFFSETOF_RE.search(line):
                if m.group(1) == cur_name:
                    cur_offsets[m.group(2)] = int(m.group(3), 16)
    flush()
    return records


@dataclasses.dataclass(frozen=True)
class EnumInfoRecord:
    name: str
    members: list  # [(raw member name, int value), ...] in file order
    underlying: str  # Dumpspace's type string, e.g. 'uint8'


def parse_enums_info(path) -> dict:
    """Parse a Dumper-7 Dumpspace/EnumsInfo.json: name -> [EnumInfoRecord, ...], one per occurrence
    (file order; a name can repeat, as compare_dumpspace-style checks require uniqueness themselves)."""
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f'path must be str or os.PathLike, got {type(path).__name__}')
    with open(path, encoding='utf-8') as f:
        doc = json.load(f)
    data = doc.get('data') if isinstance(doc, dict) else None
    if not isinstance(data, list):
        raise ValueError(f'{path}: data must be a JSON array')
    out: dict[str, list[EnumInfoRecord]] = {}
    for i, item in enumerate(data):
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError(f'{path}: data[{i}] must be a one-key object')
        (name, body), = item.items()
        if not (isinstance(body, list) and len(body) == 2 and isinstance(body[0], list) and isinstance(body[1], str)):
            raise ValueError(f'{path}: data[{i}] {name!r} must be [members, type]')
        members = []
        for m in body[0]:
            if not isinstance(m, dict) or len(m) != 1:
                raise ValueError(f'{path}: data[{i}] {name!r} has a malformed member {m!r}')
            (mname, mval), = m.items()
            if not isinstance(mname, str) or not isinstance(mval, int) or isinstance(mval, bool):
                raise ValueError(f'{path}: data[{i}] {name!r} has a malformed member {m!r}')
            members.append((mname, mval))
        out.setdefault(name, []).append(EnumInfoRecord(name=name, members=members, underlying=body[1]))
    return out


def enum_member_names(members) -> list:
    """RT6's IntEnum member-name rule (## Public Interfaces (Frozen), RT6 'Enum members') applied to
    `members` ([(raw name, value), ...], as EnumRecord.values or an EnumInfoRecord.members holds them):
    the ordered, deduplicated Python member names ClassFactory.enum_for would build."""
    seen = set()
    result = []
    for raw_name, _value in members:
        short = raw_name.rsplit('::', 1)[-1]
        v = make_name_valid(short)
        if keyword.iskeyword(v) or v in _ENUM_RESERVED:
            v = v + '_'
        if v.startswith('_'):
            v = 'V' + v
        if v in seen:
            continue
        seen.add(v)
        result.append(v)
    return result


def sample_indices(total: int, count: int) -> list:
    """`count` indices of `range(total)` spread by even stride (floor-friendly deterministic sampling);
    every index when total <= count."""
    if not isinstance(total, int) or not isinstance(count, int):
        raise TypeError('total and count must be int')
    if total < 0 or count < 0:
        raise ValueError('total and count must be >= 0')
    if total <= count:
        return list(range(total))
    step = total / count
    return sorted({int(i * step) for i in range(count)})


@dataclasses.dataclass
class FloorCheck:
    """Accumulates pass/fail samples for one invariant of ## Verification: a floor on how many were
    checked, and a cap on how many may fail (an absolute count or a fraction of checked)."""
    label: str
    floor: int = 0
    max_failures: int | None = None
    max_fail_rate: float | None = None
    checked: int = 0
    failed: int = 0
    samples: list = dataclasses.field(default_factory=list)

    def record(self, ok: bool, detail: str = '') -> None:
        self.checked += 1
        if not ok:
            self.failed += 1
            if detail and len(self.samples) < 5:
                self.samples.append(detail)

    def allowed_failures(self) -> int:
        if self.max_failures is not None:
            return self.max_failures
        if self.max_fail_rate is not None:
            return int(self.checked * self.max_fail_rate)
        return 0

    def problem(self) -> str | None:
        if self.checked < self.floor:
            return f'{self.label}: only {self.checked} checked, need >= {self.floor}'
        allowed = self.allowed_failures()
        if self.failed > allowed:
            return f'{self.label}: {self.failed}/{self.checked} failed (limit {allowed}); {self.samples}'
        return None

    def assert_ok(self, testcase) -> None:
        problem = self.problem()
        testcase.assertIsNone(problem, problem)
