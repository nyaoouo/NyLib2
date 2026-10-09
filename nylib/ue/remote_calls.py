"""Opt-in remote calls of the dumper (--allow-calls): the stem, the FText inner offsets and an FName::AppendString check."""
import contextlib
import dataclasses
import logging
import math
import struct
import time
from typing import NamedTuple

from . import calls
from .engine import utfn
from .engine.unreal import UEFunction
from .errors import CallError, MemoryReadError, TargetError
from .flags import EClassCastFlags, EPropertyFlags

logger = logging.getLogger('nylib.ue.remote_calls')

FEATURES = ('append-string', 'game-info', 'text')  # the accepted names
RUN_ORDER = ('text', 'game-info', 'append-string')  # the order run() calls them in
TEXT_KEYS = ('Off.InSDK.Text.TextDatOffset', 'Off.InSDK.Text.InTextDataStringOffset')
CALL_EXEMPT = TEXT_KEYS + ('Settings.Generator.GameName', 'Settings.Generator.GameVersion')  # a copy of runtime.session.CALL_EXEMPT
CONV_STRING_TO_TEXT = '/Script/Engine.KismetTextLibrary:Conv_StringToText'
PROBE_TEXT = 'ThisIsAGoodString!'  # 19 units with its NUL, 38 bytes compared
TEXT_SCAN_END = 0x50  # InitTextOffsets' MaxOffset
LABEL_TEXT = 'auto: Off::InSDK::Text::InitTextOffsets (ProcessEvent call)'
LABEL_GAME_NAME = 'auto: KismetSystemLibrary::GetGameName (ProcessEvent call)'
LABEL_GAME_VERSION = 'auto: KismetSystemLibrary::GetEngineVersion (ProcessEvent call)'
APPEND_CAPACITY = 1024  # wchar_t slots of each out FString
APPEND_SAMPLE = 256  # names the stride pass takes
APPEND_WIDE_FLOOR = 16  # wide (non-ASCII) names added when the game has them
APPEND_FLOOR_SCAN = 1 << 16  # slots each floor scan visits at most
MAX_FALLBACK_READ = 1 << 24  # bytes one strict fallback read may ask for
MAX_STRING_UNITS = 1 << 20  # FString units a decode accepts

_KNOWN_LABELS = ('auto:', 'profile:')
_GAME_NAME_KEY = 'Settings.Generator.GameName'
_GAME_VERSION_KEY = 'Settings.Generator.GameVersion'
_EXECUTABLE_PROTECT = (0x10, 0x20, 0x40, 0x80)  # PAGE_EXECUTE*
_ACCESSIBLE = 0xEE  # PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY
_INACCESSIBLE = 0x101  # PAGE_GUARD|PAGE_NOACCESS
_SETTLED = ('not started', 'finished')  # CallError states that leave call memory free-able


class FeatureResult(NamedTuple):
    feature: str  # one of FEATURES
    ran: bool  # at least one call reached the game
    ok: bool  # the feature produced its result
    detail: str  # one line: the log, the warning, DumpResult and --json
    seconds: float  # the feature's wall time


class SampleName(NamedTuple):
    slot: int  # the GObjects index the FName was read from
    raw: bytes  # the FName's FNameSize bytes as read; copied into call memory
    comparison_index: int
    block: int  # its name-pool block (or TNameEntryArray chunk)
    name: str  # the GNames decode of raw (a str of UTF-16 units)


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _ranged(name: str, value, low: int, high: int) -> None:
    if not _is_int(value):
        raise TypeError(f'{name} must be an int, got {type(value).__name__}')
    if not low <= value <= high:
        raise ValueError(f'{name} must be in [{low}, {high}], got {value}')


def _check_timeout(timeout) -> None:
    if timeout is None:
        return
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError(f'timeout must be None or a number, got {type(timeout).__name__}')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f'timeout must be greater than 0 and finite, got {timeout!r}')


def parse_features(value) -> tuple[str, ...]:
    """The distinct features an allow_calls value requests, in RUN_ORDER; None and an empty iterable give ()."""
    if value is None:
        return ()
    if isinstance(value, str):
        raise TypeError('allow_calls must be None or an iterable of feature names, not a str; pass a tuple like ("text",)')
    try:
        items = iter(value)
    except TypeError:
        raise TypeError(f'allow_calls must be None or an iterable of feature names, got {type(value).__name__}') from None
    wanted = set()
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f'allow-calls feature names must be str, got {type(item).__name__}')
        if item not in FEATURES:
            raise ValueError(f'unknown allow-calls feature {item!r}; choose from append-string, game-info, text')
        wanted.add(item)
    return tuple(f for f in RUN_ORDER if f in wanted)


def call_blockers(ectx) -> tuple[str, ...]:
    """The unverified keys outside CALL_EXEMPT, in unverified()'s order: while any is present no feature calls."""
    return tuple(k for k in ectx.unverified() if k not in CALL_EXEMPT)


def run(ectx, transport, features, *, timeout=calls.DEFAULT_TIMEOUT) -> tuple[FeatureResult, ...]:
    """Run the requested features in RUN_ORDER; a feature that fails degrades, a target that exits raises TargetError.
    features is what parse_features returns."""
    if not (isinstance(features, tuple) and all(isinstance(f, str) and f in RUN_ORDER for f in features)
            and features == tuple(f for f in RUN_ORDER if f in features)):
        raise ValueError(f'features must be a tuple of distinct names in the order {RUN_ORDER}, as parse_features returns; got {features!r}')
    if not features:
        return ()
    if transport is None:
        raise ValueError('remote calls need a transport, so a live target')
    _check_timeout(timeout)
    where = 'a new thread (CreateRemoteThread)' if transport.policy == 'remote-thread' else 'the calling thread'
    logger.warning('--allow-calls %s: each call runs code in the game through ProcessEvent or FName::AppendString on %s, not the game thread, '
                   'so it races the game thread and its garbage collector and can crash or corrupt the game; engine-allocated results are not freed',
                   ', '.join(features), where)
    if blockers := call_blockers(ectx):
        detail = f'not called: the unverified offsets {", ".join(blockers)} would be called through; pin them in a profile'
        for feature in features:
            logger.warning('--allow-calls %s: %s', feature, detail)
        return tuple(FeatureResult(feature, False, False, detail, 0.0) for feature in features)
    results = []
    for feature in features:
        try:
            if feature == 'text':
                r = resolve_text_offsets(ectx.engine, transport, timeout=timeout)
            elif feature == 'game-info':
                r = detect_game_info(ectx, transport, timeout=timeout)
            else:
                r = check_append_string(ectx.engine, transport, timeout=timeout)
        except CallError as exc:
            if getattr(exc, 'exited', None):
                raise TargetError(transport.process.process_id, f'the target exited during the {feature} call (it probably crashed)') from exc
            raise
        results.append(r)
    return tuple(results)


class _CallReader:
    """Reads of memory a call produced: uncached, then one strict read; IsBadReadPtr through a fresh VirtualQueryEx."""
    __slots__ = ('e', 'process')

    def __init__(self, e, transport):
        self.e, self.process = e, transport.process

    def read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.e.mem.fresh.read(address, size))
        except MemoryReadError:
            if size > MAX_FALLBACK_READ:
                raise
            return calls.read_target(self.process, address, size)

    def bad_read_ptr(self, address: int) -> bool:
        """PlatformWindows::IsBadReadPtr @ ea0dab3."""
        if not self.e.platform.is_valid_64_bit_virtual_address(address):
            return True
        try:
            protect = int(self.process.virtual_query(address).Protect)
        except OSError:
            return True
        return not protect & _ACCESSIBLE or bool(protect & _INACCESSIBLE)


class _Calls:
    """One feature's call memory and the state of its calls, released by the stage-10 rule."""

    def __init__(self, feature: str, transport, timeout):
        self.feature, self.transport, self.timeout = feature, transport, timeout
        self.arena = None
        self.made = 0  # calls that reached the game, returned or not
        self.keep = None  # why the arena may not be freed
        self.exited = False
        self.reserved = 0
        self.labels = []  # the function of each call attempted, in order
        self.where = ''  # how the calls were made; {made} is replaced by the calls made

    def open(self):
        self.arena = self.transport.arena()
        return self.arena

    @contextlib.contextmanager
    def calling(self):
        try:
            yield
        except CallError as exc:
            if getattr(exc, 'exited', None):
                self.exited = True
            elif getattr(exc, 'timed_out', None):
                self.keep = f'a call did not return within {self.timeout} s'
            elif getattr(exc, 'state', None) not in _SETTLED:
                self.keep = f'a call ended in an unknown state ({exc})'
            if getattr(exc, 'state', None) != 'not started':
                self.made += 1
            raise
        except (TypeError, ValueError):
            raise
        except BaseException as exc:
            self.made += 1
            self.keep = f'a call was interrupted ({type(exc).__name__})'
            raise
        self.made += 1

    def process_event(self, label: str, obj: int, function: int, pe: int, params: int) -> None:
        self.labels.append(label)
        with self.calling():
            calls.process_event(self.transport, obj, function, pe, params, timeout=self.timeout)

    def call(self, label: str, function: int, *args: int) -> int:
        self.labels.append(label)
        with self.calling():
            return self.transport.call(function, *args, timeout=self.timeout)

    def did(self) -> str:
        """The calls made and the call memory reserved, or '' when no call reached the game."""
        if not self.made:
            return ''
        size = self.arena.size or self.reserved
        return f'{" and ".join(dict.fromkeys(self.labels[:self.made]))} {self.where.format(made=self.made)}, {size:#x} bytes of call memory'

    def release(self) -> None:
        if (arena := self.arena) is None:
            return
        self.reserved = arena.size
        if self.exited:
            arena.leak()
            return
        keep = self.keep or ('the transport was closed' if getattr(self.transport, 'closed', False) else None)
        if keep is None:
            arena.free()
            return
        n = arena.leak()
        logger.warning('--allow-calls %s: %#x bytes of call memory stay in the game: %s', self.feature, n, keep)


def _finish(feature: str, ran: bool, ok: bool, detail: str, t0: float, c: _Calls | None = None) -> FeatureResult:
    seconds = time.perf_counter() - t0
    did = c.did() if c is not None else ''
    if did:
        logger.info('--allow-calls %s: %s: %s', feature, did, detail)
    if not ok:
        logger.warning('--allow-calls %s: %s', feature, detail)
    return FeatureResult(feature, ran, ok, detail, seconds)


def _fits(prop, struct_size: int, size: int) -> bool:
    return (offset := prop.get_offset()) >= 0 and offset + size <= struct_size


def _search_text_offsets(raw: bytes, reader, ftext_size: int) -> tuple[int, int] | None:
    """InitTextOffsets' two scans @ ea0dab3: (TextDatOffset, InTextDataStringOffset), or None when either misses."""
    text_data_ptr = None
    for i in range(0, ftext_size - 8, 8):
        ptr = struct.unpack_from('<Q', raw, i)[0]
        if not reader.bad_read_ptr(ptr):
            text_data_ptr, text_dat_offset = ptr, i
            break
    if text_data_ptr is None:
        return None
    n_units = len(PROBE_TEXT) + 1
    expected = (PROBE_TEXT + '\0').encode('utf-16-le')
    for j in range(8, TEXT_SCAN_END, 4):
        try:
            window = reader.read(text_data_ptr + j - 8, 12)
            str_ptr, n = struct.unpack('<Qi', window)
            if n == n_units and str_ptr != 0 and not reader.bad_read_ptr(str_ptr) and reader.read(str_ptr, 2 * n_units) == expected:
                return text_dat_offset, j - 8
        except MemoryReadError:
            continue
    return None


def _failure(exc, made: int) -> tuple[bool, str]:
    if isinstance(exc, CallError):
        return made > 0 or getattr(exc, 'state', None) != 'not started', f'the call failed: {exc}'
    return made > 0, f'{type(exc).__name__}: {exc}'


def resolve_text_offsets(e, transport, *, function=None, timeout=calls.DEFAULT_TIMEOUT) -> FeatureResult:
    """Off::InSDK::Text::InitTextOffsets @ ea0dab3 from its ProcessEvent call on: sets TextDatOffset and InTextDataStringOffset.
    function: the Conv_StringToText address, or None to find it by name (only on an engine whose name index is warm)."""
    if function is not None:
        if not _is_int(function):
            raise TypeError(f'function must be None or an int, got {type(function).__name__}')
        if function < 0:
            raise ValueError(f'function must be >= 0, got {function}')
    _check_timeout(timeout)
    t0 = time.perf_counter()
    if all(e.provenance.get(k, '').startswith(_KNOWN_LABELS) for k in TEXT_KEYS):
        logger.info('--allow-calls text: already resolved')
        return FeatureResult('text', False, True, 'already resolved', 0.0)
    pe_index = e.off.InSDK.ProcessEvent.PEIndex
    if pe_index <= 0:
        return _finish('text', False, False, 'ProcessEvent was not found, so Conv_StringToText cannot be called', t0)
    c = _Calls('text', transport, timeout)
    try:
        try:
            if function is None:
                fn = e.objects.find_object_fast('Conv_StringToText', EClassCastFlags.Function).cast(UEFunction)
            else:
                fn = UEFunction(e, function)
            if (fn_address := fn.get_address()) == 0:
                return _finish('text', False, False, 'Conv_StringToText was not found', t0)
            ret = fn.get_return_property()
            inp = None
            for prop in fn.get_properties():
                if not prop.has_property_flags(EPropertyFlags.ReturnParm):
                    inp = prop
            struct_size = max(fn.get_struct_size(), 1)
            if (ret.get_address() == 0 or inp is None or inp.get_address() == 0 or (ftext_size := ret.get_size()) < 8
                    or not _fits(ret, struct_size, ftext_size) or not _fits(inp, struct_size, inp.get_size())):
                return _finish('text', False, False, 'Conv_StringToText has an unexpected signature', t0)
            arena = c.open()
            params = arena.alloc(struct_size, align=16)
            arena.write(params + inp.get_offset(), arena.fstring(PROBE_TEXT))
            arena.flush()
            obj0 = e.objects.get_by_index(0).get_address()
            pe = calls.process_event_address(transport.process, e.mem, obj0, pe_index)
            c.where = f'({fn_address:#x}) called through ProcessEvent on object 0 ({obj0:#x})'
            c.process_event('Conv_StringToText', obj0, fn_address, pe, params)
            raw = arena.read(params + ret.get_offset(), ftext_size)
            if (found := _search_text_offsets(raw, _CallReader(e, transport), ftext_size)) is None:
                return _finish('text', True, False, 'Conv_StringToText ran, but no TextData pointer holding the probe string was found', t0, c)
        except CallError as exc:
            if getattr(exc, 'exited', None):
                raise
            ran, detail = _failure(exc, c.made)
            return _finish('text', ran, False, detail, t0, c)
        except (MemoryReadError, ValueError) as exc:
            ran, detail = _failure(exc, c.made)
            return _finish('text', ran, False, detail, t0, c)
    finally:
        c.release()
    dat, inner = found
    text = e.off.InSDK.Text
    text.TextDatOffset, text.InTextDataStringOffset = dat, inner
    for key in TEXT_KEYS:
        e.provenance[key] = LABEL_TEXT
    return _finish('text', True, True, f'TextDatOffset {dat:#x}, InTextDataStringOffset {inner:#x}', t0, c)


def _fstring_to_string(header: bytes, reader) -> str:
    """FString::ToString @ ea0dab3: Num - 1 units through UtfN, '' for an invalid header."""
    data, num, mx = struct.unpack('<Qii', header)
    if not (data != 0 and num > 0 and mx >= num):
        return ''
    if num > MAX_STRING_UNITS:
        raise ValueError(f'an FString of {num} units exceeds {MAX_STRING_UNITS}')
    units = reader.read(data, (num - 1) * 2).decode('utf-16-le', 'surrogatepass') if num > 1 else ''
    return utfn.utf_16_string_to_utf_8_string(units)


def detect_game_info(ectx, transport, *, timeout=calls.DEFAULT_TIMEOUT) -> FeatureResult:
    """main.cpp's stem block @ ea0dab3: GetGameName / GetEngineVersion through ProcessEvent set the stem."""
    _check_timeout(timeout)
    e = ectx.engine
    t0 = time.perf_counter()
    pe_index = e.off.InSDK.ProcessEvent.PEIndex
    if pe_index <= 0:
        return _finish('game-info', False, False, 'ProcessEvent was not found', t0)
    c = _Calls('game-info', transport, timeout)
    c.where = 'called through ProcessEvent on KismetSystemLibrary'
    texts = []
    try:
        try:
            kls = e.objects.find_class_fast('KismetSystemLibrary')
            if (kls_address := kls.get_address()) == 0:
                return _finish('game-info', False, False, 'KismetSystemLibrary was not found', t0)
            c.where = f'called through ProcessEvent on KismetSystemLibrary ({kls_address:#x})'
            targets = []
            for name in ('GetGameName', 'GetEngineVersion'):
                fn = kls.get_function('KismetSystemLibrary', name)
                if fn.get_address() == 0:
                    return _finish('game-info', False, False, f'{name} was not found', t0)
                ret = fn.get_return_property()
                struct_size = max(fn.get_struct_size(), 1)
                if ret.get_address() == 0 or ret.get_size() != 16 or not _fits(ret, struct_size, 16):
                    return _finish('game-info', False, False, f'{name} has an unexpected signature', t0)
                targets.append((name, fn.get_address(), ret.get_offset(), struct_size))
            arena = c.open()
            reader = _CallReader(e, transport)
            for name, fn_address, ret_offset, struct_size in targets:
                params = arena.alloc(struct_size, align=16)
                arena.flush()
                pe = calls.process_event_address(transport.process, e.mem, kls_address, pe_index)
                c.process_event(name, kls_address, fn_address, pe, params)
                if not (text := _fstring_to_string(arena.read(params + ret_offset, 16), reader)):
                    return _finish('game-info', True, False, f'{name} returned an empty FString (UE may have skipped the call); the read-only stem stays', t0, c)
                texts.append(text)
        except CallError as exc:
            if getattr(exc, 'exited', None):
                raise
            ran, detail = _failure(exc, c.made)
            return _finish('game-info', ran, False, detail, t0, c)
        except (MemoryReadError, ValueError) as exc:
            ran, detail = _failure(exc, c.made)
            return _finish('game-info', ran, False, detail, t0, c)
    finally:
        c.release()
    game_name, engine_version = texts
    old = ectx.stem.stem
    e.settings.Generator.GameName = game_name
    e.settings.Generator.GameVersion = engine_version
    e.provenance[_GAME_NAME_KEY] = LABEL_GAME_NAME
    e.provenance[_GAME_VERSION_KEY] = LABEL_GAME_VERSION
    ectx.stem = dataclasses.replace(ectx.stem, engine_version=engine_version, game_name=game_name)
    new = f'{engine_version}-{game_name}'
    detail = new + (' (equal to the read-only stem)' if new == old else f' (the read-only stem was {old})')
    return _finish('game-info', True, True, detail, t0, c)


def select_append_sample(e, *, sample=APPEND_SAMPLE, capacity=APPEND_CAPACITY) -> tuple[SampleName, ...]:
    """A deterministic sample of distinct object names: a GObjects stride, a two-block floor and a wide-name floor.
    Only names shorter than capacity // 2 units are taken."""
    _ranged('sample', sample, 1, 1 << 16)
    _ranged('capacity', capacity, 64, 1 << 15)
    o, internal = e.off, e.settings.Internal
    fsize = o.InSDK.Name.FNameSize or 8
    if fsize > 16:
        raise ValueError(f'FNameSize {fsize:#x} is larger than 16 bytes')
    name_offset, cmp_offset, number_offset = o.UObject.Name, o.FName.CompIdx, o.FName.Number
    outline = internal.bUseOutlineNumberName
    if not 0 <= cmp_offset <= fsize - 4 or (not outline and not 0 <= number_offset <= fsize - 4):
        raise ValueError(f'FName.CompIdx {cmp_offset:#x} or FName.Number {number_offset:#x} lies outside FNameSize {fsize:#x}')
    shift = o.InSDK.NameArray.FNamePoolBlockOffsetBits if internal.bUseNamePool else None
    objects, mem, names = e.objects, e.mem, e.names
    num = objects.num()
    candidates: dict[int, SampleName | None] = {}

    def candidate(slot: int) -> SampleName | None:
        if slot in candidates:
            return candidates[slot]
        found = None
        try:
            if address := objects.get_by_index(slot).get_address():
                raw = bytes(mem.read(address + name_offset, fsize))
                cmp = struct.unpack_from('<i', raw, cmp_offset)[0]
                number = 0 if outline else struct.unpack_from('<I', raw, number_offset)[0]
                if number == 0 and 0 < len(name := names.get_name_entry(cmp).get_wstring()) < capacity // 2:
                    found = SampleName(slot, raw, cmp, cmp >> shift if shift is not None else cmp // 0x4000, name)
        except (MemoryReadError, ValueError):
            found = None
        candidates[slot] = found
        return found

    taken: list[SampleName] = []
    taken_cmps: set[int] = set()

    def take(slot: int, accept=None) -> bool:
        if (s := candidate(slot)) is None or s.comparison_index in taken_cmps or (accept is not None and not accept(s)):
            return False
        taken.append(s)
        taken_cmps.add(s.comparison_index)
        return True

    step = max(1, num // sample)
    for start in range(0, num, step):
        if len(taken) >= sample:
            break
        for slot in range(start, min(start + step, num)):
            if take(slot):
                break
    blocks = {s.block for s in taken}
    for slot in range(num - 1, max(num - 1 - APPEND_FLOOR_SCAN, -1), -1):
        if len(blocks) >= 2:
            break
        if take(slot, lambda s: s.block not in blocks):
            blocks.add(taken[-1].block)
    wide = 0
    for slot in range(min(num, APPEND_FLOOR_SCAN)):
        if wide >= APPEND_WIDE_FLOOR:
            break
        if take(slot, lambda s: any(ch > '\x7f' for ch in s.name)):
            wide += 1
    return tuple(taken)


def _executable(process, address: int) -> bool:
    try:
        mbi = process.virtual_query(address)
        protect = int(mbi.Protect)
        return int(mbi.State) == 0x1000 and protect & 0xFF in _EXECUTABLE_PROTECT and not protect & 0x100  # MEM_COMMIT, no PAGE_GUARD
    except OSError:
        return False


def check_append_string(e, transport, *, sample=APPEND_SAMPLE, capacity=APPEND_CAPACITY, timeout=calls.DEFAULT_TIMEOUT) -> FeatureResult:
    """Call FName::AppendString on copies of a sample of object names and compare with the GNames decode; a validator, never a resolver."""
    _ranged('sample', sample, 1, 1 << 16)
    _ranged('capacity', capacity, 64, 1 << 15)
    _check_timeout(timeout)
    t0 = time.perf_counter()
    name_off, internal = e.off.InSDK.Name, e.settings.Internal
    if name_off.AppendNameToString == 0:
        return _finish('append-string', False, False, 'AppendString was not found', t0)
    if name_off.bIsAppendStringInlinedAndUsed:
        return _finish('append-string', False, False, 'AppendString is inlined (GetNameEntryFromName + FNameEntry::GetName); v1 does not call it', t0)
    if not name_off.bIsUsingAppendStringOverToString:
        return _finish('append-string', False, False, 'only FName::ToString was found; it reallocates its out string, so v1 does not call it', t0)
    try:
        names = select_append_sample(e, sample=sample, capacity=capacity)
    except ValueError as exc:
        return _finish('append-string', False, False, f'no names to sample: {exc}', t0)
    if not names:
        return _finish('append-string', False, False, 'no eligible object names to sample', t0)
    append = e.platform.get_module_base() + name_off.AppendNameToString
    if not _executable(transport.process, append):
        return _finish('append-string', False, False, 'AppendString is not executable code', t0)
    fold = bool(internal.bUseCasePreservingName)
    c = _Calls('append-string', transport, timeout)
    c.where = f'({append:#x}) called on {{made}} of {len(names)} sampled names'
    returned = 0
    failed = None
    try:
        try:
            arena = c.open()
            slots = []
            for s in names:
                this = arena.alloc(16, align=8)
                arena.write(this, s.raw.ljust(16, b'\0'))
                buf = arena.alloc(capacity * 2 + 2, align=8)
                hdr = arena.alloc(16, align=8)
                arena.write(hdr, struct.pack('<Qii', buf, 0, capacity))
                slots.append((this, buf, hdr))
            arena.flush()
            for this, buf, hdr in slots:
                try:
                    c.call('FName::AppendString', append, this, hdr)
                except CallError as exc:
                    if getattr(exc, 'exited', None):
                        raise
                    failed = exc
                    break
                returned += 1
            agree, reallocated, disagreements = 0, 0, []
            checked = returned + (failed is not None and getattr(failed, 'state', None) == 'finished')  # a stopping call that ran
            try:
                for i, (s, (this, buf, hdr)) in enumerate(zip(names[:checked], slots)):
                    data, num, mx = struct.unpack('<Qii', arena.read(hdr, 16))
                    if data != buf or mx != capacity or not 0 <= num <= capacity:
                        reallocated += 1
                        c.keep = f'AppendString reallocated {reallocated} of our out strings'
                        continue
                    if i == returned:  # the stopping call's text is never compared
                        continue
                    text = '' if num == 0 else arena.read(buf, (num - 1) * 2).decode('utf-16-le', 'surrogatepass')
                    if (text.casefold() == s.name.casefold()) if fold else text == s.name:
                        agree += 1
                    else:
                        disagreements.append((s.slot, s.name, text))
            except BaseException as exc:
                c.keep = c.keep or f'an AppendString out string could not be checked ({type(exc).__name__}), so it may have been reallocated'
                raise
        except CallError as exc:
            if getattr(exc, 'exited', None):
                raise
            ran, detail = _failure(exc, c.made)
            return _finish('append-string', ran, False, detail, t0, c)
        except (MemoryReadError, ValueError) as exc:
            ran, detail = _failure(exc, c.made)
            return _finish('append-string', ran, False, detail, t0, c)
    finally:
        c.release()
    blocks = ','.join(map(str, sorted({s.block for s in names})))
    wide = sum(any(ch > '\x7f' for ch in s.name) for s in names)
    detail = f'{agree}/{returned} names agree; blocks {blocks}; {wide} wide; {reallocated} reallocated; {len(names) - c.made} not called'
    if failed is not None:
        stop = names[returned]
        detail += f'; stopped at {stop.slot} ({stop.name!r}): {failed}'
    if disagreements:
        slot, ours, theirs = disagreements[0]
        detail += f'; first disagreement {slot}: {ours!r} vs {theirs!r}'
        if len(disagreements) > 1:
            slot, ours, theirs = disagreements[-1]
            detail += f'; last disagreement {slot}: {ours!r} vs {theirs!r}'
    ran = c.made > 0
    ok = ran and failed is None and not reallocated and agree == returned
    return _finish('append-string', ran, ok, detail, t0, c)
