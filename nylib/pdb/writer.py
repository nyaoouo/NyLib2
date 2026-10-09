"""nylib.pdb writer: lower a PdbModel to a PDB (MSF 7.0) file, pure Python."""
import dataclasses
import os
import pathlib
import struct
import uuid
from collections.abc import Sequence

from . import _codeview as _cv
from . import _hash, _msf, pe_info
from .model import (ACCESS, BASE_TYPES, CALLING_CONVENTIONS, MACHINES, POINTER_MODES, Array, Enum, FunctionType, Image,
                    ModelError, Modifier, PdbModel, Pointer, Udt, _is_guid, _normalize_guid)
from .pe_info import SectionHeader

_FIRST_TI = 0x1000
_TPI_BUCKETS = 0x3FFFF
_NIL_SN = 0xFFFF
_INDEX_INTERVAL = 8192
_FIELDLIST_SPLIT = 0xFF00 - 12  # max sub-record bytes per LF_FIELDLIST chunk (room for LF_INDEX)
_MODULE_NAME = 'nylib.pdb'
_COMPILER_NAME = 'nylib.pdb writer'

# machine -> (pointer size, simple-pointer mode bits, array index TI, CV machine)
_MACHINE_INFO = {'x64': (8, 0x600, 0x0023, 0xD0), 'x86': (4, 0x400, 0x0022, 0x07)}


def build_pdb(model: PdbModel, *, pe_path: 'str | os.PathLike | None' = None, guid: 'str | None' = None,
              age: 'int | None' = None, machine: 'str | None' = None,
              sections: 'Sequence[SectionHeader] | None' = None) -> bytes:
    """Return the bytes of a PDB for ``model`` bound to the effective (guid, age, machine, sections).

    Binding per field: explicit argument > PE (``pe_path``) > ``model.image``; a missing field is a
    ``ModelError``. The model is validated first and never mutated; the output depends only on
    ``model.normalized()`` and the effective binding. ``pe_path`` is opened read-only.
    """
    _check_arguments(guid, age, machine, sections)  # V32: argument validity
    pe_machine = pe_guid = pe_age = pe_sections = None
    signature = 0
    if pe_path is not None:
        info = pe_info.read_image_info(pe_path)  # ValueError propagates unchanged
        signature, pe_machine, pe_sections = info.time_date_stamp, info.machine, list(info.sections)
        if sections is None:  # PE sections are effective only when no sections argument overrides them
            try:
                PdbModel(image=Image(sections=pe_sections)).validate()
            except ModelError as e:
                raise ModelError(e.path, f'PE sections: {e.message}') from None
        try:
            dbg = pe_info.read_debug_info(pe_path)
        except ValueError as e:
            raise ValueError(f'{e}; to bind without pe_path, pass guid, age, machine, sections '
                             '(and out_path) explicitly') from e
        pe_guid, pe_age = dbg.guid, dbg.age
    if not isinstance(model.image, Image):
        model.validate()  # raises the canonical 'image: expected an Image, ...' error
    img = model.image
    eff_machine = machine if machine is not None else (_pe_machine_name(pe_machine) if pe_path is not None else img.machine)
    eff_guid = guid if guid is not None else (pe_guid if pe_path is not None else img.guid)
    eff_age = age if age is not None else (pe_age if pe_path is not None else img.age)
    eff_sections = (list(sections) if sections is not None
                    else (pe_sections if pe_path is not None else list(img.sections)))
    # Validate the model as bound: a copy whose image holds the effective binding, so an overridden
    # field is not checked against V1-V4 (OQ6-A). model.normalized() below re-checks V28/V30 regardless.
    bound_image = dataclasses.replace(img, machine=eff_machine, guid=eff_guid, age=eff_age, sections=eff_sections)
    dataclasses.replace(model, image=bound_image).validate()
    if eff_guid is None:
        raise ModelError('image.guid', 'guid missing after binding resolution')
    if eff_age is None:
        raise ModelError('image.age', 'age missing after binding resolution')
    if not eff_sections:
        raise ModelError('image.sections', 'sections missing after binding resolution')
    return _Writer(model.normalized(), eff_machine, _normalize_guid(eff_guid), eff_age, eff_sections,
                   signature).build()


def _pe_machine_name(coff_machine: int) -> str:
    """Map a COFF ``Machine`` value to the model's machine name, or raise V1's ``ModelError``."""
    for name, code in MACHINES.items():
        if code == coff_machine:
            return name
    raise ModelError('image.machine', f'PE machine not supported: {coff_machine:#x}')


def write_pdb(model: PdbModel, out_path: 'str | os.PathLike | None' = None, *,
              pe_path: 'str | os.PathLike | None' = None, guid: 'str | None' = None, age: 'int | None' = None,
              machine: 'str | None' = None, sections: 'Sequence[SectionHeader] | None' = None,
              overwrite: bool = False) -> pathlib.Path:
    """Build a PDB for ``model`` (as ``build_pdb``) and write it to ``out_path``; returns the resolved path.

    ``out_path=None`` requires ``pe_path`` (defaults to ``<pe dir>/<RSDS pdb name>``); refuses the PE
    file as the target, and an existing file unless ``overwrite=True``.
    """
    if out_path is None and pe_path is None:
        raise ValueError('write_pdb: out_path is required when pe_path is not given')
    # build_pdb runs before the default out_path is derived, so a missing RSDS entry always raises here.
    data = build_pdb(model, pe_path=pe_path, guid=guid, age=age, machine=machine, sections=sections)
    out = (pathlib.Path(out_path) if out_path is not None
           else pathlib.Path(pe_path).resolve().parent / pe_info.read_debug_info(pe_path).pdb_name)
    if ':' in out.name:
        raise ValueError(f'write_pdb: out_path must not be an alternate data stream: {out}')
    if pe_path is not None:
        pe = pathlib.Path(pe_path)
        same = os.path.samefile(out, pe) if out.exists() else out.resolve() == pe.resolve()
        if same:
            raise ValueError(f'write_pdb: out_path must not be the PE file: {out}')
    if out.exists() and not overwrite:
        raise FileExistsError(out)
    tmp = out.with_name(out.name + f'.tmp-{os.getpid()}')
    try:
        tmp.write_bytes(data)
        os.replace(tmp, out)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return out.resolve()


def _check_arguments(guid, age, machine, sections):
    if machine is not None and (not isinstance(machine, str) or machine not in MACHINES):
        raise ModelError('image.machine', f'invalid machine argument: {machine!r}')
    if guid is not None and not _is_guid(guid):
        raise ModelError('image.guid', f'invalid guid argument: {guid!r}')
    if age is not None and (isinstance(age, bool) or not isinstance(age, int) or not 0 <= age <= 0xFFFFFFFF):
        raise ModelError('image.age', f'invalid age argument: {age!r}')
    if sections is not None:
        if not isinstance(sections, Sequence) or isinstance(sections, (str, bytes)):
            raise ModelError('image.sections', f'sections argument: expected a sequence, got {sections!r}')
        try:
            PdbModel(image=Image(sections=list(sections))).validate()
        except ModelError as e:
            raise ModelError(e.path, f'sections argument: {e.message}') from None


class _Writer:
    def __init__(self, nm: PdbModel, machine: str, guid: str, age: int, sections: list, signature: int = 0):
        self.nm = nm
        self.machine = machine
        self.ptr_size, self.simple_ptr_mode, self.index_ti, self.cv_machine = _MACHINE_INFO[machine]
        self.guid = guid
        self.age = age
        self.sections = sections
        self.signature = signature
        self.names = {t.name: t for t in nm.types}
        self.names.update((t.name, t) for t in nm.typedefs)
        self.records = []
        self.index = {}  # record bytes -> TI
        self.fwd = {}  # top-level Udt name -> forward-reference TI
        self.defs = {}  # top-level type name -> definition TI
        self.memo = {}  # id(inline object) -> TI
        self.active = set()  # ids of inline objects being lowered
        self.where = ''

    # -- type records ------------------------------------------------------------------------------

    def _add(self, leaf: int, payload: bytes) -> int:
        try:
            rec = _cv.type_record(leaf, payload)
        except ValueError as e:
            raise ModelError(self.where, str(e)) from None
        if (ti := self.index.get(rec)) is None:
            ti = self.index[rec] = _FIRST_TI + len(self.records)
            self.records.append(rec)
        return ti

    def _resolve(self, ref):
        """Follow typedef names to a base-type name, a top-level Udt/Enum, or an inline object."""
        while isinstance(ref, str) and ref not in BASE_TYPES:
            t = self.names[ref]
            if isinstance(t, (Udt, Enum)):
                return t
            ref = t.type
        return ref

    def _is_top(self, obj) -> bool:
        return self.names.get(obj.name) is obj

    def _ti(self, ref) -> int:
        """TI a type record uses for ``ref``: named Udts through their forward reference."""
        r = self._resolve(ref)
        if isinstance(r, str):
            return BASE_TYPES[r][0]
        if isinstance(r, Udt) and self._is_top(r):
            return self.fwd[r.name]
        if isinstance(r, Enum) and self._is_top(r):
            return self._enum_def(r)
        if (ti := self.memo.get(id(r))) is not None:
            return ti
        if id(r) in self.active:
            raise ModelError(self.where, 'an inline type refers to itself through a typedef')
        self.active.add(id(r))
        if isinstance(r, Pointer):
            ti = self._pointer(r)
        elif isinstance(r, Modifier):
            ti = self._modifier(r)
        elif isinstance(r, Array):
            ti = self._add(_cv.LF_ARRAY, struct.pack('<II', self._ti(r.of), self.index_ti)
                           + _cv.numeric(r.count * self._sizeof(r.of)) + b'\0')
        elif isinstance(r, FunctionType):
            ti = self._procedure(r)
        elif isinstance(r, Udt):
            ti = self._udt_def(r)
        else:
            ti = self._enum_def(r)
        self.active.discard(id(r))
        self.memo[id(r)] = ti
        return ti

    def _sym_ti(self, ref) -> int:
        """TI a symbol record uses for ``ref``: a named non-opaque Udt by its definition."""
        if ref is None:
            return 0
        r = self._resolve(ref)
        if isinstance(r, Udt) and self._is_top(r) and not r.opaque:
            return self._udt_def(r)
        return self._ti(ref)

    def _sizeof(self, ref) -> int:
        r = self._resolve(ref)
        if isinstance(r, str):
            return BASE_TYPES[r][1]
        if isinstance(r, Udt):
            return r.size
        if isinstance(r, Enum):
            return BASE_TYPES[r.underlying][1]
        if isinstance(r, Pointer):
            return r.size if r.size is not None else self.ptr_size
        if isinstance(r, Array):
            return r.count * self._sizeof(r.of)
        if isinstance(r, Modifier):
            return self._sizeof(r.of)
        return 0

    def _pointer(self, p: Pointer, const=False, volatile=False, unaligned=False) -> int:
        const, volatile, unaligned = const or p.const, volatile or p.volatile, unaligned or p.unaligned
        size = p.size if p.size is not None else self.ptr_size
        target = self._resolve(p.to)
        if isinstance(target, str) and p.mode == 'pointer' and size == self.ptr_size and not (
                const or volatile or unaligned):
            return BASE_TYPES[target][0] | self.simple_ptr_mode
        attrs = (0x0C if size == 8 else 0x0A) | POINTER_MODES[p.mode] << 5 | size << 13
        attrs |= (0x400 if const else 0) | (0x200 if volatile else 0) | (0x800 if unaligned else 0)
        return self._add(_cv.LF_POINTER, struct.pack('<II', self._ti(p.to), attrs))

    def _modifier(self, mod: Modifier) -> int:
        target = self._resolve(mod.of)
        if isinstance(target, Pointer):
            return self._pointer(target, mod.const, mod.volatile, mod.unaligned)
        flags = (1 if mod.const else 0) | (2 if mod.volatile else 0) | (4 if mod.unaligned else 0)
        return self._add(_cv.LF_MODIFIER, struct.pack('<IH', self._ti(mod.of), flags))

    def _procedure(self, fn: FunctionType) -> int:
        ret = self._ti(fn.returns)
        args = [self._ti(a) for a in fn.args] + ([0] if fn.variadic else [])
        arglist = self._add(_cv.LF_ARGLIST, struct.pack(f'<I{len(args)}I', len(args), *args))
        return self._add(_cv.LF_PROCEDURE,
                         struct.pack('<IBBHI', ret, CALLING_CONVENTIONS[fn.call], 0, len(args), arglist))

    def _fieldlist(self, subrecs: list) -> int:
        """Emit a field list, split tail-first into LF_INDEX-chained chunks when too long; returns the head TI."""
        if 2 + sum(map(len, subrecs)) <= 0xFF00:
            return self._add(_cv.LF_FIELDLIST, b''.join(subrecs))
        chunks, cur, cur_len = [], [], 0
        for s in subrecs:
            if cur and cur_len + len(s) > _FIELDLIST_SPLIT:
                chunks.append(cur)
                cur, cur_len = [], 0
            cur.append(s)
            cur_len += len(s)
        chunks.append(cur)
        ti = None
        for chunk in reversed(chunks):
            tail = b'' if ti is None else struct.pack('<HHI', _cv.LF_INDEX, 0, ti)
            ti = self._add(_cv.LF_FIELDLIST, b''.join(chunk) + tail)
        return ti

    def _udt_def(self, u: Udt) -> int:
        top = self._is_top(u)
        if top and (ti := self.defs.get(u.name)) is not None:
            return ti
        subrecs = [_cv.fl_bclass(self._ti(b.type), b.offset, ACCESS[b.access]) for b in u.bases]
        for f in u.fields:
            t = self._ti(f.type)
            if f.bit_offset is not None:
                t = self._add(_cv.LF_BITFIELD, struct.pack('<IBB', t, f.bit_length, f.bit_offset))
            subrecs.append(_cv.fl_member(f.name, t, f.offset, ACCESS[f.access]))
        fl = self._fieldlist(subrecs)
        count = len(u.bases) + len(u.fields)
        tail = _cv.numeric(u.size) + _cv.cstr(u.name)
        if u.kind == 'union':
            ti = self._add(_cv.LF_UNION, struct.pack('<HHI', count, 0, fl) + tail)
        else:
            leaf = _cv.LF_CLASS if u.kind == 'class' else _cv.LF_STRUCTURE
            ti = self._add(leaf, struct.pack('<HHIII', count, 0, fl, 0, 0) + tail)
        if top:
            self.defs[u.name] = ti
        return ti

    def _enum_def(self, e: Enum) -> int:
        top = self._is_top(e)
        if top and (ti := self.defs.get(e.name)) is not None:
            return ti
        fl = self._fieldlist([_cv.fl_enumerate(n, v, 3) for n, v in e.values.items()])
        ti = self._add(_cv.LF_ENUM, struct.pack('<HHII', len(e.values), 0, BASE_TYPES[e.underlying][0], fl)
                       + _cv.cstr(e.name))
        if top:
            self.defs[e.name] = ti
        return ti

    def _forward_ref(self, u: Udt) -> int:
        tail = _cv.numeric(0) + _cv.cstr(u.name)
        if u.kind == 'union':
            return self._add(_cv.LF_UNION, struct.pack('<HHI', 0, _cv.CO_FWDREF, 0) + tail)
        leaf = _cv.LF_CLASS if u.kind == 'class' else _cv.LF_STRUCTURE
        return self._add(leaf, struct.pack('<HHIII', 0, _cv.CO_FWDREF, 0, 0, 0) + tail)

    def _lower(self):
        """Emit every type record in the normative TI order; returns the TIs symbol records use."""
        nm = self.nm
        for i, t in enumerate(nm.types):
            if isinstance(t, Udt):
                self.where = f'types[{i}]'
                self.fwd[t.name] = self._forward_ref(t)
        for i, t in enumerate(nm.types):
            self.where = f'types[{i}]'
            if isinstance(t, Enum):
                self._enum_def(t)
            elif not t.opaque:
                self._udt_def(t)
        typedef_tis, function_tis, data_tis = [], [], []
        for i, t in enumerate(nm.typedefs):
            self.where = f'typedefs[{i}]'
            typedef_tis.append(self._sym_ti(t.type))
        for i, f in enumerate(nm.functions):
            self.where = f'functions[{i}]'
            function_tis.append(0 if f.type is None else self._ti(f.type))
        for i, x in enumerate(nm.data):
            self.where = f'data[{i}]'
            data_tis.append(self._sym_ti(x.type))
        self.where = ''
        return typedef_tis, function_tis, data_tis

    # -- streams -----------------------------------------------------------------------------------

    def _tpi(self, hash_sn: int):
        """``(TPI stream, hash stream)``: hash values then index offsets (first record + every 8 KiB crossing)."""
        data = b''.join(self.records)
        values = b''.join(struct.pack('<I', _hash.tpi_hash(r) % _TPI_BUCKETS) for r in self.records)
        offsets = bytearray()
        total = 0
        for i, rec in enumerate(self.records):
            new = total + len(rec)
            if i == 0 or new // _INDEX_INTERVAL > total // _INDEX_INTERVAL:
                offsets += struct.pack('<II', _FIRST_TI + i, total)
            total = new
        nv = len(values)
        hdr = struct.pack('<IIIII', 20040203, 56, _FIRST_TI, _FIRST_TI + len(self.records), len(data))
        hdr += struct.pack('<HHII', hash_sn, _NIL_SN, 4, _TPI_BUCKETS)
        hdr += struct.pack('<iIiIiI', 0, nv, nv, len(offsets), nv, 0)
        return hdr + data, values + bytes(offsets)

    @staticmethod
    def _empty_tpi() -> bytes:
        return (struct.pack('<IIIII', 20040203, 56, _FIRST_TI, _FIRST_TI, 0) + struct.pack('<HHII', _NIL_SN, _NIL_SN, 4, _TPI_BUCKETS)
                + struct.pack('<iIiIiI', 0, 0, 0, 0, 0, 0))

    def _seg_off(self, rva: int):
        for i, s in enumerate(self.sections):
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return i + 1, rva - s.virtual_address
        raise ModelError(self.where, f'rva {rva:#x} is not inside any section')

    def _sym(self, kind: int, payload: bytes) -> bytes:
        try:
            return _cv.symbol_record(kind, payload)
        except ValueError as e:
            raise ModelError(self.where, str(e)) from None

    def _module_stream(self, function_tis, data_tis):
        """``(module stream, SymByteSize, [module offset of each function's proc record])``."""
        mod = bytearray(struct.pack('<I', 4))  # CV_SIGNATURE_C13
        mod += self._sym(_cv.S_OBJNAME, struct.pack('<I', 0) + _cv.cstr(_MODULE_NAME))
        mod += self._sym(_cv.S_COMPILE3, struct.pack('<IH4H4H', 1, self.cv_machine, 19, 0, 0, 0, 19, 0, 0, 0)
                         + _cv.cstr(_COMPILER_NAME))
        proc_offsets = []
        for i, (f, ti) in enumerate(zip(self.nm.functions, function_tis)):
            self.where = f'functions[{i}]'
            start = len(mod)
            proc_offsets.append(start)
            mod += self._proc_record(f, ti, start + len(self._proc_record(f, ti, 0)))
            mod += self._sym(_cv.S_END, b'')
        for i, (x, ti) in enumerate(zip(self.nm.data, data_tis)):
            if x.static:
                self.where = f'data[{i}]'
                mod += self._data_record(x, ti)
        self.where = ''
        sym_bytes = len(mod)
        mod += struct.pack('<I', 0)  # global refs size
        return bytes(mod), sym_bytes, proc_offsets

    def _proc_record(self, f, ti: int, end: int) -> bytes:
        """S_GPROC32/S_LPROC32; ``end`` is the module-stream offset of its S_END."""
        seg, off = self._seg_off(f.rva)
        return self._sym(_cv.S_LPROC32 if f.static else _cv.S_GPROC32,
                         struct.pack('<7IIHB', 0, end, 0, f.length, 0, max(f.length - 1, 0), ti, off, seg, 0)
                         + _cv.cstr(f.name))

    def _data_record(self, x, ti: int) -> bytes:
        seg, off = self._seg_off(x.rva)
        return self._sym(_cv.S_LDATA32 if x.static else _cv.S_GDATA32,
                         struct.pack('<IIH', ti, off, seg) + _cv.cstr(x.name))

    def _public_is_function(self, p) -> bool:
        if p.function is not None:
            return p.function
        seg, _off = self._seg_off(p.rva)
        return bool(self.sections[seg - 1].characteristics & (0x20 | 0x20000000))  # CNT_CODE | MEM_EXECUTE

    def _symbol_records(self, typedef_tis, data_tis, proc_offsets):
        """``(symbol-record stream, GSI stream, PSI stream)``."""
        nm = self.nm
        symrec = bytearray()
        pub_entries, addr_entries = [], []
        for i, p in sorted(enumerate(nm.publics), key=lambda ip: ip[1].name.encode('utf-8')):
            self.where = f'publics[{i}]'
            seg, off = self._seg_off(p.rva)
            name = p.name.encode('utf-8')
            pub_entries.append((name, len(symrec)))
            addr_entries.append((seg, off, name, len(symrec)))
            symrec += self._sym(_cv.S_PUB32, struct.pack('<IIH', 2 if self._public_is_function(p) else 0, off, seg)
                                + name + b'\0')
        glob_entries = []

        def add_global(name: str, rec: bytes):
            glob_entries.append((name.encode('utf-8'), len(symrec)))
            symrec.extend(rec)

        for i, (x, ti) in enumerate(zip(nm.data, data_tis)):
            self.where = f'data[{i}]'
            add_global(x.name, self._data_record(x, ti))
        for i, (t, ti) in enumerate(zip(nm.typedefs, typedef_tis)):
            self.where = f'typedefs[{i}]'
            add_global(t.name, self._sym(_cv.S_UDT, struct.pack('<I', ti) + _cv.cstr(t.name)))
        for i, (f, off) in enumerate(zip(nm.functions, proc_offsets)):
            self.where = f'functions[{i}]'
            add_global(f.name, self._sym(_cv.S_LPROCREF if f.static else _cv.S_PROCREF,
                                         struct.pack('<IIH', 0, off, 1) + _cv.cstr(f.name)))
        self.where = ''
        gsi = _hash.gsi_hash_stream(glob_entries)
        psh = _hash.gsi_hash_stream(pub_entries)
        amap = _hash.psi_address_map(addr_entries)
        psi = struct.pack('<IIIIH2xII', len(psh), len(amap), 0, 0, 0, 0, 0) + psh + amap
        return bytes(symrec), gsi, psi

    def _contributions(self) -> list:
        """Merged, clipped ``(isect, offset, size, characteristics)`` ranges, sorted by (isect, offset)."""
        ranges = {}
        items = [(f.rva, f.length) for f in self.nm.functions if f.length > 0]
        items += [(x.rva, self._sizeof(x.type)) for x in self.nm.data if x.type is not None]
        for rva, size in items:
            if size <= 0:
                continue
            seg, lo = self._seg_off(rva)
            s = self.sections[seg - 1]
            hi = min(lo + size, max(s.virtual_size, s.raw_size), 0x7FFFFFFF)
            if lo < hi:
                ranges.setdefault(seg, []).append((lo, hi))
        out = []
        for seg in sorted(ranges):
            merged = []
            for lo, hi in sorted(ranges[seg]):
                if merged and lo <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], hi)
                else:
                    merged.append([lo, hi])
            chars = self.sections[seg - 1].characteristics
            out.extend((seg, lo, hi - lo, chars) for lo, hi in merged)
        return out

    def _dbi(self, *, gsi_sn, psi_sn, sym_sn, mod_sn, sym_bytes, sechdr_sn, contribs) -> bytes:
        first = contribs[0] if contribs else (0, 0, 0, 0)
        modi = struct.pack('<I', 0) + _sec_contrib(*first) + struct.pack('<HHIIIH2xIII', 0, mod_sn, sym_bytes, 0, 0, 0, 0, 0, 0)
        modi += _cv.cstr(_MODULE_NAME) + _cv.cstr(_MODULE_NAME)
        modi += b'\0' * (-len(modi) % 4)
        sc = struct.pack('<I', 0xEFFE0000 + 19970605) + b''.join(_sec_contrib(*c) for c in contribs)
        ents = [struct.pack('<HHHHHHII', _secmap_flags(s.characteristics), 0, 0, i + 1, 0xFFFF, 0xFFFF, 0, s.virtual_size)
                for i, s in enumerate(self.sections)]
        ents.append(struct.pack('<HHHHHHII', 0x208, 0, 0, 0, 0xFFFF, 0xFFFF, 0, 0xFFFFFFFF))  # absolute address entry, Frame 0
        secmap = struct.pack('<HH', len(ents), len(ents)) + b''.join(ents)
        fileinfo = struct.pack('<HHHH', 1, 0, 0, 0)  # 1 module, 0 files: mod index 0, file count 0
        dbg = [_NIL_SN] * 11
        dbg[5] = sechdr_sn
        dbg_hdr = struct.pack('<11H', *dbg)
        hdr = struct.pack('<iIIHHHHHHiiiiiIiiHHI', -1, 19990903, self.age, gsi_sn, 0x8E0B, psi_sn, 0, sym_sn, 0,
                          len(modi), len(sc), len(secmap), len(fileinfo), 0, 0, len(dbg_hdr), 0, 0,
                          MACHINES[self.machine], 0)
        return hdr + modi + sc + secmap + fileinfo + dbg_hdr

    def build(self) -> bytes:
        try:
            typedef_tis, function_tis, data_tis = self._lower()
        except RecursionError:
            raise ModelError(self.where, 'type nesting through typedefs too deep') from None
        streams = [b'', None, None, None, self._empty_tpi()]  # 0 old directory, 1 PDB info, 2 TPI, 3 DBI, 4 IPI

        def add(data: bytes) -> int:
            streams.append(data)
            return len(streams) - 1

        hash_sn = add(b'')
        streams[2], streams[hash_sn] = self._tpi(hash_sn)
        mod, sym_bytes, proc_offsets = self._module_stream(function_tis, data_tis)
        mod_sn = add(mod)
        symrec, gsi, psi = self._symbol_records(typedef_tis, data_tis, proc_offsets)
        sym_sn = add(symrec)
        gsi_sn = add(gsi)
        psi_sn = add(psi)
        sechdr_sn = add(b''.join(
            struct.pack('<8sIIIIIIHHI', s.name.encode('latin-1'), s.virtual_size, s.virtual_address, s.raw_size,
                        s.raw_pointer, 0, 0, 0, 0, s.characteristics) for s in self.sections))
        streams[3] = self._dbi(gsi_sn=gsi_sn, psi_sn=psi_sn, sym_sn=sym_sn, mod_sn=mod_sn, sym_bytes=sym_bytes,
                               sechdr_sn=sechdr_sn, contribs=self._contributions())
        names_sn = add(_hash.string_table())
        streams[1] = (struct.pack('<III', 20000404, self.signature, self.age) + uuid.UUID(hex=self.guid).bytes_le
                      + _hash.named_stream_map({'/names': names_sn}) + struct.pack('<I', 20140508))  # feature VC140
        return _msf.write_msf(streams)


def _sec_contrib(isect: int, offset: int, size: int, characteristics: int) -> bytes:
    return struct.pack('<H2xiiIH2xII', isect, offset, size, characteristics, 0, 0, 0)


def _secmap_flags(characteristics: int) -> int:
    f = 8 | 0x100  # AddressIs32Bit | IsSelector
    if characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
        f |= 1
    if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
        f |= 2
    if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
        f |= 4
    return f
