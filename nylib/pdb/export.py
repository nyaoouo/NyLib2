"""nylib.pdb export: lower a DIA (or duck-typed) PDB session to a PdbModel.

Pure Python; imports the compiled extension only for a path source (lazily,
inside ``export_pdb``). Never imports it for a duck-typed fake session.
"""
import contextlib
import dataclasses
import os
import sys

from . import SymTag, _codeview, _msf, model

_EXT_MODULE_NAME = 'nylib.pdb._ny_pdb'

# Additive G1/G3-G8/G11-G13 names a current build must expose (extended by
# test_export_stale_extension to prove the check fires on a missing name).
_REQUIRED_NAMES = (
    ('Type', 'udt_kind'), ('Type', 'is_const'), ('Type', 'is_volatile'), ('Type', 'is_unaligned'),
    ('Type', 'is_reference'), ('Type', 'is_rvalue_reference'), ('Type', 'calling_convention'),
    ('Type', 'class_parent'), ('Symbol', 'is_function'), ('Symbol', 'is_code'), ('Symbol', 'data_kind'),
    ('Symbol', 'is_static'), ('Symbol', 'location_type'), ('Member', 'access'),
)

_MACHINE_BY_CODE = {code: name for name, code in model.MACHINES.items()}
_NATIVE_PTR = {'x64': 8, 'x86': 4}
_ACCESS_BY_INT = {1: 'private', 2: 'protected', 3: 'public'}
_KIND_BY_INT = {0: 'struct', 1: 'class', 2: 'union'}
_CALL_BY_INT = {code: name for name, code in model.CALLING_CONVENTIONS.items()}
_ENUM_FALLBACK_BY_SIZE = {1: 'signed char', 2: 'short', 4: 'int', 8: '__int64'}

_OMIT = object()  # sentinel: a zero-size reduction; the caller drops the whole item

# Type-content reports, reached once per reference or per DIA entry: kept once per (category, name, detail).
_TYPE_LEVEL = frozenset({
    'reduced_type', 'pointer_to_member', 'alias_resolved', 'calling_convention', 'enum_underlying',
    'enum_value_out_of_range', 'enum_value_missing', 'interface_as_struct', 'method', 'vfptr', 'static_member',
    'nested_type', 'virtual_base', 'friend', 'unsupported_member',
})


@dataclasses.dataclass
class Dropped:
    category: str
    name: str
    detail: str = ''


@dataclasses.dataclass
class ExportResult:
    model: model.PdbModel
    dropped: 'list[Dropped]'


class ExportError(ValueError):
    """Export failed: unsupported content with ``strict=True``, or an export-side bug (``dropped == []``)."""

    def __init__(self, dropped, message=''):
        self.dropped = list(dropped)
        super().__init__(message or f'{len(self.dropped)} item(s) dropped')


def _cpp_enum_value(underlying: str, stored: int) -> 'tuple[int, bool]':
    """Map a stored enumerator value to its C++ value under ``underlying`` (19-D).

    ``ValueError`` when ``underlying`` is not enum-capable.
    """
    rng = model.enum_range(underlying)
    if rng is None:
        raise ValueError(f'not an enum-capable base type: {underlying!r}')
    lo, hi = rng
    width = hi - lo + 1
    if lo <= stored <= hi:
        return stored, False
    unsigned = lo == 0
    if -(width // 2) <= stored <= width - 1:
        return (stored + width if unsigned else stored - width), False
    return ((stored - lo) % width) + lo, True


def _check_stale_build(ext) -> None:
    missing = [f'{cls_name}.{attr}' for cls_name, attr in _REQUIRED_NAMES if not hasattr(getattr(ext, cls_name), attr)]
    if missing:
        raise ImportError(
            f'nylib.pdb extension missing {", ".join(missing)} (stale build) - run: {sys.executable} scripts/pdb/build.py')


def export_pdb(source, *, strict: bool = False) -> ExportResult:
    """Export ``source`` (a ``.pdb`` path, or an open/duck-typed session) to a ``PdbModel``.

    A path is opened and closed here; any other object is used as given and left open.
    ``strict=True`` raises ``ExportError(dropped)`` if anything was dropped.
    """
    opened_path = isinstance(source, (str, os.PathLike))
    sess = None
    owns = False
    try:
        if opened_path:
            from . import Session  # lazy: only a path source ever loads the extension
            sess = Session(os.fspath(source))
            owns = True
            _check_stale_build(sys.modules[_EXT_MODULE_NAME])
        else:
            sess = source
            ext = sys.modules.get(_EXT_MODULE_NAME)
            if ext is not None and isinstance(sess, ext.Session):
                _check_stale_build(ext)
        exporter = _Exporter(sess)
        try:
            built = exporter.run()
        except (ExportError, ImportError, OSError):
            raise
        except Exception as e:
            raise ExportError([], f'export failed: {e}') from e
    finally:
        if owns and sess is not None:
            sess.close()
    dropped = exporter.dropped
    if strict and dropped:
        raise ExportError(dropped, f'{len(dropped)} item(s) dropped')
    return ExportResult(model=built, dropped=dropped)


class _Exporter:
    """One ``export_pdb`` call's working state (caches, name registry, drop list)."""

    def __init__(self, sess):
        self.sess = sess
        self.dropped = []
        self._drop_keys = set()
        self._muted = False         # reports suppressed (signature and comparison passes)
        self._dia_names = False     # named UDTs spelled by DIA name (the signature form)
        self._native_ptr_size = 8
        self._sections = []
        self._typedef_models = []
        self._function_models = []
        self._data_models = []
        self._public_models = []
        self._used_names = set()
        self._udt_names = {}        # sym_index_id -> assigned model name
        self._udt_by_sig = {}       # (DIA name, signature) -> assigned model name
        self._udt_first = {}        # DIA name -> the group's first assigned name (opaque merge)
        self._enum_names = {}       # sym_index_id -> assigned model name
        self._enum_by_sig = {}      # (DIA name, (underlying, values)) -> assigned model name
        self._omitted_enum_ids = set()
        self._udt_models = []
        self._enum_models = []
        self._anon_cache = {}       # (muted, dia_names, sym_index_id) -> converted inline type
        self._inlined = set()       # anonymous keys inlined by an exported item
        self._suppress_inline = False  # reporting a merged entry's drops must not record inlining (N1)

    def run(self) -> model.PdbModel:
        image = self._build_image()
        raw_types = self.sess.find_types('*')
        self._collect_enums([t for t in raw_types if t.tag == 'enum'])
        self._collect_udts([t for t in raw_types if t.tag == 'udt'])
        self._collect_typedefs()
        self._collect_functions()
        self._collect_data()
        self._collect_publics()
        self._report_anonymous_unreferenced(raw_types)
        built = model.PdbModel(image=image, types=self._enum_models + self._udt_models,
                               typedefs=self._typedef_models, functions=self._function_models,
                               data=self._data_models, publics=self._public_models)
        built.validate()
        return built.normalized()

    def _drop(self, category, name, detail=''):
        if self._muted:
            return
        if category in _TYPE_LEVEL:
            if (category, name, detail) in self._drop_keys:
                return
            self._drop_keys.add((category, name, detail))
        self.dropped.append(Dropped(category=category, name=name, detail=detail))

    @contextlib.contextmanager
    def _quiet(self, *, dia_names):
        """Mute reports; with ``dia_names``, spell named UDTs by DIA name (the signature form)."""
        saved = self._muted, self._dia_names
        self._muted, self._dia_names = True, dia_names
        try:
            yield
        finally:
            self._muted, self._dia_names = saved

    @contextlib.contextmanager
    def _report_without_inlining(self):
        """Reports fire, but anonymous inlining is not recorded (N1): a merged/absorbed entry
        may reference a different same-name anonymous variant than the kept representative."""
        saved = self._suppress_inline
        self._suppress_inline = True
        try:
            yield
        finally:
            self._suppress_inline = saved

    # -- image -------------------------------------------------------------

    def _build_image(self) -> model.Image:
        code = self.sess.machine()
        name = _MACHINE_BY_CODE.get(code)
        if name is None:
            raise ExportError([], f'unsupported machine: {code:#x}')
        self._native_ptr_size = _NATIVE_PTR[name]
        guid, age = self.sess.pdb_signature
        sections = _msf.read_section_headers(self.sess.pdb_path)  # G9; read while DIA holds the file (E6)
        if not sections:
            self._drop('section_headers', '', detail='no section-header stream')
        self._sections = list(sections)
        return model.Image(machine=name, guid=guid, age=age, sections=self._sections)

    # -- name registry -------------------------------------------------------

    def _claim_name(self, base: str) -> str:
        if base not in self._used_names:
            self._used_names.add(base)
            return base
        n = 2
        while f'{base}#{n}' in self._used_names:
            n += 1
        nm = f'{base}#{n}'
        self._used_names.add(nm)
        return nm

    def _kind_for(self, t):
        """``(model kind, is_interface)`` from G1 ``udt_kind`` (3 = ``__interface``, exported as struct)."""
        if t.udt_kind == 3:
            return 'struct', True
        return _KIND_BY_INT.get(t.udt_kind, 'struct'), False

    def _group_by_name(self, raw):
        """Named entries grouped by DIA name in first-appearance order; anonymous ones are inlined where used."""
        groups = {}
        for t in raw:
            if not t.name:
                self._drop('unnamed', '')
            elif not model.is_anonymous_name(t.name):
                groups.setdefault(t.name, []).append(t)
        return groups

    # -- enums ---------------------------------------------------------------

    def _enum_underlying(self, t, owner):
        """``(model name, keep)``: the enum-capable base-type name backing ``t``, or ``(None, False)`` to omit it."""
        bt = self._resolve_typedef(t.base_type())
        name = None
        if bt is not None and bt.tag == 'basetype':
            name = _codeview.BASE_TYPES_BY_DIA.get((bt.base_kind, bt.size))
        if name is not None and model.enum_range(name) is not None:
            return name, True
        fallback = _ENUM_FALLBACK_BY_SIZE.get(t.size)
        spelling = bt.name if bt is not None else 'none'
        self._drop('enum_underlying', owner, detail=f'{spelling} -> {fallback or "omitted"}')
        return fallback, fallback is not None

    def _enum_values(self, t, underlying, owner):
        out = {}
        for mem in t.members():
            if mem.tag != 'data':
                continue
            if mem.enum_value is None:
                self._drop('enum_value_missing', f'{owner}::{mem.name}')
                continue
            v, bad = _cpp_enum_value(underlying, mem.enum_value)
            if bad:
                self._drop('enum_value_out_of_range', f'{owner}::{mem.name}', detail=f'{mem.enum_value} -> {v}')
            out[mem.name] = v
        return out

    def _enum_content(self, t, owner):
        """``(underlying, values)`` of enum ``t``, or ``None`` when it is omitted; reports name ``owner``."""
        underlying, keep = self._enum_underlying(t, owner)
        if not keep:
            return None
        return underlying, self._enum_values(t, underlying, owner)

    def _collect_enums(self, raw):
        """Group by name and signature; an entry without enumerators joins the first one with its underlying type."""
        for name, entries in self._group_by_name(raw).items():
            infos = []
            for e in entries:
                with self._quiet(dia_names=False):
                    content = self._enum_content(e, name)
                if content is None:
                    self._enum_content(e, name)  # reports the omission
                    self._omitted_enum_ids.add(e.sym_index_id)
                    continue
                infos.append((e, *content))
            seen = {}  # signature -> assigned name
            for e, underlying, values in [i for i in infos if i[2]] + [i for i in infos if not i[2]]:
                if not values:
                    target = next((nm for (u, _v), nm in seen.items() if u == underlying), None)
                    if target is not None:
                        self._enum_names[e.sym_index_id] = target
                        self._enum_content(e, target)  # reports the absorbed entry's own drops (N1)
                        continue
                sig = (underlying, tuple(values.items()))
                if sig in seen:
                    self._enum_names[e.sym_index_id] = seen[sig]
                    self._enum_content(e, seen[sig])  # reports the merged entry's own drops (N1)
                    continue
                assigned = self._claim_name(name)
                if seen:
                    self._drop('duplicate_renamed', assigned, detail=f'same name as {name!r}, different signature')
                seen[sig] = assigned
                self._enum_names[e.sym_index_id] = assigned
                self._enum_content(e, assigned)  # reports under the assigned name
                self._enum_models.append(model.Enum(name=assigned, underlying=underlying, values=dict(values)))
            for sig, assigned in seen.items():
                self._enum_by_sig[(name, sig)] = assigned

    def _enum_ref_name(self, t):
        """Model name of a named enum by ``sym_index_id``, else by (DIA name, signature); ``None`` if omitted."""
        name = self._enum_names.get(t.sym_index_id)
        if name is not None or t.sym_index_id in self._omitted_enum_ids:
            return name
        with self._quiet(dia_names=False):
            content = self._enum_content(t, t.name)
        if content is None:
            self._omitted_enum_ids.add(t.sym_index_id)
            return None
        underlying, values = content
        name = self._enum_by_sig.get((t.name, (underlying, tuple(values.items()))))
        if name is None and not values:
            name = next((nm for (n, (u, _v)), nm in self._enum_by_sig.items() if n == t.name and u == underlying),
                        None)
        if name is None:
            raise ExportError([], f'unmapped type reference: {t.name!r}')
        self._enum_names[t.sym_index_id] = name
        return name

    def _anon_enum(self, t):
        key = (self._muted, self._dia_names, t.sym_index_id)
        if key in self._anon_cache:
            return self._anon_cache[key]
        content = self._enum_content(t, t.name)
        if content is None:
            result = self._reduce(t.name, 'enum underlying unmappable', t.size)
        else:
            result = model.Enum(name=t.name, underlying=content[0], values=dict(content[1]))
        self._anon_cache[key] = result
        if not self._muted and not self._suppress_inline:
            self._inlined.add(self._anon_key(t))
        return result

    # -- UDTs ------------------------------------------------------------------

    def _classify_members(self, t, owner):
        """``(bases, fields)`` of ``t`` as model objects; member drops are named ``owner::member``."""
        bases, fields = [], []
        for mem in t.members():
            tag = mem.tag
            if tag == 'data':
                if mem.offset == -1:
                    self._drop('static_member', f'{owner}::{mem.name}')
                    continue
                ftype = self._convert(mem.type)
                if ftype is _OMIT:
                    continue  # the reduction's drop was already reported
                bit_offset = mem.bit_offset if mem.bit_offset != -1 else None
                fields.append(model.Field(name=mem.name, type=ftype, offset=mem.offset, bit_offset=bit_offset,
                                          bit_length=mem.bit_length if bit_offset is not None else None,
                                          access=_ACCESS_BY_INT.get(mem.access, 'public')))
            elif tag == 'baseclass':
                if mem.offset == -1:
                    self._drop('virtual_base', f'{owner}::{mem.name}')
                    continue
                base_name = mem.type.name if self._dia_names else self._udt_ref_name(mem.type)
                bases.append(model.BaseClass(type=base_name, offset=mem.offset,
                                             access=_ACCESS_BY_INT.get(mem.access, 'public')))
            elif tag == 'function':
                self._drop('method', f'{owner}::{mem.name}')
            elif tag == 'vtable':
                self._drop('vfptr', owner)
            elif tag in ('udt', 'enum', 'typedef'):
                self._drop('nested_type', f'{owner}::{mem.name}')
            elif tag == 'friend':
                self._drop('friend', f'{owner}::{mem.name}')
            else:
                self._drop('unsupported_member', f'{owner}::{mem.name}', detail=tag)
        return bases, fields

    def _udt_signature(self, t):
        """Type key of the content export keeps (named UDTs by DIA name), or ``None`` for an opaque-like entry."""
        with self._quiet(dia_names=True):
            bases, fields = self._classify_members(t, t.name)
            if t.size == 0 and not bases and not fields:
                return None
            kind, _is_iface = self._kind_for(t)
            return model._type_key(model.Udt(name=t.name, size=t.size, kind=kind, fields=fields, bases=bases))

    def _collect_udts(self, raw):
        """Two passes: assign every group's name(s) first (bases/fields may reference a group that
        sorts later in DIA order), then build the kept entries' Field/BaseClass lists.
        """
        pending = []  # (assigned_name, entry) for a real, kept representative
        pending_merged = []  # (entry, target_name) for a real, merged (non-representative) entry
        for name, entries in self._group_by_name(raw).items():
            sigs = [(e, self._udt_signature(e)) for e in entries]
            real = [(e, sig) for e, sig in sigs if sig is not None]
            if not real:
                kind, is_iface = self._kind_for(entries[0])
                assigned = self._claim_name(name)
                if is_iface:
                    self._drop('interface_as_struct', assigned)
                self._udt_models.append(model.Udt(name=assigned, size=0, kind=kind, opaque=True))
                for e in entries:
                    self._udt_names[e.sym_index_id] = assigned
                self._udt_first[name] = assigned
                continue
            seen = {}  # signature -> assigned name
            for e, sig in real:
                if sig in seen:
                    target = seen[sig]
                    self._udt_names[e.sym_index_id] = target
                    pending_merged.append((e, target))
                    continue
                assigned = self._claim_name(name)
                if seen:
                    self._drop('duplicate_renamed', assigned, detail=f'same name as {name!r}, different signature')
                seen[sig] = assigned
                self._udt_names[e.sym_index_id] = assigned
                if self._kind_for(e)[1]:
                    self._drop('interface_as_struct', assigned)
                pending.append((assigned, e))
            first = next(iter(seen.values()))
            for e, sig in sigs:
                if sig is None:
                    self._udt_names[e.sym_index_id] = first
            self._udt_first[name] = first
            for sig, assigned in seen.items():
                self._udt_by_sig[(name, sig)] = assigned
        for assigned, e in pending:
            bases, fields = self._classify_members(e, assigned)
            self._udt_models.append(model.Udt(name=assigned, size=e.size, kind=self._kind_for(e)[0],
                                              fields=fields, bases=bases))
        for e, target in pending_merged:
            if self._kind_for(e)[1]:
                self._drop('interface_as_struct', target)
            with self._report_without_inlining():
                self._classify_members(e, target)  # reports the merged entry's own drops (N1)

    def _udt_ref_name(self, t):
        """Model name of a named UDT by ``sym_index_id``, else by (DIA name, signature) for an on-demand symbol."""
        name = self._udt_names.get(t.sym_index_id)
        if name is None:
            sig = self._udt_signature(t)
            name = self._udt_first.get(t.name) if sig is None else self._udt_by_sig.get((t.name, sig))
            if name is None:
                raise ExportError([], f'unmapped type reference: {t.name!r}')
            self._udt_names[t.sym_index_id] = name
        return name

    def _anon_udt(self, t):
        key = (self._muted, self._dia_names, t.sym_index_id)
        if key in self._anon_cache:
            return self._anon_cache[key]
        kind, is_iface = self._kind_for(t)
        if is_iface:
            self._drop('interface_as_struct', t.name)
        result = model.Udt(name=t.name, size=t.size, kind=kind)
        self._anon_cache[key] = result  # filled in place: a self-reference through a pointer finds it
        result.bases, result.fields = self._classify_members(t, t.name)
        if not self._muted and not self._suppress_inline:
            self._inlined.add(self._anon_key(t))
        return result

    def _anon_key(self, t):
        """Structural identity of an anonymous udt/enum entry, qualifiers ignored (reachability)."""
        with self._quiet(dia_names=False):
            obj = self._anon_udt(t) if t.tag == 'udt' else self._anon_enum(t)
        return t.name, _key(obj)

    def _report_anonymous_unreferenced(self, raw_types):
        """``anonymous_unreferenced`` once per anonymous structural identity that no exported item inlines."""
        reported = set()
        for t in raw_types:
            if t.tag not in ('udt', 'enum') or not t.name or not model.is_anonymous_name(t.name):
                continue
            key = self._anon_key(t)
            if key not in self._inlined and key not in reported:
                reported.add(key)
                self._drop('anonymous_unreferenced', t.name)

    # -- generic TypeRef conversion --------------------------------------------

    def _reduce(self, name, detail, size, *, arg_pos=False):
        """``reduced_type``: ``unsigned char[size]``, or ``_OMIT`` for size 0."""
        if arg_pos and size:
            detail = f'{detail}; decayed to a pointer (argument/return position)'
        self._drop('reduced_type', name, detail=detail)
        return model.Array(of='unsigned char', count=size) if size else _OMIT

    def _resolve_typedef(self, t):
        names = []
        while t is not None and t.tag == 'typedef':
            names.append(t.name)
            t = t.base_type()
        if names:
            self._drop('alias_resolved', names[0])
        return t

    def _convert(self, t, *, arg_pos=False):
        """Model TypeRef of DIA type ``t``: ``None`` for no type, ``_OMIT`` for a size-0 reduction."""
        if t is None:
            return None
        t = self._resolve_typedef(t)
        if t is None:
            return None
        tag = t.tag
        if tag == 'pointertype':
            return self._convert_pointer(t, arg_pos=arg_pos)
        if tag == 'arraytype':
            of = self._convert(t.base_type())
            if of is _OMIT:
                return _OMIT
            if arg_pos:
                self._drop('reduced_type', t.name or '<array>',
                           detail='array decayed to a pointer (argument/return position)')
            return model.Array(of=of, count=t.count)
        if tag == 'functiontype':
            return self._convert_function(t)
        const, vol, unal = bool(t.is_const), bool(t.is_volatile), bool(t.is_unaligned)
        inner = self._convert_unqualified(t, arg_pos=arg_pos)
        if not (const or vol or unal) or inner is _OMIT or isinstance(inner, model.Array):
            return inner  # a reduction drops the qualifier (V20)
        return model.Modifier(of=inner, const=const, volatile=vol, unaligned=unal)

    def _convert_unqualified(self, t, *, arg_pos):
        tag = t.tag
        if tag == 'basetype':
            name = _codeview.BASE_TYPES_BY_DIA.get((t.base_kind, t.size))
            if name is not None:
                return name
            return self._reduce(t.name or '<basetype>', f'bt={t.base_kind} size={t.size}', t.size, arg_pos=arg_pos)
        if tag == 'enum':
            if model.is_anonymous_name(t.name):
                return self._anon_enum(t)
            name = self._enum_ref_name(t)
            if name is not None:
                return name
            return self._reduce(t.name, 'enum underlying unmappable', t.size, arg_pos=arg_pos)
        if tag == 'udt':
            if model.is_anonymous_name(t.name):
                return self._anon_udt(t)
            return t.name if self._dia_names else self._udt_ref_name(t)
        return self._reduce(getattr(t, 'name', '') or '<type>', f'tag={tag}', t.size, arg_pos=arg_pos)

    def _convert_pointer(self, t, *, arg_pos):
        if (parent := t.class_parent()) is not None:
            note = '; decayed to a pointer (argument/return position)' if arg_pos else ''
            self._drop('pointer_to_member', t.name or '<ptr>', detail=f'{parent.name}::* size={t.size}{note}')
            return model.Array(of='unsigned char', count=t.size) if t.size else _OMIT
        size = t.size
        if size not in (4, 8):
            # it occupies a full pointer slot despite its reported size (e.g. std::nullptr_t, E11)
            return self._reduce(t.name or '<ptr>', f'pointer size {size}', self._native_ptr_size, arg_pos=arg_pos)
        to = self._convert(t.base_type())
        if to is _OMIT:
            return self._reduce(t.name or '<ptr>', 'pointer target omitted', size, arg_pos=arg_pos)
        mode = 'rvalue_ref' if t.is_rvalue_reference else ('lvalue_ref' if t.is_reference else 'pointer')
        return model.Pointer(to=to, mode=mode, const=bool(t.is_const), volatile=bool(t.is_volatile),
                             unaligned=bool(t.is_unaligned), size=None if size == self._native_ptr_size else size)

    def _convert_function(self, t):
        """A ``FunctionType`` (array/function arguments and returns decay to pointers), or ``_OMIT``."""
        arg_types = [m.type for m in t.members() if m.tag == 'functionargtype']
        variadic = False
        if arg_types and arg_types[-1] is not None and _is_notype(arg_types[-1]):
            variadic = True
            arg_types = arg_types[:-1]
        args = [self._convert(a, arg_pos=True) for a in arg_types]
        ret = t.base_type()
        if ret is not None and _is_notype(ret):
            self._drop('reduced_type', t.name or '<fn>', detail='no-type return')
        returns = 'void' if (ret is None or _is_notype(ret)) else self._convert(ret, arg_pos=True)
        call_name = _CALL_BY_INT.get(t.calling_convention)
        if call_name is None:
            self._drop('calling_convention', t.name or '<fn>', detail=f'call code {t.calling_convention}')
            call_name = 'cdecl'
        if returns is _OMIT or any(a is _OMIT for a in args):
            return _OMIT
        return model.FunctionType(returns=_decay(returns), args=[_decay(a) for a in args],
                                  variadic=variadic, call=call_name)

    # -- typedefs, functions, data, publics ------------------------------------

    def _typedef_is_identity(self, t, name):
        """True for ``typedef struct X X;``: target resolves to an UNQUALIFIED named udt/enum
        called ``name`` (N5); ``typedef const struct X X`` goes through the collision check."""
        while t is not None and t.tag == 'typedef':
            t = t.base_type()
        return (t is not None and t.tag in ('udt', 'enum') and t.name == name
                and not (t.is_const or t.is_volatile or t.is_unaligned))

    def _collect_typedefs(self):
        seen = {}  # name -> type key of the kept target
        for sym in self.sess.find_symbols('*', SymTag.Typedef):
            name = sym.name
            if not name:
                self._drop('unnamed', '')
                continue
            if self._typedef_is_identity(sym.type, name):
                continue  # silently absent
            with self._quiet(dia_names=False):
                key = _key(self._convert(sym.type))
            if name in seen:
                if key != seen[name]:
                    self._drop('duplicate_typedef', name, detail='same name, different target')
                continue
            if name in self._used_names or name in model.BASE_TYPES:
                self._drop('typedef_name_collision', name)
                continue
            seen[name] = key
            target = self._convert(sym.type)
            if target is _OMIT:
                continue  # omitted with its reduced_type report
            self._used_names.add(name)
            self._typedef_models.append(model.Typedef(name=name, type=target))

    def _collect_functions(self):
        raw = []
        for sym in self.sess.find_symbols('*', SymTag.Function):
            name = sym.name
            if not name:
                self._drop('unnamed', '')
                continue
            if self._is_absolute(sym):
                self._drop('absolute_symbol', name)
                continue
            t = sym.type
            if t is not None and _is_notype(t):
                t = None  # a compiler-generated funclet/label: DIA's no-type marker, i.e. untyped
            if t is not None and t.tag == 'functiontype' and t.class_parent() is not None:
                self._drop('method_type_flattened', name)
            ftype = None if t is None else self._convert(t)
            if ftype is not None and not isinstance(ftype, model.FunctionType):
                self._drop('reduced_type', name, detail=f'no model function type at rva {sym.rva:#x}; exported untyped')
                ftype = None
            raw.append(model.Function(name=name, rva=sym.rva, length=sym.length, type=ftype,
                                      static=bool(sym.is_static)))
        self._function_models = _merge_exact_duplicates(raw)

    def _collect_data(self):
        raw = []
        for sym in self.sess.find_symbols('*', SymTag.Data):
            name = sym.name
            if not name:
                self._drop('unnamed', '')
                continue
            loc = sym.location_type
            if loc == 10:
                self._drop('constant', name)
                continue
            if loc == 2:
                self._drop('tls_data', name)
                continue
            if loc != 1:
                self._drop('unsupported_data', name, detail=f'location_type={loc}')
                continue
            if self._is_absolute(sym):
                self._drop('absolute_symbol', name)
                continue
            dt = sym.type
            if dt is not None and _is_notype(dt):
                dt = None
            dtype = None if dt is None else self._convert(dt)
            if dtype is _OMIT:
                continue  # omitted with its reduced_type report
            raw.append(model.Data(name=name, rva=sym.rva, type=dtype, static=sym.data_kind == 5))
        self._data_models = _merge_exact_duplicates(raw)

    def _collect_publics(self):
        raw, seen = [], set()
        for sym in self.sess.find_symbols('*', SymTag.PublicSymbol):
            name = sym.name
            if not name:
                self._drop('unnamed', '')
                continue
            if self._is_absolute(sym):
                self._drop('absolute_symbol', name)
                continue
            if name in seen:
                self._drop('duplicate_public', name)
                continue
            seen.add(name)
            raw.append(model.Public(name=name, rva=sym.rva, function=bool(sym.is_function)))
        self._public_models = raw

    def _is_absolute(self, sym) -> bool:
        """rva 0, or a section number past ``image.sections`` (the absolute pseudo-section)."""
        return sym.rva == 0 or sym.section > len(self._sections)


def _merge_exact_duplicates(records):
    """Keep one of each run of model-equal records (OQ15-A); distinct records all stay."""
    kept, by_key = [], {}
    for r in records:
        bucket = by_key.setdefault((r.name, r.rva), [])
        if r not in bucket:
            bucket.append(r)
            kept.append(r)
    return kept


def _decay(value):
    """An ``Array``/``FunctionType`` argument or return becomes a pointer (V21/V22), as the args domain prescribes."""
    if isinstance(value, model.Array):
        return model.Pointer(to=value.of)
    if isinstance(value, model.FunctionType):
        return model.Pointer(to=value)
    return value


def _key(value) -> str:
    """Comparison key of a converted TypeRef (``model._type_key``); ``_OMIT`` keys apart."""
    return '<omitted>' if value is _OMIT else model._type_key(value)


def _is_notype(t) -> bool:
    """``<bt0:0>``: DIA's ellipsis/no-type marker (``btNoType``, size 0), distinct from ``void``."""
    return t.tag == 'basetype' and t.base_kind == 0 and t.size == 0
