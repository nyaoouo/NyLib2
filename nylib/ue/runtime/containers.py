"""Container codecs and views (RT5): TArray, TSet, TMap, strings, fixed arrays, multicast delegates.
Views read fresh on every access; resizing or rehashing raises NotImplementedError.
"""
import struct

from . import codecs
from .codecs import _ErrorCodec, _align, _array_header
from ..engine import containers as _ec
from ..engine.accessor import view
from ...ctype import Field, SField, c_int32, c_uint32, c_uint64, check_finalize


class _SparseHeader(_ec.ViewStruct):
    """TSparseArray prefix inside a TSet/TMap @ ea0dab3 (0x38): Data TArray, inline AllocationFlags, free list."""
    _size_ = 0x38
    Data = SField(c_uint64, 0x0)
    DataNum = SField(c_int32, 0x8)
    DataMax = SField(c_int32, 0xC)
    InlineWords = Field(c_uint32 * 4, 0x10)
    SecondaryData = SField(c_uint64, 0x20)
    NumBits = SField(c_int32, 0x28)
    MaxBits = SField(c_int32, 0x2C)
    FirstFreeIndex = SField(c_int32, 0x30)
    NumFreeIndices = SField(c_int32, 0x34)


check_finalize(_SparseHeader)


def _check_codec(obj, name: str) -> None:
    if not (hasattr(obj, 'size') and hasattr(obj, 'align') and hasattr(obj, 'get') and hasattr(obj, 'set')):
        raise TypeError(f'{name} must be a Codec (size, align, get, set), got {type(obj).__name__}')


def _read_sparse(ctx, address: int, label: str, kind: str):
    hdr = view(_SparseHeader, address, ctx.acc)
    data, data_num, data_max = hdr.Data, hdr.DataNum, hdr.DataMax
    num_bits, num_free = hdr.NumBits, hdr.NumFreeIndices
    if not (0 <= num_free <= data_num <= data_max and num_bits >= data_num and (data_num == 0 or data != 0)):
        raise ValueError(f'{label}: corrupt {kind} (Data {data:#x}, Num {data_num}, Max {data_max}, '
                          f'NumFreeIndices {num_free}, NumBits {num_bits})')
    return hdr, data, data_num, data_num - num_free


def _bit_words(ctx, hdr, count: int, label: str) -> tuple:
    n_words = (count + 31) // 32
    if n_words == 0:
        return ()
    if hdr.SecondaryData:
        return struct.unpack(f'<{n_words}I', ctx.acc.read(hdr.SecondaryData, n_words * 4))
    inline = tuple(hdr.InlineWords)
    if n_words > len(inline):
        raise ValueError(f'{label}: corrupt allocation flags ({count} bits need {n_words} words, {len(inline)} inline)')
    return inline[:n_words]


def _bit_set(words: tuple, i: int) -> bool:
    return ((words[i >> 5] >> (i & 31)) & 1) != 0


def _pair_layout(key, value) -> tuple[int, int, int]:
    voff = _align(key.size, value.align)
    pair_size = _align(voff + value.size, max(key.align, value.align))
    return voff, pair_size, max(key.align, value.align)


def _sparse_slot_size(value_size: int, value_align: int) -> int:
    es = _align(_align(value_size, 4) + 8, max(value_align, 4))
    return max(es, 8)


class TArrayValue:
    """A TArray view @ ea0dab3: header and elements read fresh through the inner codec."""

    def __init__(self, ctx, address: int, inner, label: str):
        self.ctx = ctx
        self.address = address
        self.inner = inner
        self.label = label

    def num(self) -> int:
        return _array_header(self.ctx, self.address, self.label)[1]

    def max(self) -> int:
        return _array_header(self.ctx, self.address, self.label)[2]

    def data(self) -> int:
        return _array_header(self.ctx, self.address, self.label)[0]

    def __len__(self) -> int:
        return self.num()

    def _addr(self, i, data: int, num: int) -> int:
        if isinstance(i, bool) or not isinstance(i, int):
            raise TypeError(f'index must be int, got {type(i).__name__}')
        idx = i + num if i < 0 else i
        if not (0 <= idx < num):
            raise IndexError(i)
        return data + idx * self.inner.size

    def __getitem__(self, item):
        data, num, _ = _array_header(self.ctx, self.address, self.label)
        if isinstance(item, slice):
            return [self.inner.get(self.ctx, data + i * self.inner.size, f'{self.label}[{i}]')
                    for i in range(*item.indices(num))]
        addr = self._addr(item, data, num)
        return self.inner.get(self.ctx, addr, f'{self.label}[{item}]')

    def __setitem__(self, item, value) -> None:
        data, num, _ = _array_header(self.ctx, self.address, self.label)
        addr = self._addr(item, data, num)
        self.inner.set(self.ctx, addr, value, f'{self.label}[{item}]')

    def __iter__(self):
        data, num, _ = _array_header(self.ctx, self.address, self.label)
        for i in range(num):
            yield self.inner.get(self.ctx, data + i * self.inner.size, f'{self.label}[{i}]')

    def to_list(self) -> list:
        return list(self)

    def __repr__(self) -> str:
        return f'TArray[{self.inner.kind}](len={self.num()})'

    def _refused(self, *_a, **_k):
        raise NotImplementedError(f'{self.label}: {codecs.HINT_RESIZE}')

    append = extend = insert = pop = remove = clear = _refused


class TSetValue:
    """A TSet view @ ea0dab3: allocated TSparseArray slots read in slot order, linear membership test."""

    def __init__(self, ctx, address: int, element, label: str):
        self.ctx = ctx
        self.address = address
        self.element = element
        self.label = label

    def _slots(self):
        hdr, data, data_num, _num = _read_sparse(self.ctx, self.address, self.label, 'TSet')
        words = _bit_words(self.ctx, hdr, data_num, self.label)
        stride = _sparse_slot_size(self.element.size, self.element.align)
        for i in range(data_num):
            if _bit_set(words, i):
                yield data + i * stride

    def __len__(self) -> int:
        return _read_sparse(self.ctx, self.address, self.label, 'TSet')[3]

    def __iter__(self):
        for addr in self._slots():
            yield self.element.get(self.ctx, addr, f'{self.label}[*]')

    def __contains__(self, value) -> bool:
        return any(v == value for v in self)

    def to_list(self) -> list:
        return list(self)

    def __repr__(self) -> str:
        return f'TSet[{self.element.kind}](len={len(self)})'

    def _refused(self, *_a, **_k):
        raise NotImplementedError(f'{self.label}: {codecs.HINT_RESIZE}')

    add = discard = remove = clear = _refused


class TMapValue:
    """A TMap view @ ea0dab3: allocated TSparseArray slots of TPair<K, V>, linear key lookup."""

    def __init__(self, ctx, address: int, key, value, label: str):
        self.ctx = ctx
        self.address = address
        self.key = key
        self.value = value
        self.label = label

    def _slots(self):
        hdr, data, data_num, _num = _read_sparse(self.ctx, self.address, self.label, 'TMap')
        words = _bit_words(self.ctx, hdr, data_num, self.label)
        voff, pair_size, pair_align = _pair_layout(self.key, self.value)
        stride = _sparse_slot_size(pair_size, pair_align)
        for i in range(data_num):
            if _bit_set(words, i):
                yield data + i * stride, voff

    def __len__(self) -> int:
        return _read_sparse(self.ctx, self.address, self.label, 'TMap')[3]

    def __iter__(self):
        for addr, _voff in self._slots():
            yield self.key.get(self.ctx, addr, f'{self.label}.key')

    def keys(self) -> list:
        return list(self)

    def values(self) -> list:
        return [self.value.get(self.ctx, addr + voff, f'{self.label}.value') for addr, voff in self._slots()]

    def items(self) -> list:
        result = []
        for addr, voff in self._slots():
            k = self.key.get(self.ctx, addr, f'{self.label}.key')
            result.append((k, self.value.get(self.ctx, addr + voff, f'{self.label}[{k!r}]')))
        return result

    def __getitem__(self, key):
        for addr, voff in self._slots():
            if self.key.get(self.ctx, addr, f'{self.label}.key') == key:
                return self.value.get(self.ctx, addr + voff, f'{self.label}[{key!r}]')
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key) -> bool:
        try:
            self[key]
        except KeyError:
            return False
        return True

    def __setitem__(self, key, value) -> None:
        for addr, voff in self._slots():
            if self.key.get(self.ctx, addr, f'{self.label}.key') == key:
                self.value.set(self.ctx, addr + voff, value, f'{self.label}[{key!r}]')
                return
        raise NotImplementedError(f'{self.label}: adding a key needs the engine allocator and a rehash, which v1 does not do')

    def __repr__(self) -> str:
        return f'TMap[{self.key.kind}, {self.value.kind}](len={len(self)})'

    def _refused(self, *_a, **_k):
        raise NotImplementedError(f'{self.label}: {codecs.HINT_RESIZE}')

    __delitem__ = pop = update = clear = _refused


class FixedArrayValue:
    """A fixed-count C array view (ArrayDim > 1): elements at a constant stride, no resize."""

    def __init__(self, ctx, address: int, element, count: int, label: str):
        self.ctx = ctx
        self.address = address
        self.element = element
        self.count = count
        self.label = label

    def __len__(self) -> int:
        return self.count

    def _addr(self, i) -> int:
        if isinstance(i, bool) or not isinstance(i, int):
            raise TypeError(f'index must be int, got {type(i).__name__}')
        idx = i + self.count if i < 0 else i
        if not (0 <= idx < self.count):
            raise IndexError(i)
        return self.address + idx * self.element.size

    def __getitem__(self, item):
        if isinstance(item, slice):
            return [self[i] for i in range(*item.indices(self.count))]
        return self.element.get(self.ctx, self._addr(item), f'{self.label}[{item}]')

    def __setitem__(self, item, value) -> None:
        self.element.set(self.ctx, self._addr(item), value, f'{self.label}[{item}]')

    def __iter__(self):
        for i in range(self.count):
            yield self.element.get(self.ctx, self.address + i * self.element.size, f'{self.label}[{i}]')

    def to_list(self) -> list:
        return list(self)

    def __repr__(self) -> str:
        return f'FixedArray[{self.element.kind}]({self.count})'


class MulticastDelegateValue:
    """A multicast inline delegate view @ ea0dab3: the InvocationList TArray at size - 0x10."""

    def __init__(self, ctx, address: int, size: int, label: str):
        self.ctx = ctx
        self.address = address
        self.size = size
        self.label = label

    def _list_address(self) -> int:
        return self.address + self.size - 0x10

    def bindings(self) -> list:
        stride = self.ctx.e.property_sizes.DelegateProperty
        data, num, _ = _array_header(self.ctx, self._list_address(), self.label)
        result = []
        for i in range(num):
            addr = data + i * stride
            index, serial = struct.unpack('<ii', self.ctx.acc.read(addr, 8))
            name = self.ctx.names.read(addr + 8)
            if name != 'None':
                result.append(codecs.DelegateBinding(object=self.ctx.weak_get(index, serial), function_name=name))
        return result

    def __len__(self) -> int:
        return _array_header(self.ctx, self._list_address(), self.label)[1]

    def __repr__(self) -> str:
        return f'MulticastDelegate(len={len(self)})'


class _ArrayCodec:
    kind = 'ArrayProperty'
    size = 0x10
    align = 8

    def __init__(self, inner):
        self.inner = inner

    def get(self, ctx, address, label):
        return TArrayValue(ctx, address, self.inner, label)

    def set(self, ctx, address, value, label):
        codecs._commit(ctx, self._ops(ctx, address, value, label), label)

    def _ops(self, ctx, address, value, label):
        if not isinstance(value, (list, tuple, TArrayValue)):
            raise TypeError(f'{label}: expected a list, tuple or TArrayValue, got {type(value).__name__}')
        if isinstance(value, TArrayValue):
            value = value.to_list()
        data, num, _ = _array_header(ctx, address, label)
        if len(value) != num:
            raise ValueError(f'{label}: {codecs.HINT_RESIZE}')
        ops = []
        for i, v in enumerate(value):
            ops += codecs._plan(self.inner, ctx, data + i * self.inner.size, v, f'{label}[{i}]')
        return ops


class _SetCodec:
    kind = 'SetProperty'
    size = 0x50
    align = 8

    def __init__(self, element):
        self.element = element

    def get(self, ctx, address, label):
        return TSetValue(ctx, address, self.element, label)

    def set(self, ctx, address, value, label):
        raise NotImplementedError(f'{label}: replacing a TSet or TMap needs the engine allocator and a rehash, which v1 does not do')

    _ops = set


class _MapCodec:
    kind = 'MapProperty'
    size = 0x50
    align = 8

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def get(self, ctx, address, label):
        return TMapValue(ctx, address, self.key, self.value, label)

    def set(self, ctx, address, value, label):
        raise NotImplementedError(f'{label}: replacing a TSet or TMap needs the engine allocator and a rehash, which v1 does not do')

    _ops = set


_STRING_KINDS = {
    'StrProperty': ('utf-16-le', 2),
    'AnsiStrProperty': ('latin-1', 1),
    'Utf8StrProperty': ('utf-8', 1),
}


class _StringCodec:
    size = 0x10
    align = 8

    def __init__(self, kind: str):
        self.kind = kind
        self.encoding, self.unit = _STRING_KINDS[kind]

    def get(self, ctx, address, label):
        return codecs._read_string(ctx, address, label, self.encoding, self.unit)

    def set(self, ctx, address, value, label):
        codecs._commit(ctx, self._ops(ctx, address, value, label), label)

    def _ops(self, ctx, address, value, label):
        if not isinstance(value, str):
            raise TypeError(f'{label}: expected str, got {type(value).__name__}')
        if value == '':
            return [(address + 0x8, struct.pack('<i', 0))]
        encode_errors = 'surrogatepass' if self.encoding == 'utf-16-le' else 'strict'
        try:
            encoded = value.encode(self.encoding, errors=encode_errors)
        except UnicodeEncodeError as exc:
            raise ValueError(f'{label}: {exc}') from exc
        units = len(encoded) // self.unit
        data, _num, mx = _array_header(ctx, address, label)
        need = units + 1
        if need > mx:
            raise ValueError(f'{label}: the new value needs {need} characters but the buffer holds {mx}; {codecs.HINT_RESIZE}')
        return [(data, encoded + b'\0' * self.unit), (address + 0x8, struct.pack('<i', need))]


class _MulticastCodec:
    kind = 'MulticastInlineDelegateProperty'
    align = 8

    def __init__(self, size: int):
        self.size = size

    def get(self, ctx, address, label):
        return MulticastDelegateValue(ctx, address, self.size, label)

    def set(self, ctx, address, value, label):
        raise NotImplementedError(f'{label}: multicast delegate invocation lists cannot be replaced in v1')

    _ops = set


class _FixedArrayCodec:
    kind = 'FixedArray'

    def __init__(self, element, count: int):
        self.element = element
        self.count = count
        self.size = element.size * count
        self.align = element.align

    def get(self, ctx, address, label):
        return FixedArrayValue(ctx, address, self.element, self.count, label)

    def set(self, ctx, address, value, label):
        codecs._commit(ctx, self._ops(ctx, address, value, label), label)

    def _ops(self, ctx, address, value, label):
        if not isinstance(value, (list, tuple)):
            raise TypeError(f'{label}: expected a list or tuple, got {type(value).__name__}')
        if len(value) != self.count:
            raise ValueError(f'{label}: expected {self.count} elements, got {len(value)}')
        ops = []
        for i, v in enumerate(value):
            ops += codecs._plan(self.element, ctx, address + i * self.element.size, v, f'{label}[{i}]')
        return ops


def array_codec(ctx, inner):
    _check_codec(inner, 'inner')
    return _ArrayCodec(inner)


def set_codec(ctx, element):
    _check_codec(element, 'element')
    return _SetCodec(element)


def map_codec(ctx, key, value):
    _check_codec(key, 'key')
    _check_codec(value, 'value')
    return _MapCodec(key, value)


def string_codec(ctx, kind: str):
    if not isinstance(kind, str):
        raise TypeError(f'kind must be str, got {type(kind).__name__}')
    if kind not in _STRING_KINDS:
        raise ValueError(f'unknown string kind {kind!r}')
    return _StringCodec(kind)


def multicast_codec(ctx, size: int):
    if isinstance(size, bool) or not isinstance(size, int):
        raise TypeError(f'size must be int, got {type(size).__name__}')
    if size < 1:
        raise ValueError(f'size must be >= 1, got {size}')
    return _MulticastCodec(size)


def fixed_array_codec(element, count: int):
    _check_codec(element, 'element')
    if isinstance(count, bool) or not isinstance(count, int):
        raise TypeError(f'count must be int, got {type(count).__name__}')
    if count < 1:
        raise ValueError(f'count must be >= 1, got {count}')
    return _FixedArrayCodec(element, count)


def _sub_codec(ctx, sub_ptype):
    """(codec, None) on success, or (None, exc) for a missing sub-type or one that builds an error or unsupported codec."""
    if sub_ptype is None:
        return None, LookupError('missing sub-type')
    codec = codecs.make_codec(ctx, sub_ptype)
    if (exc := codecs._build_error(codec)) is not None:
        return None, exc
    return codec, None


def make_container_codec(ctx, ptype, size: int | None):
    if size is not None and (isinstance(size, bool) or not isinstance(size, int)):
        raise TypeError(f'size must be int or None, got {type(size).__name__}')
    if size is not None and size < 1:
        raise ValueError(f'size must be >= 1, got {size}')
    kind = getattr(ptype, 'kind', None)
    if not isinstance(kind, str):
        raise TypeError(f'ptype must be a PropType, got {type(ptype).__name__}')

    if kind == 'ArrayProperty':
        sub, exc = _sub_codec(ctx, ptype.inner)
        if exc is not None:
            return _ErrorCodec(kind, size, exc)
        if size is not None and size != 0x10:
            return _ErrorCodec(kind, size, ValueError(f'{kind} cannot be {size:#x} bytes'))
        return array_codec(ctx, sub)

    if kind == 'SetProperty':
        sub, exc = _sub_codec(ctx, ptype.element)
        if exc is not None:
            return _ErrorCodec(kind, size, exc)
        if size is not None and size != 0x50:
            return _ErrorCodec(kind, size, ValueError(f'{kind} cannot be {size:#x} bytes'))
        return set_codec(ctx, sub)

    if kind == 'MapProperty':
        ksub, kexc = _sub_codec(ctx, ptype.key)
        if kexc is not None:
            return _ErrorCodec(kind, size, kexc)
        vsub, vexc = _sub_codec(ctx, ptype.value)
        if vexc is not None:
            return _ErrorCodec(kind, size, vexc)
        if size is not None and size != 0x50:
            return _ErrorCodec(kind, size, ValueError(f'{kind} cannot be {size:#x} bytes'))
        return map_codec(ctx, ksub, vsub)

    if kind in _STRING_KINDS:
        if size is not None and size != 0x10:
            return _ErrorCodec(kind, size, ValueError(f'{kind} cannot be {size:#x} bytes'))
        return string_codec(ctx, kind)

    if kind == 'MulticastInlineDelegateProperty':
        expected = ctx.e.property_sizes.MulticastInlineDelegateProperty
        if size is not None and size != expected:
            return _ErrorCodec(kind, size, ValueError(f'{kind} cannot be {size:#x} bytes'))
        return multicast_codec(ctx, size if size is not None else expected)

    raise ValueError(f'make_container_codec does not handle kind {kind!r}')
