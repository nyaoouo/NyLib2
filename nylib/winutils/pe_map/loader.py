"""Host-independent PE image installation and lifecycle."""

import dataclasses
import enum
import hashlib
import typing

from .core import ImagePlan, PEFormatError, SectionPlan, UnsupportedImageError, build_plan, parse_image
from .contracts import ICrtGlue, MapHost, NoopCrtGlue


class InstallTier(enum.IntEnum):
    MINIMAL = 1
    RUNTIME = 2
    STRICT = 3


class SectSkip(Exception):
    """Request post-attach discard of the current mapped block."""


@dataclasses.dataclass(frozen=True)
class MappedBlock:
    kind: str
    name: str
    index: int | None
    rva: int
    size: int
    address: int
    section: SectionPlan | None


class BlockDiscardError(RuntimeError):
    """A discard operation failed after the DLL attached; ``loaded`` remains active."""

    def __init__(self, loaded: 'LoadedImage', block: MappedBlock):
        self.loaded = loaded
        self.block = block
        super().__init__(f'failed to discard mapped block {block.name!r} at RVA {block.rva:#x}')


class LoadedImage:
    """Own one mapped image and the metadata needed to call and unload it."""

    def __init__(self, host: MapHost, plan: ImagePlan, tier: InstallTier, crt_glue: ICrtGlue):
        self.host = host
        self.base = plan.target_base
        self.size = plan.image.size_of_image
        self.entry_point = plan.entry_point
        self.tier = tier
        self.exports = {symbol.name: self.base + symbol.rva for symbol in plan.image.exports
                        if symbol.name and symbol.forwarder is None}
        self.ordinals = {symbol.ordinal: self.base + symbol.rva for symbol in plan.image.exports
                         if symbol.forwarder is None}
        self.tls_callbacks = tuple(self.base + rva for rva in plan.image.tls.callbacks) if plan.image.tls else ()
        self._plan = plan
        self._crt_glue = crt_glue
        self._crt_token: object = None
        self._crt_prepared = False
        self._entry_started = False
        self._attached_callbacks: list[int] = []
        self._unwind_token: object = None
        self._tls_token: object = None
        self._modules: list[object] = []
        self._active = True
        self.discarded_blocks: tuple[MappedBlock, ...] = ()

    @property
    def active(self) -> bool:
        return self._active

    def get_export(self, name: str | int) -> int:
        if not self._active:
            raise RuntimeError('image is unloaded')
        table = self.ordinals if isinstance(name, int) else self.exports
        try:
            return table[name]
        except KeyError:
            raise KeyError(f'export {name!r} is unavailable') from None

    def call_export(self, name: str | int, *args: int) -> int:
        return self.host.runtime.call(self.get_export(name), *args)

    def unload(self) -> None:
        if not self._active: return
        error = None
        for callback in self._attached_callbacks:
            try:
                self.host.runtime.call(callback, self.base, 0, 0)
            except Exception as exc:
                if error is None: error = exc
        if self._entry_started and self.entry_point:
            try:
                self.host.runtime.call(self.entry_point, self.base, 0, 0)
            except Exception as exc:
                if error is None: error = exc
        if self._crt_prepared:
            try:
                self._crt_glue.cleanup(self._plan, self._crt_token)
            except Exception as exc:
                if error is None: error = exc
        if self._unwind_token is not None:
            try:
                self.host.runtime.unregister_unwind(self._unwind_token)
            except Exception as exc:
                if error is None: error = exc
        if self._tls_token is not None:
            try:
                self.host.runtime.release_tls(self._tls_token)
            except Exception as exc:
                if error is None: error = exc
        for module in reversed(self._modules):
            try:
                self.host.modules.release(module)
            except Exception as exc:
                if error is None: error = exc
        try:
            self.host.memory.free(self.base)
        except Exception as exc:
            if error is None: error = exc
        self._active = False
        if error is not None: raise error

    def __enter__(self) -> 'LoadedImage':
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.unload()


def _check_tier(plan: ImagePlan, tier: InstallTier, host: MapHost) -> None:
    image = plan.image
    if image.machine != host.machine:
        raise UnsupportedImageError(f'image machine {image.machine:#x} does not match host machine {host.machine:#x}')
    if image.machine != 0x8664:
        raise UnsupportedImageError('this loader currently supports AMD64 DLLs only')
    if image.section_alignment < 0x1000:
        raise UnsupportedImageError('section alignment below a page is unsupported')
    if image.directories[14].rva:
        raise UnsupportedImageError('CLR images are unsupported')
    if any(section.protection == 0x40 for section in image.sections):
        raise UnsupportedImageError('writable/executable sections are unsupported')
    if image.dll_characteristics & 0x4000 or image.load_config and image.load_config.guard_flags:
        raise UnsupportedImageError('CFG images require native loader support')
    if tier == InstallTier.MINIMAL:
        if image.tls or image.unwind or image.delay_imports or image.load_config:
            raise UnsupportedImageError('image requires RUNTIME tier features')
    if image.tls and not getattr(host.runtime, 'supports_tls_process_callbacks', True):
        raise UnsupportedImageError('host does not support TLS process callbacks')
    if image.tls and (image.tls.template_size or image.tls.zero_fill) and not host.runtime.supports_static_tls:
        raise UnsupportedImageError('host does not support static TLS templates')
    if tier == InstallTier.STRICT and image.tls and not host.runtime.supports_tls_thread_lifecycle:
        raise UnsupportedImageError('host does not support TLS thread lifecycle')


def _copy_image(host: MapHost, plan: ImagePlan, source: memoryview) -> None:
    image, base = plan.image, plan.target_base
    host.memory.write(base, source[:image.size_of_headers].tobytes())
    for section in image.sections:
        if section.source_size:
            host.memory.write(base + section.target_rva,
                              source[section.source_offset:section.source_offset + section.source_size].tobytes())
    for fixup in plan.relocations:
        address = base + fixup.target_rva
        value = int.from_bytes(host.memory.read(address, fixup.width), 'little')
        mask = (1 << (fixup.width * 8)) - 1
        host.memory.write(address, ((value + fixup.delta) & mask).to_bytes(fixup.width, 'little'))


def _resolve_imports(loaded: LoadedImage) -> None:
    host, plan, tier = loaded.host, loaded._plan, loaded.tier
    image = plan.image
    requests = image.imports + (image.delay_imports if tier >= InstallTier.RUNTIME else ())
    for request in requests:
        module = host.modules.acquire(request.module)
        loaded._modules.append(module)
        for symbol in request.symbols:
            address = host.modules.resolve(module, symbol.ordinal if symbol.ordinal is not None else symbol.name)
            host.memory.write(plan.target_base + symbol.thunk_rva, address.to_bytes(image.pointer_size, 'little'))
        if request.module_handle_rva:
            host.memory.write(plan.target_base + request.module_handle_rva,
                              host.modules.base(module).to_bytes(image.pointer_size, 'little'))


def _resolve_forwarders(loaded: LoadedImage) -> None:
    for symbol in loaded._plan.image.exports:
        if symbol.forwarder is None: continue
        module_name, separator, target = symbol.forwarder.rpartition('.')
        if not separator or not module_name or not target:
            raise PEFormatError(f'invalid export forwarder {symbol.forwarder!r}')
        if not module_name.lower().endswith('.dll'):
            module_name += '.dll'
        name = int(target[1:]) if target.startswith('#') and target[1:].isdigit() else target
        module = loaded.host.modules.acquire(module_name)
        loaded._modules.append(module)
        address = loaded.host.modules.resolve(module, name)
        loaded.ordinals[symbol.ordinal] = address
        if symbol.name:
            loaded.exports[symbol.name] = address


def _register_unwind(loaded: LoadedImage) -> None:
    image = loaded._plan.image
    if not image.unwind: return
    directory = image.directories[3]
    loaded._unwind_token = loaded.host.runtime.register_unwind(loaded.base, directory.rva, len(image.unwind))


def _prepare_tls(loaded: LoadedImage) -> None:
    tls = loaded._plan.image.tls
    if tls is None: return
    loaded._tls_token = loaded.host.runtime.prepare_tls(loaded.base, tls, loaded.host.memory)


def _protect_image(host: MapHost, plan: ImagePlan) -> None:
    image, base = plan.image, plan.target_base
    host.memory.protect(base, image.size_of_headers, 0x02)
    for section in image.sections:
        host.memory.protect(base + section.target_rva, section.mapped_size, section.protection)
    host.memory.flush(base, image.size_of_image)


def _mapped_blocks(plan: ImagePlan) -> tuple[MappedBlock, ...]:
    image, base = plan.image, plan.target_base
    headers_size = (image.size_of_headers + 0xfff) & ~0xfff
    blocks = [MappedBlock('headers', '<headers>', None, 0, headers_size, base, None)]
    blocks.extend(MappedBlock('section', section.name, index, section.target_rva, section.mapped_size,
                              base + section.target_rva, section) for index, section in enumerate(image.sections))
    return tuple(blocks)


def _required_ranges(plan: ImagePlan) -> typing.Iterator[tuple[int, int, str]]:
    image = plan.image
    if image.entry_rva:
        yield image.entry_rva, 1, 'DLL entry'
    for symbol in image.exports:
        if symbol.forwarder is None and symbol.rva:
            yield symbol.rva, 1, 'direct export'
    for request in image.imports + image.delay_imports:
        for symbol in request.symbols:
            yield symbol.thunk_rva, image.pointer_size, 'import address table'
        if request.module_handle_rva:
            yield request.module_handle_rva, image.pointer_size, 'delay-import module handle'
    if image.tls:
        yield image.directories[9].rva, image.directories[9].size, 'TLS directory'
        yield image.tls.index_rva, 4, 'TLS index'
        if image.tls.template_size:
            yield image.tls.template_rva, image.tls.template_size, 'TLS template'
        for callback in image.tls.callbacks:
            yield callback, 1, 'TLS callback'
    if image.unwind:
        yield image.directories[3].rva, image.directories[3].size, 'unwind table'
        for entry in image.unwind:
            yield entry.info_rva, 1, 'unwind information'
    if image.load_config and image.load_config.security_cookie_rva is not None:
        yield image.load_config.security_cookie_rva, image.pointer_size, 'security cookie'


def _requested_discards(plan: ImagePlan, host: MapHost,
                        on_block: typing.Callable[[ImagePlan, MappedBlock], None] | None) -> tuple[MappedBlock, ...]:
    if on_block is None: return ()
    requested = []
    for block in _mapped_blocks(plan):
        try:
            on_block(plan, block)
        except SectSkip:
            requested.append(block)
    if requested and host.discarder is None:
        raise UnsupportedImageError('host has no mapped-block discard capability')
    for block in requested:
        if block.rva % 0x1000 or block.size % 0x1000 or block.rva + block.size > plan.image.size_of_image:
            raise UnsupportedImageError(f'mapped block {block.name!r} is not page-aligned inside the image')
        for rva, size, reason in _required_ranges(plan):
            if rva < block.rva + block.size and block.rva < rva + size:
                raise UnsupportedImageError(f'mapped block {block.name!r} contains {reason}')
    return tuple(requested)


def load(image_bytes: bytes | bytearray | memoryview, *, tier: InstallTier = InstallTier.MINIMAL,
         host: MapHost, crt_glue: ICrtGlue | None = None,
         on_block: typing.Callable[[ImagePlan, MappedBlock], None] | None = None) -> LoadedImage:
    """Map and attach an AMD64 DLL through a caller-provided host."""
    tier = InstallTier(tier)
    image = parse_image(image_bytes)
    _check_tier(build_plan(image, image.preferred_base), tier, host)
    source = memoryview(image_bytes).cast('B')
    if len(source) != image.source_size or hashlib.sha256(source).digest() != image.source_sha256:
        raise PEFormatError('source buffer changed after parsing')
    base = host.memory.alloc(image.size_of_image, image.preferred_base)
    try:
        plan = build_plan(image, base)
    except Exception:
        host.memory.free(base)
        raise
    loaded = LoadedImage(host, plan, tier, crt_glue or NoopCrtGlue())
    try:
        _copy_image(host, plan, source)
        _resolve_imports(loaded)
        _resolve_forwarders(loaded)
        if tier >= InstallTier.RUNTIME:
            _prepare_tls(loaded)
        _protect_image(host, plan)
        if tier >= InstallTier.RUNTIME:
            _register_unwind(loaded)
        loaded._crt_token = loaded._crt_glue.prepare(plan)
        loaded._crt_prepared = True
        for callback in loaded.tls_callbacks:
            loaded._attached_callbacks.append(callback)
            host.runtime.call(callback, base, 1, 0)
        if loaded.entry_point:
            loaded._entry_started = True
            if not host.runtime.call(loaded.entry_point, base, 1, 0):
                raise RuntimeError('DLL entry rejected process attach')
        requested = _requested_discards(plan, host, on_block)
    except Exception:
        loaded.unload()
        raise
    for block in requested:
        try:
            host.discarder.discard(block.address, block.size)
        except Exception as exc:
            raise BlockDiscardError(loaded, block) from exc
        loaded.discarded_blocks += (block,)
    return loaded
