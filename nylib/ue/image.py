"""Write the game's main module as an on-disk PE image (I6, 7-c): memory bytes -> nylib.winutils.pe_unmap layout."""
import contextlib
import dataclasses
import hashlib
import logging
import os
import time

from .memory import MemorySource
from .model import hexs
from .store import safe_dir_name
from ..winutils.pe_unmap import pe_unmap

logger = logging.getLogger('nylib.ue.image')

IMAGE_DIR = 'image'
IMAGE_MAX_BYTES = 1 << 30  # a larger SizeOfImage is skipped, never read
READ_STEP = 16 << 20  # bytes per fresh read
PAGE_SIZE = 0x1000  # the unit of the unreadable count


def _u16(buf, off: int) -> int: return int.from_bytes(buf[off:off + 2], 'little')
def _u32(buf, off: int) -> int: return int.from_bytes(buf[off:off + 4], 'little')


def _put_u64(buf, off: int, value: int) -> None:
    buf[off:off + 8] = value.to_bytes(8, 'little')


def _mark_pages(pages: set, lo: int, hi: int) -> None:
    p = lo - lo % PAGE_SIZE
    while p < hi:
        pages.add(p)
        p += PAGE_SIZE


def _unreadable_pages(covered: list, base: int, size_of_image: int) -> set:
    """PAGE_SIZE-aligned addresses of every page of [base, base + size_of_image) with an unread byte."""
    merged = []
    for s, e in sorted(covered):
        if merged and s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    pages, pos = set(), base
    for s, e in merged:
        if s > pos:
            _mark_pages(pages, pos, s)
        pos = max(pos, e)
    if pos < base + size_of_image:
        _mark_pages(pages, pos, base + size_of_image)
    return pages


def _original_image_base(disk_exe) -> int | None:
    """ImageBase of the same-build exe on disk; None when it cannot be read or is not a PE32+ AMD64 file."""
    try:
        with open(disk_exe, 'rb') as f:
            head = f.read(0x40)
            if len(head) < 0x40 or head[:2] != b'MZ':
                return None
            e_lfanew = int.from_bytes(head[0x3C:0x40], 'little')
            f.seek(e_lfanew)
            opt = f.read(24 + 0x20)
            if len(opt) < 24 + 0x20 or opt[:4] != b'PE\0\0' or int.from_bytes(opt[24:26], 'little') != 0x20B:
                return None
            return int.from_bytes(opt[24 + 0x18:24 + 0x20], 'little')
    except OSError:
        return None


@dataclasses.dataclass(frozen=True)
class ImageResult:
    rel_path: str  # f'{IMAGE_DIR}/{store.safe_dir_name(exe)}', '/'-separated; set when skipped too
    path: str | None  # absolute path written (inside <folder>.partial during a dump); None when skipped
    size: int  # bytes written; 0 when skipped
    sha256: str | None  # lower-case hex SHA-256 of the bytes written; None when skipped
    image_base: int  # the module base: the ImageBase written into the file's header
    original_image_base: int | None  # ImageBase of the same-build exe file on disk; None when unknown or skipped
    unreadable_pages: int  # PAGE_SIZE pages of [base, base + size_of_image) not fully read
    first_unreadable: int | None  # address of the first such page
    skipped: str | None  # why no file was written; None when it was written
    seconds: float

    def to_meta(self) -> dict:
        return {
            'file': self.rel_path if self.path else None,
            'size': hexs(self.size) if self.path else None,
            'sha256': self.sha256,
            'image_base': hexs(self.image_base),
            'original_image_base': None if self.original_image_base is None else hexs(self.original_image_base),
            'unreadable_pages': self.unreadable_pages,
            'skipped': self.skipped,
        }

    @property
    def warnings(self) -> tuple[str, ...]:
        if self.skipped:
            return (f'image skipped: {self.skipped}',)
        if self.unreadable_pages > 0:
            return (f'image {self.rel_path}: {self.unreadable_pages} unreadable pages zero-filled, '
                    f'the first at {self.first_unreadable:#x}',)
        return ()


def write_image(source, *, base: int, size_of_image: int, exe: str, folder, disk_exe=None) -> ImageResult:
    """Write the module at `base` as an on-disk PE file `<folder>/image/<exe>` (I6).
    Never raises for an unreadable or malformed image: a problem is reported through `ImageResult.skipped`."""
    if not isinstance(source, MemorySource):
        raise TypeError(f'source must be a MemorySource, got {type(source).__name__}')
    if not isinstance(base, int) or isinstance(base, bool):
        raise TypeError(f'base must be int, got {type(base).__name__}')
    if not isinstance(size_of_image, int) or isinstance(size_of_image, bool):
        raise TypeError(f'size_of_image must be int, got {type(size_of_image).__name__}')
    if not isinstance(exe, str):
        raise TypeError(f'exe must be a str, got {type(exe).__name__}')
    if not isinstance(folder, (str, os.PathLike)):
        raise TypeError(f'folder must be str or os.PathLike, got {type(folder).__name__}')
    if disk_exe is not None and not isinstance(disk_exe, (str, os.PathLike)):
        raise TypeError(f'disk_exe must be str, os.PathLike or None, got {type(disk_exe).__name__}')

    t0 = time.perf_counter()
    rel_path = f'{IMAGE_DIR}/{safe_dir_name(exe)}'
    folder = os.fspath(folder)

    def skipped(reason, *, unreadable=0, first=None, exc_info=False):
        logger.debug('image skipped: %s', reason, exc_info=exc_info)
        return ImageResult(rel_path=rel_path, path=None, size=0, sha256=None, image_base=base,
                            original_image_base=None, unreadable_pages=unreadable, first_unreadable=first,
                            skipped=reason, seconds=time.perf_counter() - t0)

    if base <= 0 or base % PAGE_SIZE != 0 or size_of_image <= 0 or base + size_of_image > 1 << 64:
        return skipped(f'no valid image range at {base:#x} of {size_of_image:#x} bytes')
    if size_of_image > IMAGE_MAX_BYTES:
        return skipped(f'SizeOfImage {size_of_image:#x} exceeds the {IMAGE_MAX_BYTES:#x}-byte limit')

    try:
        buf = bytearray(size_of_image)
    except MemoryError:
        return skipped(f'not enough memory for a {size_of_image:#x}-byte image', exc_info=True)

    # Reads go through .fresh (uncached) in READ_STEP pieces; a failed piece is retried page by page.
    fresh = source.fresh
    covered = []
    for addr, n in fresh.readable_ranges(base, size_of_image):
        pos, end = addr, addr + n
        while pos < end:
            piece_len = min(READ_STEP, end - pos)
            data = fresh.try_read(pos, piece_len)
            if data is not None:
                buf[pos - base:pos - base + piece_len] = data
                covered.append((pos, pos + piece_len))
            else:
                p, piece_end = pos - pos % PAGE_SIZE, pos + piece_len
                while p < piece_end:
                    part_end = min(p + PAGE_SIZE, base + size_of_image)
                    part = fresh.try_read(p, part_end - p)
                    if part is not None:
                        buf[p - base:part_end - base] = part
                        covered.append((p, part_end))
                    p += PAGE_SIZE
            pos += piece_len

    page_set = _unreadable_pages(covered, base, size_of_image)
    unreadable_pages, first_unreadable = len(page_set), (min(page_set) if page_set else None)

    if base in page_set:
        return skipped(f'the PE headers at {base:#x} are unreadable', unreadable=unreadable_pages, first=first_unreadable)

    e_lfanew = _u32(buf, 0x3C)
    opt = e_lfanew + 24
    if 0 < e_lfanew and opt + 0x70 <= size_of_image and _u16(buf, opt) == 0x20B:
        size_of_headers = _u32(buf, opt + 0x3C)
        header_end = base + min(size_of_headers, size_of_image)
        if any(p < header_end for p in page_set):
            return skipped(f'the PE headers at {base:#x} are unreadable', unreadable=unreadable_pages, first=first_unreadable)
        _put_u64(buf, opt + 0x18, base)  # ImageBase := the runtime module base (Q42 = A)
        if _u32(buf, opt + 0x6C) > 4 and opt + 0x98 <= size_of_image:
            buf[opt + 0x90:opt + 0x98] = bytes(8)  # DataDirectory[4]: a file-offset overlay pointer memory never holds

    data = pe_unmap(buf)
    buf = None  # release the SizeOfImage buffer before the write
    if data is None:
        return skipped('not a PE32+ AMD64 image', unreadable=unreadable_pages, first=first_unreadable)

    dest = os.path.join(folder, *rel_path.split('/'))
    try:
        os.makedirs(os.path.join(folder, IMAGE_DIR), exist_ok=True)
        with open(dest, 'wb') as f:
            f.write(data)
    except OSError as e:
        if os.path.exists(dest):
            with contextlib.suppress(OSError):
                os.remove(dest)
        return skipped(f'cannot write {rel_path}: {e.strerror or e}', unreadable=unreadable_pages,
                        first=first_unreadable, exc_info=True)

    original_image_base = _original_image_base(disk_exe) if disk_exe is not None else None
    sha256 = hashlib.sha256(data).hexdigest()
    seconds = time.perf_counter() - t0
    logger.debug('image %s: %d bytes, %d unreadable pages, %.2fs', dest, len(data), unreadable_pages, seconds)
    return ImageResult(rel_path=rel_path, path=dest, size=len(data), sha256=sha256, image_base=base,
                        original_image_base=original_image_base, unreadable_pages=unreadable_pages,
                        first_unreadable=first_unreadable, skipped=None, seconds=seconds)
