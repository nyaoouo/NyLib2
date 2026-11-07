# nylib.utils.bcn

Native BC1 (DXT1) block decoding to RGBA8 through a bundled C DLL. No compiler or extra Python package is needed at runtime.

Keywords: bcn, BC1, DXT1, decode_bc1, texture decode, block compression, RGBA8, ctypes, DLL, load, BcnError, GIL

## Quick start

Decode one synthetic block, then a 136x136 tile made from the same block:

```python
from nylib.utils import bcn

block = bytes.fromhex('ffff000000000000')
pixels = bcn.decode_bc1(block, 4, 4)
assert pixels == bytearray(b'\xff' * 64)

tile = block * (34 * 34)
pixels = bcn.decode_bc1(tile, 136, 136)
assert len(pixels) == 136 * 136 * 4
assert pixels == bytearray(b'\xff' * len(pixels))
```

## Input and output

`decode_bc1(src, width, height)` accepts integer dimensions through `__index__`; both must be positive multiples of 4. `src` may be `bytes`, `bytearray`, a `memoryview`, or any C-contiguous buffer. Any item format or shape is accepted; length is counted in bytes.

The source holds 8-byte blocks in row-major block order. At least `8 * (width // 4) * (height // 4)` bytes are required; trailing bytes are ignored. Each block has two little-endian RGB565 endpoints and a little-endian 32-bit index word, with two bits per texel in row-major order.

The result is a new, resizable `bytearray` of `width * height * 4` bytes: tightly packed RGBA8, rows top to bottom. Pixel `(x, y)` starts at `4 * (y * width + x)`.

RGB565 channels expand by bit replication. When endpoint 0 is greater than endpoint 1, interpolated channels use `((2 * a + b) * 683) >> 11` and `((a + 2 * b) * 683) >> 11`. Otherwise the third colour is `(a + b) >> 1` and the fourth is black. Alpha is always 255, including three-colour index 3.

For integer dimensions and one-dimensional C-contiguous buffers with one-byte items, output and argument errors match the pure-Python BC1 decoder in `nylib.ue.assets`. This includes every input that the asset reader passes.

## Threads and the GIL

`decode_bc1()` and `load()` may run concurrently from multiple threads. The DLL loads once under a lock and stays loaded. The native decode releases the GIL; Python argument checks, output allocation and buffer pinning hold it.

The source is pinned without copying for the duration of the call. Threads may share it, but must not modify it during decoding. Each call allocates its own output; memory use is the result plus constant overhead. A decode cannot be cancelled mid-call.

Measured on 512x512 regions of a real map texture with Python 3.12 and 3.14, the native decode takes about 0.8 ms and the pure-Python decoder about 28-30 ms (35-38x). Whole `Texture.read_region()` calls, which also read and decompress, run at about 490 regions per second on one thread and about 600 on two or four.

## Errors

Argument checks run before loading the DLL:

| Error | Cause |
| --- | --- |
| `TypeError` | A dimension does not support `__index__`, or `src` is not bytes-like |
| `ValueError` | Dimensions are not positive multiples of 4, the source is not C-contiguous, or it is too short |
| `BcnError` | Unsupported platform, a DLL load failure, a missing export, or a nonzero native return |

Other buffer-export errors, exceptions from `__index__`, and allocation failures propagate unchanged. `BcnError.path` is the absolute DLL path when applicable, otherwise `None`; a DLL load failure retains its `OSError` as the cause.

Use `load()` to check native availability explicitly. It takes no arguments and returns `None`; a failed load can be retried:

```python
from nylib.utils import bcn

bcn.load()
```

## Notes

- The bundled `bcn_win64.dll` supports Windows x64 only. Importing the package loads no DLL; the first `load()` or valid decode does. Python 3.11 and free-threaded 3.14t are untested.
- `nylib.ue.assets` automatically selects the native decoder on its first BC1 decode. If loading raises `BcnError`, it logs one WARNING and uses pure Python for the rest of the process, with the same pixels. `bcn.load()` checks native availability directly.
- The wheel includes the DLL. The PyInstaller hook `hook-nylib.utils.bcn.py` bundles it under `nylib/utils/bcn/`; in-tree apps need nylib's hooks directory configured as described in [readme.md](../../../readme.md#packaging-with-pyinstaller).
- See [PROVENANCE.md](../../../nylib/utils/bcn/PROVENANCE.md) for the source, licence, toolchain and binary hash. From a checkout, `.\.venv\Scripts\python.exe scripts/bcn/build.py --check` rebuilds with the pinned MSVC toolchain and requires byte-identical output. `--install` refreshes the bundled DLL; `--scan PATH...` checks for embedded local paths.
