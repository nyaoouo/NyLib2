# nylib.utils.imagecodec

Encode RGBA8 pixels as JPEG (through the Windows Imaging Component, by ctypes) or as PNG (written by nylib with the stdlib's `zlib`). Stateless functions over any bytes-like buffer; use it to publish map tiles, overviews and icons from pixels you already hold.

Keywords: imagecodec, encode_jpeg, encode_png, JPEG, PNG, RGBA, RGBA8, WIC, Windows Imaging Component, zlib, alpha, background, composite, quality, subsampling, ImageCodecError, ENCODER_REVISION, ctypes, tiles, icons

## Quick start

All three blocks build their own pixels (R, G, B, A bytes per pixel, rows top to bottom):

```python
from nylib.utils import imagecodec

w = h = 512
row = b''.join(bytes((x * 255 // (w - 1), 128, 255 - x * 255 // (w - 1), 255)) for x in range(w))
tile = imagecodec.encode_jpeg(row * h, w, h)  # quality 90, 4:2:0
assert tile[:2] == b'\xff\xd8' and tile[-2:] == b'\xff\xd9'
```

An overview at quality 85, and an icon with transparency as PNG:

```python
from nylib.utils import imagecodec

row = b''.join(bytes((x % 256, 90, 200, 255)) for x in range(4096))
overview = imagecodec.encode_jpeg(row * 4096, 4096, 4096, quality=85)

icon = b''.join(bytes((200, 30, 30, 255 if (x // 8 + y // 8) % 2 else 0)) for y in range(48) for x in range(140))
png = imagecodec.encode_png(icon, 140, 48)
assert png[:8] == b'\x89PNG\r\n\x1a\n'
print(len(overview), len(png))
```

## Pixels

- RGBA8: four bytes per pixel in R, G, B, A order, rows top to bottom, no row padding, straight (not premultiplied) alpha. The values are stored as given, with no colour conversion.
- `pixels` is any C-contiguous buffer: `bytes`, `bytearray`, `memoryview`, `array.array`, a ctypes array, or a numpy `uint8` array of shape `(height, width, 4)`. Its item format does not matter; its bytes are read as RGBA8, and `nbytes` must be `width * height * 4`.
- The buffer is only read, never kept, and is released when the call returns or raises. The image is read in strips of at most 4 MiB, so no copy of the whole image is made.
- With a `nylib.ue.assets` `Region`, pass its fields. Passing the `Region` itself raises a `TypeError` that names this form:

```python
# needs: a Region from nylib.ue.assets, with .pixels, .width and .height
from nylib.utils import imagecodec

jpeg = imagecodec.encode_jpeg(region.pixels, region.width, region.height)
```

## JPEG

- `encode_jpeg(pixels, width, height, *, quality=90, subsampling='4:2:0', background=None)`; `width` and `height` are 1..65500, `quality` 1..100.
- Baseline JFIF with the standard Huffman tables (WIC cannot optimise them), and a 72 x 72 dpi APP0 header.
- Quantisation tables are libjpeg's for every quality: with `s = 5000 // q if q < 50 else 200 - 2 * q`, each entry is `min(255, max(1, (base * s + 50) // 100))`, over the standard luminance and chrominance bases.
- `subsampling` is `'4:2:0'` (Y 2x2), `'4:2:2'` (Y 2x1) or `'4:4:4'`; Cb and Cr are 1x1.
- JPEG has no alpha, so a non-opaque pixel is refused unless you give a `background=(r, g, b)` to composite over. Each channel becomes `(c * a + bg * (255 - a) + 127) // 255`: alpha 255 keeps the pixel, alpha 0 gives the background. An all-opaque image ignores `background`.

```python
from nylib.utils import imagecodec

px = bytes((255, 0, 0, 128)) * 4 * 4
try:
    imagecodec.encode_jpeg(px, 4, 4)
except ValueError as e:
    print(e)  # 16 of 16 pixels are not opaque and JPEG has no alpha; pass background=(r, g, b) to composite them
jpeg = imagecodec.encode_jpeg(px, 4, 4, background=(0, 0, 0))  # red at half alpha over black
```

## PNG

- `encode_png(pixels, width, height)`; `width` and `height` are 1..65535.
- Written by nylib: the signature, IHDR (8-bit RGBA, colour type 6, also for an opaque image), IDAT and IEND, and no other chunk. Every row uses filter 0 and all rows form one zlib stream at level 9.
- Lossless: decoding gives back every byte, the RGB of fully transparent pixels included.
- Flat icon art comes out small (0.72 times the original files, at the median, on 40 game icons). Smooth content comes out larger than with an adaptive-filter encoder: a 4096x4096 gradient is about 2.7 times WIC's size.
- The bytes follow the Python build's zlib: 3.12 (zlib 1.3.1) and 3.14 (zlib-ng) write different files that decode to the same pixels.
- It makes no COM call and loads no DLL, so it runs on every platform and on 32-bit Python.

## Threads, COM and the GIL

- Both functions keep no state and may run on any number of threads at once.
- The first `encode_jpeg` call loads `windowscodecs.dll` from the system directory and calls `CoIncrementMTAUsage` once: the process keeps a multithreaded apartment until it exits. Nothing else is set up; the call never initialises COM on its thread, and works on threads with no COM, an STA or an MTA.
- The GIL is released while WIC encodes pixels (`WriteSource` and `WritePixels`, one call per strip) and in the first call's DLL load. It is held for the rest: the opacity pass (0.7 ms per tile, about 45 ms per overview), the copy of each strip and of the result. A pure-Python thread beside an overview encode keeps nearly full speed through the WIC part.
- PNG compresses one strip per `compress` call, and zlib releases the GIL inside it.
- One call's own allocations stay within 16 MiB + 2 x `len(result)`; concurrent calls add up.
- A thread pool gains on tiles (numbers below). There is no cancellation inside a call.

## Errors

- Wrong arguments raise `TypeError` or `ValueError` before any DLL load or COM call, on every platform.
- `encode_jpeg` raises `ImageCodecError(message, *, func=None, hresult=None)` for a failed WIC or Win32 call (`func` names the call, `hresult` is unsigned 32-bit), a DLL that does not load, an unexpected pixel format, or a malformed result. Off Windows, or on 32-bit Python, it raises the same error with `func` and `hresult` both `None`; `encode_png` still works.

```python
from nylib.utils import imagecodec

try:
    imagecodec.encode_jpeg(b'\xff' * 16, 2, 2)
except imagecodec.ImageCodecError as e:
    print(e.func, hex(e.hresult or 0), e)
```

## Measured

Windows 11 build 26200, CPython 3.14.4 / 3.12.10, each case in a fresh process. The timings were taken while other jobs were running on the same machine, so read them as upper bounds; the memory figures do not depend on load.

| case | time, 3.14 / 3.12 | process growth |
| --- | --- | --- |
| JPEG 512x512 q90 (z5 tile) | p50 2.0 / 2.0 ms; first call 5 ms | +1.4 / 1.6 MiB |
| JPEG 4096x4096 q85 (overview) | p50 124 / 117 ms; 7.0 MB | +17.2 / 17.5 MiB |
| JPEG 4096x4096 over a background, alpha ramp | 1.45 / 1.45 s | +13.7 / 15.5 MiB |
| the opacity check, 4096x4096 | 45 / 48 ms | none |
| PNG 140x48 icon | p50 1.8 / 2.4 ms | +0.3 MiB |
| PNG 256x256 icon | p50 3.3 / 5.5 ms | +0.6 / 0.55 MiB |
| PNG 4096x4096 overview | 2.2 / 3.1 s; 46 MB | +89 / 91 MiB |
| 1x1 JPEG, the fixed cost | p50 0.21 ms; first call of a process 4 ms | |
| 400 tiles, 1 and 4 threads | 441 / 959 and 499 / 897 tiles/s | |
| tile beside a busy Python thread | 15.4 / 15.5 ms (2.0 ms alone) | |

On a real map cache (36 tiles at q90, 3 overviews at q85), re-decoded by Windows: PSNR 42.8 dB at the minimum and 48.8 at the median for tiles, 45.2 dB at the minimum for overviews; the files are about 2 % larger than the cache's own Huffman-optimised ones (median 1.02 times). All 40 icon PNGs decode back to their input pixels exactly.

## Notes

- `ENCODER_REVISION` (an `int`, 1 today) rises only when the meaning of the output changes: the table rule, subsampling, the alpha or composite rule, the JFIF header, the PNG chunk list, or the decoded pixels. It does not rise for other bytes with the same meaning, such as another Windows build or another Python's zlib.
- The same arguments give the same bytes on one machine; JPEG bytes are the same under 3.12 and 3.14, PNG bytes per Python build.
- No decoding, no other formats, no BGRA, stride or premultiplied input. `format=`, `stride=` and `premultiplied=` are reserved names; today they raise Python's own `TypeError` for an unexpected keyword.
- Only 64-bit Windows is tested for JPEG; ARM64 Windows is expected to work and is unverified.
