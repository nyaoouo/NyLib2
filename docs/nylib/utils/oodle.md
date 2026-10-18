# nylib.utils.oodle

Ctypes bindings for Oodle Data compression and the Oodle Network 1 UDP/TCP packet codecs, over the bundled Oodle 2.9.14 DLLs or a game's own copy. Use it to compress/decompress asset blobs, or to encode/decode the Oodle-compressed packets some game network protocols use.

Keywords: oodle, OodleLZ, compress, decompress, Kraken, Mermaid, Selkie, Hydra, Leviathan, UdpCodec, TcpCodec, Oodle Network, packet codec, game networking, ctypes, load, version, dll, OodleError

## Quick start

A Kraken round trip needs nothing but the bundled DLL:

```python
from nylib.utils import oodle

data = b'hello world' * 100
compressed = oodle.compress(data, oodle.Compressor.Kraken)
assert oodle.decompress(compressed, len(data)) == data
```

`load()`, `version()` and `dll()` work with no arguments too (they lazy-load the bundled core DLL on first use):

```python
from nylib.utils import oodle

print(oodle.version())          # '2.9.14'
print(oodle.dll('core')._name)  # absolute path of the loaded core DLL
```

## Decode into `out`, and from multiple threads

Pass `out=` to decode straight into a buffer you already own, with no extra copy; `compress`/`decompress` may run concurrently from any number of threads as long as their `out` buffers do not overlap (`src` may be shared).

```python
from nylib.utils import oodle

data = b'abc' * 1000
comp = oodle.compress(data)
buf = bytearray(len(data))
view = oodle.decompress(comp, len(data), out=buf)
assert bytes(view) == data and view.obj is buf
```

## Load a game's own DLL

`load()` swaps the process default for `'core'` or `'net'`; calls already in flight, and codecs already built, keep the DLL they started with.

```python
# needs: a game's own oo2core_9_win64.dll / oo2net_9_win64.dll on disk
from nylib.utils import oodle

oodle.load('core', r'C:\Game\oo2core_9_win64.dll')
oodle.load('net', r'C:\Game\oo2net_9_win64.dll')
print(oodle.version())
```

## Oodle Network: UDP and TCP sessions

`UdpCodec` packets are independent, so one instance can both compress and decompress. `TcpCodec` serves one direction of one stream: build the sender and the receiver from the same `copy()` so they start in lockstep.

```python
from nylib.utils import oodle

window, packet = b'\x00' * 32768, b'some packet payload' * 10

udp = oodle.UdpCodec(window, hash_bits=17)
enc = udp.compress(packet)
assert udp.decompress(enc, len(packet)) == packet

base = oodle.TcpCodec(window, hash_bits=17)
sender, receiver = base.copy(), base.copy()
enc2 = sender.compress(packet)
assert receiver.decompress(enc2, len(packet)) == packet
```

## Errors

Every failed native call raises `OodleError`, with the failing export in `.func`, its return value in `.result`, and the expected byte count in `.expected`.

```python
from nylib.utils import oodle

data = b'hello world' * 100
comp = oodle.compress(data)
try:
    oodle.decompress(comp, len(data) + 1)
except oodle.OodleError as e:
    print(e.func, e.result, e.expected)  # 'OodleLZ_Decompress' 0 1101
```

## Notes

- `raw_size` must equal the original length exactly; Oodle stores none. One exception: a `raw_size` that is a multiple of 256 KiB below the true size of a multi-chunk stream decodes that prefix and succeeds.
- Oodle streams carry no checksum: undetected corruption returns `raw_size` bytes of garbage. The network codecs are no safer here - `UdpCodec` does not catch every wrong `raw_size` either, so a caller that cares about sync must track packet order itself.
- `UdpCodec` and `TcpCodec` bind whichever `'net'` DLL is current at construction time; a later `oodle.load('net', ...)` does not affect codecs already built, including copies made with `.copy()`.
- Windows x64 only (including native ARM64 CPython, which also has 8-byte pointers); every other platform raises `OodleError('Oodle DLLs are Windows x64 only')` on first use.
- See [PROVENANCE.md](../../../nylib/utils/oodle/PROVENANCE.md) for where the bundled DLLs come from, their hashes, and the licence.
- TCP: a mismatched or out-of-order packet poisons the `TcpCodec` - every later call raises until you rebuild from an earlier `copy()` - and TCP decode copies out of a private guarded buffer, so unlike UDP it is not zero-copy. A contained fault there is a first-chance access violation: under `faulthandler` it still raises `OodleError`, but also prints a report, and a debugger breaks on it; a host whose own vectored exception handler terminates on access violations (a game's crash reporter or anti-cheat wrapped around an injected sniffer) can end the process on such a packet instead. This is never silent memory corruption.
