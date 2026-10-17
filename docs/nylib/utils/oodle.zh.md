> 本文档为 oodle.md 的中文阅读副本；英文版为权威来源（canonical）。

<!-- dt:meta v="1" lang="zh" source="oodle.md" -->

<!-- dt:section id="__preamble__" hash="fc55c3f9b342" -->
# nylib.utils.oodle

针对 Oodle Data 压缩以及 Oodle Network 1 的 UDP/TCP 包编解码器的 ctypes 绑定，基于随附的 Oodle 2.9.14 DLL 或游戏自带的副本。使用它来压缩/解压资源数据块,或对一些游戏网络协议所使用的 Oodle 压缩包进行编码/解码。

关键词: oodle, OodleLZ, compress, decompress, Kraken, Mermaid, Selkie, Hydra, Leviathan, UdpCodec, TcpCodec, Oodle Network, packet codec, game networking, ctypes, load, version, dll, OodleError

<!-- dt:section id="quick-start-0" hash="38f7482687b6" -->
## 快速开始

Kraken 的一次压缩/解压只需要内置的 DLL：

```python
from nylib.utils import oodle

data = b'hello world' * 100
compressed = oodle.compress(data, oodle.Compressor.Kraken)
assert oodle.decompress(compressed, len(data)) == data
```

`load()`、`version()` 和 `dll()` 也可以不带参数调用（它们会在首次使用时惰性加载内置的 core DLL）：

```python
from nylib.utils import oodle

print(oodle.version())          # '2.9.14'
print(oodle.dll('core')._name)  # absolute path of the loaded core DLL
```

<!-- dt:section id="decode-into-out-and-from-multiple-threads-0" hash="eaa50d28c449" -->
## 解码到 `out`，并从多个线程

传入 `out=` 可直接解码到你已拥有的缓冲区，无需额外拷贝；只要各自的 `out` 缓冲区不重叠（`src` 可以共享），`compress`/`decompress` 可以从任意数量的线程并发运行。

```python
from nylib.utils import oodle

data = b'abc' * 1000
comp = oodle.compress(data)
buf = bytearray(len(data))
view = oodle.decompress(comp, len(data), out=buf)
assert bytes(view) == data and view.obj is buf
```

<!-- dt:section id="load-a-game-s-own-dll-0" hash="347e69310006" -->
## 加载游戏自带的 DLL

`load()` 会替换进程中 `'core'` 或 `'net'` 的默认实现；已经在执行中的调用、以及已经构建好的编解码器，仍会沿用它们启动时所用的 DLL。

```python
# needs: a game's own oo2core_9_win64.dll / oo2net_9_win64.dll on disk
from nylib.utils import oodle

oodle.load('core', r'C:\Game\oo2core_9_win64.dll')
oodle.load('net', r'C:\Game\oo2net_9_win64.dll')
print(oodle.version())
```

<!-- dt:section id="oodle-network-udp-and-tcp-sessions-0" hash="210e610a782b" -->
## Oodle 网络：UDP 和 TCP 会话

`UdpCodec` 的数据包是相互独立的,所以同一个实例既可以压缩也可以解压。`TcpCodec` 只服务于一个流的一个方向:用同一个 `copy()` 构建发送端和接收端,让它们从一开始就保持同步。

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

<!-- dt:section id="errors-0" hash="449e0e3cadda" -->
## 错误

每个失败的原生调用都会抛出 `OodleError`，其中 `.func` 为失败的导出函数，`.result` 为其返回值，`.expected` 为预期的字节数。

```python
from nylib.utils import oodle

data = b'hello world' * 100
comp = oodle.compress(data)
try:
    oodle.decompress(comp, len(data) + 1)
except oodle.OodleError as e:
    print(e.func, e.result, e.expected)  # 'OodleLZ_Decompress' 0 1101
```

<!-- dt:section id="notes-0" hash="6bdb1b9f45a3" -->
## 注意事项

- `raw_size` 必须与原始长度完全相等；Oodle 不存储它。一个例外：当 `raw_size` 是 256 KiB 的倍数且小于多块流的真实大小时，会解码该前缀并成功。
- Oodle 流不携带校验和：未被检测到的损坏会返回 `raw_size` 字节的垃圾数据。网络编解码器在这方面也不更安全 —— `UdpCodec` 并不能捕获每一个错误的 `raw_size`，因此关心同步的调用方必须自己跟踪数据包顺序。
- `UdpCodec` 和 `TcpCodec` 在构造时绑定当时生效的 `'net'` DLL；之后的 `oodle.load('net', ...)` 不会影响已构建的编解码器，包括用 `.copy()` 制作的副本。
- 仅支持 Windows x64(包括原生 ARM64 CPython，它同样拥有 8 字节指针)；其他任何平台在首次使用时都会抛出 `OodleError('Oodle DLLs are Windows x64 only')`。
- 关于随附 DLL 的来源、哈希值和许可证，参见 [PROVENANCE.md](../../../nylib/utils/oodle/PROVENANCE.md)。
- TCP：一个不匹配或乱序的数据包会污染 `TcpCodec` —— 之后的每次调用都会抛出异常，直到你从更早的 `copy()` 重建为止 —— 并且 TCP 解码是从一个私有的受保护缓冲区中拷贝出来的，因此与 UDP 不同，它不是零拷贝的。那里的受控故障是一次 first-chance access violation：在 `faulthandler` 下它仍会抛出 `OodleError`，但也会打印一份报告，调试器会在此中断；而一个自身的向量化异常处理程序在发生访问冲突时就终止进程的宿主(例如游戏的崩溃报告器或包裹着被注入的嗅探器的反作弊)，可能会因这样的数据包而直接终止进程。这从来都不是静默的内存损坏(loud, never silent memory corruption)。
