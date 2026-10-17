"""Oodle Data compression and the Oodle Network 1 UDP codec over the bundled (or a game's) Oodle 2.9 DLLs; Windows x64, loaded on first use."""
from ._lib import OodleError, dll, load, version
from ._data import CompressionLevel, Compressor, compress, compress_bound, decompress
from ._net import UdpCodec

__all__ = ['load', 'version', 'dll', 'Compressor', 'CompressionLevel', 'compress', 'compress_bound', 'decompress', 'UdpCodec', 'OodleError']
