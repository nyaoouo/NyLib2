"""Oodle Data compression over the bundled (or a game's) Oodle 2.9 DLLs; Windows x64, loaded on first use."""
from ._lib import OodleError, dll, load, version
from ._data import CompressionLevel, Compressor, compress, compress_bound, decompress

__all__ = ['load', 'version', 'dll', 'Compressor', 'CompressionLevel', 'compress', 'compress_bound', 'decompress', 'OodleError']
