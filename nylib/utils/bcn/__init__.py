"""Native BC1 decoding through a bundled DLL, loaded on first use."""
from ._lib import BcnError, decode_bc1, load

__all__ = ['decode_bc1', 'load', 'BcnError']
