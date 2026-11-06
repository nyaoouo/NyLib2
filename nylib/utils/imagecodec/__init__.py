"""JPEG (Windows WIC) and PNG (stdlib zlib) encoding of RGBA8 pixels; nothing loads until the first call."""
from ._encode import ENCODER_REVISION, encode_jpeg, encode_png
from ._wic import ImageCodecError

__all__ = ['encode_jpeg', 'encode_png', 'ImageCodecError', 'ENCODER_REVISION']
