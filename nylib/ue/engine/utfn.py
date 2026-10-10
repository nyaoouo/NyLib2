"""UtfN.hpp @ ea0dab3 conversions; UTF-16 text is a str of code units (UTF-16LE decoded with surrogatepass)."""
import array


def _units(text: str) -> array.array:
    units = array.array('H')
    units.frombytes(text.encode('utf-16-le', 'surrogatepass'))
    return units


def _is_high_surrogate(cp: int) -> bool:
    return 0xD800 <= cp < 0xDC00


def _is_low_surrogate(cp: int) -> bool:
    return 0xDC00 <= cp <= 0xDFFF


def _utf16_is_valid_unicode_char(lower: int, upper: int) -> bool:
    if _is_high_surrogate(upper):
        return _is_low_surrogate(lower)
    return not _is_low_surrogate(lower) and not _is_high_surrogate(lower) and not _is_low_surrogate(upper)


def _utf32_is_valid_unicode_char(cp: int) -> bool:
    return cp < 0x10FFFF and (cp < 0xD800 or cp > 0xDFFF)


def _utf16_pair_to_utf32(lower: int, upper: int) -> int:
    if not _utf16_is_valid_unicode_char(lower, upper):
        return 0
    if upper:
        return ((((upper - 0xD800) & 0xFFFF) << 10) | ((lower - 0xDC00) & 0xFFFF)) + 0x10000
    return lower


def _utf32_to_utf8(cp: int) -> str:
    # an invalid char is utf8_bytes{0}: one NUL codepoint (GetUtf8CharLenght(0) == 1)
    return chr(cp) if _utf32_is_valid_unicode_char(cp) else '\0'


def _get_utf8_char_length(c: int) -> int:
    if c & 0x80 == 0:
        return 1
    if c & 0xF0 == 0xF0:
        return 4
    if c & 0xE0 == 0xE0:
        return 3
    if c & 0xC0 == 0xC0:
        return 2
    return 0


def _is_valid_followup(cp: int) -> bool:
    return cp & 0xC0 == 0x80


def _utf8_bytes_to_utf32(c0: int, c1: int, c2: int, c3: int) -> int:
    if c0 & 0x80 == 0:
        return c0 if c1 == 0 and c2 == 0 and c3 == 0 else 0
    if c0 & 0xF0 == 0xF0:
        cp = (c3 & 0x7F) | (c2 & 0x7F) << 6 | (c1 & 0x7F) << 12 | (c0 & 0x0F) << 18
        overlong = c0 & 0xC0 != 0 and c1 == 0x80
        valid = not overlong and _is_valid_followup(c1) and _is_valid_followup(c2) and _is_valid_followup(c3)
    elif c0 & 0xE0 == 0xE0:
        cp = (c2 & 0x7F) | (c1 & 0x7F) << 6 | (c0 & 0x1F) << 12
        overlong = c0 & 0xE0 != 0 and c1 == 0x80
        valid = not overlong and _is_valid_followup(c1) and _is_valid_followup(c2) and c3 == 0
    elif c0 & 0xC0 == 0xC0:
        cp = (c1 & 0x7F) | (c0 & 0x3F) << 6
        overlong = c0 & 0xF0 != 0 and c1 == 0x80
        valid = not overlong and _is_valid_followup(c1) and c2 == 0 and c3 == 0
    else:
        return 0
    return cp if valid and _utf32_is_valid_unicode_char(cp) else 0


def _utf32_to_utf16(cp: int) -> str:
    # an invalid char is utf16_pair{}: one NUL code unit; a valid pair decodes to chr(cp)
    return chr(cp) if _utf32_is_valid_unicode_char(cp) else '\0'


def utf_16_string_to_utf_8_string(units: str) -> str:
    """UtfN::Utf16StringToUtf8String @ ea0dab3."""
    cu, out = _units(units), []
    current, end = 0, len(cu)
    while current != end:  # utf16_iterator::ReadChar, then the loop body
        upper, lower = 0, cu[current]
        current += 1
        if _is_high_surrogate(lower):
            if current == end:  # the last character ended abruptly
                break
            upper, lower = lower, cu[current]
            current += 1
        out.append(_utf32_to_utf8(_utf16_pair_to_utf32(lower, upper)))
    return ''.join(out)


def utf_8_string_to_utf_16_string(data: bytes) -> str:
    """UtfN::Utf8StringToUtf16String @ ea0dab3."""
    out, end = [], len(data)
    current = next_start = 0

    def read_char():
        nonlocal current, next_start, char
        if next_start == end:
            return
        char = [0, 0, 0, 0]
        if not (length := _get_utf8_char_length(data[next_start])):  # ea0dab3 never advances here (endless loop)
            raise ValueError(f'invalid UTF-8 lead byte {data[next_start]:#04x} at offset {next_start}')
        for i in range(length):
            if next_start == end:  # the last character ended abruptly
                current = end
                char = [0, 0, 0, 0]
                break
            char[i] = data[next_start]
            next_start += 1

    char = [0, 0, 0, 0]
    read_char()
    while current != end:
        out.append(_utf32_to_utf16(_utf8_bytes_to_utf32(*char)))
        current = next_start
        read_char()
    return ''.join(out)


def wstring_to_string(units: str) -> str:
    """UtfN::WStringToString @ ea0dab3 (its UTF-16 branch)."""
    return utf_16_string_to_utf_8_string(units)


def string_to_wstring(data: bytes) -> str:
    """UtfN::StringToWString @ ea0dab3 (its UTF-16 branch)."""
    return utf_8_string_to_utf_16_string(data)
