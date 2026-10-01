"""Import a nylib.ue snapshot into an IDA 9.x database: exec and vtable names, globals, UE types and UFunction comments.

Run modes: File > Script file (Alt+F7) or the plugin (Edit > Plugins > UE Dumper Import, Ctrl-Alt-U) open the dialog;
`idat -A -S"ue_dumper_import.py --snapshot DIR --types all" <idb>` imports in batch; `import ue_dumper_import as uei; uei.run(DIR)`.
"""
import argparse
import bisect
import collections
import hashlib
import json
import os
import re
import sys
import time
import traceback

try:
    import ida_idaapi
except ImportError:
    ida_idaapi = None

SCHEMA_NAME = 'nylib.ue.snapshot'
SCHEMA_MAJOR = 1

_OFFSETS_SCHEMA = 'nylib.ue.offsets'
_OBJECTS_SCHEMA = 'nylib.ue.objects'
_NETNODE = '$ nylib.ue.import'
_TYPE_MARK = 'nylib.ue: '
_COMMENT_MARK = 'UFunction '
_ALSO_MARK = 'also: '
_COMMENT_BYTE_LIMIT = 1020  # IDA 9.3 silently truncates a repeatable comment past ~1024 bytes
_TAG = '[ue_dumper_import]'
_GLOBALS = ('GObjects', 'GNames', 'GWorld', 'ProcessEvent', 'AppendString')
_GLOBAL_IDA_NAMES = {'GObjects': 'GObjects', 'GNames': 'GNames', 'GWorld': 'GWorld',
                     'ProcessEvent': '_ZN7UObject12ProcessEventEv', 'AppendString': '_ZN5FName12AppendStringEv'}
_EXEC_PROTOTYPE = 'void __fastcall(UObject *Context, FFrame *Stack, void *Result)'
_PE_PROTOTYPE = 'void __fastcall(UObject *this, UFunction *Function, void *Parms)'
_RF_CLASS_DEFAULT_OBJECT = 0x10
_FUNC_NATIVE = 0x400
_CPF_CONST_PARM, _CPF_PARM, _CPF_OUT_PARM, _CPF_RETURN_PARM = 0x2, 0x80, 0x100, 0x400
_CPF_REFERENCE_PARM, _CPF_UOBJECT_WRAPPER = 0x8000000, 0x0004000000000000
_CACHE_SIZE = 4096
_ADDRESS_LIMIT = 1 << 64
_HEX_RE = re.compile(r'-?0[xX][0-9A-Fa-f]+')
_UHEX_RE = re.compile(r'0[xX][0-9A-Fa-f]+')
_SHA256_RE = re.compile(r'[0-9A-Fa-f]{64}')
_VERSION_RE = re.compile(r'\d+\.\d+')
_LONE_SURROGATE_RE = re.compile('[\ud800-\udfff]')

# EFunctionFlags names of nylib/ue/flags.py (Dumper-7 Enums.h), copied.
_EFUNCTION_FLAGS = (
    ('Final', 0x00000001), ('RequiredAPI', 0x00000002), ('BlueprintAuthorityOnly', 0x00000004),
    ('BlueprintCosmetic', 0x00000008), ('Net', 0x00000040), ('NetReliable', 0x00000080), ('NetRequest', 0x00000100),
    ('Exec', 0x00000200), ('Native', 0x00000400), ('Event', 0x00000800), ('NetResponse', 0x00001000),
    ('Static', 0x00002000), ('NetMulticast', 0x00004000), ('UbergraphFunction', 0x00008000),
    ('MulticastDelegate', 0x00010000), ('Public', 0x00020000), ('Private', 0x00040000), ('Protected', 0x00080000),
    ('Delegate', 0x00100000), ('NetServer', 0x00200000), ('HasOutParms', 0x00400000), ('HasDefaults', 0x00800000),
    ('NetClient', 0x01000000), ('DLLImport', 0x02000000), ('BlueprintCallable', 0x04000000),
    ('BlueprintEvent', 0x08000000), ('BlueprintPure', 0x10000000), ('EditorOnly', 0x20000000), ('Const', 0x40000000),
    ('NetValidate', 0x80000000),
)


class SnapshotFormatError(Exception):
    """The folder is not a snapshot this importer can read."""

    def __init__(self, folder, reason: str):
        super().__init__(f'{os.fspath(folder) if isinstance(folder, os.PathLike) else folder}: {reason}')
        self.folder = folder
        self.reason = reason


class BuildRefusedError(Exception):
    """The IDB's input file does not match (or cannot be matched with) the snapshot's executable."""

    def __init__(self, verdict: str, text: str):
        super().__init__(text)
        self.verdict = verdict
        self.text = text


class _UsageError(ValueError):
    pass


class _Bad(Exception):
    pass


# --- naming rules copied from nylib/ue/names.py (NameRuleGuardTests compares them) ---

_DIGIT_WORDS = ('Zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine')

# Unicode 15.1 XID_Start / XID_Continue ranges, transcribed verbatim from Dumper-7's
# UnicodeNames.h @ dd8fe34 (LLVM project data). XID_Continue for MakeNameValid is their union;
# Python's isidentifier() disagrees on hundreds of code points (e.g. U+30FB), so it is not used.
_XID_START_RANGES = (
    (0x0041,0x005A), (0x0061,0x007A), (0x00AA,0x00AA), (0x00B5,0x00B5), (0x00BA,0x00BA), (0x00C0,0x00D6), (0x00D8,0x00F6), (0x00F8,0x02C1),
    (0x02C6,0x02D1), (0x02E0,0x02E4), (0x02EC,0x02EC), (0x02EE,0x02EE), (0x0370,0x0374), (0x0376,0x0377), (0x037B,0x037D), (0x037F,0x037F),
    (0x0386,0x0386), (0x0388,0x038A), (0x038C,0x038C), (0x038E,0x03A1), (0x03A3,0x03F5), (0x03F7,0x0481), (0x048A,0x052F), (0x0531,0x0556),
    (0x0559,0x0559), (0x0560,0x0588), (0x05D0,0x05EA), (0x05EF,0x05F2), (0x0620,0x064A), (0x066E,0x066F), (0x0671,0x06D3), (0x06D5,0x06D5),
    (0x06E5,0x06E6), (0x06EE,0x06EF), (0x06FA,0x06FC), (0x06FF,0x06FF), (0x0710,0x0710), (0x0712,0x072F), (0x074D,0x07A5), (0x07B1,0x07B1),
    (0x07CA,0x07EA), (0x07F4,0x07F5), (0x07FA,0x07FA), (0x0800,0x0815), (0x081A,0x081A), (0x0824,0x0824), (0x0828,0x0828), (0x0840,0x0858),
    (0x0860,0x086A), (0x0870,0x0887), (0x0889,0x088E), (0x08A0,0x08C9), (0x0904,0x0939), (0x093D,0x093D), (0x0950,0x0950), (0x0958,0x0961),
    (0x0971,0x0980), (0x0985,0x098C), (0x098F,0x0990), (0x0993,0x09A8), (0x09AA,0x09B0), (0x09B2,0x09B2), (0x09B6,0x09B9), (0x09BD,0x09BD),
    (0x09CE,0x09CE), (0x09DC,0x09DD), (0x09DF,0x09E1), (0x09F0,0x09F1), (0x09FC,0x09FC), (0x0A05,0x0A0A), (0x0A0F,0x0A10), (0x0A13,0x0A28),
    (0x0A2A,0x0A30), (0x0A32,0x0A33), (0x0A35,0x0A36), (0x0A38,0x0A39), (0x0A59,0x0A5C), (0x0A5E,0x0A5E), (0x0A72,0x0A74), (0x0A85,0x0A8D),
    (0x0A8F,0x0A91), (0x0A93,0x0AA8), (0x0AAA,0x0AB0), (0x0AB2,0x0AB3), (0x0AB5,0x0AB9), (0x0ABD,0x0ABD), (0x0AD0,0x0AD0), (0x0AE0,0x0AE1),
    (0x0AF9,0x0AF9), (0x0B05,0x0B0C), (0x0B0F,0x0B10), (0x0B13,0x0B28), (0x0B2A,0x0B30), (0x0B32,0x0B33), (0x0B35,0x0B39), (0x0B3D,0x0B3D),
    (0x0B5C,0x0B5D), (0x0B5F,0x0B61), (0x0B71,0x0B71), (0x0B83,0x0B83), (0x0B85,0x0B8A), (0x0B8E,0x0B90), (0x0B92,0x0B95), (0x0B99,0x0B9A),
    (0x0B9C,0x0B9C), (0x0B9E,0x0B9F), (0x0BA3,0x0BA4), (0x0BA8,0x0BAA), (0x0BAE,0x0BB9), (0x0BD0,0x0BD0), (0x0C05,0x0C0C), (0x0C0E,0x0C10),
    (0x0C12,0x0C28), (0x0C2A,0x0C39), (0x0C3D,0x0C3D), (0x0C58,0x0C5A), (0x0C5D,0x0C5D), (0x0C60,0x0C61), (0x0C80,0x0C80), (0x0C85,0x0C8C),
    (0x0C8E,0x0C90), (0x0C92,0x0CA8), (0x0CAA,0x0CB3), (0x0CB5,0x0CB9), (0x0CBD,0x0CBD), (0x0CDD,0x0CDE), (0x0CE0,0x0CE1), (0x0CF1,0x0CF2),
    (0x0D04,0x0D0C), (0x0D0E,0x0D10), (0x0D12,0x0D3A), (0x0D3D,0x0D3D), (0x0D4E,0x0D4E), (0x0D54,0x0D56), (0x0D5F,0x0D61), (0x0D7A,0x0D7F),
    (0x0D85,0x0D96), (0x0D9A,0x0DB1), (0x0DB3,0x0DBB), (0x0DBD,0x0DBD), (0x0DC0,0x0DC6), (0x0E01,0x0E30), (0x0E32,0x0E32), (0x0E40,0x0E46),
    (0x0E81,0x0E82), (0x0E84,0x0E84), (0x0E86,0x0E8A), (0x0E8C,0x0EA3), (0x0EA5,0x0EA5), (0x0EA7,0x0EB0), (0x0EB2,0x0EB2), (0x0EBD,0x0EBD),
    (0x0EC0,0x0EC4), (0x0EC6,0x0EC6), (0x0EDC,0x0EDF), (0x0F00,0x0F00), (0x0F40,0x0F47), (0x0F49,0x0F6C), (0x0F88,0x0F8C), (0x1000,0x102A),
    (0x103F,0x103F), (0x1050,0x1055), (0x105A,0x105D), (0x1061,0x1061), (0x1065,0x1066), (0x106E,0x1070), (0x1075,0x1081), (0x108E,0x108E),
    (0x10A0,0x10C5), (0x10C7,0x10C7), (0x10CD,0x10CD), (0x10D0,0x10FA), (0x10FC,0x1248), (0x124A,0x124D), (0x1250,0x1256), (0x1258,0x1258),
    (0x125A,0x125D), (0x1260,0x1288), (0x128A,0x128D), (0x1290,0x12B0), (0x12B2,0x12B5), (0x12B8,0x12BE), (0x12C0,0x12C0), (0x12C2,0x12C5),
    (0x12C8,0x12D6), (0x12D8,0x1310), (0x1312,0x1315), (0x1318,0x135A), (0x1380,0x138F), (0x13A0,0x13F5), (0x13F8,0x13FD), (0x1401,0x166C),
    (0x166F,0x167F), (0x1681,0x169A), (0x16A0,0x16EA), (0x16EE,0x16F8), (0x1700,0x1711), (0x171F,0x1731), (0x1740,0x1751), (0x1760,0x176C),
    (0x176E,0x1770), (0x1780,0x17B3), (0x17D7,0x17D7), (0x17DC,0x17DC), (0x1820,0x1878), (0x1880,0x18A8), (0x18AA,0x18AA), (0x18B0,0x18F5),
    (0x1900,0x191E), (0x1950,0x196D), (0x1970,0x1974), (0x1980,0x19AB), (0x19B0,0x19C9), (0x1A00,0x1A16), (0x1A20,0x1A54), (0x1AA7,0x1AA7),
    (0x1B05,0x1B33), (0x1B45,0x1B4C), (0x1B83,0x1BA0), (0x1BAE,0x1BAF), (0x1BBA,0x1BE5), (0x1C00,0x1C23), (0x1C4D,0x1C4F), (0x1C5A,0x1C7D),
    (0x1C80,0x1C88), (0x1C90,0x1CBA), (0x1CBD,0x1CBF), (0x1CE9,0x1CEC), (0x1CEE,0x1CF3), (0x1CF5,0x1CF6), (0x1CFA,0x1CFA), (0x1D00,0x1DBF),
    (0x1E00,0x1F15), (0x1F18,0x1F1D), (0x1F20,0x1F45), (0x1F48,0x1F4D), (0x1F50,0x1F57), (0x1F59,0x1F59), (0x1F5B,0x1F5B), (0x1F5D,0x1F5D),
    (0x1F5F,0x1F7D), (0x1F80,0x1FB4), (0x1FB6,0x1FBC), (0x1FBE,0x1FBE), (0x1FC2,0x1FC4), (0x1FC6,0x1FCC), (0x1FD0,0x1FD3), (0x1FD6,0x1FDB),
    (0x1FE0,0x1FEC), (0x1FF2,0x1FF4), (0x1FF6,0x1FFC), (0x2071,0x2071), (0x207F,0x207F), (0x2090,0x209C), (0x2102,0x2102), (0x2107,0x2107),
    (0x210A,0x2113), (0x2115,0x2115), (0x2118,0x211D), (0x2124,0x2124), (0x2126,0x2126), (0x2128,0x2128), (0x212A,0x2139), (0x213C,0x213F),
    (0x2145,0x2149), (0x214E,0x214E), (0x2160,0x2188), (0x2C00,0x2CE4), (0x2CEB,0x2CEE), (0x2CF2,0x2CF3), (0x2D00,0x2D25), (0x2D27,0x2D27),
    (0x2D2D,0x2D2D), (0x2D30,0x2D67), (0x2D6F,0x2D6F), (0x2D80,0x2D96), (0x2DA0,0x2DA6), (0x2DA8,0x2DAE), (0x2DB0,0x2DB6), (0x2DB8,0x2DBE),
    (0x2DC0,0x2DC6), (0x2DC8,0x2DCE), (0x2DD0,0x2DD6), (0x2DD8,0x2DDE), (0x3005,0x3007), (0x3021,0x3029), (0x3031,0x3035), (0x3038,0x303C),
    (0x3041,0x3096), (0x309D,0x309F), (0x30A1,0x30FA), (0x30FC,0x30FF), (0x3105,0x312F), (0x3131,0x318E), (0x31A0,0x31BF), (0x31F0,0x31FF),
    (0x3400,0x4DBF), (0x4E00,0xA48C), (0xA4D0,0xA4FD), (0xA500,0xA60C), (0xA610,0xA61F), (0xA62A,0xA62B), (0xA640,0xA66E), (0xA67F,0xA69D),
    (0xA6A0,0xA6EF), (0xA717,0xA71F), (0xA722,0xA788), (0xA78B,0xA7CA), (0xA7D0,0xA7D1), (0xA7D3,0xA7D3), (0xA7D5,0xA7D9), (0xA7F2,0xA801),
    (0xA803,0xA805), (0xA807,0xA80A), (0xA80C,0xA822), (0xA840,0xA873), (0xA882,0xA8B3), (0xA8F2,0xA8F7), (0xA8FB,0xA8FB), (0xA8FD,0xA8FE),
    (0xA90A,0xA925), (0xA930,0xA946), (0xA960,0xA97C), (0xA984,0xA9B2), (0xA9CF,0xA9CF), (0xA9E0,0xA9E4), (0xA9E6,0xA9EF), (0xA9FA,0xA9FE),
    (0xAA00,0xAA28), (0xAA40,0xAA42), (0xAA44,0xAA4B), (0xAA60,0xAA76), (0xAA7A,0xAA7A), (0xAA7E,0xAAAF), (0xAAB1,0xAAB1), (0xAAB5,0xAAB6),
    (0xAAB9,0xAABD), (0xAAC0,0xAAC0), (0xAAC2,0xAAC2), (0xAADB,0xAADD), (0xAAE0,0xAAEA), (0xAAF2,0xAAF4), (0xAB01,0xAB06), (0xAB09,0xAB0E),
    (0xAB11,0xAB16), (0xAB20,0xAB26), (0xAB28,0xAB2E), (0xAB30,0xAB5A), (0xAB5C,0xAB69), (0xAB70,0xABE2), (0xAC00,0xD7A3), (0xD7B0,0xD7C6),
    (0xD7CB,0xD7FB), (0xF900,0xFA6D), (0xFA70,0xFAD9), (0xFB00,0xFB06), (0xFB13,0xFB17), (0xFB1D,0xFB1D), (0xFB1F,0xFB28), (0xFB2A,0xFB36),
    (0xFB38,0xFB3C), (0xFB3E,0xFB3E), (0xFB40,0xFB41), (0xFB43,0xFB44), (0xFB46,0xFBB1), (0xFBD3,0xFC5D), (0xFC64,0xFD3D), (0xFD50,0xFD8F),
    (0xFD92,0xFDC7), (0xFDF0,0xFDF9), (0xFE71,0xFE71), (0xFE73,0xFE73), (0xFE77,0xFE77), (0xFE79,0xFE79), (0xFE7B,0xFE7B), (0xFE7D,0xFE7D),
    (0xFE7F,0xFEFC), (0xFF21,0xFF3A), (0xFF41,0xFF5A), (0xFF66,0xFF9D), (0xFFA0,0xFFBE), (0xFFC2,0xFFC7), (0xFFCA,0xFFCF), (0xFFD2,0xFFD7),
    (0xFFDA,0xFFDC), (0x10000,0x1000B), (0x1000D,0x10026), (0x10028,0x1003A), (0x1003C,0x1003D), (0x1003F,0x1004D), (0x10050,0x1005D), (0x10080,0x100FA),
    (0x10140,0x10174), (0x10280,0x1029C), (0x102A0,0x102D0), (0x10300,0x1031F), (0x1032D,0x1034A), (0x10350,0x10375), (0x10380,0x1039D), (0x103A0,0x103C3),
    (0x103C8,0x103CF), (0x103D1,0x103D5), (0x10400,0x1049D), (0x104B0,0x104D3), (0x104D8,0x104FB), (0x10500,0x10527), (0x10530,0x10563), (0x10570,0x1057A),
    (0x1057C,0x1058A), (0x1058C,0x10592), (0x10594,0x10595), (0x10597,0x105A1), (0x105A3,0x105B1), (0x105B3,0x105B9), (0x105BB,0x105BC), (0x10600,0x10736),
    (0x10740,0x10755), (0x10760,0x10767), (0x10780,0x10785), (0x10787,0x107B0), (0x107B2,0x107BA), (0x10800,0x10805), (0x10808,0x10808), (0x1080A,0x10835),
    (0x10837,0x10838), (0x1083C,0x1083C), (0x1083F,0x10855), (0x10860,0x10876), (0x10880,0x1089E), (0x108E0,0x108F2), (0x108F4,0x108F5), (0x10900,0x10915),
    (0x10920,0x10939), (0x10980,0x109B7), (0x109BE,0x109BF), (0x10A00,0x10A00), (0x10A10,0x10A13), (0x10A15,0x10A17), (0x10A19,0x10A35), (0x10A60,0x10A7C),
    (0x10A80,0x10A9C), (0x10AC0,0x10AC7), (0x10AC9,0x10AE4), (0x10B00,0x10B35), (0x10B40,0x10B55), (0x10B60,0x10B72), (0x10B80,0x10B91), (0x10C00,0x10C48),
    (0x10C80,0x10CB2), (0x10CC0,0x10CF2), (0x10D00,0x10D23), (0x10E80,0x10EA9), (0x10EB0,0x10EB1), (0x10F00,0x10F1C), (0x10F27,0x10F27), (0x10F30,0x10F45),
    (0x10F70,0x10F81), (0x10FB0,0x10FC4), (0x10FE0,0x10FF6), (0x11003,0x11037), (0x11071,0x11072), (0x11075,0x11075), (0x11083,0x110AF), (0x110D0,0x110E8),
    (0x11103,0x11126), (0x11144,0x11144), (0x11147,0x11147), (0x11150,0x11172), (0x11176,0x11176), (0x11183,0x111B2), (0x111C1,0x111C4), (0x111DA,0x111DA),
    (0x111DC,0x111DC), (0x11200,0x11211), (0x11213,0x1122B), (0x1123F,0x11240), (0x11280,0x11286), (0x11288,0x11288), (0x1128A,0x1128D), (0x1128F,0x1129D),
    (0x1129F,0x112A8), (0x112B0,0x112DE), (0x11305,0x1130C), (0x1130F,0x11310), (0x11313,0x11328), (0x1132A,0x11330), (0x11332,0x11333), (0x11335,0x11339),
    (0x1133D,0x1133D), (0x11350,0x11350), (0x1135D,0x11361), (0x11400,0x11434), (0x11447,0x1144A), (0x1145F,0x11461), (0x11480,0x114AF), (0x114C4,0x114C5),
    (0x114C7,0x114C7), (0x11580,0x115AE), (0x115D8,0x115DB), (0x11600,0x1162F), (0x11644,0x11644), (0x11680,0x116AA), (0x116B8,0x116B8), (0x11700,0x1171A),
    (0x11740,0x11746), (0x11800,0x1182B), (0x118A0,0x118DF), (0x118FF,0x11906), (0x11909,0x11909), (0x1190C,0x11913), (0x11915,0x11916), (0x11918,0x1192F),
    (0x1193F,0x1193F), (0x11941,0x11941), (0x119A0,0x119A7), (0x119AA,0x119D0), (0x119E1,0x119E1), (0x119E3,0x119E3), (0x11A00,0x11A00), (0x11A0B,0x11A32),
    (0x11A3A,0x11A3A), (0x11A50,0x11A50), (0x11A5C,0x11A89), (0x11A9D,0x11A9D), (0x11AB0,0x11AF8), (0x11C00,0x11C08), (0x11C0A,0x11C2E), (0x11C40,0x11C40),
    (0x11C72,0x11C8F), (0x11D00,0x11D06), (0x11D08,0x11D09), (0x11D0B,0x11D30), (0x11D46,0x11D46), (0x11D60,0x11D65), (0x11D67,0x11D68), (0x11D6A,0x11D89),
    (0x11D98,0x11D98), (0x11EE0,0x11EF2), (0x11F02,0x11F02), (0x11F04,0x11F10), (0x11F12,0x11F33), (0x11FB0,0x11FB0), (0x12000,0x12399), (0x12400,0x1246E),
    (0x12480,0x12543), (0x12F90,0x12FF0), (0x13000,0x1342F), (0x13441,0x13446), (0x14400,0x14646), (0x16800,0x16A38), (0x16A40,0x16A5E), (0x16A70,0x16ABE),
    (0x16AD0,0x16AED), (0x16B00,0x16B2F), (0x16B40,0x16B43), (0x16B63,0x16B77), (0x16B7D,0x16B8F), (0x16E40,0x16E7F), (0x16F00,0x16F4A), (0x16F50,0x16F50),
    (0x16F93,0x16F9F), (0x16FE0,0x16FE1), (0x16FE3,0x16FE3), (0x17000,0x187F7), (0x18800,0x18CD5), (0x18D00,0x18D08), (0x1AFF0,0x1AFF3), (0x1AFF5,0x1AFFB),
    (0x1AFFD,0x1AFFE), (0x1B000,0x1B122), (0x1B132,0x1B132), (0x1B150,0x1B152), (0x1B155,0x1B155), (0x1B164,0x1B167), (0x1B170,0x1B2FB), (0x1BC00,0x1BC6A),
    (0x1BC70,0x1BC7C), (0x1BC80,0x1BC88), (0x1BC90,0x1BC99), (0x1D400,0x1D454), (0x1D456,0x1D49C), (0x1D49E,0x1D49F), (0x1D4A2,0x1D4A2), (0x1D4A5,0x1D4A6),
    (0x1D4A9,0x1D4AC), (0x1D4AE,0x1D4B9), (0x1D4BB,0x1D4BB), (0x1D4BD,0x1D4C3), (0x1D4C5,0x1D505), (0x1D507,0x1D50A), (0x1D50D,0x1D514), (0x1D516,0x1D51C),
    (0x1D51E,0x1D539), (0x1D53B,0x1D53E), (0x1D540,0x1D544), (0x1D546,0x1D546), (0x1D54A,0x1D550), (0x1D552,0x1D6A5), (0x1D6A8,0x1D6C0), (0x1D6C2,0x1D6DA),
    (0x1D6DC,0x1D6FA), (0x1D6FC,0x1D714), (0x1D716,0x1D734), (0x1D736,0x1D74E), (0x1D750,0x1D76E), (0x1D770,0x1D788), (0x1D78A,0x1D7A8), (0x1D7AA,0x1D7C2),
    (0x1D7C4,0x1D7CB), (0x1DF00,0x1DF1E), (0x1DF25,0x1DF2A), (0x1E030,0x1E06D), (0x1E100,0x1E12C), (0x1E137,0x1E13D), (0x1E14E,0x1E14E), (0x1E290,0x1E2AD),
    (0x1E2C0,0x1E2EB), (0x1E4D0,0x1E4EB), (0x1E7E0,0x1E7E6), (0x1E7E8,0x1E7EB), (0x1E7ED,0x1E7EE), (0x1E7F0,0x1E7FE), (0x1E800,0x1E8C4), (0x1E900,0x1E943),
    (0x1E94B,0x1E94B), (0x1EE00,0x1EE03), (0x1EE05,0x1EE1F), (0x1EE21,0x1EE22), (0x1EE24,0x1EE24), (0x1EE27,0x1EE27), (0x1EE29,0x1EE32), (0x1EE34,0x1EE37),
    (0x1EE39,0x1EE39), (0x1EE3B,0x1EE3B), (0x1EE42,0x1EE42), (0x1EE47,0x1EE47), (0x1EE49,0x1EE49), (0x1EE4B,0x1EE4B), (0x1EE4D,0x1EE4F), (0x1EE51,0x1EE52),
    (0x1EE54,0x1EE54), (0x1EE57,0x1EE57), (0x1EE59,0x1EE59), (0x1EE5B,0x1EE5B), (0x1EE5D,0x1EE5D), (0x1EE5F,0x1EE5F), (0x1EE61,0x1EE62), (0x1EE64,0x1EE64),
    (0x1EE67,0x1EE6A), (0x1EE6C,0x1EE72), (0x1EE74,0x1EE77), (0x1EE79,0x1EE7C), (0x1EE7E,0x1EE7E), (0x1EE80,0x1EE89), (0x1EE8B,0x1EE9B), (0x1EEA1,0x1EEA3),
    (0x1EEA5,0x1EEA9), (0x1EEAB,0x1EEBB), (0x20000,0x2A6DF), (0x2A700,0x2B739), (0x2B740,0x2B81D), (0x2B820,0x2CEA1), (0x2CEB0,0x2EBE0), (0x2EBF0,0x2EE5D),
    (0x2F800,0x2FA1D), (0x30000,0x3134A), (0x31350,0x323AF),
)
_XID_CONTINUE_ONLY_RANGES = (
    (0x0030,0x0039), (0x005F,0x005F), (0x00B7,0x00B7), (0x0300,0x036F), (0x0387,0x0387), (0x0483,0x0487), (0x0591,0x05BD), (0x05BF,0x05BF),
    (0x05C1,0x05C2), (0x05C4,0x05C5), (0x05C7,0x05C7), (0x0610,0x061A), (0x064B,0x0669), (0x0670,0x0670), (0x06D6,0x06DC), (0x06DF,0x06E4),
    (0x06E7,0x06E8), (0x06EA,0x06ED), (0x06F0,0x06F9), (0x0711,0x0711), (0x0730,0x074A), (0x07A6,0x07B0), (0x07C0,0x07C9), (0x07EB,0x07F3),
    (0x07FD,0x07FD), (0x0816,0x0819), (0x081B,0x0823), (0x0825,0x0827), (0x0829,0x082D), (0x0859,0x085B), (0x0898,0x089F), (0x08CA,0x08E1),
    (0x08E3,0x0903), (0x093A,0x093C), (0x093E,0x094F), (0x0951,0x0957), (0x0962,0x0963), (0x0966,0x096F), (0x0981,0x0983), (0x09BC,0x09BC),
    (0x09BE,0x09C4), (0x09C7,0x09C8), (0x09CB,0x09CD), (0x09D7,0x09D7), (0x09E2,0x09E3), (0x09E6,0x09EF), (0x09FE,0x09FE), (0x0A01,0x0A03),
    (0x0A3C,0x0A3C), (0x0A3E,0x0A42), (0x0A47,0x0A48), (0x0A4B,0x0A4D), (0x0A51,0x0A51), (0x0A66,0x0A71), (0x0A75,0x0A75), (0x0A81,0x0A83),
    (0x0ABC,0x0ABC), (0x0ABE,0x0AC5), (0x0AC7,0x0AC9), (0x0ACB,0x0ACD), (0x0AE2,0x0AE3), (0x0AE6,0x0AEF), (0x0AFA,0x0AFF), (0x0B01,0x0B03),
    (0x0B3C,0x0B3C), (0x0B3E,0x0B44), (0x0B47,0x0B48), (0x0B4B,0x0B4D), (0x0B55,0x0B57), (0x0B62,0x0B63), (0x0B66,0x0B6F), (0x0B82,0x0B82),
    (0x0BBE,0x0BC2), (0x0BC6,0x0BC8), (0x0BCA,0x0BCD), (0x0BD7,0x0BD7), (0x0BE6,0x0BEF), (0x0C00,0x0C04), (0x0C3C,0x0C3C), (0x0C3E,0x0C44),
    (0x0C46,0x0C48), (0x0C4A,0x0C4D), (0x0C55,0x0C56), (0x0C62,0x0C63), (0x0C66,0x0C6F), (0x0C81,0x0C83), (0x0CBC,0x0CBC), (0x0CBE,0x0CC4),
    (0x0CC6,0x0CC8), (0x0CCA,0x0CCD), (0x0CD5,0x0CD6), (0x0CE2,0x0CE3), (0x0CE6,0x0CEF), (0x0CF3,0x0CF3), (0x0D00,0x0D03), (0x0D3B,0x0D3C),
    (0x0D3E,0x0D44), (0x0D46,0x0D48), (0x0D4A,0x0D4D), (0x0D57,0x0D57), (0x0D62,0x0D63), (0x0D66,0x0D6F), (0x0D81,0x0D83), (0x0DCA,0x0DCA),
    (0x0DCF,0x0DD4), (0x0DD6,0x0DD6), (0x0DD8,0x0DDF), (0x0DE6,0x0DEF), (0x0DF2,0x0DF3), (0x0E31,0x0E31), (0x0E33,0x0E3A), (0x0E47,0x0E4E),
    (0x0E50,0x0E59), (0x0EB1,0x0EB1), (0x0EB3,0x0EBC), (0x0EC8,0x0ECE), (0x0ED0,0x0ED9), (0x0F18,0x0F19), (0x0F20,0x0F29), (0x0F35,0x0F35),
    (0x0F37,0x0F37), (0x0F39,0x0F39), (0x0F3E,0x0F3F), (0x0F71,0x0F84), (0x0F86,0x0F87), (0x0F8D,0x0F97), (0x0F99,0x0FBC), (0x0FC6,0x0FC6),
    (0x102B,0x103E), (0x1040,0x1049), (0x1056,0x1059), (0x105E,0x1060), (0x1062,0x1064), (0x1067,0x106D), (0x1071,0x1074), (0x1082,0x108D),
    (0x108F,0x109D), (0x135D,0x135F), (0x1369,0x1371), (0x1712,0x1715), (0x1732,0x1734), (0x1752,0x1753), (0x1772,0x1773), (0x17B4,0x17D3),
    (0x17DD,0x17DD), (0x17E0,0x17E9), (0x180B,0x180D), (0x180F,0x1819), (0x18A9,0x18A9), (0x1920,0x192B), (0x1930,0x193B), (0x1946,0x194F),
    (0x19D0,0x19DA), (0x1A17,0x1A1B), (0x1A55,0x1A5E), (0x1A60,0x1A7C), (0x1A7F,0x1A89), (0x1A90,0x1A99), (0x1AB0,0x1ABD), (0x1ABF,0x1ACE),
    (0x1B00,0x1B04), (0x1B34,0x1B44), (0x1B50,0x1B59), (0x1B6B,0x1B73), (0x1B80,0x1B82), (0x1BA1,0x1BAD), (0x1BB0,0x1BB9), (0x1BE6,0x1BF3),
    (0x1C24,0x1C37), (0x1C40,0x1C49), (0x1C50,0x1C59), (0x1CD0,0x1CD2), (0x1CD4,0x1CE8), (0x1CED,0x1CED), (0x1CF4,0x1CF4), (0x1CF7,0x1CF9),
    (0x1DC0,0x1DFF), (0x200C,0x200D), (0x203F,0x2040), (0x2054,0x2054), (0x20D0,0x20DC), (0x20E1,0x20E1), (0x20E5,0x20F0), (0x2CEF,0x2CF1),
    (0x2D7F,0x2D7F), (0x2DE0,0x2DFF), (0x302A,0x302F), (0x3099,0x309A), (0x30FB,0x30FB), (0xA620,0xA629), (0xA66F,0xA66F), (0xA674,0xA67D),
    (0xA69E,0xA69F), (0xA6F0,0xA6F1), (0xA802,0xA802), (0xA806,0xA806), (0xA80B,0xA80B), (0xA823,0xA827), (0xA82C,0xA82C), (0xA880,0xA881),
    (0xA8B4,0xA8C5), (0xA8D0,0xA8D9), (0xA8E0,0xA8F1), (0xA8FF,0xA909), (0xA926,0xA92D), (0xA947,0xA953), (0xA980,0xA983), (0xA9B3,0xA9C0),
    (0xA9D0,0xA9D9), (0xA9E5,0xA9E5), (0xA9F0,0xA9F9), (0xAA29,0xAA36), (0xAA43,0xAA43), (0xAA4C,0xAA4D), (0xAA50,0xAA59), (0xAA7B,0xAA7D),
    (0xAAB0,0xAAB0), (0xAAB2,0xAAB4), (0xAAB7,0xAAB8), (0xAABE,0xAABF), (0xAAC1,0xAAC1), (0xAAEB,0xAAEF), (0xAAF5,0xAAF6), (0xABE3,0xABEA),
    (0xABEC,0xABED), (0xABF0,0xABF9), (0xFB1E,0xFB1E), (0xFE00,0xFE0F), (0xFE20,0xFE2F), (0xFE33,0xFE34), (0xFE4D,0xFE4F), (0xFF10,0xFF19),
    (0xFF3F,0xFF3F), (0xFF65,0xFF65), (0xFF9E,0xFF9F), (0x101FD,0x101FD), (0x102E0,0x102E0), (0x10376,0x1037A), (0x104A0,0x104A9), (0x10A01,0x10A03),
    (0x10A05,0x10A06), (0x10A0C,0x10A0F), (0x10A38,0x10A3A), (0x10A3F,0x10A3F), (0x10AE5,0x10AE6), (0x10D24,0x10D27), (0x10D30,0x10D39), (0x10EAB,0x10EAC),
    (0x10EFD,0x10EFF), (0x10F46,0x10F50), (0x10F82,0x10F85), (0x11000,0x11002), (0x11038,0x11046), (0x11066,0x11070), (0x11073,0x11074), (0x1107F,0x11082),
    (0x110B0,0x110BA), (0x110C2,0x110C2), (0x110F0,0x110F9), (0x11100,0x11102), (0x11127,0x11134), (0x11136,0x1113F), (0x11145,0x11146), (0x11173,0x11173),
    (0x11180,0x11182), (0x111B3,0x111C0), (0x111C9,0x111CC), (0x111CE,0x111D9), (0x1122C,0x11237), (0x1123E,0x1123E), (0x11241,0x11241), (0x112DF,0x112EA),
    (0x112F0,0x112F9), (0x11300,0x11303), (0x1133B,0x1133C), (0x1133E,0x11344), (0x11347,0x11348), (0x1134B,0x1134D), (0x11357,0x11357), (0x11362,0x11363),
    (0x11366,0x1136C), (0x11370,0x11374), (0x11435,0x11446), (0x11450,0x11459), (0x1145E,0x1145E), (0x114B0,0x114C3), (0x114D0,0x114D9), (0x115AF,0x115B5),
    (0x115B8,0x115C0), (0x115DC,0x115DD), (0x11630,0x11640), (0x11650,0x11659), (0x116AB,0x116B7), (0x116C0,0x116C9), (0x1171D,0x1172B), (0x11730,0x11739),
    (0x1182C,0x1183A), (0x118E0,0x118E9), (0x11930,0x11935), (0x11937,0x11938), (0x1193B,0x1193E), (0x11940,0x11940), (0x11942,0x11943), (0x11950,0x11959),
    (0x119D1,0x119D7), (0x119DA,0x119E0), (0x119E4,0x119E4), (0x11A01,0x11A0A), (0x11A33,0x11A39), (0x11A3B,0x11A3E), (0x11A47,0x11A47), (0x11A51,0x11A5B),
    (0x11A8A,0x11A99), (0x11C2F,0x11C36), (0x11C38,0x11C3F), (0x11C50,0x11C59), (0x11C92,0x11CA7), (0x11CA9,0x11CB6), (0x11D31,0x11D36), (0x11D3A,0x11D3A),
    (0x11D3C,0x11D3D), (0x11D3F,0x11D45), (0x11D47,0x11D47), (0x11D50,0x11D59), (0x11D8A,0x11D8E), (0x11D90,0x11D91), (0x11D93,0x11D97), (0x11DA0,0x11DA9),
    (0x11EF3,0x11EF6), (0x11F00,0x11F01), (0x11F03,0x11F03), (0x11F34,0x11F3A), (0x11F3E,0x11F42), (0x11F50,0x11F59), (0x13440,0x13440), (0x13447,0x13455),
    (0x16A60,0x16A69), (0x16AC0,0x16AC9), (0x16AF0,0x16AF4), (0x16B30,0x16B36), (0x16B50,0x16B59), (0x16F4F,0x16F4F), (0x16F51,0x16F87), (0x16F8F,0x16F92),
    (0x16FE4,0x16FE4), (0x16FF0,0x16FF1), (0x1BC9D,0x1BC9E), (0x1CF00,0x1CF2D), (0x1CF30,0x1CF46), (0x1D165,0x1D169), (0x1D16D,0x1D172), (0x1D17B,0x1D182),
    (0x1D185,0x1D18B), (0x1D1AA,0x1D1AD), (0x1D242,0x1D244), (0x1D7CE,0x1D7FF), (0x1DA00,0x1DA36), (0x1DA3B,0x1DA6C), (0x1DA75,0x1DA75), (0x1DA84,0x1DA84),
    (0x1DA9B,0x1DA9F), (0x1DAA1,0x1DAAF), (0x1E000,0x1E006), (0x1E008,0x1E018), (0x1E01B,0x1E021), (0x1E023,0x1E024), (0x1E026,0x1E02A), (0x1E08F,0x1E08F),
    (0x1E130,0x1E136), (0x1E140,0x1E149), (0x1E2AE,0x1E2AE), (0x1E2EC,0x1E2F9), (0x1E4EC,0x1E4F9), (0x1E8D0,0x1E8D6), (0x1E944,0x1E94A), (0x1E950,0x1E959),
    (0x1FBF0,0x1FBF9), (0xE0100,0xE01EF),
)
_XID_RANGES = tuple(sorted(_XID_START_RANGES + _XID_CONTINUE_ONLY_RANGES))
_XID_RANGE_STARTS = tuple(r[0] for r in _XID_RANGES)


def _is_xid_continue(ch: str) -> bool:
    cp = ord(ch)
    i = bisect.bisect_right(_XID_RANGE_STARTS, cp) - 1
    return i >= 0 and cp <= _XID_RANGES[i][1]


def _check_str(name: str, value) -> None:
    if not isinstance(value, str):
        raise TypeError(f'{name} must be str, got {type(value).__name__}')


def _strip_path(raw: str) -> str:
    return raw.rsplit('/', 1)[-1]


def make_name_valid(name: str) -> str:
    _check_str('name', name)
    if name == 'bool':
        return 'Bool'
    if name == 'NULL':
        return 'NULLL'
    if not name:
        return ''
    if name[0] in '0123456789':
        name = _DIGIT_WORDS[ord(name[0]) - ord('0')] + name[1:]
    return ''.join(ch if _is_xid_continue(ch) else '_' for ch in name)


def mangle_exec(class_cpp: str, function_valid: str) -> str:
    _check_str('class_cpp', class_cpp)
    _check_str('function_valid', function_valid)
    class_len = len(class_cpp.encode('utf-8'))
    func_len = len(function_valid.encode('utf-8'))
    return f'_ZN{class_len}{class_cpp}{func_len + 4}exec{function_valid}Ev'


def _text(s: str) -> str:
    return _LONE_SURROGATE_RE.sub(chr(0xFFFD), s)


def _digest(text: str) -> str:
    """SHA-256 hex of `text` encoded UTF-8 with surrogatepass (R8's `C` and `T` records)."""
    return hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()


def _type_key(name: str) -> int:
    """The netnode index of type `name`'s `T` record."""
    return int.from_bytes(hashlib.sha256(name.encode('utf-8', 'surrogatepass')).digest()[:8], 'little') >> 1


# --- F8 records (nylib/ue/model.py), validated as model.from_json does ---

_PROPERTY_KINDS = (
    'ByteProperty', 'Int8Property', 'Int16Property', 'IntProperty', 'Int64Property',
    'UInt16Property', 'UInt32Property', 'UInt64Property', 'FloatProperty', 'DoubleProperty',
    'BoolProperty', 'EnumProperty', 'NameProperty', 'StrProperty', 'TextProperty',
    'Utf8StrProperty', 'AnsiStrProperty',
    'ObjectProperty', 'WeakObjectProperty', 'LazyObjectProperty', 'SoftObjectProperty',
    'InterfaceProperty', 'ClassProperty', 'SoftClassProperty',
    'StructProperty', 'ArrayProperty', 'SetProperty', 'MapProperty', 'OptionalProperty',
    'DelegateProperty', 'MulticastInlineDelegateProperty', 'MulticastSparseDelegateProperty',
    'FieldPathProperty',
)
_KIND_KEYS = {
    'ByteProperty': ('enum',), 'BoolProperty': ('field_size', 'byte_offset', 'byte_mask', 'field_mask'),
    'EnumProperty': ('enum', 'underlying'), 'ObjectProperty': ('class',), 'WeakObjectProperty': ('class',),
    'LazyObjectProperty': ('class',), 'SoftObjectProperty': ('class',), 'InterfaceProperty': ('class',),
    'ClassProperty': ('class', 'meta_class'), 'SoftClassProperty': ('class', 'meta_class'),
    'StructProperty': ('struct',), 'ArrayProperty': ('inner',), 'SetProperty': ('element',),
    'OptionalProperty': ('value',), 'MapProperty': ('key', 'value'), 'DelegateProperty': ('signature',),
    'MulticastInlineDelegateProperty': ('signature',), 'MulticastSparseDelegateProperty': ('signature',),
    'FieldPathProperty': ('field_class',),
}
_NESTED_KEYS = ('underlying', 'inner', 'element', 'key', 'value')
_INT_KEYS = ('field_size', 'byte_offset', 'byte_mask', 'field_mask')
_ENUM_SIZE_SOURCES = ('reflection', 'property', 'max_value')


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _req(d: dict, key: str, typ, nullable: bool = False):
    if key not in d:
        raise _Bad(f'missing key {key!r}')
    v = d[key]
    if v is None and nullable:
        return None
    if not (_is_int(v) if typ is int else isinstance(v, typ)):
        raise _Bad(f'key {key!r} must be a {typ.__name__}' + (' or null' if nullable else ''))
    return v


def _unhex(text) -> int:
    if not isinstance(text, str) or not _HEX_RE.fullmatch(text):
        raise _Bad(f'invalid hex literal {text!r}')
    return int(text, 16)


def _hexkey(d: dict, key: str) -> int:
    return _unhex(_req(d, key, str))


def _ptype(d) -> dict:
    if not isinstance(d, dict):
        raise _Bad(f'PropType data must be a dict, got {type(d).__name__}')
    prop = d.get('prop')
    if not isinstance(prop, str):
        raise _Bad("missing key 'prop'")
    if 'kind' in d:
        kind = d['kind']
        if kind not in _PROPERTY_KINDS and kind != 'unknown':
            raise _Bad(f'invalid PropType kind {kind!r}')
    elif d.get('unknown') is True:
        kind = 'unknown'
    else:
        kind = prop if prop in _PROPERTY_KINDS else 'unknown'
    t = {'prop': prop, 'kind': kind}
    for key in _KIND_KEYS.get(kind, ()):
        raw = d.get(key)
        if key in _NESTED_KEYS:
            if raw is not None and not isinstance(raw, dict):
                raise _Bad(f'key {key!r} must be a dict or null')
            t[key] = _ptype(raw) if raw is not None else None
        elif key in _INT_KEYS:
            if raw is not None and not _is_int(raw):
                raise _Bad(f'key {key!r} must be an int or null')
            t[key] = raw
        else:
            if raw is not None and not isinstance(raw, str):
                raise _Bad(f'key {key!r} must be a str or null')
            t[key] = raw
    return t


def _prop(d) -> dict:
    if not isinstance(d, dict):
        raise _Bad(f'PropertyRecord data must be a dict, got {type(d).__name__}')
    return {'name': _req(d, 'name', str), 'offset': _hexkey(d, 'offset'), 'size': _hexkey(d, 'size'),
            'array_dim': _req(d, 'array_dim', int), 'flags': _hexkey(d, 'flags'), 'type': _ptype(_req(d, 'type', dict))}


def _function(d, path: str, name: str, package: str) -> dict:
    if not isinstance(d, dict):
        raise _Bad(f'FunctionRecord data must be a dict, got {type(d).__name__}')
    params = _req(d, 'params', list)
    exec_rva = _req(d, 'exec_rva', str, nullable=True)
    return {'kind': 'function', 'path': path, 'name': name, 'package': package, 'flags': _hexkey(d, 'flags'),
            'params_size': _hexkey(d, 'params_size'), 'params': [_prop(p) for p in params],
            'exec_rva': _unhex(exec_rva) if exec_rva is not None else None}


def _record(d) -> dict:
    if not isinstance(d, dict):
        raise _Bad(f'type data must be a dict, got {type(d).__name__}')
    kind = d.get('kind')
    if kind in ('class', 'struct'):
        path = _req(d, 'path', str)
        package = _req(d, 'package', str)
        rec = {'kind': kind, 'path': path, 'name': _req(d, 'name', str), 'cpp_name': _req(d, 'cpp_name', str),
               'package': package, 'super': _req(d, 'super', str, nullable=True), 'size': _hexkey(d, 'size'),
               'min_alignment': _req(d, 'min_alignment', int),
               'properties': [_prop(p) for p in _req(d, 'properties', list)], 'functions': {}}
        if kind == 'class':
            rec['cast_flags'] = _hexkey(d, 'cast_flags')
            rec['cdo'] = _req(d, 'cdo', str, nullable=True)
            for i in _req(d, 'interfaces', list):
                if not isinstance(i, dict):
                    raise _Bad('InterfaceRecord data must be a dict')
                _req(i, 'class', str), _hexkey(i, 'pointer_offset'), _req(i, 'implemented_by_k2', bool)
            rec['functions'] = {fname: _function(fd, f'{path}:{fname}', fname, package)
                                for fname, fd in _req(d, 'functions', dict).items()}
        return rec
    if kind == 'enum':
        values = []
        for item in _req(d, 'values', list):
            if not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str) or not _is_int(item[1]):
                raise _Bad(f'invalid enum value entry {item!r}')
            values.append((item[0], item[1]))
        rec = {'kind': 'enum', 'path': _req(d, 'path', str), 'name': _req(d, 'name', str),
               'cpp_name': _req(d, 'cpp_name', str), 'package': _req(d, 'package', str),
               'underlying_size': _req(d, 'underlying_size', int),
               'underlying_size_from': _req(d, 'underlying_size_from', str),
               'underlying_signed': _req(d, 'underlying_signed', bool, nullable=True), 'values': values}
        if rec['underlying_size'] not in (1, 2, 4, 8):
            raise _Bad(f"invalid underlying_size {rec['underlying_size']!r}")
        if rec['underlying_size_from'] not in _ENUM_SIZE_SOURCES:
            raise _Bad(f"invalid underlying_size_from {rec['underlying_size_from']!r}")
        return rec
    if kind == 'function':
        return _function(d, _req(d, 'path', str), _req(d, 'name', str), _req(d, 'package', str))
    raise _Bad(f'unknown kind {kind!r}')


# --- the 2A folder (S1, nylib/ue/snapshot.py) ---

_I, _A, _F, _C, _O, _N, _V = range(7)  # object row fields: index, address, flags, class, outer, name, vtable rva


class _Objects:
    """ObjectTable of nylib/ue/model.py: paths, packages and class lookups over objects.jsonl rows."""

    def __init__(self, rows: list):
        self.by_index = {r[_I]: r for r in rows}
        self.order = [r[_I] for r in rows]
        self._paths = {}
        self._index_of_path = None
        self._package_class = next((r[_I] for r in rows if r[_N] == 'Package' and (o := self.by_index.get(r[_O])) is not None
                                    and o[_N] == '/Script/CoreUObject'), -1)

    def get(self, index: int):
        return self.by_index.get(index)

    def is_package(self, index: int) -> bool:
        rec = self.by_index[index]
        if self._package_class != -1:
            return rec[_C] == self._package_class
        return self.by_index.get(rec[_O]) is None

    def _chain(self, index: int) -> list:
        chain = [index]
        seen = {index}
        current = index
        while (outer := self.by_index.get(self.by_index[current][_O])) is not None:
            if outer[_I] in seen or len(chain) >= 257:
                raise ValueError(f'outer chain of object {index} is cyclic or longer than 256')
            chain.append(outer[_I])
            seen.add(outer[_I])
            current = outer[_I]
        return chain

    def path(self, index: int) -> str:
        if index in self._paths:
            return self._paths[index]
        chain = self._chain(index)
        cache_pos = next((pos for pos in range(1, len(chain)) if chain[pos] in self._paths), None)
        if cache_pos is not None:
            result = self._paths[chain[cache_pos]]
            start = cache_pos - 1
        else:
            result = self.by_index[chain[-1]][_N]
            self._paths[chain[-1]] = result
            start = len(chain) - 2
        for pos in range(start, -1, -1):
            outer_idx = chain[pos + 1]
            oo = self.by_index.get(self.by_index[outer_idx][_O])
            sep = ':' if (not self.is_package(outer_idx) and oo is not None and self.is_package(oo[_I])) else '.'
            result = f'{result}{sep}{self.by_index[chain[pos]][_N]}'
            self._paths[chain[pos]] = result
        return result

    def index_of_path(self, path: str):
        if self._index_of_path is None:
            mapping = {}
            for idx in self.order:
                try:
                    p = self.path(idx)
                except ValueError:
                    continue
                mapping.setdefault(p, idx)
            self._index_of_path = mapping
        return self._index_of_path.get(path)


def _read_text(path: str, folder, missing: str) -> str:
    if not os.path.isfile(path):
        raise SnapshotFormatError(folder, missing)
    with open(path, 'rb') as f:
        data = f.read()
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        raise SnapshotFormatError(folder, f'{os.path.basename(path)} is not valid utf-8') from None


def _loads(text: str, folder, label: str):
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        raise SnapshotFormatError(folder, f'{label} is not valid json') from None


def _check_schema(doc, folder, name: str, label: str):
    if not isinstance(doc, dict):
        raise SnapshotFormatError(folder, f'{label} is not a json object')
    schema = doc.get('schema')
    if not isinstance(schema, dict) or schema.get('name') != name:
        raise SnapshotFormatError(folder, f'{label}.schema is missing or invalid')


def _jsonl_lines(text: str, folder, label: str) -> list:
    if not text.endswith('\n'):
        raise SnapshotFormatError(folder, f'{label} does not end with a newline')
    lines = text.split('\n')[:-1]
    for n, line in enumerate(lines, 1):
        if line == '':
            raise SnapshotFormatError(folder, f'{label} line {n} is empty')
    return lines


def _load_meta(folder, folder_str: str) -> dict:
    meta_path = os.path.join(folder_str, 'meta.json')
    meta = _loads(_read_text(meta_path, folder, 'not a completed snapshot'), folder, 'meta.json')
    _check_schema(meta, folder, SCHEMA_NAME, 'meta.json')
    version = meta['schema'].get('version')
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise SnapshotFormatError(folder, 'meta.json.schema.version is missing or invalid')
    try:
        major = int(version.split('.', 1)[0])
    except ValueError:
        raise SnapshotFormatError(folder, 'meta.json.schema.version is missing or invalid') from None
    if major != SCHEMA_MAJOR:
        generator = meta.get('generator')
        writer = generator.get('version') if isinstance(generator, dict) else None
        writer = writer if isinstance(writer, str) else 'unknown'
        raise SnapshotFormatError(folder, f'{meta_path} has schema {version}; this importer understands {SCHEMA_MAJOR}.x. '
                                          f'Use the ue_dumper_import.py of the nylib.ue version that wrote it ({writer}).')
    return meta


def _load_objects(folder, folder_str: str) -> _Objects:
    lines = _jsonl_lines(_read_text(os.path.join(folder_str, 'objects.jsonl'), folder, 'missing objects.jsonl'),
                         folder, 'objects.jsonl')
    if not lines:
        raise SnapshotFormatError(folder, 'objects.jsonl has no header')
    _check_schema(_loads(lines[0], folder, 'objects.jsonl header'), folder, _OBJECTS_SCHEMA, 'objects.jsonl')
    rows = []
    prev = -1
    for n, line in enumerate(lines[1:], 2):
        row = _loads(line, folder, f'objects.jsonl line {n}')
        try:
            if not isinstance(row, list) or len(row) not in (6, 7):
                raise _Bad('invalid object row')
            index, address, flags, cls, outer, name = row[:6]
            if not (_is_int(index) and _is_int(cls) and _is_int(outer) and isinstance(name, str)):
                raise _Bad('invalid object row')
            rec = (index, _unhex(address), _unhex(flags), cls, outer, name, _unhex(row[6]) if len(row) == 7 else None)
        except _Bad as e:
            raise SnapshotFormatError(folder, f'objects.jsonl line {n}: {e}') from None
        if not 0 <= rec[_A] < _ADDRESS_LIMIT:
            raise SnapshotFormatError(folder, f'objects.jsonl line {n}: address out of range')
        if index <= prev:
            raise SnapshotFormatError(folder, f'objects.jsonl line {n}: index {index} does not increase past {prev}')
        prev = index
        rows.append(rec)
    return _Objects(rows)


def _load_index(folder, folder_str: str):
    jsonl_path = os.path.join(folder_str, 'types.jsonl')
    if not os.path.isfile(jsonl_path):
        raise SnapshotFormatError(folder, 'missing types.jsonl')
    size = os.path.getsize(jsonl_path)
    doc = _loads(_read_text(os.path.join(folder_str, 'types.idx.json'), folder, 'missing types.idx.json'),
                 folder, 'types.idx.json')
    if not isinstance(doc, dict):
        raise SnapshotFormatError(folder, 'types.idx.json is not a json object')
    idx = {}
    for key, value in doc.items():
        if (not isinstance(value, list) or len(value) != 2 or not _is_int(value[0]) or not _is_int(value[1])
                or value[0] < 0 or value[1] < 1 or value[0] + value[1] + 1 > size):
            raise SnapshotFormatError(folder, f'types.idx.json: invalid entry for {key!r}')
        idx[key] = (value[0], value[1])
    return idx, jsonl_path


class SnapshotView:
    """A completed snapshot: meta, offsets and objects in memory; types read through types.idx.json on demand."""

    def __init__(self, folder, meta: dict, offsets: dict, objects: _Objects, idx: dict, types_path: str):
        self.folder = folder
        self.meta = meta
        self.offsets = offsets
        self.objects = objects
        self._idx = idx
        self._file = open(types_path, 'rb')
        self._cache = collections.OrderedDict()
        self._closed = False

    def _check(self):
        if self._closed:
            raise ValueError('snapshot is closed')

    def close(self) -> None:
        if not self._closed:
            self._file.close()
            self._cache.clear()
            self._closed = True

    def __enter__(self) -> 'SnapshotView':
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def paths(self) -> list:
        self._check()
        return list(self._idx)

    def _exact(self, path: str):
        if path in self._cache:
            self._cache.move_to_end(path)
            return self._cache[path]
        entry = self._idx.get(path)
        if entry is None:
            return None
        self._file.seek(entry[0])
        data = self._file.read(entry[1])
        try:
            d = json.loads(data.decode('utf-8'))
            if not isinstance(d, dict):
                raise _Bad('not a json object')
            if d.get('path') != path:
                raise _Bad(f"index entry points at {d.get('path')!r}")
            rec = _record(d)
        except (_Bad, ValueError, RecursionError) as e:
            raise SnapshotFormatError(self.folder, f'types.jsonl: type {path!r}: {e}') from None
        self._cache[path] = rec
        if len(self._cache) > _CACHE_SIZE:
            self._cache.popitem(last=False)
        return rec

    def type(self, path: str):
        """The type record at `path` (a class function as `Class:Func`), or None."""
        self._check()
        rec = self._exact(path)
        i = path.find(':') if rec is None else -1
        while i >= 0:
            cls = self._exact(path[:i])
            if cls is not None and cls['kind'] == 'class' and (fn := cls['functions'].get(path[i + 1:])) is not None:
                return fn
            i = path.find(':', i + 1)
        return rec

    def type_of_object(self, index: int):
        self._check()
        try:
            p = self.objects.path(index)
        except ValueError:
            return None
        return self.type(p)

    def scan(self):
        """Yield (path, raw json dict) for every types.jsonl line in file order."""
        self._check()
        self._file.seek(0)
        for n, line in enumerate(self._file, 1):
            try:
                d = json.loads(line.decode('utf-8'))
            except (ValueError, RecursionError):
                raise SnapshotFormatError(self.folder, f'types.jsonl line {n} is not valid json') from None
            if not isinstance(d, dict) or not isinstance(d.get('path'), str):
                raise SnapshotFormatError(self.folder, f'types.jsonl line {n}: missing key \'path\'')
            yield d['path'], d


def load_snapshot(folder) -> SnapshotView:
    """Open a completed 2A snapshot folder; raises SnapshotFormatError for anything else (OSError propagates)."""
    if not isinstance(folder, (str, os.PathLike)):
        raise TypeError(f'folder must be str or os.PathLike, got {type(folder).__name__}')
    folder_str = os.fspath(folder)
    if os.path.basename(os.path.normpath(folder_str)).rstrip('. ').lower().endswith('.partial'):
        raise SnapshotFormatError(folder, 'not a completed snapshot')
    meta = _load_meta(folder, folder_str)
    offsets = _loads(_read_text(os.path.join(folder_str, 'offsets.json'), folder, 'missing offsets.json'),
                     folder, 'offsets.json')
    _check_schema(offsets, folder, _OFFSETS_SCHEMA, 'offsets.json')
    objects = _load_objects(folder, folder_str)
    idx, types_path = _load_index(folder, folder_str)
    return SnapshotView(folder, meta, offsets, objects, idx, types_path)


# --- names (S2: idmap V1, nylib/ue/exports/idmap.py) ---

def _cdo_record(view: SnapshotView, o):
    objs = view.objects
    class_obj = objs.get(o[_C])
    class_rec = view.type_of_object(class_obj[_I]) if class_obj is not None else None
    if class_rec is None or class_rec['kind'] != 'class' or o[_V] is None:
        return None
    super_rec = view.type(class_rec['super']) if class_rec['super'] is not None else None
    super_cdo = None
    if super_rec is not None and super_rec['kind'] == 'class' and super_rec['cdo'] is not None:
        super_cdo = objs.index_of_path(super_rec['cdo'])
    super_vtable = objs.by_index[super_cdo][_V] if super_cdo is not None else None
    if super_rec is not None and super_vtable is not None and super_vtable == o[_V]:
        return None
    return o[_V] & 0xFFFFFFFF, class_rec['cpp_name'] + '_VFT', class_rec


def _walk_idmap(view: SnapshotView, dups: 'dict | None' = None):
    """Yield (rva, name, function or None, class record) in idmap order; skipped duplicate execs go to `dups`."""
    seen = set()
    for i in view.objects.order:
        o = view.objects.by_index[i]
        if o[_F] & _RF_CLASS_DEFAULT_OBJECT:
            if (r := _cdo_record(view, o)) is not None:
                yield r[0], r[1], None, r[2]
            continue
        rec = view.type_of_object(i)
        if rec is None or rec['kind'] != 'class':
            continue
        for fn in rec['functions'].values():
            if not fn['flags'] & _FUNC_NATIVE or fn['exec_rva'] is None:
                continue
            rva = fn['exec_rva'] & 0xFFFFFFFF
            name = mangle_exec(rec['cpp_name'], make_name_valid(_strip_path(fn['name'])))
            if rva in seen:
                if dups is not None:
                    dups.setdefault(rva, []).append((name, fn, rec))
                continue
            seen.add(rva)
            yield rva, name, fn, rec


def name_records(view: SnapshotView) -> list:
    """The idmap V1 records of the snapshot, in order, duplicates kept."""
    view._check()
    return [(rva, name) for rva, name, _fn, _cls in _walk_idmap(view)]


def global_records(view: SnapshotView) -> dict:
    """{global: rva} for the five globals whose meta.json rva is a 0x hex string."""
    view._check()
    g = view.meta.get('globals')
    out = {}
    if isinstance(g, dict):
        for name in _GLOBALS:
            rva = g[name].get('rva') if isinstance(g.get(name), dict) else None
            if isinstance(rva, str) and _UHEX_RE.fullmatch(rva):
                out[name] = int(rva, 16)
    return out


# --- C8.6 offsets.json keys and the R6 core members ---

# One row per C8.6 key: the stage-4 E3 key and its path in offsets.json (P5 O5, Q28 = A: the path is the key split at '.').
_OFFSET_KEY_PATHS = {k: tuple(k.split('.')) for k in (
    'Off.UObject.Vft', 'Off.UObject.Flags', 'Off.UObject.Index', 'Off.UObject.Class', 'Off.UObject.Name', 'Off.UObject.Outer',
    'Off.UField.Next',
    'Off.UStruct.SuperStruct', 'Off.UStruct.Children', 'Off.UStruct.ChildProperties', 'Off.UStruct.Size', 'Off.UStruct.MinAlignment',
    'Off.UClass.CastFlags', 'Off.UClass.ClassDefaultObject',
    'Off.UFunction.FunctionFlags', 'Off.UFunction.ExecFunction',
    'Off.UEnum.Names',
    'Off.FName.CompIdx', 'Off.FName.Number', 'Off.InSDK.Name.FNameSize',
    'Off.FField.Vft', 'Off.FField.Class', 'Off.FField.Owner', 'Off.FField.Next', 'Off.FField.Name', 'Off.FField.Flags',
    'Off.Property.ArrayDim', 'Off.Property.ElementSize', 'Off.Property.PropertyFlags', 'Off.Property.Offset_Internal',
    'Off.InSDK.Properties.PropertySize',
    'Off.ByteProperty.Enum', 'Off.BoolProperty.Base', 'Off.ObjectProperty.PropertyClass', 'Off.ClassProperty.MetaClass',
    'Off.StructProperty.Struct', 'Off.ArrayProperty.Inner', 'Off.DelegateProperty.SignatureFunction', 'Off.MapProperty.Base',
    'Off.SetProperty.ElementProp', 'Off.EnumProperty.Base', 'Off.FieldPathProperty.FieldClass',
    'Off.OptionalProperty.ValueProperty',
    'Off.FUObjectArray.FixedLayout', 'Off.FUObjectArray.ChunkedFixedLayout', 'Off.FUObjectArray.bIsChunked',
    'Off.InSDK.ObjArray.FUObjectItemSize', 'Off.InSDK.ObjArray.FUObjectItemInitialOffset',
    'Off.InSDK.Text.TextSize',
    'Off.FFieldClass.Name', 'Off.FFieldClass.Id', 'Off.FFieldClass.CastFlags', 'Off.FFieldClass.ClassFlags',
    'Off.FFieldClass.SuperClass',
    'Settings.Internal.bUseFProperty', 'Settings.Internal.bUseMaskForFieldOwner', 'Settings.Internal.bUseOutlineNumberName',
    'Settings.Internal.bUseCasePreservingName', 'Settings.Internal.bUseNamePool', 'PropertySizes.FieldPathProperty',
)}


class _Missing(Exception):
    pass


class _Keys:
    def __init__(self, offsets: dict):
        self.offsets = offsets
        self.missing = []

    def _raw(self, key: str):
        node = self.offsets
        for part in _OFFSET_KEY_PATHS[key]:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def _miss(self, key: str):
        if key not in self.missing:
            self.missing.append(key)
        raise _Missing(key)

    def i(self, key: str) -> int:
        v = self._raw(key)
        if _is_int(v):
            return v
        if isinstance(v, str) and _HEX_RE.fullmatch(v):
            return int(v, 16)
        self._miss(key)

    def b(self, key: str) -> bool:
        v = self._raw(key)
        if isinstance(v, bool):
            return v
        self._miss(key)

    def layout(self, key: str, fields: tuple) -> dict:
        v = self._raw(key)
        if isinstance(v, dict) and all(isinstance(v.get(f), str) and _HEX_RE.fullmatch(v[f]) for f in fields):
            return {f: int(v[f], 16) for f in fields}
        self._miss(key)


def _i(n: int, signed: bool = True):
    return ('int', n, signed)


def _named(name: str):
    return ('named', name)


def _ptr(name: 'str | None' = None):
    return ('ptr', ('void',) if name is None else ('named', name))


_CORE_BASES = {'UField': 'UObject', 'UStruct': 'UField', 'UClass': 'UStruct', 'UFunction': 'UStruct', 'UEnum': 'UField',
               'FProperty': 'FField', 'FClassProperty': 'FObjectPropertyBase'}
_REFLECTED_CORE = ('UObject', 'UField', 'UStruct', 'UClass', 'UFunction', 'UEnum')
_PROPERTY_TYPES = ('FByteProperty', 'FBoolProperty', 'FObjectPropertyBase', 'FClassProperty', 'FStructProperty',
                   'FArrayProperty', 'FDelegateProperty', 'FMapProperty', 'FSetProperty', 'FEnumProperty',
                   'FFieldPathProperty', 'FOptionalProperty')
_PAIR_NAME = 'TPair<FName, int64>'


def _core_layout(offsets: dict):
    """R6: (members [(type, member, offset, size, spec)], type sizes {type: size or None}, missing keys)."""
    k = _Keys(offsets)
    rows = []

    def add(t, m, off, size, spec):
        try:
            rows.append((t, m, off(), size() if callable(size) else size, spec))
        except _Missing:
            pass

    def flag(key):
        try:
            return k.b(key)
        except _Missing:
            return None

    fname = lambda: k.i('Off.InSDK.Name.FNameSize')
    for m, key, size, spec in (('VTable', 'Vft', 8, _ptr()), ('Flags', 'Flags', 4, _i(4, False)), ('Index', 'Index', 4, _i(4)),
                               ('Class', 'Class', 8, _ptr('UClass')), ('Name', 'Name', fname, _named('FName')),
                               ('Outer', 'Outer', 8, _ptr('UObject'))):
        add('UObject', m, lambda key=key: k.i(f'Off.UObject.{key}'), size, spec)
    add('UField', 'Next', lambda: k.i('Off.UField.Next'), 8, _ptr('UField'))
    use_fprop = flag('Settings.Internal.bUseFProperty')
    for m, size, spec in (('SuperStruct', 8, _ptr('UStruct')), ('Children', 8, _ptr('UField')),
                          ('ChildProperties', 8, _ptr('FField')), ('Size', 4, _i(4)), ('MinAlignment', 2, _i(2))):
        if m != 'ChildProperties' or use_fprop:
            add('UStruct', m, lambda m=m: k.i(f'Off.UStruct.{m}'), size, spec)
    add('UClass', 'CastFlags', lambda: k.i('Off.UClass.CastFlags'), 8, _i(8, False))
    add('UClass', 'ClassDefaultObject', lambda: k.i('Off.UClass.ClassDefaultObject'), 8, _ptr('UObject'))
    add('UFunction', 'FunctionFlags', lambda: k.i('Off.UFunction.FunctionFlags'), 4, _i(4, False))
    add('UFunction', 'ExecFunction', lambda: k.i('Off.UFunction.ExecFunction'), 8, _ptr())
    add('UEnum', 'Names', lambda: k.i('Off.UEnum.Names'), 0x10, _named(f'TArray<{_PAIR_NAME}>'))
    name_pool = flag('Settings.Internal.bUseNamePool')
    add('FName', 'ComparisonIndex', lambda: k.i('Off.FName.CompIdx'), 4, _i(4))
    if flag('Settings.Internal.bUseOutlineNumberName') is False:
        add('FName', 'Number', lambda: k.i('Off.FName.Number'), 4, _i(4, not name_pool))
    if flag('Settings.Internal.bUseCasePreservingName'):
        add('FName', 'DisplayIndex', lambda: 0x8 if k.i('Off.FName.Number') == 4 else 0x4, 4, _i(4))
    if use_fprop:
        mask = flag('Settings.Internal.bUseMaskForFieldOwner')
        for m, key, size, spec in (('Name', 'Name', fname, _named('FName')), ('Id', 'Id', 8, _i(8, False)),
                                   ('CastFlags', 'CastFlags', 8, _i(8, False)), ('ClassFlags', 'ClassFlags', 4, _i(4, False)),
                                   ('SuperClass', 'SuperClass', 8, _ptr('FFieldClass'))):
            add('FFieldClass', m, lambda key=key: k.i(f'Off.FFieldClass.{key}'), size, spec)
        add('FFieldVariant', 'Container', lambda: 0, 8, _ptr())
        if mask is False:
            add('FFieldVariant', 'bIsUObject', lambda: 8, 1, ('bool',))
        for m, key, size, spec in (('VTable', 'Vft', 8, _ptr()), ('ClassPrivate', 'Class', 8, _ptr('FFieldClass')),
                                   ('Owner', 'Owner', lambda: k.b('Settings.Internal.bUseMaskForFieldOwner') and 8 or 0x10,
                                    _named('FFieldVariant')),
                                   ('Next', 'Next', 8, _ptr('FField')), ('Name', 'Name', fname, _named('FName')),
                                   ('ObjFlags', 'Flags', 4, _i(4))):
            add('FField', m, lambda key=key: k.i(f'Off.FField.{key}'), size, spec)
        for m, key, size, spec in (('ArrayDim', 'ArrayDim', 4, _i(4)), ('ElementSize', 'ElementSize', 4, _i(4)),
                                   ('PropertyFlags', 'PropertyFlags', 8, _i(8, False)), ('Offset', 'Offset_Internal', 4, _i(4))):
            add('FProperty', m, lambda key=key: k.i(f'Off.Property.{key}'), size, spec)
        prop = lambda key, delta=0: (lambda: k.i(key) + delta)
        add('FByteProperty', 'Enum', prop('Off.ByteProperty.Enum'), 8, _ptr('UEnum'))
        for n, m in enumerate(('FieldSize', 'ByteOffset', 'ByteMask', 'FieldMask')):
            add('FBoolProperty', m, prop('Off.BoolProperty.Base', n), 1, _i(1, False))
        add('FObjectPropertyBase', 'PropertyClass', prop('Off.ObjectProperty.PropertyClass'), 8, _ptr('UClass'))
        add('FClassProperty', 'MetaClass', prop('Off.ClassProperty.MetaClass'), 8, _ptr('UClass'))
        add('FStructProperty', 'Struct', prop('Off.StructProperty.Struct'), 8, _ptr('UStruct'))
        add('FArrayProperty', 'InnerProperty', prop('Off.ArrayProperty.Inner'), 8, _ptr('FProperty'))
        add('FDelegateProperty', 'SignatureFunction', prop('Off.DelegateProperty.SignatureFunction'), 8, _ptr('UFunction'))
        add('FMapProperty', 'KeyProperty', prop('Off.MapProperty.Base'), 8, _ptr('FProperty'))
        add('FMapProperty', 'ValueProperty', prop('Off.MapProperty.Base', 8), 8, _ptr('FProperty'))
        add('FSetProperty', 'ElementProperty', prop('Off.SetProperty.ElementProp'), 8, _ptr('FProperty'))
        add('FEnumProperty', 'UnderlayingProperty', prop('Off.EnumProperty.Base'), 8, _ptr('FProperty'))
        add('FEnumProperty', 'Enum', prop('Off.EnumProperty.Base', 8), 8, _ptr('UEnum'))
        add('FFieldPathProperty', 'FieldClass', prop('Off.FieldPathProperty.FieldClass'), 8, _ptr('FFieldClass'))
        add('FOptionalProperty', 'ValueProperty', prop('Off.OptionalProperty.ValueProperty'), 8, _ptr('FProperty'))
    sizes = {}
    try:
        if k.b('Off.FUObjectArray.bIsChunked'):
            lay = k.layout('Off.FUObjectArray.ChunkedFixedLayout',
                           ('ObjectsOffset', 'MaxElementsOffset', 'NumElementsOffset', 'MaxChunksOffset', 'NumChunksOffset'))
            for m, key, size, spec in (('Objects', 'ObjectsOffset', 8, ('ptr', ('ptr', _named('FUObjectItem')))),
                                       ('MaxElements', 'MaxElementsOffset', 4, _i(4)), ('NumElements', 'NumElementsOffset', 4, _i(4)),
                                       ('MaxChunks', 'MaxChunksOffset', 4, _i(4)), ('NumChunks', 'NumChunksOffset', 4, _i(4))):
                add('TUObjectArray', m, lambda key=key: lay[key], size, spec)
            sizes['TUObjectArray'] = max(lay['ObjectsOffset'] + 8, lay['MaxElementsOffset'] + 8, lay['NumElementsOffset'] + 4,
                                         lay['MaxChunksOffset'] + 4, lay['NumChunksOffset'] + 4)
        else:
            lay = k.layout('Off.FUObjectArray.FixedLayout', ('ObjectsOffset', 'MaxObjectsOffset', 'NumObjectsOffset'))
            for m, key, size, spec in (('Objects', 'ObjectsOffset', 8, _ptr('FUObjectItem')),
                                       ('MaxElements', 'MaxObjectsOffset', 4, _i(4)), ('NumElements', 'NumObjectsOffset', 4, _i(4))):
                add('TUObjectArray', m, lambda key=key: lay[key], size, spec)
            sizes['TUObjectArray'] = max(lay['ObjectsOffset'] + 8, lay['NumObjectsOffset'] + 4, lay['MaxObjectsOffset'] + 4)
    except _Missing:
        pass
    add('FUObjectItem', 'Object', lambda: k.i('Off.InSDK.ObjArray.FUObjectItemInitialOffset'), 8, _ptr('UObject'))
    add('FWeakObjectPtr', 'ObjectIndex', lambda: 0, 4, _i(4))
    add('FWeakObjectPtr', 'ObjectSerialNumber', lambda: 4, 4, _i(4))
    for n, m in enumerate('ABCD'):
        add('FUniqueObjectGuid', m, lambda n=n: 4 * n, 4, _i(4, False))
    add('FScriptInterface', 'ObjectPointer', lambda: 0, 8, _ptr('UObject'))
    add('FScriptInterface', 'InterfacePointer', lambda: 8, 8, _ptr())
    add('FScriptDelegate', 'Object', lambda: 0, 8, _named('FWeakObjectPtr'))
    add('FScriptDelegate', 'FunctionName', lambda: 8, fname, _named('FName'))
    if use_fprop:
        add('FFieldPath', 'ResolvedField', lambda: 0, 8, _ptr('FField'))
        try:
            editor = k.i('PropertySizes.FieldPathProperty') > 0x20
            if editor:
                add('FFieldPath', 'InitialFieldClass', lambda: 8, 8, _ptr('FFieldClass'))
                add('FFieldPath', 'FieldPathSerialNumber', lambda: 0x10, 4, _i(4))
            add('FFieldPath', 'ResolvedOwner', lambda: 0x14 if editor else 8, 8, _named('FWeakObjectPtr'))
            add('FFieldPath', 'Path', lambda: 0x1C if editor else 0x10, 0x10, _named('TArray<FName>'))
        except _Missing:
            pass
    for t, fn in (('FName', fname), ('FProperty', lambda: k.i('Off.InSDK.Properties.PropertySize')),
                  ('FUObjectItem', lambda: k.i('Off.InSDK.ObjArray.FUObjectItemSize')),
                  ('FScriptDelegate', lambda: 8 + fname()), ('FFieldPath', lambda: k.i('PropertySizes.FieldPathProperty'))):
        try:
            sizes[t] = fn()
        except _Missing:
            pass
    sizes.update(FWeakObjectPtr=8, FUniqueObjectGuid=0x10, FScriptInterface=0x10)
    if use_fprop and (mask := flag('Settings.Internal.bUseMaskForFieldOwner')) is not None:
        sizes['FFieldVariant'] = 8 if mask else 0x10
    return rows, sizes, list(k.missing)


def core_members(view: SnapshotView) -> dict:
    """{(type, member): (offset, size)} of Dumper-7's predefined members (R6) whose offsets.json keys resolved."""
    view._check()
    rows, _sizes, _missing = _core_layout(view.offsets)
    return {(t, m): (off, size) for t, m, off, size, _spec in rows}


# --- the build check (R9) ---

def _snapshot_build(meta) -> tuple:
    target = meta.get('target') if isinstance(meta, dict) else None
    target = target if isinstance(target, dict) else {}
    module = target.get('module') if isinstance(target.get('module'), dict) else {}
    sha = target.get('exe_sha256')
    sha = sha.lower() if isinstance(sha, str) and _SHA256_RE.fullmatch(sha) else None
    ts, size = module.get('pe_timestamp'), module.get('size')
    ts = int(ts, 16) if isinstance(ts, str) and _UHEX_RE.fullmatch(ts) else None
    size = int(size, 16) if isinstance(size, str) and _UHEX_RE.fullmatch(size) else None
    exe = target.get('exe') if isinstance(target.get('exe'), str) else '?'
    return sha, ts, size, exe


def _idb_build(idb) -> tuple:
    idb = idb if isinstance(idb, dict) else {}
    sha = idb.get('sha256')
    sha = sha.lower() if isinstance(sha, str) and _SHA256_RE.fullmatch(sha) else None
    ts, size = idb.get('pe_timestamp'), idb.get('size_of_image')
    ts = ts if _is_int(ts) and ts >= 0 else None
    size = size if _is_int(size) and size >= 0 else None
    name = idb.get('input_file') if isinstance(idb.get('input_file'), str) else '?'
    return sha, ts, size, name


def _build_line(label: str, exe: str, sha, ts) -> str:
    sha_text = f'{sha[:4]}...{sha[-2:]}' if sha else '(none)'
    ts_text = f'0x{ts:08X}' if ts is not None else '(none)'
    return f'  {label:<10} {exe}  SHA-256 {sha_text}  PE {ts_text}'


def check_build(meta, idb) -> tuple:
    """(verdict, text): 'sha256' | 'pe' | 'mismatch' | 'unknown' and the line or dialog text that explains it."""
    try:
        s_sha, s_ts, s_size, s_exe = _snapshot_build(meta)
        i_sha, i_ts, i_size, i_exe = _idb_build(idb)
        if s_sha and i_sha and s_sha == i_sha:
            return 'sha256', "OK: the SHA-256 of this IDB's input file matches the snapshot"
        lines = _build_line('IDB input', i_exe, i_sha, i_ts) + '\n' + _build_line('snapshot', s_exe, s_sha, s_ts)
        if None not in (s_ts, s_size, i_ts, i_size):
            if s_ts == i_ts and s_size == i_size:
                return 'pe', "OK: the PE timestamp and image size of this IDB's input file match the snapshot"
            return 'mismatch', (f"This IDB was not built from the snapshot's executable.\n{lines}\n"
                                'Names would land on the wrong addresses. Import anyway?')
        return 'unknown', ("This IDB's input file cannot be compared with the snapshot's executable "
                           f'(no common SHA-256 or PE timestamp and size).\n{lines}\n'
                           'Names would land on the wrong addresses. Import anyway?')
    except Exception as e:  # never raises (I8)
        return 'unknown', f'the build cannot be checked: {type(e).__name__}: {e}'


# --- planning: names, globals, types, comments ---

def _plain_ident(kind: str, name: str) -> str:
    return name


def _ida_ident(kind: str, name: str) -> str:
    import ida_name
    vt = {'type': ida_name.VNT_TYPE, 'member': ida_name.VNT_UDTMEM, 'ident': ida_name.VNT_IDENT}[kind]
    return ida_name.validate_name(name, vt, ida_name.SN_NOCHECK) or name


def _default_ident():
    try:
        import ida_name  # noqa: F401
    except ImportError:
        return _plain_ident
    return _ida_ident


def _short_name(path: str) -> str:
    return re.split('[.:]', path)[-1]


def _folder(package: str) -> str:
    if package.startswith('/Script/'):
        return 'UE/' + package[len('/Script/'):]
    return 'UE/' + package.strip('/')


def _flag_names(flags: int) -> str:
    names = [n for n, v in _EFUNCTION_FLAGS if flags & v]
    rest = flags & ~sum(v for _n, v in _EFUNCTION_FLAGS)
    if rest:
        names.append(f'0x{rest:X}')
    return '|'.join(names) if names else '0'


class _TypePlanner:
    """R3-R6 and R13 in plain Python: the UDTs, enums and forward declarations an import creates."""

    def __init__(self, view: SnapshotView, *, types: str, roots, core_types: bool, enums: bool, ident):
        self.view = view
        self.mode = types
        self.core_types = core_types
        self.enums_on = enums
        self.ident = ident
        self.info = {}
        for path, d in view.scan():
            kind = d.get('kind')
            if kind not in ('class', 'struct', 'enum'):
                continue
            try:
                entry = {'kind': kind, 'cpp_name': _req(d, 'cpp_name', str), 'package': _req(d, 'package', str)}
                if kind == 'enum':
                    entry['width'] = _req(d, 'underlying_size', int)
                    entry['signed'] = _req(d, 'underlying_signed', bool, nullable=True)
                else:
                    entry['super'] = _req(d, 'super', str, nullable=True)
                    entry['size'] = _hexkey(d, 'size')
                    align = max(_req(d, 'min_alignment', int), 1)
                    entry['udt_size'] = -(-entry['size'] // align) * align if kind == 'struct' else entry['size']
            except _Bad as e:
                raise SnapshotFormatError(view.folder, f'types.jsonl: type {path!r}: {e}') from None
            self.info[path] = entry
        self.names = self._assign_names()
        self.by_name = {n: p for p, n in self.names.items()}
        self.roots = self._resolve_roots(roots)
        rows, self.core_sizes, self.missing_keys = _core_layout(view.offsets)
        self.core_rows = collections.defaultdict(list)
        for t, m, off, size, spec in rows:
            self.core_rows[t].append((m, off, size, spec))
        self.udts = collections.OrderedDict()
        self.support = collections.OrderedDict()
        self.enum_plans = collections.OrderedDict()
        self.value_refs = set()
        self.used_enums = set()
        self.basics = set()
        self.dropped = 0
        self.untyped = 0
        self._layouts = {}
        self._visiting = set()

    def _assign_names(self) -> dict:
        by_name = collections.defaultdict(list)
        for path, e in self.info.items():
            by_name[self.ident('type', e['cpp_name'])].append(path)
        taken = set(by_name)
        names = {}
        for name, paths in by_name.items():
            paths.sort()
            names[paths[0]] = name
            for p in paths[1:]:
                seg = make_name_valid(self.info[p]['package'].rstrip('/').rsplit('/', 1)[-1])
                cand = self.ident('type', f'{name}__{seg}')
                n = 2
                while cand in taken:
                    cand = self.ident('type', f'{name}__{n}')
                    n += 1
                taken.add(cand)
                names[p] = cand
        return names

    def _resolve_roots(self, roots) -> list:
        out = []
        for r in roots:
            if r in self.info:
                out.append(r)
                continue
            matches = sorted(p for p in self.info if _short_name(p) == r)
            if not matches:
                raise _UsageError(f'no type named {r!r}')
            if len(matches) > 1:
                raise _UsageError(f'{r!r} names several types: ' + ', '.join(matches))
            out.append(matches[0])
        return out

    # -- spelling (R3, GetMemberTypeStringWithoutConst @ ea0dab3 without the class/struct keywords)

    def _type_name(self, path, fallback_prefix: str, default: str) -> str:
        if path is None:
            return default
        if path in self.names:
            return self.names[path]
        return fallback_prefix + make_name_valid(_short_name(path))

    def spell(self, t, flags: int = 0) -> str:
        k = t['kind']
        simple = {'UInt16Property': 'uint16', 'UInt32Property': 'uint32', 'UInt64Property': 'uint64', 'Int8Property': 'int8',
                  'Int16Property': 'int16', 'IntProperty': 'int32', 'Int64Property': 'int64', 'FloatProperty': 'float',
                  'DoubleProperty': 'double', 'NameProperty': 'FName', 'StrProperty': 'FString', 'TextProperty': 'FText',
                  'Utf8StrProperty': 'FUtf8String', 'AnsiStrProperty': 'FUtf8String'}
        if k in simple:
            return simple[k]
        if k == 'ByteProperty':
            return self._type_name(t['enum'], 'E', 'uint8') if t['enum'] else 'uint8'
        if k == 'BoolProperty':
            return 'bool' if t['field_mask'] in (None, 0xFF) else 'uint8'
        if k == 'ClassProperty':
            if flags & _CPF_UOBJECT_WRAPPER:
                return f"TSubclassOf<{self._type_name(t['meta_class'], 'U', 'UObject')}>"
            return 'UClass*'
        if k == 'StructProperty':
            return self._type_name(t['struct'], 'F', 'FStruct')
        if k == 'ArrayProperty':
            return f"TArray<{self.spell(t['inner']) if t['inner'] else 'void'}>"
        wrappers = {'WeakObjectProperty': 'TWeakObjectPtr', 'LazyObjectProperty': 'TLazyObjectPtr',
                    'SoftClassProperty': 'TSoftClassPtr', 'SoftObjectProperty': 'TSoftObjectPtr'}
        if k in wrappers:
            return f"{wrappers[k]}<{self._type_name(t['class'], 'U', 'UObject')}>"
        if k == 'ObjectProperty':
            return self._type_name(t['class'], 'U', 'UObject') + '*'
        if k == 'MapProperty':
            return f"TMap<{self.spell(t['key']) if t['key'] else 'void'}, {self.spell(t['value']) if t['value'] else 'void'}>"
        if k == 'SetProperty':
            return f"TSet<{self.spell(t['element']) if t['element'] else 'void'}>"
        if k == 'EnumProperty':
            if t['enum']:
                return self._type_name(t['enum'], 'E', 'uint8')
            return self.spell(t['underlying']) if t['underlying'] else 'uint8'
        if k == 'InterfaceProperty':
            return f"TScriptInterface<{self._type_name(t['class'], 'I', 'IInterface')}>"
        if k in ('DelegateProperty', 'MulticastInlineDelegateProperty'):
            name = 'TDelegate' if k == 'DelegateProperty' else 'TMulticastInlineDelegate'
            return f'{name}<{self._signature(t["signature"])}>'
        if k == 'FieldPathProperty':
            return f"TFieldPath<F{make_name_valid(_short_name(t['field_class'])) if t['field_class'] else 'Field'}>"
        if k == 'OptionalProperty':
            return f"TOptional<{self.spell(t['value']) if t['value'] else 'void'}>"
        return f"F{make_name_valid(t['prop'])}_"

    def _signature(self, path) -> str:
        fn = self.view.type(path) if path else None
        if fn is None or fn.get('kind') != 'function':
            return 'void()'
        ret = 'void'
        params = []
        for p in sorted(fn['params'], key=lambda p: p['offset']):
            f = p['flags']
            t = self.spell(p['type'], f)
            if f & _CPF_RETURN_PARM:
                if f & _CPF_CONST_PARM:
                    ret = 'const ' + t  # ea0dab3 sets the return type only for a const return
                continue
            ref, out = bool(f & _CPF_REFERENCE_PARM), bool(f & (_CPF_REFERENCE_PARM | _CPF_OUT_PARM))
            if f & _CPF_CONST_PARM and (not out or ref):
                t = 'const ' + t
            if out:
                t += '&' if ref else '*'
            if not out and p['type']['kind'] in ('StructProperty', 'ArrayProperty', 'StrProperty', 'MapProperty', 'SetProperty'):
                t = t + '&' if f & _CPF_CONST_PARM else 'const ' + t + '&'
            params.append(f"{t} {make_name_valid(p['name'])}")
        return f"{ret}({', '.join(params)})"

    # -- member typing (R4)

    def _enum_name(self, path, size: int):
        e = self.info.get(path) if path else None
        if e is None or e['kind'] != 'enum' or not self.enums_on or e['width'] != size:
            return None
        if self.mode == 'referenced':
            self.used_enums.add(path)
        return self.names[path]

    def _udt(self, name: str, size: int, *, path=None, folder='UE/Core', base=None, base_size=0, members=(), comment=None):
        return {'name': name, 'path': path, 'folder': folder, 'size': size, 'base': base, 'base_size': base_size,
                'members': list(members), 'comment': comment or (_TYPE_MARK + 'core')}

    def _type_ident(self, name: str) -> str:
        if (v := self.ident('type', name)) == name:
            return name
        fallback = name.replace('<', '_').replace('>', '').replace(', ', '_').replace('*', 'Ptr')
        return self.ident('type', fallback)

    def _support(self, name: str, size: int, members=()) -> str:
        name = self._type_ident(name)
        if name in self.by_name and name not in self.support:
            name = f'{name}__core'
        have = self.support.get(name)
        if have is not None and have['size'] != size:
            name = f'{name}__{size:X}'
            have = self.support.get(name)
        if have is None:
            self.support[name] = self._udt(name, size, members=members)
        return name

    def _support_named(self, name: str) -> 'str | None':
        """Create a support type the core layout or a member names: FName, FString, FText, TArray, TPair."""
        if name == 'FName':
            size = self.core_sizes.get('FName', 8)
            rows = self.core_rows.get('FName', [])
            return self._basic(self._support('FName', size, [(m, off * 8, sz * 8, spec) for m, off, sz, spec in rows]))
        if name == 'FString':
            return self._basic(self._support('FString', 0x10, [('Data', 0, 64, ('ptr', ('wchar',))), ('Num', 64, 32, _i(4)),
                                                                ('Max', 96, 32, _i(4))]))
        if name == 'FText':
            try:
                size = _Keys(self.view.offsets).i('Off.InSDK.Text.TextSize')
            except _Missing:
                size = 0x18
            return self._basic(self._support('FText', size))
        if name == _PAIR_NAME:
            fsize = self.core_sizes.get('FName', 8)
            self._support_named('FName')
            off = (fsize + 7) & ~7
            return self._support(_PAIR_NAME, off + 8, [('Key', 0, fsize * 8, _named('FName')), ('Value', off * 8, 64, _i(8))])
        if name.startswith('TArray<') and name.endswith('>'):
            inner = name[len('TArray<'):-1]
            if inner in ('FName', _PAIR_NAME):
                self._support_named(inner)
            return self._tarray(name, _named(inner))
        return None

    def _basic(self, name: str) -> str:
        self.basics.add(name)
        return name

    def _tarray(self, name: str, elem_spec) -> str:
        return self._support(name, 0x10, [('Data', 0, 64, ('ptr', elem_spec)), ('Num', 64, 32, _i(4)), ('Max', 96, 32, _i(4))])

    def _interface(self, t, size: int) -> str:
        if size != 0x10:
            return self._support(self.spell(t), size)
        return self._support(self.spell(t), 0x10, [('ObjectPointer', 0, 64, _ptr('UObject')), ('InterfacePointer', 64, 64, _ptr())])

    def _elem_spec(self, t):
        """The IDA type of a TArray element; only a declaration is needed (Data is a pointer)."""
        k = t['kind']
        ints = {'Int8Property': _i(1), 'Int16Property': _i(2), 'IntProperty': _i(4), 'Int64Property': _i(8),
                'UInt16Property': _i(2, False), 'UInt32Property': _i(4, False), 'UInt64Property': _i(8, False),
                'FloatProperty': ('float', 4), 'DoubleProperty': ('float', 8)}
        if k in ints:
            return ints[k]
        if k == 'BoolProperty':
            return ('bool',)
        if k in ('ByteProperty', 'EnumProperty'):
            e = self.info.get(t['enum']) if t['enum'] else None
            if e is not None and e['kind'] == 'enum' and (n := self._enum_name(t['enum'], e['width'])):
                return _named(n)
            if k == 'EnumProperty' and t['underlying']:
                return self._elem_spec(t['underlying'])
            return _i(1, False)
        if k in ('NameProperty', 'StrProperty', 'TextProperty'):
            return _named(self._support_named(self.spell(t)))
        if k == 'ObjectProperty':
            return self._ref(_named(self._type_name(t['class'], 'U', 'UObject')))
        if k == 'InterfaceProperty':
            return _named(self._interface(t, 0x10))
        if k == 'ClassProperty':
            return self._ref(_named('UClass'))
        if k == 'StructProperty':
            return _named(self._type_name(t['struct'], 'F', 'FStruct'))
        if k == 'ArrayProperty':
            inner = self._elem_spec(t['inner']) if t['inner'] else ('void',)
            return _named(self._tarray(self.spell(t), inner))
        return _named(self.spell(t))

    def _ref(self, spec):
        return ('ptr', spec)

    def _member_spec(self, p):
        """(spec, bit offset within the member, untyped) for one reflected property (R4)."""
        t, size = p['type'], p['size']
        k = t['kind']
        ints = {'Int8Property': (1, True), 'Int16Property': (2, True), 'IntProperty': (4, True), 'Int64Property': (8, True),
                'UInt16Property': (2, False), 'UInt32Property': (4, False), 'UInt64Property': (8, False)}
        if k in ints:
            return _i(*ints[k]), 0, False
        if k in ('FloatProperty', 'DoubleProperty'):
            return ('float', 4 if k == 'FloatProperty' else 8), 0, False
        if k == 'ByteProperty':
            n = self._enum_name(t['enum'], size)
            return (_named(n) if n else _i(size, False)), 0, False
        if k == 'EnumProperty':
            if n := self._enum_name(t['enum'], size):
                return _named(n), 0, False
            u = t['underlying']
            signed = u is not None and u['kind'] in ('Int8Property', 'Int16Property', 'IntProperty', 'Int64Property')
            return _i(size, signed), 0, False
        if k == 'BoolProperty':
            fm = t['field_mask']
            if fm is not None and fm != 0xFF and fm > 0 and fm & (fm - 1) == 0:
                bit = (t['byte_offset'] or 0) * 8 + fm.bit_length() - 1
                return ('bitfield', t['field_size'] or size), bit, False
            return (('bool',) if size == 1 else _i(size, False)), 0, False
        if k in ('NameProperty', 'StrProperty', 'TextProperty'):
            return _named(self._support_named(self.spell(t))), 0, False
        if k == 'ObjectProperty':
            return self._ref(_named(self._type_name(t['class'], 'U', 'UObject'))), 0, False
        if k == 'InterfaceProperty':
            return _named(self._interface(t, size)), 0, False
        if k == 'ClassProperty':
            return self._ref(_named('UClass')), 0, False
        if k == 'StructProperty':
            path = t['struct']
            e = self.info.get(path) if path else None
            if e is None or e['kind'] == 'enum':
                return ('array', _i(1, False), size), 0, True
            self.value_refs.add(path)
            return _named(self.names[path]), 0, False
        if k == 'ArrayProperty':
            inner = self._elem_spec(t['inner']) if t['inner'] else ('void',)
            return _named(self._tarray(self.spell(t), inner)), 0, False
        if k == 'WeakObjectProperty' and size == 8:
            return _named(self._support(self.spell(t), 8, [('ObjectIndex', 0, 32, _i(4)), ('ObjectSerialNumber', 32, 32, _i(4))])), 0, False
        return _named(self._support(self.spell(t), size)), 0, False

    def spec_size(self, spec) -> int:
        k = spec[0]
        if k in ('int', 'float'):
            return spec[1]
        if k in ('bool',):
            return 1
        if k == 'wchar':
            return 2
        if k == 'ptr':
            return 8
        if k == 'array':
            return self.spec_size(spec[1]) * spec[2]
        if k == 'bitfield':
            return spec[1]
        if k == 'named':
            n = spec[1]
            if n in self.support:
                return self.support[n]['size']
            if n in self.udts:
                return self.udts[n]['size']
            if (p := self.by_name.get(n)) is not None:
                e = self.info[p]
                return e['width'] if e['kind'] == 'enum' else e['udt_size']
        return 0

    def _layout(self, path: str) -> dict:
        """A record's planned members, base-class size in bytes and its super chain's member end in bits (R4, R6)."""
        if (lay := self._layouts.get(path)) is not None:
            return lay
        rec = self.view.type(path)
        name = self.names[path]
        base, start, end = None, 0, 0
        sup = rec['super']
        if sup is not None and sup in self.info and self.info[sup]['kind'] != 'enum':
            base, start = self.names[sup], self.info[sup]['size']
            self._visiting.add(path)
            try:
                end = start * 8 if sup in self._visiting else self._layout(sup)['end']
            finally:
                self._visiting.discard(path)
            low = min((p['offset'] for p in rec['properties']), default=start)
            if low < start:  # the child reuses the super's tail padding (Dumper-7: Info.Size = LowestOffset)
                start = min(start, max(low, (end + 7) // 8))
        saved, self.value_refs = self.value_refs, set()
        try:
            members, dropped, untyped = self._layout_members(rec, name, start * 8)
        finally:
            saved, self.value_refs = self.value_refs, saved
        end = max([end] + [lo + nbits for _n, lo, nbits, _s in members])
        lay = {'base': base, 'start': start, 'end': end, 'members': members, 'dropped': dropped, 'untyped': untyped,
               'refs': saved}
        self._layouts[path] = lay
        return lay

    def _plan_record(self, rec: dict):
        name = self.names[rec['path']]
        lay = self._layout(rec['path'])
        if lay['base'] is not None:
            self.value_refs.add(rec['super'])
        self.value_refs |= lay['refs']
        self.untyped += lay['untyped']
        self.dropped += len(lay['dropped'])
        comment = '\n'.join([_TYPE_MARK + _text(rec['path'])] + lay['dropped'])
        self.udts[name] = self._udt(name, self.info[rec['path']]['udt_size'], path=rec['path'], folder=_folder(rec['package']), base=lay['base'],
                                    base_size=lay['start'] if lay['base'] else 0, members=self._name_members(lay['members']),
                                    comment=comment)

    def _layout_members(self, rec: dict, name: str, start: int) -> tuple:
        size = self.info[rec['path']]['udt_size']
        members, dropped, used, untyped_count = [], [], [], 0
        for p in rec['properties']:
            spec, bit, untyped = self._member_spec(p)
            dim = p['array_dim'] if p['array_dim'] > 1 else 1
            if spec[0] == 'bitfield':
                lo, nbits = p['offset'] * 8 + bit, 1
                if dim > 1:
                    spec, lo, nbits, untyped = ('array', _i(1, False), p['size'] * dim), p['offset'] * 8, p['size'] * dim * 8, True
            else:
                elem = self.spec_size(spec)
                if elem > p['size'] or (spec[0] == 'named' and elem == 0):
                    spec, elem, untyped = ('array', _i(1, False), p['size']), p['size'], True
                if dim > 1:
                    spec = ('array', spec, dim)
                lo, nbits = p['offset'] * 8, elem * dim * 8
            reason = None
            if lo < start:
                reason = 'overlaps the super'
            elif lo + nbits > size * 8:
                reason = 'ends beyond the size'
            elif any(lo < e and s < lo + nbits for s, e, _n in used):
                reason = 'overlaps ' + next(n for s, e, n in used if lo < e and s < lo + nbits)
            if reason:
                dropped.append(f"dropped: {_text(p['name'])} @0x{p['offset']:X} size 0x{p['size'] * dim:X} ({reason})")
                continue
            untyped_count += untyped
            used.append((lo, lo + nbits, p['name']))
            members.append([p['name'], lo, nbits, spec])
        if self.core_types and name in _REFLECTED_CORE and rec['package'] == '/Script/CoreUObject':
            for m, off, sz, spec in self.core_rows.get(name, ()):
                lo, nbits = off * 8, sz * 8
                if lo >= start and lo + nbits <= size * 8 and not any(lo < e and s < lo + nbits for s, e, _n in used):
                    used.append((lo, lo + nbits, m))
                    members.append([m, lo, nbits, self._core_spec(spec, sz)])
        return members, dropped, untyped_count

    def _name_members(self, members: list) -> list:
        seen = set()
        out = []
        for raw, lo, nbits, spec in members:
            n = self.ident('member', make_name_valid(raw) or '_')
            cand, i = n, 1
            while cand in seen:
                cand = f'{n}_{i}'
                i += 1
            seen.add(cand)
            out.append((cand, lo, nbits, spec))
        return sorted(out, key=lambda m: m[1])

    def _plan_enum(self, rec: dict):
        name = self.names[rec['path']]
        width = rec['underlying_size']
        members, seen = [], set()
        for raw, value in rec['values']:
            short = raw.rsplit('::', 1)[-1]
            n = f'{name}::{short}'
            v = self.ident('ident', n)
            if v != n:
                v = self.ident('ident', f'{name}__{short}')
            cand, i = v, 1
            while cand in seen:
                cand = f'{v}_{i}'
                i += 1
            seen.add(cand)
            members.append((cand, value))
        self.enum_plans[name] = {'name': name, 'path': rec['path'], 'folder': _folder(rec['package']), 'width': width,
                                 'signed': rec['underlying_signed'] is True, 'members': members,
                                 'comment': _TYPE_MARK + _text(rec['path'])}

    def _plan_core(self):
        planned = {u['name'] for u in self.udts.values()}
        for t in _REFLECTED_CORE + ('FFieldClass', 'FFieldVariant', 'FField', 'FProperty') + _PROPERTY_TYPES + (
                'TUObjectArray', 'FUObjectItem', 'FWeakObjectPtr', 'FUniqueObjectGuid', 'FScriptInterface',
                'FScriptDelegate', 'FFieldPath'):
            rows = self.core_rows.get(t)
            if not rows or t in planned:
                continue
            base = _CORE_BASES.get(t, 'FProperty' if t in _PROPERTY_TYPES else None)
            base_size = 0
            if base is not None:
                if base not in self.udts and base not in self.support:
                    base = None
                else:
                    base_size = (self.udts.get(base) or self.support.get(base))['size']
            end = max(off + sz for _m, off, sz, _s in rows)
            path = self.by_name.get(t)
            path = path if path is not None and self.info[path]['kind'] != 'enum' else None
            size = self.core_sizes.get(t) or (self.info[path]['udt_size'] if path else max(end, base_size))
            members = [(m, off * 8, sz * 8, self._core_spec(spec, sz)) for m, off, sz, spec in rows
                       if off >= base_size and off + sz <= size]
            self.udts[t] = self._udt(t, size, base=base, base_size=base_size, members=sorted(members, key=lambda m: m[1]))
        self._support_named('FName')

    def _core_spec(self, spec, size: int):
        """A core member's spec, with its support type created; a by-value type of another size becomes bytes."""
        if spec[0] == 'named':
            name = self._support_named(spec[1]) or spec[1]
            spec = _named(name)
            if spec[1] not in _REFLECTED_CORE and self.spec_size(spec) not in (0, size) and spec[1] not in self.udts:
                return ('array', _i(1, False), size)
        return spec

    def plan(self) -> dict:
        self.value_refs = set()
        self.used_enums = set()
        if self.mode == 'all':
            selected = sorted(p for p, e in self.info.items() if e['kind'] != 'enum')
        elif self.mode == 'referenced':
            selected, queue = [], [r for r in self.roots if self.info[r]['kind'] != 'enum']
            self.used_enums.update(r for r in self.roots if self.info[r]['kind'] == 'enum')
            done = set()
            while queue:
                p = queue.pop(0)
                if p in done:
                    continue
                done.add(p)
                selected.append(p)
                self.value_refs = set()
                self._plan_record(self.view.type(p))
                queue.extend(sorted(self.value_refs - done))
            selected = sorted(selected)
        else:
            selected = []
        if self.mode != 'referenced':
            for p in selected:
                self._plan_record(self.view.type(p))
        records = collections.OrderedDict((n, self.udts[n]) for n in sorted(self.udts, key=lambda n: self.udts[n]['path']))
        self.udts = records
        if self.core_types:
            self._plan_core()
        if self.enums_on:
            enum_paths = sorted(self.used_enums) if self.mode == 'referenced' else sorted(
                p for p, e in self.info.items() if e['kind'] == 'enum')
            for p in enum_paths:
                self._plan_enum(self.view.type(p))
        all_udts = collections.OrderedDict(list(self.udts.items()) + list(self.support.items()))
        defined = set(all_udts) | set(self.enum_plans)
        fwd = []
        for u in all_udts.values():
            for _n, _lo, _bits, spec in u['members']:
                for ref in _pointer_targets(spec):
                    if ref not in defined and ref not in fwd:
                        fwd.append(ref)
        order = _dependency_order(all_udts)
        return {'udts': [all_udts[n] for n in order], 'enums': list(self.enum_plans.values()), 'fwd': fwd,
                'records': len(self.udts) - sum(1 for u in self.udts.values() if u['path'] is None),
                'core': sum(1 for u in self.udts.values() if u['path'] is None) + len(self.basics),
                'containers': len(self.support) - len(self.basics),
                'members_dropped': self.dropped, 'members_untyped': self.untyped, 'missing_keys': self.missing_keys,
                'selected': selected}


def _pointer_targets(spec):
    if spec[0] == 'ptr':
        inner = spec[1]
        while inner[0] in ('ptr', 'array'):
            inner = inner[1]
        if inner[0] == 'named':
            yield inner[1]
    elif spec[0] == 'array':
        yield from _pointer_targets(spec[1])


def _value_deps(udt: dict):
    if udt['base']:
        yield udt['base']
    for _n, _lo, _bits, spec in udt['members']:
        while spec[0] == 'array':
            spec = spec[1]
        if spec[0] == 'named':
            yield spec[1]


def _dependency_order(udts: dict) -> list:
    order, state = [], {}
    for root in udts:
        if state.get(root):
            continue
        state[root] = 1
        stack = [(root, iter(_value_deps(udts[root])))]
        while stack:
            node, deps = stack[-1]
            for d in deps:
                if d in udts and not state.get(d):
                    state[d] = 1
                    stack.append((d, iter(_value_deps(udts[d]))))
                    break
            else:
                stack.pop()
                state[node] = 2
                order.append(node)
    return order


def _comment_lines(planner: _TypePlanner, fn: dict) -> list:
    params, ret = [], 'void'
    for p in fn['params']:
        f = p['flags']
        if not f & _CPF_PARM:
            continue
        t = planner.spell(p['type'], f)
        if f & _CPF_RETURN_PARM:
            ret = t
            continue
        ref = '&' if f & (_CPF_OUT_PARM | _CPF_REFERENCE_PARM) else ''
        out = ' [out]' if f & _CPF_OUT_PARM and not f & _CPF_CONST_PARM else ''
        params.append(f"{t}{ref} {p['name']}{out}")
    return [f"{_COMMENT_MARK}{fn['path']}", f"{_flag_names(fn['flags'])}, params 0x{fn['params_size']:X}",
            f"({', '.join(params)}) -> {ret}"]


def _also_line(names: list, used: int) -> str:
    """'also: n1, n2, ...', whole names only, dropped from the end with a '(+N more)' marker so the line
    plus `used` other bytes of the same comment stays inside IDA's cap (R2; never splits a name mid-character).
    """
    budget = max(0, _COMMENT_BYTE_LIMIT - used)
    full = _ALSO_MARK + ', '.join(names)
    if len(full.encode('utf-8')) <= budget:
        return full
    lo, hi, best = 0, len(names), ''
    while lo <= hi:
        mid = (lo + hi) // 2
        omitted = len(names) - mid
        line = _ALSO_MARK + ', '.join(names[:mid]) + (f' (+{omitted} more)' if omitted else '')
        if len(line.encode('utf-8')) <= budget:
            best, lo = line, mid + 1
        else:
            hi = mid - 1
    return best


def _fit(s: str, limit: int) -> str:
    """`s` cut to `limit` UTF-8 bytes on a character boundary, ending in '...' when cut; `s` has no lone surrogate."""
    b = s.encode('utf-8')
    if len(b) <= limit:
        return s
    return b[:max(0, limit - 3)].decode('utf-8', 'ignore') + '...'


def _exec_comment(lines: list, also: list) -> list:
    """The exec comment within IDA's cap: line 3 is shortened first, the 'also:' line takes what remains."""
    lines = [_text(line) for line in lines]
    shortest_also = len((_ALSO_MARK + f' (+{len(also)} more)').encode('utf-8')) + 1 if also else 0
    head = len('\n'.join(lines[:2]).encode('utf-8')) + 1
    lines[2] = _fit(lines[2], _COMMENT_BYTE_LIMIT - head - shortest_also)
    if also and (line := _also_line(also, len('\n'.join(lines).encode('utf-8')) + 1)):
        lines.append(line)
    return lines


def _check_options(types, roots):
    if types not in ('all', 'referenced', 'none'):
        raise ValueError(f"types must be 'all', 'referenced' or 'none', got {types!r}")
    if isinstance(roots, (str, bytes)) or not hasattr(roots, '__iter__'):
        raise TypeError('roots must be an iterable of str')
    roots = list(roots)
    if not all(isinstance(r, str) for r in roots):
        raise TypeError('roots must be an iterable of str')
    if types == 'referenced' and not roots:
        raise _UsageError("types='referenced' needs at least one root")
    return roots


def plan(view: SnapshotView, *, types='all', roots=(), exec_names=True, vtables=True, global_names=True,
         core_types=True, enums=True, comments=True, ident=None) -> dict:
    """Everything run() would put into the IDB, in plain Python (`ident` validates identifiers; default: IDA's if present)."""
    view._check()
    roots = _check_options(types, roots)
    ident = ident or _default_ident()
    planner = _TypePlanner(view, types=types, roots=roots, core_types=core_types, enums=enums, ident=ident)
    type_plan = planner.plan() if (types != 'none' or core_types or enums) else {
        'udts': [], 'enums': [], 'fwd': [], 'records': 0, 'core': 0, 'containers': 0, 'members_dropped': 0, 'members_untyped': 0,
        'missing_keys': planner.missing_keys, 'selected': []}
    dups = {}
    by_rva = collections.OrderedDict()
    exec_fn = collections.OrderedDict()
    counts = {'exec': 0, 'vtables': 0}
    for rva, name, fn, cls in _walk_idmap(view, dups):
        if fn is None and not vtables or fn is not None and not exec_names:
            if fn is not None:
                exec_fn[rva] = fn
            continue
        counts['vtables' if fn is None else 'exec'] += 1
        by_rva.setdefault(rva, []).append(name)
        if fn is not None:
            exec_fn[rva] = fn
    names = [(rva, ns[0], ns[1:]) for rva, ns in by_rva.items()]
    notes = collections.OrderedDict()
    for rva, ns in by_rva.items():
        also = ns[1:] + [n for n, _f, _c in dups.get(rva, ())]
        if also:
            notes[rva] = [_also_line(also, 0)]
    if comments:
        for rva, fn in exec_fn.items():
            also = [n for n in by_rva.get(rva, [])[1:]] + [n for n, _f, _c in dups.get(rva, ())]
            notes[rva] = _exec_comment(_comment_lines(planner, fn), also)
    comment_plan = [(rva, _fit(_text('\n'.join(lines)), _COMMENT_BYTE_LIMIT), rva in exec_fn and comments)
                    for rva, lines in notes.items()]
    globals_plan, skipped = [], []
    if global_names:
        recs = global_records(view)
        for g in _GLOBALS:
            if g not in recs:
                skipped.append(g)
                continue
            decl = {'GWorld': 'UWorld *', 'GObjects': 'TUObjectArray', 'ProcessEvent': _PE_PROTOTYPE}.get(g)
            globals_plan.append((g, recs[g], _GLOBAL_IDA_NAMES[g], g in ('ProcessEvent', 'AppendString'), decl))
    return {'names': names, 'comments': comment_plan, 'exec_rvas': list(exec_fn) if comments else [],
            'globals': globals_plan, 'globals_skipped': skipped, 'types': type_plan, 'counts': counts}


# --- IDA apply (IDA 9.x only) ---

def _require_ida():
    if sys.version_info < (3, 10):
        raise RuntimeError(f'ue_dumper_import needs Python 3.10 or later; this IDA runs Python {sys.version.split()[0]}')
    try:
        import ida_typeinf
        import ida_kernwin  # noqa: F401
    except ImportError:
        raise RuntimeError('ue_dumper_import.run needs IDA: run it inside IDA 9.x or idalib') from None
    if not hasattr(ida_typeinf, 'udt_type_data_t') or not hasattr(ida_typeinf.udt_type_data_t, 'set_fixed'):
        raise RuntimeError('ue_dumper_import needs IDA 9.0 or later; on IDA 7.x / 8.x import the .idmap with the IDAExecFunctionsImporter plugin')


def _idb_facts() -> dict:
    import struct
    import ida_nalt
    import idautils
    facts = {'input_file': os.path.basename(ida_nalt.get_root_filename() or '') or '?'}
    sha = ida_nalt.retrieve_input_file_sha256()
    if isinstance(sha, (bytes, bytearray)) and len(sha) == 32:
        facts['sha256'] = sha.hex()
    try:
        hdr = idautils.peutils_t().header()
    except Exception:
        hdr = None
    if isinstance(hdr, (bytes, bytearray)) and len(hdr) >= 84 and hdr[:4] == b'PE\0\0':
        facts['pe_timestamp'] = struct.unpack_from('<I', hdr, 8)[0]
        facts['size_of_image'] = struct.unpack_from('<I', hdr, 24 + 56)[0]
    return facts


class _Applier:
    """Applies a plan() to the open IDB under R8 (keep what is not ours, change nothing that already matches)."""

    def __init__(self, overwrite: bool, verbose: bool):
        import ida_netnode
        self.overwrite = overwrite
        self.verbose = verbose
        self.nn = ida_netnode.netnode(_NETNODE, 0, True)
        self.report = {'names': dict.fromkeys(('set', 'unchanged', 'replaced', 'kept', 'failed', 'renamed_for_ida'), 0),
                       'types': dict.fromkeys(('created', 'replaced', 'unchanged', 'kept', 'failed', 'members_dropped',
                                               'members_untyped'), 0),
                       'comments': dict.fromkeys(('set', 'unchanged', 'replaced', 'kept', 'failed'), 0),
                       'kept': [], 'failures': []}
        self.cancelled = False
        self._ticks = 0

    def tick(self) -> bool:
        import ida_kernwin
        self._ticks += 1
        if self._ticks % 256 == 0 and ida_kernwin.is_idaq() and ida_kernwin.user_cancelled():
            self.cancelled = True
        return self.cancelled

    def fail(self, bucket: str, what: str, reason: str):
        self.report[bucket]['failed'] += 1
        self.report['failures'].append((what, reason))

    def keep(self, bucket: str, kind: str, ea: 'int | None', cur: str, planned: str):
        self.report[bucket]['kept'] += 1
        self.report['kept'].append((ea, cur, planned, kind))

    def _rec(self, ea: int, tag: str):
        v = self.nn.supstr_ea(ea, ord(tag))
        if not v and tag in 'NP':
            v = self.nn.supstr(ea, ord(tag))  # the absolute-ea key of imports before C8.G.2
        return tuple(v.split('\n', 1)) if v and '\n' in v else None

    def _record(self, ea: int, tag: str, value: str, rec=None):
        if rec != tuple(value.split('\n', 1)):
            self.nn.supset_ea(ea, value, ord(tag))

    def _comment_digest(self, ea: int) -> 'str | None':
        rec = self._rec(ea, 'C')
        return rec[1] if rec and rec[0] == '1' else None

    def _type_digest(self, name: str) -> 'str | None':
        v = self.nn.supstr(_type_key(name), ord('T'))
        parts = v.split('\n') if v else []
        return parts[1] if len(parts) == 3 and parts[0] == '1' and parts[2] == name else None

    def _record_type(self, name: str, digest: str):
        if self._type_digest(name) != digest:
            self.nn.supset(_type_key(name), f'1\n{digest}\n{name}', ord('T'))

    # -- types

    def _tif(self, spec):
        import ida_typeinf as T
        k = spec[0]
        if k == 'void':
            return T.tinfo_t(T.BT_VOID)
        if k == 'int':
            bt = {1: T.BT_INT8, 2: T.BT_INT16, 4: T.BT_INT32, 8: T.BT_INT64}[spec[1]]
            return T.tinfo_t(bt | (T.BTMT_SIGNED if spec[2] else T.BTMT_USIGNED))
        if k == 'float':
            return T.tinfo_t(T.BTF_FLOAT if spec[1] == 4 else T.BTF_DOUBLE)
        if k == 'bool':
            return T.tinfo_t(T.BTF_BOOL)
        if k == 'wchar':
            t = T.tinfo_t()
            if T.parse_decl(t, None, 'wchar_t __ue_wchar;', T.PT_SIL) is not None:
                return t
            return T.tinfo_t(T.BT_INT16 | T.BTMT_USIGNED)
        if k == 'ptr':
            t = T.tinfo_t()
            t.create_ptr(self._tif(spec[1]))
            return t
        if k == 'array':
            t = T.tinfo_t()
            t.create_array(self._tif(spec[1]), spec[2])
            return t
        if k == 'bitfield':
            t = T.tinfo_t()
            t.create_bitfield(spec[1], 1, True)
            return t
        if k == 'named':
            if self._existing(spec[1]) is None:
                T.tinfo_t().create_forward_decl(None, T.BTF_STRUCT, spec[1])
            t = T.tinfo_t()
            t.create_typedef(None, spec[1], T.BTF_TYPEDEF, False)  # a reference by name, never an inlined copy
            return t
        raise ValueError(f'unknown type spec {spec!r}')

    def _existing(self, name: str):
        import ida_typeinf as T
        t = T.tinfo_t()
        return t if t.get_named_type(None, name) else None

    @staticmethod
    def _shape(t, cmt: 'str | None' = None) -> tuple:
        """The `T` record's digest input; `cmt` stands in for the type comment of a type not yet in the IDB."""
        import ida_typeinf as T
        cmt = (t.get_type_cmt() or '') if cmt is None else cmt
        if t.is_enum():
            ei = T.enum_type_data_t()
            t.get_enum_details(ei)
            return 'enum', t.get_size(), bool(ei.is_number_signed()), cmt, [(m.name, int(m.value), m.cmt or '') for m in ei]
        u = T.udt_type_data_t()
        if not t.get_udt_details(u):
            return 'other', str(t), cmt
        return ('udt', t.get_size(), bool(u.is_fixed()), bool(u.is_cppobj()), cmt,
                [(m.name, int(m.offset), int(m.size), str(m.type), bool(m.is_baseclass()), m.cmt or '') for m in u])

    def _put_type(self, name: str, new, comment: str, folder: str) -> str:
        import ida_typeinf as T
        cur = self._existing(name)
        if cur is not None and not cur.is_forward_decl():
            have = repr(self._shape(cur))
            if have == repr(self._shape(new, comment)):
                self._record_type(name, _digest(have))
                return 'unchanged'
            rec = self._type_digest(name)
            ours = _digest(have) == rec if rec is not None else (cur.get_type_cmt() or '').startswith(_TYPE_MARK)
            if not ours and not self.overwrite:
                return 'kept'
            action = 'replaced'
        else:
            action = 'created'
        rc = new.set_named_type(None, name, T.NTF_REPLACE)
        if rc != T.TERR_OK:
            raise RuntimeError(f'set_named_type returned {rc}')
        named = self._existing(name)
        if named is None or named.set_type_cmt(comment) != T.TERR_OK:
            raise RuntimeError('cannot set the type comment')
        self._record_type(name, _digest(repr(self._shape(self._existing(name)))))
        if action == 'created':
            self._move(name, folder)
        return action

    def _move(self, name: str, folder: str):
        import ida_dirtree
        dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_LOCAL_TYPES)
        target = f'/{folder}/{name}'
        if dt.isfile(target):
            return
        parts = folder.split('/')
        for n in range(1, len(parts) + 1):
            d = '/' + '/'.join(parts[:n])
            if not dt.isdir(d):
                dt.mkdir(d)
        dt.rename(name, target)

    def _udt_tif(self, u: dict):
        import ida_typeinf as T
        udt = T.udt_type_data_t()
        udt.taudt_bits |= T.TAUDT_CPPOBJ
        if u['base']:
            m = T.udm_t()
            m.name = u['base']
            m.type = self._tif(_named(u['base']))
            m.offset = 0
            m.size = u['base_size'] * 8
            m.set_baseclass(True)
            udt.push_back(m)
        for name, lo, nbits, spec in u['members']:
            m = T.udm_t()
            m.name = name
            m.type = self._tif(spec)
            m.offset = lo
            m.size = nbits
            udt.push_back(m)
        udt.total_size = u['size']
        udt.unpadded_size = u['size']
        udt.set_fixed(True)
        t = T.tinfo_t()
        if not t.create_udt(udt, T.BTF_STRUCT):
            raise RuntimeError('create_udt failed')
        return t

    def _enum_tif(self, e: dict):
        import ida_typeinf as T
        ei = T.enum_type_data_t()
        ei.set_nbytes(e['width'])
        if e['signed']:
            ei.set_enum_radix(16, True)
        mask = (1 << (8 * e['width'])) - 1
        for name, value in e['members']:
            ei.add_constant(name, value & mask)
        t = T.tinfo_t()
        if not t.create_enum(ei):
            raise RuntimeError('create_enum failed')
        return t

    def forward_declare(self, names):
        import ida_typeinf as T
        for name in names:
            if self._existing(name) is None:
                T.tinfo_t().create_forward_decl(None, T.BTF_STRUCT, name)

    def apply_types(self, tp: dict):
        r = self.report['types']
        r['members_dropped'] += tp['members_dropped']
        r['members_untyped'] += tp['members_untyped']
        self.forward_declare([u['name'] for u in tp['udts']] + tp['fwd'])
        for e in tp['enums']:
            if self.tick():
                return
            try:
                self._count_type(e, self._put_type(e['name'], self._enum_tif(e), e['comment'], e['folder']))
            except Exception as ex:
                self.fail('types', f"enum {e['name']}", f'{type(ex).__name__}: {ex}')
        for u in tp['udts']:
            if self.tick():
                return
            try:
                self._count_type(u, self._put_type(u['name'], self._udt_tif(u), u['comment'], u['folder']))
            except Exception as ex:
                self.fail('types', f"type {u['name']}", f'{type(ex).__name__}: {ex}')

    def _count_type(self, planned: dict, action: str):
        if action == 'kept':
            self.keep('types', 'type', None, planned['name'], planned['comment'].split('\n', 1)[0])
        else:
            self.report['types'][action] += 1

    # -- names

    def _set_name(self, ea: int, planned: str) -> 'str | None':
        import ida_name
        flags = ida_name.SN_NOCHECK | ida_name.SN_NOWARN
        if ida_name.set_name(ea, planned, flags):
            return planned
        valid = ida_name.validate_name(planned, ida_name.VNT_IDENT, ida_name.SN_NOCHECK)
        if valid and valid != planned and ida_name.set_name(ea, valid, flags):
            self.report['names']['renamed_for_ida'] += 1
            return valid
        if ida_name.set_name(ea, valid or planned, flags | ida_name.SN_FORCE):
            self.report['names']['renamed_for_ida'] += 1
            return ida_name.get_name(ea)
        return None

    def apply_name(self, ea: int, planned: str):
        import ida_bytes
        import ida_name
        r = self.report['names']
        cur = ida_name.get_name(ea) or ''
        rec = self._rec(ea, 'N')
        if cur == planned or (rec and rec[0] == planned and rec[1] == cur):
            self._record(ea, 'N', f'{planned}\n{cur}', rec)
            r['unchanged'] += 1
            return
        flags = ida_bytes.get_flags(ea)
        if not cur or ida_bytes.has_dummy_name(flags) or ida_bytes.has_auto_name(flags):
            action = 'set'
        elif rec and rec[1] == cur or self.overwrite:
            action = 'replaced'
        else:
            self.keep('names', 'name', ea, cur, planned)
            return
        if ida_bytes.is_tail(flags):
            self.fail('names', f'name {planned} at {ea:#x}', 'the address is inside an instruction or data item')
            return
        applied = self._set_name(ea, planned)
        if applied is None:
            self.fail('names', f'name {planned} at {ea:#x}', 'IDA refused the name')
            return
        self._record(ea, 'N', f'{planned}\n{applied}')
        r[action] += 1

    # -- comments and prototypes

    def apply_comment(self, ea: int, text: str):
        import ida_bytes
        import ida_funcs
        r = self.report['comments']
        pfn = ida_funcs.get_func(ea)
        on_func = pfn is not None and pfn.start_ea == ea
        read = lambda: (ida_funcs.get_func_cmt(pfn, True) if on_func else ida_bytes.get_cmt(ea, True)) or ''
        cur = read()
        rec = self._comment_digest(ea)
        if cur == text:
            if rec != _digest(cur):
                self._record(ea, 'C', f'1\n{_digest(cur)}')
            r['unchanged'] += 1
            return
        if not cur:
            action = 'set'
        elif (_digest(cur) == rec if rec is not None else cur.startswith(_COMMENT_MARK)) or self.overwrite:
            action = 'replaced'
        else:
            self.keep('comments', 'comment', ea, cur.split('\n', 1)[0], text.split('\n', 1)[0])
            return
        if not on_func and ida_bytes.is_tail(ida_bytes.get_flags(ea)):
            self.fail('comments', f'comment at {ea:#x}', 'the address is inside an instruction or data item')
            return
        ok = ida_funcs.set_func_cmt(pfn, text, True) if on_func else ida_bytes.set_cmt(ea, text, True)
        if not ok:
            self.fail('comments', f'comment at {ea:#x}', 'IDA refused the comment')
            return
        self._record(ea, 'C', f'1\n{_digest(read())}')
        r[action] += 1

    def apply_type_at(self, ea: int, decl: str, bucket: str, *, function: bool):
        import ida_funcs
        import ida_nalt
        import ida_typeinf as T
        r = self.report[bucket]
        if function:
            pfn = ida_funcs.get_func(ea)
            if pfn is None or pfn.start_ea != ea:
                return
        t = T.tinfo_t()
        text = decl.replace('__fastcall(', '__fastcall __ue_decl(', 1) if function else f'{decl} __ue_decl'
        if T.parse_decl(t, None, text + ';', T.PT_SIL) is None:
            self.fail(bucket, f'type at {ea:#x}', f'cannot parse {decl!r}')
            return
        planned = str(t)
        cur_t = T.tinfo_t()
        cur = str(cur_t) if ida_nalt.get_tinfo(cur_t, ea) else ''
        rec = self._rec(ea, 'P')
        if cur == planned:
            self._record(ea, 'P', f'{planned}\n{planned}', rec)
            r['unchanged'] += 1
            return
        if not cur:
            action = 'set'
        elif rec and rec[1] == cur or self.overwrite:
            action = 'replaced'
        else:
            self.keep(bucket, 'decl', ea, cur, planned)
            return
        if not function and not self.overwrite and self._user_data_in_span(ea, t.get_size(), own_item=action == 'replaced'):
            self.keep(bucket, 'decl', ea, '<user data in span>', planned)
            return
        if not T.apply_tinfo(ea, t, T.TINFO_DEFINITE):
            self.fail(bucket, f'type at {ea:#x}', f'IDA refused {decl!r}')
            return
        self._record(ea, 'P', f'{planned}\n{planned}')
        r[action] += 1

    @staticmethod
    def _user_data_in_span(ea: int, size: int, *, own_item: bool) -> bool:
        """`ea` is inside another item, or [ea, ea+size) holds a user name, a comment or an item reaching past it.

        `own_item`: the item at `ea` is ours, so its own size does not count.
        """
        import ida_bytes
        import ida_idaapi
        import ida_name
        if ida_bytes.is_tail(ida_bytes.get_flags(ea)):
            return True
        end = ea + max(size, 1)
        h = ea
        while h != ida_idaapi.BADADDR and h < end:
            f = ida_bytes.get_flags(h)
            if h != ea and (ida_name.get_name(h) and not ida_bytes.has_dummy_name(f) and not ida_bytes.has_auto_name(f)
                            or ida_bytes.get_cmt(h, False) or ida_bytes.get_cmt(h, True)):
                return True
            if h + ida_bytes.get_item_size(h) > end and not (own_item and h == ea):
                return True
            h = ida_bytes.next_head(h, end)
        return False


def _say(line: str):
    print(f'{_TAG} {line}')


def _fmt(n: int) -> str:
    return f'{n:,}'


def run(snapshot, *, types='all', roots=(), exec_names=True, vtables=True, global_names=True,
        core_types=True, enums=True, comments=True, overwrite=False, force=False, verbose=False) -> dict:
    """Import `snapshot` into the open IDB and return the report; refuses a mismatched build unless `force`."""
    if not isinstance(snapshot, (str, os.PathLike)):
        raise TypeError(f'snapshot must be str or os.PathLike, got {type(snapshot).__name__}')
    roots = _check_options(types, roots)
    _require_ida()
    import ida_kernwin
    import ida_nalt
    started = time.monotonic()
    with load_snapshot(snapshot) as view:
        address_bound = exec_names or vtables or global_names or comments
        make_plan = lambda: plan(view, types=types, roots=roots, exec_names=exec_names, vtables=vtables, global_names=global_names,
                                 core_types=core_types, enums=enums, comments=comments, ident=_ida_ident)
        p = make_plan() if types == 'referenced' else None  # a bad root is a usage error before any build verdict
        schema = view.meta['schema']['version']
        ts = _snapshot_build(view.meta)[1]
        head = f"snapshot {os.path.basename(os.path.normpath(os.fspath(snapshot)))} · schema {schema} · "
        if address_bound:
            verdict, text = check_build(view.meta, _idb_facts())
            build = f'build 0x{ts:08X}' if ts is not None else 'build'
            if verdict in ('mismatch', 'unknown'):
                if not force:
                    _say(head + f"{build} {'does not match this IDB' if verdict == 'mismatch' else 'cannot be checked'}")
                    for line in text.split('\n'):
                        _say(line)
                    raise BuildRefusedError(verdict, text)
                _say(head + f'{build} {verdict}; importing anyway (force)')
            else:
                _say(head + f"{build} matches ({'SHA-256' if verdict == 'sha256' else 'PE timestamp and size'})")
        else:
            verdict = 'skipped'
            _say(head + 'build check skipped (no address-bound action)')
        if p is None:
            p = make_plan()
    ap = _Applier(overwrite, verbose)
    base = ida_nalt.get_imagebase()
    waitbox = ida_kernwin.is_idaq()
    if waitbox:
        ida_kernwin.show_wait_box('Importing the UE snapshot...')
    try:
        with ida_kernwin.disabled_script_timeout_t():
            if p['types']['udts'] or p['types']['enums']:
                ap.apply_types(p['types'])
            if p['exec_rvas'] or p['globals']:
                ap.forward_declare(('UObject', 'UFunction', 'FFrame'))
            for rva, name, _also in p['names']:
                if ap.tick():
                    break
                ap.apply_name(base + rva, name)
            for g, rva, name, is_func, decl in p['globals']:
                if ap.cancelled:
                    break
                ap.apply_name(base + rva, name)
                if decl and (is_func or ap._existing(decl.rstrip(' *')) is not None):
                    ap.apply_type_at(base + rva, decl, 'names', function=is_func)
            for rva, text, is_exec in p['comments']:
                if ap.tick():
                    break
                ap.apply_comment(base + rva, text)
            for rva in p['exec_rvas']:
                if ap.tick():
                    break
                ap.apply_type_at(base + rva, _EXEC_PROTOTYPE, 'comments', function=True)
    finally:
        if waitbox:
            ida_kernwin.hide_wait_box()
    report = {'snapshot': os.fspath(snapshot), 'build': verdict, 'forced': bool(force and verdict in ('mismatch', 'unknown')),
              'names': ap.report['names'], 'types': ap.report['types'], 'comments': ap.report['comments'],
              'kept': ap.report['kept'], 'failures': ap.report['failures'], 'seconds': round(time.monotonic() - started, 3),
              'cancelled': ap.cancelled}
    _print_report(report, p, verbose)
    return report


def _print_report(report: dict, p: dict, verbose: bool):
    t = report['types']
    kept_names = [k for k in report['kept'] if k[3] == 'name']
    kept_other = [k for k in report['kept'] if k[3] != 'name']
    _say(f"names     {_fmt(p['counts']['exec'])} exec · {_fmt(p['counts']['vtables'])} vtables · "
         f"{len(p['globals'])} globals; kept {_fmt(len(kept_names))} names you set by hand")
    if p['globals_skipped']:
        _say('globals   skipped (no rva in the snapshot): ' + ' '.join(p['globals_skipped']))
    tp = p['types']
    _say(f"types     {_fmt(tp['core'])} core · {_fmt(tp['containers'])} containers · {_fmt(len(tp['enums']))} enums · "
         f"{_fmt(tp['records'])} classes and structs; {_fmt(t['failed'])} failed")
    if tp['missing_keys']:
        _say('types     offsets.json keys missing, their core members are omitted: ' + ', '.join(tp['missing_keys']))
    _say(f"comments  {_fmt(len(p['exec_rvas']))} exec functions")
    _say('report    ' + ' '.join(f'{b}.{k} {v}' for b in ('names', 'types', 'comments') for k, v in report[b].items()))
    for what, reason in report['failures'][:None if verbose else 10]:
        _say(f'failed    {what}: {reason}')
    if report['cancelled']:
        _say('cancelled; running it again continues where this run stopped')
    _say(f"done in {report['seconds']:.1f} s; running it again updates the same types and names in place")
    if kept_names:
        shown = kept_names if verbose else kept_names[:3]
        _say(f'kept names (first {len(shown)} of {len(kept_names)}, the rest with -v):' if len(shown) < len(kept_names)
             else f'kept names ({len(kept_names)}):')
        for ea, cur, planned, _kind in shown:
            print(f'    0x{ea:X}  {cur:<28} (snapshot: {planned})')
    if kept_other:
        shown = kept_other if verbose else kept_other[:3]
        _say(f'kept comments, prototypes and types (first {len(shown)} of {len(kept_other)}, the rest with -v):'
             if len(shown) < len(kept_other) else f'kept comments, prototypes and types ({len(kept_other)}):')
        for ea, cur, planned, kind in shown:
            print(f"    {'-' if ea is None else f'0x{ea:X}'}  {kind:<7} {cur:<28} (snapshot: {planned})")


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog='ue_dumper_import.py', description='Import a nylib.ue snapshot into this IDB.')
    ap.add_argument('--snapshot', required=True, metavar='PATH')
    ap.add_argument('--no-exec', dest='exec_names', action='store_false')
    ap.add_argument('--no-vtables', dest='vtables', action='store_false')
    ap.add_argument('--no-globals', dest='global_names', action='store_false')
    ap.add_argument('--no-core-types', dest='core_types', action='store_false')
    ap.add_argument('--no-enums', dest='enums', action='store_false')
    ap.add_argument('--types', choices=('all', 'referenced', 'none'), default='all')
    ap.add_argument('--roots', default='', metavar='A,B')
    ap.add_argument('--no-comments', dest='comments', action='store_false')
    ap.add_argument('--overwrite', action='store_true')
    ap.add_argument('--force', action='store_true')
    ap.add_argument('-v', dest='verbose', action='store_true')
    return ap


def main(argv: 'list | None' = None) -> int:
    """Batch entry: 0 done, 1 error or a failed action, 2 usage, 3 build refused."""
    try:
        args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as e:
        return 0 if e.code in (0, None) else 2
    roots = [r.strip() for r in args.roots.split(',') if r.strip()]
    try:
        report = run(args.snapshot, types=args.types, roots=roots, exec_names=args.exec_names, vtables=args.vtables,
                     global_names=args.global_names, core_types=args.core_types, enums=args.enums, comments=args.comments,
                     overwrite=args.overwrite, force=args.force, verbose=args.verbose)
    except _UsageError as e:
        _say(f'error: {e}')
        return 2
    except BuildRefusedError:
        _say('refused: the build does not match; pass --force to import anyway')
        return 3
    except (SnapshotFormatError, RuntimeError) as e:
        _say(f'error: {e}')
        return 1
    except Exception as e:
        traceback.print_exc()
        _say(f'error: unexpected {type(e).__name__}: {e}')
        return 1
    return 1 if report['failures'] or report['cancelled'] else 0


# --- the dialog (run modes 1 and 2) ---

def _last_folder() -> str:
    import ida_netnode
    return ida_netnode.netnode(_NETNODE, 0, True).hashstr('last_folder') or ''


def _remember_folder(folder: str):
    import ida_netnode
    ida_netnode.netnode(_NETNODE, 0, True).hashset_buf('last_folder', folder)


def _describe(folder: str) -> tuple:
    try:
        with load_snapshot(folder) as view:
            target = view.meta.get('target') if isinstance(view.meta.get('target'), dict) else {}
            info = ' · '.join(str(x) for x in (target.get('game_name') or target.get('stem') or '?',
                                                    'schema ' + view.meta['schema']['version'],
                                                    view.meta.get('created', '?'), view.meta.get('mode', '?')))
            return info, check_build(view.meta, _idb_facts())[1].split('\n', 1)[0]
    except (SnapshotFormatError, OSError) as e:
        return str(e), ''


def _dialog():
    _require_ida()
    import ida_kernwin
    F = ida_kernwin.Form

    class ImportForm(F):
        def __init__(self, folder: str):
            info, build = _describe(folder) if folder else ('', '')
            super().__init__(r"""STARTITEM 0
BUTTON YES* Import
BUTTON CANCEL Cancel
UE Dumper Import

{FormChangeCb}
<Snapshot :{iFolder}>
<Info     :{iInfo}>
<Build    :{iBuild}>
<##Names##exec functions:{cExec}>
<vtables:{cVft}>
<globals:{cGlobals}>{cgNames}>
<##Types##engine core types:{cCore}>
<enums:{cEnums}>{cgTypes}>
<all classes and structs:{rAll}>
<only these and what they reference:{rRef}>
<none:{rNone}>{rgScope}>
<Roots :{iRoots}>
<##Comments##UFunction signature and flags on each exec function:{cComments}>{cgComments}>
<##Conflicts##overwrite names I set by hand (off: keep yours and list them):{cOverwrite}>{cgConflicts}>
""", {
                'FormChangeCb': F.FormChangeCb(self.on_change),
                'iFolder': F.DirInput(value=folder),
                'iInfo': F.StringInput(value=info, swidth=70),
                'iBuild': F.StringInput(value=build, swidth=70),
                'cgNames': F.ChkGroupControl(('cExec', 'cVft', 'cGlobals'), value=7),
                'cgTypes': F.ChkGroupControl(('cCore', 'cEnums'), value=3),
                'rgScope': F.RadGroupControl(('rAll', 'rRef', 'rNone'), value=0),
                'iRoots': F.StringInput(swidth=60),
                'cgComments': F.ChkGroupControl(('cComments',), value=1),
                'cgConflicts': F.ChkGroupControl(('cOverwrite',), value=0),
            })

        def on_change(self, fid):
            if fid == self.iFolder.id:
                info, build = _describe(self.GetControlValue(self.iFolder))
                self.SetControlValue(self.iInfo, info)
                self.SetControlValue(self.iBuild, build)
            return 1

    form = ImportForm(_last_folder())
    form.Compile()
    try:
        if form.Execute() != 1:
            return
        folder = form.iFolder.value
        names, tps, cm, conf = form.cgNames.value, form.cgTypes.value, form.cgComments.value, form.cgConflicts.value
        options = dict(types=('all', 'referenced', 'none')[form.rgScope.value],
                       roots=[r.strip() for r in form.iRoots.value.split(',') if r.strip()],
                       exec_names=bool(names & 1), vtables=bool(names & 2), global_names=bool(names & 4),
                       core_types=bool(tps & 1), enums=bool(tps & 2), comments=bool(cm & 1), overwrite=bool(conf & 1))
    finally:
        form.Free()
    _remember_folder(folder)
    try:
        try:
            run(folder, **options)
        except BuildRefusedError as e:
            if ida_kernwin.ask_buttons('Import anyway', 'Cancel', '', ida_kernwin.ASKBTN_NO, e.text) == ida_kernwin.ASKBTN_YES:
                run(folder, force=True, **options)
    except (SnapshotFormatError, BuildRefusedError, ValueError, TypeError, RuntimeError) as e:
        _say(f'error: {e}')
        ida_kernwin.warning(str(e))
    except Exception as e:
        traceback.print_exc()
        _say(f'error: unexpected {type(e).__name__}: {e}')
        ida_kernwin.warning(f'unexpected {type(e).__name__}: {e}')


def _dialog_or_say():
    try:
        _dialog()
    except RuntimeError as e:  # an unsupported IDA or Python: one line, no traceback
        _say(f'error: {e}')
        import ida_kernwin
        ida_kernwin.warning(str(e))


if ida_idaapi is not None:
    class UeDumperImportPlugin(ida_idaapi.plugin_t):
        flags = 0
        wanted_name = 'UE Dumper Import'
        wanted_hotkey = 'Ctrl-Alt-U'
        comment = 'Import a nylib.ue snapshot: names, types and UFunction comments'
        help = comment

        def init(self):
            return ida_idaapi.PLUGIN_OK

        def run(self, arg):
            _dialog_or_say()

        def term(self):
            pass

    def PLUGIN_ENTRY():
        return UeDumperImportPlugin()


def _script_main():
    try:
        import idc
        import ida_kernwin
        import ida_pro
    except ImportError:
        sys.exit(main())
    argv = list(idc.ARGV[1:]) if len(idc.ARGV) > 1 else []
    if not argv:
        _dialog_or_say()
        return
    code = main(argv)
    if not ida_kernwin.is_idaq():
        ida_pro.qexit(code)


if __name__ == '__main__':
    _script_main()
