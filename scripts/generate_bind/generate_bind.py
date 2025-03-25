import dataclasses
import io
import os.path
import pathlib
import re
import string
import sys
import typing

from nylib.winutils import ensure_env

dll_path = pathlib.Path(ensure_env.ensure_msys2_file('/clang64/bin/libclang.dll'))
lib_path = pathlib.Path(ensure_env.ensure_msys2_file('/clang64/lib/python3.11/site-packages/clang/__init__.py'))
sys.path.append(str(lib_path.parent.parent))
from clang import cindex
cindex.Config.set_library_file(str(dll_path))

operator_mapping = {
    '()': '__call__',
    '+': '__add__',
    '-': '__sub__',
    '*': '__mul__',
    '/': '__truediv__',
    '%': '__mod__',
    '+=': '__iadd__',
    '-=': '__isub__',
    '*=': '__imul__',
    '/=': '__itruediv__',
    '%=': '__imod__',
    '&': '__and__',
    '|': '__or__',
    '^': '__xor__',
    '<<': '__lshift__',
    '>>': '__rshift__',
    '~': '__invert__',
    '==': '__eq__',
    '!=': '__ne__',
    '<': '__lt__',
    '<=': '__le__',
    '>': '__gt__',
    '>=': '__ge__',

    # not python operators
    '=': 'assign',
    '++': 'inc',
    '--': 'dec',
}


def get_item_full_name(cursor: cindex.Cursor):
    s = cursor.spelling
    p = cursor.semantic_parent
    while p:
        if p.kind == cindex.CursorKind.TRANSLATION_UNIT: break
        s = p.spelling + '::' + s
        p = p.semantic_parent
    return s


@dataclasses.dataclass
class Parser:
    _parsers = {}

    def __init__(self, cursor_filter: typing.Callable[[cindex.Cursor], bool] = None):
        self.cursor_filter = cursor_filter
        self.ctx = []
        self.path = []

        self.pointer_types = set()
        self.array_types = set()

    def ex_types_bind(self, parent_name: str):
        base = (
            "([](py::object &m) {{\n"
            "{body}\n"
            "}})({parent_name});"
        )
        body = ''.join(f"nybind::PointerWrapper<{t}>::bind({parent_name});\n" for t in self.pointer_types) + \
               ''.join(f"nybind::ArrayWrapper<{t}>::bind({parent_name});\n" for t in self.array_types)
        return base.format(body=string_indent(body.rstrip()), parent_name=parent_name)

    @property
    def path_str(self):
        return '::'.join(self.path)

    @classmethod
    def add_parser(cls, cursor_kind: cindex.CursorKind):
        def decorator(func: typing.Callable[[Parser, cindex.Cursor, str], typing.Tuple[str | None, str | None]]):
            assert cursor_kind not in cls._parsers
            cls._parsers[cursor_kind] = func
            return func

        return decorator

    def parse(self, cursor: cindex.Cursor, parent_name: str) -> typing.Tuple[str | None, str | None]:
        if self.cursor_filter and not self.cursor_filter(cursor): return None, None
        self.ctx.append(cursor)
        if cursor.kind in self._parsers:
            res = self._parsers[cursor.kind](self, cursor, parent_name)
        else:
            # raise Exception(f"Unknown cursor kind: {cursor.kind}")
            res = f"m;  /* Not implemented: {cursor.kind} {cursor.spelling} at {cursor.location.file}:{cursor.location.line} */", None
        self.ctx.pop()
        return res

    def parse_many(self, cursors: typing.Iterable[cindex.Cursor], parent_name: str, body=None, extra=None):
        body = body or io.StringIO()
        extra = extra or io.StringIO()
        for child in cursors:
            item, extra_item = self.parse(child, parent_name)
            if item:
                print(item, file=body)
            if extra_item:
                print(extra_item, file=extra)
        return body, extra


DEFAULT_INDENT = '    '


def string_indent(string: str, indent: str | int = DEFAULT_INDENT):
    if isinstance(indent, int): indent = ' ' * indent
    return re.sub(r'^', indent, string, flags=re.MULTILINE)


@Parser.add_parser(cindex.CursorKind.TRANSLATION_UNIT)
def parse_translation_unit(self: Parser, cursor: cindex.Cursor, parent_name: str):
    body, extra = self.parse_many(cursor.get_children(), parent_name)
    return body.getvalue(), extra.getvalue()


@Parser.add_parser(cindex.CursorKind.TYPEDEF_DECL)
def parse_typedef(self: Parser, cursor: cindex.Cursor, parent_name: str):
    return None, None


@Parser.add_parser(cindex.CursorKind.STRUCT_DECL)
def parse_struct(self: Parser, cursor: cindex.Cursor, parent_name: str):
    if not cursor.is_definition(): return None, None
    base = (
        "([](py::object &m) {{\n"
        "{body}\n"
        "}})({parent_name});"
    )
    self.path.append(cursor.spelling)
    body = io.StringIO()
    extra = io.StringIO()
    impls = [get_item_full_name(cursor)]
    children = []
    for child in cursor.get_children():
        if child.kind == cindex.CursorKind.CXX_BASE_SPECIFIER:
            impls.append(get_item_full_name(child.referenced))
        else:
            children.append(child)
    print(f"auto c = py::class_<{', '.join(impls)}>(m, \"{cursor.spelling}\");", file=body)
    self.parse_many(children, 'c', body, extra)
    print("return c;", file=body, end='')
    self.path.pop()
    return base.format(body=string_indent(body.getvalue()), parent_name=parent_name), extra.getvalue()


@Parser.add_parser(cindex.CursorKind.FIELD_DECL)
def parse_field(self: Parser, cursor: cindex.Cursor, parent_name: str):
    if not cursor.is_definition(): return None, None
    # deal with special types
    if cursor.type.kind == cindex.TypeKind.POINTER:
        return f"{parent_name} /* {cursor.type.spelling} */;", None
        pointee = cursor.type.get_pointee()
        while pointee.kind == cindex.TypeKind.TYPEDEF: pointee = pointee.get_canonical()
        if pointee.kind == cindex.TypeKind.FUNCTIONPROTO:
            expr = f"NYBIND_DEF_C_FUNC_P_FIELD({self.path_str},{cursor.spelling})"
        else:
            type_name = pointee.spelling
            self.pointer_types.add(type_name[6:] if type_name.startswith('const ') else type_name)
            expr = f"NYBIND_DEF_POINTER_FIELD({self.path_str},{cursor.spelling})"
    elif cursor.type.kind == cindex.TypeKind.CONSTANTARRAY:
        return f"{parent_name} /* {cursor.type.spelling} */;", None
        element_type = cursor.type.element_type
        while element_type.kind == cindex.TypeKind.TYPEDEF: element_type = element_type.get_canonical()
        type_name = element_type.spelling
        self.array_types.add(type_name[6:] if type_name.startswith('const ') else type_name)
        expr = f"NYBIND_DEF_ARRAY_FIELD({self.path_str},{cursor.spelling})"
    # bitfield
    elif cursor.type.kind == cindex.TypeKind.UINT:
        expr = f"def_readwrite(\"{cursor.spelling}\", &{get_item_full_name(cursor)})"
    else:
        expr = f"def_readwrite(\"{cursor.spelling}\", &{get_item_full_name(cursor)})"
    return f"{parent_name}.{expr} /* {cursor.type.spelling} */;", None


@Parser.add_parser(cindex.CursorKind.ENUM_DECL)
def parse_enum(self: Parser, cursor: cindex.Cursor, parent_name: str):
    if not cursor.is_definition(): return None, None
    base = (
        "([](py::object &m) {{\n"
        "{body}\n"
        "}})({parent_name});"
    )
    self.path.append(cursor.spelling)
    body = io.StringIO()
    extra = io.StringIO()
    print(f"NYBIND_ENUM_CAST({get_item_full_name(cursor)});", file=extra, end='')

    print(f"auto IntEnum = py::module_::import(\"enum\").attr(\"IntEnum\");", file=body)
    print(f"m.attr(\"{cursor.spelling}\") = IntEnum(\"{cursor.spelling}\",  py::dict(", file=body)
    for child in cursor.get_children():
        if child.kind == cindex.CursorKind.ENUM_CONSTANT_DECL:
            print(string_indent(f"py::arg(\"{child.spelling}\") = {get_item_full_name(child)},"), file=body)
        else:
            raise RuntimeError(f"Unknown enum child: {child.kind} at {child.location.file}:{child.location.line}")
    body.seek(body.tell() - 2) # remove last comma
    print(f"\n));\nauto e = m.attr(\"{cursor.spelling}\");", file=body)
    for child in cursor.get_children():
        if child.kind == cindex.CursorKind.ENUM_CONSTANT_DECL:
            print(f"m.attr(\"{child.spelling}\") = e.attr(\"{child.spelling}\");", file=body)
    print(f"return e;", file=body, end='')
    self.path.pop()

    return base.format(body=string_indent(body.getvalue()), parent_name=parent_name), extra.getvalue()


@Parser.add_parser(cindex.CursorKind.NAMESPACE)
def parse_namespace(self: Parser, cursor: cindex.Cursor, parent_name: str):
    base = (
        "([](py::module &m_) {{\n"
        "{body}\n"
        "}})({parent_name});"
    )
    body = io.StringIO()
    extra = io.StringIO()
    print(f"auto m = m_.def_submodule(\"{cursor.spelling}\");", file=body)
    self.path.append(cursor.spelling)
    self.parse_many(cursor.get_children(), 'm', body, extra)
    self.path.pop()
    print("return m;", file=body, end='')
    return base.format(body=string_indent(body.getvalue()), parent_name=parent_name), extra.getvalue()


def parse(tu: cindex.TranslationUnit, function_name: str, cursor_filter: typing.Callable[[cindex.Cursor], bool] = None):
    base = (
        "#include <pybind_generate_utils.h>\n"
        "{extra}\n"
        "py::module {function_name}(py::module &m) {{\n"
        "{body}\n"
        "}}"
    )
    parser = Parser(cursor_filter)
    body, extra = parser.parse(tu.cursor, 'm')
    body = parser.ex_types_bind('m') + '\n' + body
    return base.format(body=string_indent(body + "\nreturn m;"), extra=extra, function_name=function_name)
