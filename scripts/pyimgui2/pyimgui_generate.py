import atexit
import io
import json
import keyword
import os
import pathlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from nylib.utils.pip import required
from nylib.winutils import ensure_env
from func_wrappers import wrappers as specified_wrappers


class CodeWriter:
    class IndentPopper:
        def __init__(self, writer, need_push=True):
            self.writer = writer
            self.need_push = need_push

        def __enter__(self):
            if self.need_push:
                self.writer.push_indent()

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.writer.pop_indent()

    def __init__(self, init_ind=0, indent_size=4):
        self.buf = io.StringIO()
        self.indent = init_ind
        self.indent_size = indent_size

    def push_indent(self):
        self.indent += 1
        return self.IndentPopper(self, False)

    def pop_indent(self):
        self.indent -= 1

    def write(self, s):
        self.buf.write(s.replace('\n', '\n' + ' ' * self.indent_size * self.indent))

    def getvalue(self):
        return self.buf.getvalue()


@dataclass
class EnumSpec:
    name: str
    constants: list[tuple[str, int | None]] = field(default_factory=list)


@dataclass
class FieldSpec:
    name: str
    type: str
    is_array: bool = False
    array_size: int | None = None
    is_bitfield: bool = False
    default: str | None = None


@dataclass
class RecordSpec:
    name: str
    fields: list[FieldSpec] = field(default_factory=list)
    methods: list['FunctionSpec'] = field(default_factory=list)
    source: str = ''


@dataclass
class FunctionSpec:
    name: str
    result: str
    args: list[FieldSpec] = field(default_factory=list)
    source: str = ''
    variadic: bool = False
    is_static: bool = False


class ImguiParser:
    def __init__(self, imgui_dir):
        self.imgui_dir = pathlib.Path(imgui_dir)
        self.records: dict[str, RecordSpec] = {}
        self.enums: dict[str, EnumSpec] = {}
        self.functions: dict[str, list[FunctionSpec]] = {}
        self.typedefs: dict[str, str] = {}

    def parse(self):
        from clang import cindex

        index = cindex.Index.create()
        args = [
            '-x', 'c++',
            '-std=c++20',
            '-fms-extensions',
            '-fms-compatibility',
            '-fms-compatibility-version=19.40',
            '-target', 'x86_64-pc-windows-msvc',
            f'-I{self.imgui_dir}',
            f'-I{self.imgui_dir / "backends"}',
        ]
        vc_env = ensure_env.msvc.load_vcvarsall('x86_amd64')
        for include_dir in vc_env.get('INCLUDE', '').split(os.pathsep):
            if include_dir:
                args.append(f'-isystem{include_dir}')
        tu = index.parse(
            str(self.imgui_dir / 'imgui_internal.h'),
            args=args,
            options=cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES,
        )
        diagnostics = [str(diag) for diag in tu.diagnostics if diag.severity >= diag.Error]
        if diagnostics:
            raise RuntimeError('libclang failed to parse imgui_internal.h:\n' + '\n'.join(diagnostics))

        imgui_root = str(self.imgui_dir.resolve())

        def is_imgui_file(cursor):
            file = cursor.location.file
            if file is None:
                return False
            try:
                return os.path.commonpath([str(pathlib.Path(file.name).resolve()), imgui_root]) == imgui_root
            except ValueError:
                return False

        def parse_record(cursor):
            if not cursor.spelling or not cursor.is_definition():
                return
            if '::' in cursor.type.spelling:
                return
            spec = RecordSpec(cursor.spelling)
            if cursor.location.file is not None:
                spec.source = pathlib.Path(cursor.location.file.name).name
            for child in cursor.get_children():
                if child.access_specifier not in (cindex.AccessSpecifier.INVALID, cindex.AccessSpecifier.PUBLIC):
                    continue
                if child.kind == cindex.CursorKind.FIELD_DECL and child.spelling:
                    try:
                        is_bitfield = child.is_bitfield()
                    except Exception:
                        is_bitfield = False
                    is_array = child.type.kind == cindex.TypeKind.CONSTANTARRAY
                    array_size = None
                    field_type = child.type.spelling
                    if is_array:
                        try:
                            array_size = child.type.element_count
                            field_type = child.type.element_type.spelling
                        except Exception:
                            pass
                    spec.fields.append(FieldSpec(
                        child.spelling,
                        field_type,
                        is_array,
                        array_size,
                        is_bitfield,
                    ))
                elif child.kind == cindex.CursorKind.CXX_METHOD and child.spelling:
                    if child.spelling.startswith('operator'):
                        continue
                    spec.methods.append(make_function_spec(child))
            self.records[spec.name] = spec

        def parse_enum(cursor):
            name = cursor.spelling or f'anonymous_{len(self.enums)}'
            spec = EnumSpec(name)
            for child in cursor.get_children():
                if child.kind == cindex.CursorKind.ENUM_CONSTANT_DECL:
                    try:
                        value = child.enum_value
                    except Exception:
                        value = None
                    spec.constants.append((child.spelling, value))
            if spec.constants:
                self.enums[name] = spec

        def make_function_spec(cursor):
            spec = FunctionSpec(cursor.spelling, cursor.result_type.spelling)
            if cursor.location.file is not None:
                spec.source = pathlib.Path(cursor.location.file.name).name
            try:
                spec.variadic = cursor.type.is_function_variadic()
            except Exception:
                spec.variadic = False
            try:
                spec.is_static = cursor.is_static_method()
            except Exception:
                spec.is_static = False
            for child in cursor.get_children():
                if child.kind == cindex.CursorKind.PARM_DECL:
                    default = None
                    tokens = [token.spelling for token in child.get_tokens()]
                    if '=' in tokens:
                        default = ' '.join(tokens[tokens.index('=') + 1:])
                    spec.args.append(FieldSpec(child.spelling, child.type.spelling, default=default))
            return spec

        def parse_function(cursor):
            if cursor.semantic_parent.spelling != 'ImGui':
                return
            spec = make_function_spec(cursor)
            self.functions.setdefault(spec.name, []).append(spec)

        def parse_typedef(cursor):
            if cursor.spelling:
                self.typedefs[cursor.spelling] = cursor.underlying_typedef_type.spelling

        def walk(cursor):
            if is_imgui_file(cursor):
                if cursor.kind in (cindex.CursorKind.STRUCT_DECL, cindex.CursorKind.CLASS_DECL):
                    parse_record(cursor)
                elif cursor.kind == cindex.CursorKind.ENUM_DECL:
                    parse_enum(cursor)
                elif cursor.kind == cindex.CursorKind.FUNCTION_DECL:
                    parse_function(cursor)
                elif cursor.kind == cindex.CursorKind.TYPEDEF_DECL:
                    parse_typedef(cursor)
            for child in cursor.get_children():
                walk(child)

        walk(tu.cursor)
        return self


class PyImguiGenerator:
    def __init__(self, imgui_dir, output_dir, backends):
        self.imgui_dir = pathlib.Path(imgui_dir)
        self.output_dir = pathlib.Path(output_dir)
        self.core_dir = self.output_dir / 'pyimgui_core'
        self.backends = backends
        self.out = []
        self.parser = ImguiParser(imgui_dir)
        self.stub_field_types: dict[str, dict[str, str]] = {}
        self.stub_function_return_types: dict[str, dict[str, str]] = {}

    def generate(self):
        self.parser.parse()
        self.generate_runtime()
        self.generate_enums()
        self.generate_structs()
        self.generate_globals()
        self.out.append((
            self.output_dir / 'pyimgui.h',
            '#pragma once\n'
            '#include "gHeader.h"\n'
            '#include "./pyimgui_core/enums.h"\n'
            '#include "./pyimgui_core/structs.h"\n'
            '#include "./pyimgui_core/globals.h"\n\n'
            '#define PYIMGUI_CORE_NAMESPACE mNameSpace::PyImguiCore\n'
            'namespace mNameSpace{ namespace PyImguiCore{\n'
            'void pybind_setup_pyimgui_core(pybind11::module_ m);\n'
            '}}\n'
        ))
        self.out.append((
            self.output_dir / 'pyimgui.cpp',
            '#include "pyimgui.h"\n'
            'namespace mNameSpace{ namespace PyImguiCore{\n'
            'void pybind_setup_pyimgui_core(pybind11::module_ m) {\n'
            '    pybind_setup_pyimgui_enums(m);\n'
            '    pybind_setup_pyimgui_structs(m);\n'
            '    pybind_setup_pyimgui_globals(m);\n'
            '}\n'
            '}}\n'
        ))
        self.flush()
        return [fn for fn, _ in self.out if fn.suffix == '.cpp']

    def generate_runtime(self):
        trait_defs = CodeWriter(0)
        trait_defs.write('namespace PYBIND11_NAMESPACE { namespace detail {\n')
        for record_name in sorted(self.parser.records):
            if self._is_flat_copy_type(record_name):
                continue
            trait_defs.write(f'template <> struct is_copy_constructible<{record_name}> : std::false_type {{}};\n')
            trait_defs.write(f'template <> struct is_move_constructible<{record_name}> : std::false_type {{}};\n')
        trait_defs.write('}}\n')
        self.out.append((
            self.core_dir / 'runtime.h',
            '#pragma once\n'
            '#include "gHeader.h"\n'
            f'{trait_defs.getvalue()}'
            '#include "PyImguiCoreRuntime.h"\n'
        ))

    def generate_enums(self):
        enum_defs = CodeWriter(1)
        enum_casts = CodeWriter(0)
        enum_defs.write('auto IntEnum = py::module_::import("enum").attr("IntEnum");\n')
        enum_casts.write(r'''
#define ENUM_CAST(T) \
namespace PYBIND11_NAMESPACE { namespace detail { \
    template <> struct type_caster<T> { \
    public: \
        PYBIND11_TYPE_CASTER(T, const_name("T")); \
        bool load(handle src, bool convert) { \
            PyObject* source = src.ptr(); \
            PyObject* tmp = PyNumber_Long(source); \
            if (!tmp) return false; \
            value = (T)PyLong_AsLong(tmp); \
            Py_DECREF(tmp); \
            return !PyErr_Occurred(); \
        } \
        static handle cast(T src, return_value_policy policy, handle parent) { \
            return PyLong_FromLong((long)src); \
        } \
    }; \
}}

''')
        exported = set()
        used_python_enum_names = set()
        for enum in self.parser.enums.values():
            constants = [(const_name, value) for const_name, value in enum.constants if const_name and value is not None]
            if not constants:
                continue
            if enum.name.startswith('anonymous_'):
                for const_name, value in constants:
                    if const_name in exported:
                        continue
                    exported.add(const_name)
                    enum_defs.write(f'm.attr("{const_name}") = py::int_({value});\n')
                continue
            enum_python_name = self._python_enum_name(enum.name)
            enum_python_name_base = enum_python_name
            enum_python_name_suffix = 2
            while enum_python_name in used_python_enum_names:
                enum_python_name = f'{enum_python_name_base}{enum_python_name_suffix}'
                enum_python_name_suffix += 1
            used_python_enum_names.add(enum_python_name)
            enum_defs.write(f'm.attr("{enum_python_name}") = IntEnum("{enum_python_name}", py::dict(\n')
            with enum_defs.push_indent():
                for index, (const_name, value) in enumerate(constants):
                    enum_defs.write(f'py::arg("{const_name}") = py::int_({value})')
                    enum_defs.write(',\n' if index < len(constants) - 1 else '\n')
            enum_defs.write('), py::arg("module") = m.attr("__name__"));\n')
            enum_var = f'enum_{enum_python_name}'
            enum_defs.write(f'auto {enum_var} = m.attr("{enum_python_name}");\n')
            for const_name, value in constants:
                if const_name in exported:
                    continue
                exported.add(const_name)
                enum_defs.write(f'm.attr("{const_name}") = {enum_var}.attr("{const_name}");\n')
            enum_casts.write(f'ENUM_CAST({enum.name});\n')

        # ENUM_CAST macro + all per-enum type_caster specializations live in the
        # header so they're visible in every TU that emits pybind11 bindings
        # (structs.cpp, globals.cpp, …). If they live in enums.cpp only,
        # other TUs fall back to "Unregistered type" at runtime.
        self.out.append((
            self.core_dir / 'enums.h',
            '#pragma once\n'
            '#include "gHeader.h"\n'
            f'{enum_casts.getvalue()}\n'
            'namespace mNameSpace{ namespace PyImguiCore{\n'
            'void pybind_setup_pyimgui_enums(pybind11::module_ m);\n'
            '}}\n'
        ))
        self.out.append((
            self.core_dir / 'enums.cpp',
            '#include "./enums.h"\n'
            'namespace mNameSpace{ namespace PyImguiCore{\n'
            'void pybind_setup_pyimgui_enums(pybind11::module_ m) {\n'
            f'{enum_defs.getvalue()}'
            '}\n'
            '}}\n'
        ))

    @staticmethod
    def _clean_type(type_name):
        return ' '.join(type_name.replace(' *', '*').replace(' &', '&').split())

    @staticmethod
    def _arg_name(name, index):
        if not name or not name.isidentifier() or keyword.iskeyword(name):
            return f'arg{index}'
        return name

    @staticmethod
    def _is_function_pointer(type_name):
        return bool(re.search(r'\(\s*\*\s*\)', type_name))

    @staticmethod
    def _python_enum_name(type_name):
        type_name = type_name.rstrip('_')
        return type_name or '_'

    def _base_type(self, type_name):
        type_name = self._clean_type(type_name)
        while type_name.startswith('const '):
            type_name = type_name[6:]
        for prefix in ('struct ', 'enum ', 'class '):
            if type_name.startswith(prefix):
                type_name = type_name[len(prefix):]
        return type_name.rstrip('*&').strip()

    def _typedef_base_type(self, type_name):
        base_type = self._base_type(type_name)
        seen = set()
        while base_type in self.parser.typedefs and base_type not in seen:
            seen.add(base_type)
            resolved = self._clean_type(self.parser.typedefs[base_type])
            if self._is_function_pointer(resolved) or '*' in resolved:
                break
            base_type = self._base_type(resolved)
        return base_type

    def _is_scalar_type(self, type_name):
        type_name = self._typedef_base_type(type_name)
        scalar_types = {
            'void', 'bool', 'char', 'signed char', 'unsigned char', 'short', 'unsigned short',
            'int', 'unsigned int', 'long', 'unsigned long', 'long long', 'unsigned long long',
            'float', 'double', 'size_t', 'ImU8', 'ImS8', 'ImU16', 'ImS16', 'ImU32', 'ImS32',
            'ImU64', 'ImS64', 'ImWchar', 'ImGuiID', 'ImDrawIdx', 'ImGuiKeyChord',
        }
        if type_name in scalar_types or type_name in self.parser.enums:
            return True
        return bool(re.fullmatch(r'ImGui[A-Za-z0-9_]*Flags|ImDrawFlags', type_name))

    def _is_record_type(self, type_name):
        return self._base_type(type_name) in self.parser.records

    def _is_public_record_type(self, type_name):
        record = self.parser.records.get(self._base_type(type_name))
        return record is not None and record.source == 'imgui.h'

    def _is_supported_value_type(self, type_name):
        type_name = self._clean_type(type_name)
        if self._is_function_pointer(type_name):
            return False
        if type_name in {'const char*', 'char const*'}:
            return True
        if '*' in type_name:
            return False
        return self._is_scalar_type(type_name) or self._is_public_record_type(type_name)

    def _is_supported_return_type(self, type_name):
        type_name = self._clean_type(type_name)
        if self._is_function_pointer(type_name):
            return False
        if type_name in {'void', 'const char*', 'char const*', 'char*'}:
            return True
        if type_name.endswith('*'):
            base_type = self._base_type(type_name)
            return base_type == 'void' or self._is_record_type(type_name) or self._is_supported_memory_element_type(base_type)
        if type_name.endswith('&'):
            return self._is_record_type(type_name)
        if self._is_record_type(type_name):
            return True
        return self._is_supported_value_type(type_name)

    def _return_policy(self, type_name):
        type_name = self._clean_type(type_name)
        if type_name.endswith('*') or type_name.endswith('&'):
            if self._is_record_type(type_name):
                return ', py::return_value_policy::reference'
        return ''

    def _is_enum_like_type(self, type_name):
        original_type = self._base_type(type_name)
        resolved_type = self._typedef_base_type(type_name)
        if original_type in self.parser.enums or resolved_type in self.parser.enums:
            return True
        return bool(
            re.fullmatch(r'ImGui[A-Za-z0-9_]*Flags|ImDrawFlags', original_type)
            or re.fullmatch(r'ImGui[A-Za-z0-9_]*Flags|ImDrawFlags', resolved_type)
        )

    def _format_default(self, type_name, default):
        if default is None:
            return None
        if self._is_enum_like_type(type_name):
            return f'py::int_((long long)({default}))'
        return default

    def _format_output_value(self, type_name, value):
        if self._is_enum_like_type(type_name):
            return f'py::int_((long long)({value}))'
        return value

    def _parse_imvector_type(self, type_name):
        match = re.fullmatch(r'ImVector<(.+)>', self._clean_type(type_name))
        if not match:
            return None
        return self._clean_type(match.group(1))

    def _parse_imspan_type(self, type_name):
        match = re.fullmatch(r'ImSpan<(.+)>', self._clean_type(type_name))
        if not match:
            return None
        return self._clean_type(match.group(1))

    def _canonical_vector_element_type(self, type_name):
        type_name = self._clean_type(type_name)
        pointer_suffix = ''
        while type_name.endswith('*'):
            pointer_suffix += '*'
            type_name = type_name[:-1].strip()
        type_name = self._base_type(type_name)
        seen = set()
        while type_name in self.parser.typedefs and type_name not in seen:
            seen.add(type_name)
            resolved = self._clean_type(self.parser.typedefs[type_name])
            if self._is_function_pointer(resolved):
                break
            while resolved.endswith('*'):
                pointer_suffix += '*'
                resolved = resolved[:-1].strip()
            type_name = self._base_type(resolved)
        return f'{type_name}{pointer_suffix}'

    def _is_supported_vector_element_type(self, type_name):
        type_name = self._clean_type(type_name)
        if type_name.endswith('*'):
            return self._is_record_type(type_name)
        return self._is_scalar_type(type_name) or self._is_record_type(type_name)

    def _collect_function_imvector_types(self, spec):
        for arg in spec.args:
            arg_type = self._clean_type(arg.type)
            base_type = self._base_type(arg_type)
            if not arg_type.endswith('*') or arg_type[:-1].strip() != base_type:
                continue
            if element_type := self._parse_imvector_type(base_type):
                element_type = self._canonical_vector_element_type(element_type)
                if self._is_supported_vector_element_type(element_type):
                    self.imvector_types.add(element_type)

    def _pointer_depth(self, type_name):
        return self._clean_type(type_name).count('*')

    def _resolved_pointer_alias_type(self, type_name):
        type_name = self._clean_type(type_name)
        if '*' in type_name or self._is_function_pointer(type_name):
            return None
        resolved = self.parser.typedefs.get(self._base_type(type_name))
        if not resolved:
            return None
        resolved = self._clean_type(resolved)
        if '*' not in resolved or self._is_function_pointer(resolved):
            return None
        return resolved

    def _parse_fixed_array_type(self, type_name):
        match = re.fullmatch(r'(.+?)\s*\[\s*(\d+)\s*\]', self._clean_type(type_name))
        if not match:
            return None
        return self._clean_type(match.group(1)), int(match.group(2))

    def _is_cstring_array_type(self, type_name):
        type_name = self._clean_type(type_name).replace(' ', '')
        return type_name in {'constchar*const[]', 'charconst*const[]'}

    def _memory_element_type(self, type_name):
        return self._base_type(type_name)

    def _is_supported_memory_element_type(self, type_name):
        type_name = self._memory_element_type(type_name)
        if type_name == 'void' or self._is_function_pointer(type_name):
            return False
        return self._is_scalar_type(type_name) or self._is_record_type(type_name)

    def _is_flat_copy_type(self, type_name, seen=None):
        type_name = self._memory_element_type(type_name)
        if self._is_scalar_type(type_name):
            return True
        record = self.parser.records.get(self._base_type(type_name))
        if record is None:
            return False
        seen = set() if seen is None else seen
        if record.name in seen:
            return False
        seen.add(record.name)
        is_flat = True
        for field in record.fields:
            field_type = self._clean_type(field.type)
            if field.is_bitfield or self._is_function_pointer(field_type):
                is_flat = False
                break
            if self._parse_imvector_type(field_type) or field_type.endswith('*') or field_type.endswith('&'):
                is_flat = False
                break
            if field.is_array and not field.array_size:
                is_flat = False
                break
            if self._is_scalar_type(field_type):
                continue
            if self._is_record_type(field_type) and self._is_flat_copy_type(field_type, seen):
                continue
            is_flat = False
            break
        seen.remove(record.name)
        return is_flat

    def _is_pycast_type(self, type_name):
        type_name = self._memory_element_type(type_name)
        return not self._is_record_type(type_name) or self._is_public_record_type(type_name)

    def _memory_type_expr(self, element_type, *, pointer_items=False, read_only=False):
        element_type = self._memory_element_type(element_type)
        allow_flat_copy = self._is_flat_copy_type(element_type)
        allow_pycast = self._is_pycast_type(element_type)
        if self._is_record_type(element_type) and not allow_pycast:
            item_size = f'sizeof({element_type}*)' if pointer_items else f'sizeof({element_type})'
            return f'pyimgui_make_raw_memory_type({json.dumps(element_type)}, {item_size}, sizeof({element_type}), {str(pointer_items).lower()}, {str(read_only).lower()})'
        return f'pyimgui_make_memory_type<{element_type}, {str(pointer_items).lower()}, {str(allow_flat_copy).lower()}, {str(allow_pycast).lower()}>({json.dumps(element_type)}, {str(read_only).lower()})'

    def _pointer_wrapper_expr(self, address_expr, element_type, read_only=False, *, pointer_items=False, count=0):
        element_type = self._memory_element_type(element_type)
        return (
            f'PyPointer((uintptr_t)({address_expr}), '
            f'{self._memory_type_expr(element_type, pointer_items=pointer_items, read_only=read_only)}, (size_t)({count}))'
        )

    def _array_flat_wrapper_expr(self, address_expr, element_type, length, read_only=False):
        element_type = self._memory_element_type(element_type)
        return (
            f'PyArrayFlat((uintptr_t)({address_expr}), '
            f'{self._memory_type_expr(element_type, read_only=read_only)}, (size_t)({length}))'
        )

    def _array_wrapper_expr(self, address_expr, element_type, length, read_only=False, *, pointer_items=False):
        element_type = self._memory_element_type(element_type)
        return (
            f'PyArray((uintptr_t)({address_expr}), '
            f'{self._memory_type_expr(element_type, pointer_items=pointer_items, read_only=read_only)}, (size_t)({length}))'
        )

    def _record_pointer_getter(self, record_name, field_name, field_type):
        base_type = self._base_type(field_type)
        pointer_type = f'const {base_type}' if field_type.startswith('const ') else base_type
        return (
            f'[]({record_name}& self) -> py::object {{ '
            f'if (!self.{field_name}) return py::none(); '
            f'return py::cast(reinterpret_cast<{pointer_type}*>(self.{field_name}), py::return_value_policy::reference); '
            '}'
        )

    def _record_pointer_setter(self, record_name, field_name, field_type):
        base_type = self._base_type(field_type)
        return f'[]({record_name}& self, py::object value) {{ self.{field_name} = pyimgui_ptr_from_object<{base_type}>(value); }}'

    def _type_suffix(self, type_name):
        type_name = self._clean_type(type_name)
        type_name = type_name.replace('const ', '').replace('*', 'Ptr').replace('&', 'Ref')
        return re.sub(r'[^A-Za-z0-9_]+', '_', type_name).strip('_')

    def _imvector_class_name(self, element_type):
        return f'ImVector_{self._type_suffix(element_type)}'

    def _stub_scalar_type(self, type_name):
        original_type = self._base_type(type_name)
        resolved_type = self._typedef_base_type(type_name)
        if original_type in self.parser.enums:
            return self._python_enum_name(original_type)
        if resolved_type in self.parser.enums:
            return self._python_enum_name(resolved_type)
        if resolved_type == 'bool':
            return 'bool'
        if resolved_type in {'float', 'double'}:
            return 'float'
        if resolved_type in {
                'char', 'signed char', 'unsigned char', 'short', 'unsigned short', 'int', 'unsigned int',
                'long', 'unsigned long', 'long long', 'unsigned long long', 'size_t', 'ImU8', 'ImS8',
                'ImU16', 'ImS16', 'ImU32', 'ImS32', 'ImU64', 'ImS64', 'ImWchar', 'ImGuiID',
                'ImDrawIdx', 'ImGuiKeyChord',
        }:
            return 'int'
        if self._is_enum_like_type(resolved_type):
            return 'int'
        return 'typing.Any'

    def _stub_memory_item_type(self, type_name):
        base_type = self._base_type(type_name)
        if self._is_record_type(base_type):
            return base_type
        if self._is_scalar_type(base_type):
            return self._stub_scalar_type(base_type)
        return 'typing.Any'

    def _field_stub_type(self, record_name, field):
        if specified_wrappers.get(f'_CLS_FIELD_:{record_name}::{field.name}'):
            return None
        field_type = self._clean_type(field.type)
        if not field.name or self._is_function_pointer(field_type):
            return None
        if field.is_bitfield:
            if self._is_scalar_type(field_type):
                return self._stub_scalar_type(field_type)
            return None
        if field.is_array:
            if field.array_size and field_type.endswith('*'):
                if field_type in {'const char*', 'char const*'}:
                    return 'tuple[str | None, ...]'
                if element_type := self._parse_imvector_type(self._base_type(field_type)):
                    element_type = self._canonical_vector_element_type(element_type)
                    if self._is_supported_vector_element_type(element_type):
                        return f'tuple[{self._imvector_class_name(element_type)} | None, ...]'
                if self._pointer_depth(field_type) == 1 and self._is_record_type(field_type):
                    return f'Array[{self._base_type(field_type)}]'
                return None
            if field.array_size and self._is_supported_memory_element_type(field_type):
                return f'ArrayFlat[{self._stub_memory_item_type(field_type)}]'
            return None
        if element_type := self._parse_imvector_type(field_type):
            element_type = self._canonical_vector_element_type(element_type)
            if self._is_supported_vector_element_type(element_type):
                return self._imvector_class_name(element_type)
            return None
        if element_type := self._parse_imspan_type(field_type):
            element_type = self._typedef_base_type(element_type)
            if self._is_record_type(element_type):
                return f'tuple[{element_type}, ...]'
            if self._is_scalar_type(element_type):
                return f'tuple[{self._stub_scalar_type(element_type)}, ...]'
            return None
        if self._is_record_type(field_type) and '*' not in field_type and '&' not in field_type:
            base_type = self._base_type(field_type)
            if self._is_pycast_type(base_type):
                return base_type
            return f'Pointer[{base_type}]'
        if field_type.endswith('*'):
            if field_type in {'const char*', 'char const*'}:
                return 'str | None'
            base_type = self._base_type(field_type)
            if self._pointer_depth(field_type) == 1 and base_type == 'void':
                return 'Pointer[typing.Any]'
            if self._pointer_depth(field_type) == 1 and self._is_record_type(field_type):
                if self._is_pycast_type(base_type):
                    return f'{base_type} | None'
                return f'Pointer[{base_type}]'
            if self._pointer_depth(field_type) == 2 and self._is_record_type(field_type):
                return f'Pointer[{base_type}]'
            if self._pointer_depth(field_type) == 1 and self._is_supported_memory_element_type(field_type):
                return f'Pointer[{self._stub_memory_item_type(field_type)}]'
            if self._pointer_depth(field_type) == 1:
                return 'Pointer[typing.Any]'
        if self._resolved_pointer_alias_type(field_type):
            return 'Pointer[typing.Any]'
        return None

    def _function_stub_return_type(self, result_type):
        result_type = self._clean_type(result_type)
        if result_type in {'const char*', 'char const*', 'char*'}:
            return 'str'
        if result_type.endswith('*') and self._is_record_type(result_type):
            return f'{self._base_type(result_type)} | None'
        if result_type.endswith('*'):
            base_type = self._base_type(result_type)
            if base_type == 'void':
                return 'Pointer[typing.Any]'
            if self._pointer_depth(result_type) == 1 and self._is_supported_memory_element_type(base_type):
                return f'Pointer[{self._stub_memory_item_type(base_type)}]'
            return 'Pointer[typing.Any]'
        if result_type.endswith('&') and self._is_record_type(result_type):
            return self._base_type(result_type)
        if self._is_record_type(result_type) and '*' not in result_type and '&' not in result_type:
            return self._base_type(result_type)
        return None

    def _stub_value_type(self, type_name):
        type_name = self._clean_type(type_name)
        if type_name == 'void':
            return None
        if stub_type := self._function_stub_return_type(type_name):
            return stub_type
        if self._is_scalar_type(type_name):
            return self._stub_scalar_type(type_name)
        return 'typing.Any'

    def _fixed_array_stub_type(self, element_type):
        return f'list[{self._stub_memory_item_type(element_type)}]'

    def _record_return_value_expr(self, result_type, value_expr, *, for_tuple=False):
        result_type = self._clean_type(result_type)
        if result_type in {'const char*', 'char const*', 'char*'}:
            return value_expr
        if result_type.endswith('*') and self._is_record_type(result_type):
            if for_tuple:
                return f'py::cast({value_expr}, py::return_value_policy::reference)'
            return value_expr
        if result_type.endswith('*'):
            base_type = self._base_type(result_type)
            if base_type == 'void' or self._pointer_depth(result_type) > 1:
                return f'PyPointer((uintptr_t)({value_expr}), pyimgui_void_memory_type())'
            if self._is_supported_memory_element_type(base_type):
                return self._pointer_wrapper_expr(value_expr, base_type, result_type.startswith('const '))
        if result_type.endswith('&') and self._is_record_type(result_type):
            if for_tuple:
                return f'py::cast(&{value_expr}, py::return_value_policy::reference)'
            return f'&{value_expr}'
        return self._format_output_value(result_type, value_expr)

    def make_field_def(self, record_name, field):
        if wrapper := specified_wrappers.get(f'_CLS_FIELD_:{record_name}::{field.name}'):
            return wrapper
        field_type = self._clean_type(field.type)
        if not field.name or self._is_function_pointer(field_type):
            return f'// TODO field {record_name}::{field.name}: {field.type}'
        if field.is_bitfield:
            if self._is_scalar_type(field_type):
                # Accept the setter as `long long` and cast inside the lambda so we
                # don't depend on cross-TU visibility of enum type_casters.
                base_field_type = field_type[6:].strip() if field_type.startswith('const ') else field_type
                getter_body = self._format_output_value(field_type, f"self.{field.name}")
                getter = f'[]({record_name}& self) {{ return {getter_body}; }}'
                setter = f'[]({record_name}& self, long long value) {{ self.{field.name} = ({base_field_type})value; }}'
                return f'.def_property("{field.name}", {getter}, {setter})'
            return f'// TODO field {record_name}::{field.name}: bitfield {field.type}'
        if field.is_array:
            if field.array_size and field_type.endswith('*'):
                if field_type in {'const char*', 'char const*'}:
                    tuple_var = f'__{field.name}_tuple'
                    index_var = f'__{field.name}_i'
                    return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ py::tuple {tuple_var}({field.array_size}); for (py::ssize_t {index_var} = 0; {index_var} < {field.array_size}; ++{index_var}) {tuple_var}[{index_var}] = self.{field.name}[{index_var}] ? py::cast(self.{field.name}[{index_var}]) : py::none(); return {tuple_var}; }}, py::return_value_policy::reference_internal)'
                if element_type := self._parse_imvector_type(self._base_type(field_type)):
                    element_type = self._canonical_vector_element_type(element_type)
                    if self._is_supported_vector_element_type(element_type):
                        self.imvector_types.add(element_type)
                        tuple_var = f'__{field.name}_tuple'
                        index_var = f'__{field.name}_i'
                        vector_var = f'__{field.name}_vector'
                        return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ py::tuple {tuple_var}({field.array_size}); for (py::ssize_t {index_var} = 0; {index_var} < {field.array_size}; ++{index_var}) {{ auto* {vector_var} = self.{field.name}[{index_var}]; {tuple_var}[{index_var}] = {vector_var} ? py::cast(PyImVectorWrapper<{element_type}>({vector_var})) : py::none(); }} return {tuple_var}; }}, py::return_value_policy::reference_internal)'
                if self._pointer_depth(field_type) == 1 and self._is_record_type(field_type):
                    expr = self._array_wrapper_expr(
                        f'&self.{field.name}[0]',
                        self._base_type(field_type),
                        field.array_size,
                        field_type.startswith('const '),
                        pointer_items=True,
                    )
                    return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ return {expr}; }}, py::return_value_policy::reference_internal)'
                return f'// TODO field {record_name}::{field.name}: pointer array {field.type}'
            if field.array_size and self._is_supported_memory_element_type(field_type):
                expr = self._array_flat_wrapper_expr(f'&self.{field.name}[0]', field_type, field.array_size, field_type.startswith('const '))
                return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ return {expr}; }}, py::return_value_policy::reference_internal)'
            return f'// TODO field {record_name}::{field.name}: array {field.type}'
        if element_type := self._parse_imvector_type(field_type):
            element_type = self._canonical_vector_element_type(element_type)
            if not self._is_supported_vector_element_type(element_type):
                return f'// TODO field {record_name}::{field.name}: unsupported ImVector element {element_type}'
            self.imvector_types.add(element_type)
            return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ return PyImVectorWrapper<{element_type}>(&self.{field.name}); }})'
        if element_type := self._parse_imspan_type(field_type):
            element_type = self._typedef_base_type(element_type)
            if self._is_record_type(element_type) or self._is_scalar_type(element_type):
                tuple_var = f'__{field.name}_tuple'
                index_var = f'__{field.name}_i'
                if self._is_record_type(element_type):
                    item_expr = f'py::cast(&self.{field.name}[(int){index_var}], py::return_value_policy::reference)'
                else:
                    item_expr = f'py::cast(self.{field.name}[(int){index_var}])'
                return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ py::tuple {tuple_var}((py::ssize_t)self.{field.name}.size()); for (py::ssize_t {index_var} = 0; {index_var} < (py::ssize_t)self.{field.name}.size(); ++{index_var}) {tuple_var}[{index_var}] = {item_expr}; return {tuple_var}; }}, py::return_value_policy::reference_internal)'
            return f'// TODO field {record_name}::{field.name}: unsupported ImSpan element {element_type}'
        if self._is_record_type(field_type) and '*' not in field_type and '&' not in field_type:
            base_type = self._base_type(field_type)
            if not self._is_pycast_type(base_type):
                expr = self._pointer_wrapper_expr(f'&self.{field.name}', base_type, field_type.startswith('const '), count=1)
                return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ return {expr}; }}, py::return_value_policy::reference_internal)'
            pointer_type = f'const {base_type}*' if field_type.startswith('const ') else f'{base_type}*'
            if field_type.startswith('const '):
                return f'.def_property_readonly("{field.name}", []({record_name}& self) -> {pointer_type} {{ return &self.{field.name}; }}, py::return_value_policy::reference_internal)'
            # Non-const pycast record field — read returns a reference (so in-place
            # mutation works: `io.DisplaySize.x = 800`), assignment copies a value.
            getter = f'[]({record_name}& self) -> {pointer_type} {{ return &self.{field.name}; }}'
            setter = f'[]({record_name}& self, const {base_type}& value) {{ self.{field.name} = value; }}'
            return f'.def_property("{field.name}", {getter}, {setter}, py::return_value_policy::reference_internal)'
        if field_type.endswith('*'):
            if field_type in {'const char*', 'char const*'}:
                # const char* field — needs to expose None for nullptr and accept
                # str-or-None on assignment. The C side stores raw const char*, so
                # the assigned string must outlive the pointer; we keep it in a
                # lambda-local static keyed by the field address.
                getter = (
                    f'[]({record_name}& self) {{ '
                    f'return self.{field.name} ? py::cast(self.{field.name}) : py::object(py::none()); '
                    f'}}'
                )
                setter = (
                    f'[]({record_name}& self, py::object value) {{ '
                    f'static std::unordered_map<const char**, std::string> __store; '
                    f'auto __slot = const_cast<const char**>(&self.{field.name}); '
                    f'if (value.is_none()) {{ __store.erase(__slot); self.{field.name} = nullptr; return; }} '
                    f'auto& __s = __store[__slot]; __s = value.cast<std::string>(); '
                    f'self.{field.name} = __s.c_str(); '
                    f'}}'
                )
                return f'.def_property("{field.name}", {getter}, {setter}, py::return_value_policy::reference)'
            if self._pointer_depth(field_type) == 1 and self._base_type(field_type) == 'void':
                getter = f'[]({record_name}& self) {{ return PyPointer((uintptr_t)(self.{field.name}), pyimgui_void_memory_type()); }}'
                if field_type.startswith('const '):
                    return f'.def_property_readonly("{field.name}", {getter}, py::return_value_policy::reference_internal)'
                setter = f'[]({record_name}& self, py::object value) {{ self.{field.name} = reinterpret_cast<void*>(pyimgui_address_from_object(value)); }}'
                return f'.def_property("{field.name}", {getter}, {setter}, py::return_value_policy::reference_internal)'
            if self._pointer_depth(field_type) == 1 and self._is_record_type(field_type):
                if not self._is_pycast_type(field_type):
                    expr = self._pointer_wrapper_expr(f'self.{field.name}', self._base_type(field_type), field_type.startswith('const '))
                    getter = f'[]({record_name}& self) {{ return {expr}; }}'
                    if field_type.startswith('const '):
                        return f'.def_property_readonly("{field.name}", {getter}, py::return_value_policy::reference_internal)'
                    setter = f'[]({record_name}& self, py::object value) {{ self.{field.name} = reinterpret_cast<{self._base_type(field_type)}*>(pyimgui_address_from_object(value)); }}'
                    return f'.def_property("{field.name}", {getter}, {setter}, py::return_value_policy::reference_internal)'
                getter = self._record_pointer_getter(record_name, field.name, field_type)
                if field_type.startswith('const '):
                    return f'.def_property_readonly("{field.name}", {getter}, py::return_value_policy::reference_internal)'
                setter = self._record_pointer_setter(record_name, field.name, field_type)
                return f'.def_property("{field.name}", {getter}, {setter}, py::return_value_policy::reference_internal)'
            if self._pointer_depth(field_type) == 2 and self._is_record_type(field_type):
                expr = self._pointer_wrapper_expr(f'self.{field.name}', self._base_type(field_type), field_type.startswith('const '), pointer_items=True)
                return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ return {expr}; }}, py::return_value_policy::reference_internal)'
            if self._pointer_depth(field_type) == 1 and self._is_supported_memory_element_type(field_type):
                expr = self._pointer_wrapper_expr(f'self.{field.name}', field_type, field_type.startswith('const '))
                return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ return {expr}; }}, py::return_value_policy::reference_internal)'
            if self._pointer_depth(field_type) == 1:
                getter = f'[]({record_name}& self) {{ return PyPointer((uintptr_t)(self.{field.name}), pyimgui_void_memory_type()); }}'
                if field_type.startswith('const '):
                    return f'.def_property_readonly("{field.name}", {getter}, py::return_value_policy::reference_internal)'
                setter = f'[]({record_name}& self, py::object value) {{ self.{field.name} = reinterpret_cast<{field_type}>(pyimgui_address_from_object(value)); }}'
                return f'.def_property("{field.name}", {getter}, {setter}, py::return_value_policy::reference_internal)'
            return f'// TODO field {record_name}::{field.name}: pointer {field.type}'
        if pointer_alias_type := self._resolved_pointer_alias_type(field_type):
            getter = f'[]({record_name}& self) {{ return PyPointer((uintptr_t)(self.{field.name}), pyimgui_void_memory_type()); }}'
            if pointer_alias_type.startswith('const '):
                return f'.def_property_readonly("{field.name}", {getter}, py::return_value_policy::reference_internal)'
            setter = f'[]({record_name}& self, py::object value) {{ self.{field.name} = reinterpret_cast<{field_type}>(pyimgui_address_from_object(value)); }}'
            return f'.def_property("{field.name}", {getter}, {setter}, py::return_value_policy::reference_internal)'
        if not self._is_supported_value_type(field_type):
            return f'// TODO field {record_name}::{field.name}: {field.type}'
        # Enum / flags fields: emit a property with int conversion. def_readwrite
        # requires the enum's type_caster to be visible at this translation unit,
        # which the ENUM_CAST specializations in enums.cpp are NOT. Wrapping
        # via py::int_ sidesteps that and matches how we handle bitfields.
        if self._is_enum_like_type(field_type):
            base_field_type = field_type[6:].strip() if field_type.startswith('const ') else field_type
            getter = f'[]({record_name}& self) {{ return py::int_((long long)(self.{field.name})); }}'
            if field_type.startswith('const '):
                return f'.def_property_readonly("{field.name}", {getter})'
            setter = f'[]({record_name}& self, long long value) {{ self.{field.name} = ({base_field_type})value; }}'
            return f'.def_property("{field.name}", {getter}, {setter})'
        if field_type.startswith('const '):
            return f'.def_property_readonly("{field.name}", []({record_name}& self) {{ return self.{field.name}; }})'
        return f'.def_readwrite("{field.name}", &{record_name}::{field.name})'

    def make_function_def(self, spec, *, owner=None, chain=False):
        if spec.variadic:
            return f'// TODO {spec.name}: variadic function'
        result_type = self._clean_type(spec.result)
        if not self._is_supported_return_type(result_type):
            return f'// TODO {spec.name}: unsupported return type {spec.result}'
        stub_return_type = self._function_stub_return_type(result_type)
        lambda_args = []
        py_args = []
        call_args = []
        prelude = []
        postlude = []
        return_values = []
        extra_stub_return_types = []
        skip_arg_indexes = set()
        if owner and not spec.is_static:
            lambda_args.append(f'{owner}& self')
        for index, arg in enumerate(spec.args):
            if index in skip_arg_indexes:
                continue
            arg_type = self._clean_type(arg.type)
            arg_name = self._arg_name(arg.name, index)
            if self._is_cstring_array_type(arg_type):
                storage_var = f'__{arg_name}_storage'
                ptrs_var = f'__{arg_name}_ptrs'
                index_var = f'__{arg_name}_i'
                size_var = f'__{arg_name}_size'
                lambda_args.append(f'py::sequence {arg_name}')
                py_args.append(f'py::arg("{arg_name}")')
                prelude.append(f'auto {size_var} = {arg_name}.size();')
                prelude.append(f'std::vector<std::string> {storage_var}; {storage_var}.reserve({size_var});')
                prelude.append(f'std::vector<const char*> {ptrs_var}; {ptrs_var}.reserve({size_var});')
                prelude.append(f'for (size_t {index_var} = 0; {index_var} < {size_var}; ++{index_var}) {{ {storage_var}.push_back({arg_name}[{index_var}].cast<std::string>()); {ptrs_var}.push_back({storage_var}.back().c_str()); }}')
                call_args.append(f'{ptrs_var}.data()')
                if index + 1 < len(spec.args):
                    next_arg = spec.args[index + 1]
                    next_arg_type = self._clean_type(next_arg.type)
                    next_arg_name = self._arg_name(next_arg.name, index + 1)
                    if self._is_scalar_type(next_arg_type) and next_arg_name in {f'{arg_name}_count', f'{arg_name}_size', 'count'}:
                        skip_arg_indexes.add(index + 1)
                        call_args.append(f'static_cast<{self._base_type(next_arg_type)}>({ptrs_var}.size())')
                continue
            if fixed_array := self._parse_fixed_array_type(arg_type):
                element_type, array_size = fixed_array
                if not self._is_supported_memory_element_type(element_type):
                    return f'// TODO {spec.name}: unsupported array argument {arg.name} {arg.type}'
                array_var = f'__{arg_name}_array'
                index_var = f'__{arg_name}_i'
                list_var = f'__{arg_name}_out'
                prelude.append(f'{element_type} {array_var}[{array_size}] = {{}};')
                if not arg_name.startswith('out_'):
                    lambda_args.append(f'py::sequence {arg_name}')
                    py_args.append(f'py::arg("{arg_name}")')
                    prelude.append(f'if ({arg_name}.size() != {array_size}) _throwV_("Expected {arg_name} to have length {{}}", {array_size});')
                    if self._is_record_type(element_type):
                        prelude.append(
                            f'for (py::ssize_t {index_var} = 0; {index_var} < {array_size}; ++{index_var}) {{ '
                            f'auto* __item = pyimgui_ptr_from_object<{element_type}>(py::reinterpret_borrow<py::object>({arg_name}[{index_var}])); '
                            f'if (!__item) _throw_("Fixed array record item cannot be None"); '
                            f'{array_var}[{index_var}] = *__item; }}'
                        )
                    else:
                        prelude.append(f'for (py::ssize_t {index_var} = 0; {index_var} < {array_size}; ++{index_var}) {array_var}[{index_var}] = {arg_name}[{index_var}].cast<{element_type}>();')
                call_args.append(array_var)
                postlude.append(f'py::list {list_var}; for (py::ssize_t {index_var} = 0; {index_var} < {array_size}; ++{index_var}) {list_var}.append(py::cast({array_var}[{index_var}]));')
                return_values.append(list_var)
                extra_stub_return_types.append(self._fixed_array_stub_type(element_type))
                continue
            if arg_type.endswith('*') and arg_type not in {'const char*', 'char const*'}:
                base_type = self._base_type(arg_type)
                pointer_depth = self._pointer_depth(arg_type)
                if arg_type[:-1].strip() == base_type and (element_type := self._parse_imvector_type(base_type)):
                    element_type = self._canonical_vector_element_type(element_type)
                    if element_type in {'const char*', 'char const*', 'char*'}:
                        storage_var = f'__{arg_name}_storage'
                        vector_var = f'__{arg_name}_vector'
                        index_var = f'__{arg_name}_i'
                        size_var = f'__{arg_name}_size'
                        lambda_args.append(f'py::sequence {arg_name}')
                        py_args.append(f'py::arg("{arg_name}")')
                        prelude.append(f'auto {size_var} = {arg_name}.size();')
                        prelude.append(f'std::vector<std::string> {storage_var}; {storage_var}.reserve({size_var});')
                        prelude.append(f'ImVector<const char*> {vector_var}; {vector_var}.reserve((int){size_var});')
                        prelude.append(f'for (size_t {index_var} = 0; {index_var} < {size_var}; ++{index_var}) {{ {storage_var}.push_back({arg_name}[{index_var}].cast<std::string>()); {vector_var}.push_back({storage_var}.back().c_str()); }}')
                        call_args.append(f'&{vector_var}')
                        continue
                    if not self._is_supported_vector_element_type(element_type):
                        return f'// TODO {spec.name}: unsupported ImVector pointer argument {arg.name} {arg.type}'
                    self.imvector_types.add(element_type)
                    vector_var = f'__{arg_name}_vector'
                    lambda_args.append(f'py::object {arg_name}')
                    py_arg = f'py::arg("{arg_name}")'
                    if arg.default in {'NULL', 'nullptr'}:
                        py_arg += ' = py::none()'
                    py_args.append(py_arg)
                    prelude.append(f'auto* {vector_var} = {arg_name}.is_none() ? nullptr : py::cast<PyImVectorWrapper<{element_type}>*>({arg_name});')
                    if arg.default not in {'NULL', 'nullptr'}:
                        prelude.append(f'if (!{vector_var} || !{vector_var}->vector) _throw_("{arg_name} must be an ImVector wrapper");')
                    call_args.append(f'{vector_var} ? {vector_var}->vector : nullptr')
                    continue
                if pointer_depth == 2 and self._is_record_type(base_type):
                    if arg_name.startswith('out_'):
                        pointer_var = f'__{arg_name}_ptr'
                        prelude.append(f'{base_type}* {pointer_var} = nullptr;')
                        call_args.append(f'&{pointer_var}')
                        return_values.append(self._pointer_wrapper_expr(pointer_var, base_type))
                        extra_stub_return_types.append(f'Pointer[{base_type}]')
                        continue
                    lambda_args.append(f'py::object {arg_name}')
                    py_arg = f'py::arg("{arg_name}")'
                    if arg.default in {'NULL', 'nullptr'}:
                        py_arg += ' = py::none()'
                    py_args.append(py_arg)
                    pointer_array_var = f'__{arg_name}_ptrs'
                    prelude.append(f'auto {pointer_array_var} = pyimgui_input_pointer_array_from_object<{base_type}>({arg_name});')
                    call_args.append(f'{pointer_array_var}.get()')
                    continue
                if pointer_depth == 2 and arg_name.startswith('out_'):
                    pointer_type = self._clean_type(arg_type[:-1])
                    pointer_var = f'__{arg_name}_ptr'
                    prelude.append(f'{pointer_type} {pointer_var} = nullptr;')
                    call_args.append(f'&{pointer_var}')
                    if pointer_type in {'const char*', 'char const*', 'char*'}:
                        return_values.append(f'({pointer_var} ? py::cast({pointer_var}) : py::none())')
                        extra_stub_return_types.append('str | None')
                    elif base_type == 'void':
                        return_values.append(f'PyPointer((uintptr_t)({pointer_var}), pyimgui_void_memory_type())')
                        extra_stub_return_types.append('Pointer[typing.Any]')
                    elif self._is_supported_memory_element_type(base_type):
                        return_values.append(self._pointer_wrapper_expr(pointer_var, base_type, pointer_type.startswith('const ')))
                        extra_stub_return_types.append(f'Pointer[{self._stub_memory_item_type(base_type)}]')
                    else:
                        return f'// TODO {spec.name}: pointer argument {arg.name} {arg.type}'
                    continue
                if pointer_depth > 1:
                    return f'// TODO {spec.name}: pointer argument {arg.name} {arg.type}'
                if self._is_record_type(base_type):
                    lambda_args.append(f'py::object {arg_name}')
                    py_arg = f'py::arg("{arg_name}")'
                    if arg.default in {'NULL', 'nullptr'}:
                        py_arg += ' = py::none()'
                    py_args.append(py_arg)
                    cast_prefix = 'const ' if arg_type.startswith('const ') else ''
                    if self._is_flat_copy_type(base_type):
                        input_array_var = f'__{arg_name}_items'
                        prelude.append(f'auto {input_array_var} = pyimgui_input_value_array_from_object<{base_type}>({arg_name});')
                        call_args.append(f'reinterpret_cast<{cast_prefix}{base_type}*>({input_array_var}.get())')
                    else:
                        call_args.append(f'reinterpret_cast<{cast_prefix}{base_type}*>(pyimgui_ptr_from_object<{base_type}>({arg_name}))')
                    continue
                if arg_type.startswith('const ') and base_type != 'void' and self._is_supported_memory_element_type(base_type):
                    lambda_args.append(f'py::object {arg_name}')
                    py_arg = f'py::arg("{arg_name}")'
                    if arg.default in {'NULL', 'nullptr'}:
                        py_arg += ' = py::none()'
                    py_args.append(py_arg)
                    input_array_var = f'__{arg_name}_items'
                    prelude.append(f'auto {input_array_var} = pyimgui_input_value_array_from_object<{base_type}>({arg_name});')
                    call_args.append(f'reinterpret_cast<const {base_type}*>({input_array_var}.get())')
                    continue
                if arg_type.startswith('const ') and base_type == 'void':
                    lambda_args.append(f'py::object {arg_name}')
                    py_arg = f'py::arg("{arg_name}")'
                    if arg.default in {'NULL', 'nullptr'}:
                        py_arg += ' = py::none()'
                    py_args.append(py_arg)
                    call_args.append(f'reinterpret_cast<const {base_type}*>(pyimgui_address_from_object({arg_name}))')
                    continue
                if arg_type.startswith('const '):
                    return f'// TODO {spec.name}: pointer argument {arg.name} {arg.type}'
                if base_type != 'void' and self._is_scalar_type(base_type):
                    if arg_name.startswith('out_'):
                        prelude.append(f'{base_type} {arg_name} = {{}};')
                        call_args.append(f'&{arg_name}')
                        return_values.append(self._format_output_value(base_type, arg_name))
                        extra_stub_return_types.append(self._stub_scalar_type(base_type))
                    elif arg.default in {'NULL', 'nullptr'}:
                        lambda_args.append(f'std::optional<{base_type}> {arg_name}')
                        py_args.append(f'py::arg("{arg_name}") = py::none()')
                        call_args.append(f'({arg_name} ? &*{arg_name} : nullptr)')
                        return_values.append(f'({arg_name} ? py::cast(*{arg_name}) : py::none())')
                    else:
                        lambda_args.append(f'{base_type} {arg_name}')
                        py_args.append(f'py::arg("{arg_name}")')
                        call_args.append(f'&{arg_name}')
                        return_values.append(self._format_output_value(base_type, arg_name))
                    continue
                if base_type == 'void' or self._is_record_type(base_type):
                    lambda_args.append(f'py::object {arg_name}')
                    py_arg = f'py::arg("{arg_name}")'
                    if arg.default in {'NULL', 'nullptr'}:
                        py_arg += ' = py::none()'
                    py_args.append(py_arg)
                    call_args.append(f'reinterpret_cast<{base_type}*>(pyimgui_address_from_object({arg_name}))')
                    continue
                return f'// TODO {spec.name}: pointer argument {arg.name} {arg.type}'
            if arg_type.endswith('&') and self._is_record_type(arg_type) and not self._is_supported_value_type(arg_type):
                base_type = self._base_type(arg_type)
                ptr_var = f'__{arg_name}_ptr'
                lambda_args.append(f'py::object {arg_name}')
                py_args.append(f'py::arg("{arg_name}")')
                prelude.append(f'auto* {ptr_var} = pyimgui_ptr_from_object<{base_type}>({arg_name}); if (!{ptr_var}) _throw_("{arg_name} cannot be None");')
                if arg_type.startswith('const '):
                    call_args.append(f'*reinterpret_cast<const {base_type}*>({ptr_var})')
                else:
                    call_args.append(f'*{ptr_var}')
                continue
            if arg_type.endswith('&') and not arg_type.startswith('const ') and not self._is_record_type(arg_type):
                base_type = self._base_type(arg_type)
                if base_type != 'void' and self._is_scalar_type(base_type):
                    if arg_name.startswith('out_'):
                        prelude.append(f'{base_type} {arg_name} = {{}};')
                        call_args.append(arg_name)
                        return_values.append(self._format_output_value(base_type, arg_name))
                        extra_stub_return_types.append(self._stub_scalar_type(base_type))
                    else:
                        lambda_args.append(f'{base_type} {arg_name}')
                        py_args.append(f'py::arg("{arg_name}")')
                        call_args.append(arg_name)
                        return_values.append(self._format_output_value(base_type, arg_name))
                    continue
                return f'// TODO {spec.name}: non-record reference argument {arg.name} {arg.type}'
            if not self._is_supported_value_type(arg_type):
                return f'// TODO {spec.name}: unsupported argument {arg.name} {arg.type}'
            # Special case: `const char* x = NULL/nullptr` — pybind11 cannot route
            # a nullptr default through a `const char*` parameter (None is not
            # convertible to str). Route via py::object so None ↔ nullptr.
            if arg_type in {'const char*', 'char const*'} and arg.default in {'NULL', 'nullptr', '0'}:
                cstr_var = f'__{arg_name}_cstr'
                storage_var = f'__{arg_name}_str'
                lambda_args.append(f'py::object {arg_name}')
                py_args.append(f'py::arg("{arg_name}") = py::none()')
                prelude.append(
                    f'std::string {storage_var}; '
                    f'const char* {cstr_var} = {arg_name}.is_none() ? nullptr : '
                    f'({storage_var} = {arg_name}.cast<std::string>(), {storage_var}.c_str());'
                )
                call_args.append(cstr_var)
                continue
            lambda_args.append(f'{arg_type} {arg_name}')
            py_arg = f'py::arg("{arg_name}")'
            if arg.default is not None:
                py_arg += f' = {self._format_default(arg_type, arg.default)}'
            py_args.append(py_arg)
            call_args.append(arg_name)
        lambda_arg_list = ', '.join(lambda_args)
        call_arg_list = ', '.join(call_args)
        if owner:
            if spec.is_static:
                call = f'{owner}::{spec.name}({call_arg_list})'
                def_name = '.def_static'
            else:
                call = f'self.{spec.name}({call_arg_list})'
                def_name = '.def'
        else:
            call = f'ImGui::{spec.name}({call_arg_list})'
            def_name = 'm.def'
        body_parts = prelude[:]
        if result_type == 'void':
            body_parts.append(f'{call};')
        else:
            if result_type.endswith('&') and self._is_record_type(result_type):
                body_parts.append(f'auto& __ret = {call};')
            else:
                body_parts.append(f'auto __ret = {call};')
            return_values.insert(0, self._record_return_value_expr(result_type, '__ret', for_tuple=bool(return_values)))
        body_parts.extend(postlude)
        if len(return_values) == 1:
            body_parts.append(f'return {return_values[0]};')
        elif len(return_values) > 1:
            body_parts.append(f'return py::make_tuple({", ".join(return_values)});')
        body = ' '.join(body_parts)
        py_arg_list = ''.join(f', {arg}' for arg in py_args)
        policy = self._return_policy(result_type) if len(return_values) == 1 else ''
        if extra_stub_return_types:
            stub_return_values = extra_stub_return_types[:]
            if result_stub_type := self._stub_value_type(result_type):
                stub_return_values.insert(0, result_stub_type)
            if len(stub_return_values) == 1:
                self.stub_function_return_types.setdefault(owner or '', {})[spec.name] = stub_return_values[0]
            else:
                self.stub_function_return_types.setdefault(owner or '', {})[spec.name] = f'tuple[{", ".join(stub_return_values)}]'
        elif stub_return_type:
            self.stub_function_return_types.setdefault(owner or '', {})[spec.name] = stub_return_type
        if chain:
            return f'{def_name}("{spec.name}", []({lambda_arg_list}) {{ {body} }}{py_arg_list}{policy})'
        return f'{def_name}("{spec.name}", []({lambda_arg_list}) {{ {body} }}{py_arg_list}{policy});'

    def generate_structs(self):
        self.imvector_types = set()
        struct_defs = CodeWriter(1)
        for overloads in self.parser.functions.values():
            for overload in overloads:
                self._collect_function_imvector_types(overload)
        for record in self.parser.records.values():
            for method in record.methods:
                self._collect_function_imvector_types(method)
        priority_records = {'ImVec2': 0, 'ImVec4': 1}
        for record_name in sorted(self.parser.records, key=lambda name: (priority_records.get(name, 100), name)):
            record = self.parser.records[record_name]
            if wrapper := specified_wrappers.get(f'_CLS_:{record_name}'):
                struct_defs.write(f'{wrapper}\n')
                continue
            extra = specified_wrappers.get(f'_CLS_EXTRA_:{record_name}')
            wrap_default_init = not (extra and 'py::init' in extra)
            if wrap_default_init:
                struct_defs.write(f'pyimgui_add_default_init(py::class_<{record_name}>(m, "{record_name}", py::dynamic_attr())')
            else:
                struct_defs.write(f'py::class_<{record_name}>(m, "{record_name}", py::dynamic_attr())')
            with struct_defs.push_indent():
                for field in record.fields:
                    if stub_type := self._field_stub_type(record_name, field):
                        self.stub_field_types.setdefault(record_name, {})[field.name] = stub_type
                    struct_defs.write('\n' + self.make_field_def(record_name, field))
                seen_methods = set()
                for method in record.methods:
                    if method.name.startswith('~'):
                        continue
                    method_key = f'_MFUNC_:{record_name}::{method.name}'
                    if method_key in specified_wrappers:
                        method_def = specified_wrappers[method_key]
                    else:
                        signature = (method.name, method.result, tuple(arg.type for arg in method.args), method.is_static)
                        if signature in seen_methods:
                            continue
                        seen_methods.add(signature)
                        method_def = self.make_function_def(method, owner=record_name, chain=True)
                    if method_def:
                        struct_defs.write('\n' + method_def)
                if extra:
                    struct_defs.write('\n' + extra)
            if wrap_default_init:
                struct_defs.write('\n);\n')
            else:
                struct_defs.write('\n;\n')

        template_defs = CodeWriter(1)
        for element_type in sorted(self.imvector_types):
            template_defs.write(f'PyImVectorWrapper<{element_type}>::pybind_setup(m, "{self._imvector_class_name(element_type)}");\n')

        runtime_defs = CodeWriter(1)
        for record_name in sorted(self.parser.records):
            allow_flat_copy = self._is_flat_copy_type(record_name)
            allow_pycast = self._is_pycast_type(record_name)
            if allow_pycast:
                runtime_defs.write(
                    f'pyimgui_register_memory_type(m.attr("{record_name}"), '
                    f'pyimgui_make_memory_type<{record_name}, true, {str(allow_flat_copy).lower()}, true>("{record_name}"));\n'
                )
            else:
                runtime_defs.write(
                    f'pyimgui_register_memory_type(m.attr("{record_name}"), '
                    f'pyimgui_make_raw_memory_type("{record_name}", sizeof({record_name}*), sizeof({record_name}), true));\n'
                )
            if allow_pycast:
                runtime_defs.write(
                    f'm.def("PtrIdx", []({record_name}& obj, py::ssize_t index) -> {record_name}* {{ '
                    f'if (index < 0) _throwV_("Negative pointer index: {{}}", index); return &obj + index; '
                    f'}}, py::arg("obj"), py::arg("index"), py::return_value_policy::reference);\n'
                )

        self.out.append((
            self.core_dir / 'structs.h',
            '#pragma once\n'
            '#include "gHeader.h"\n'
            '#include "./enums.h"\n'
            '#include "./runtime.h"\n'
            'namespace mNameSpace{ namespace PyImguiCore{\n'
            'void pybind_setup_pyimgui_structs(pybind11::module_ m);\n'
            '}}\n'
        ))
        self.out.append((
            self.core_dir / 'structs.cpp',
            '#include "./structs.h"\n'
            'namespace mNameSpace{ namespace PyImguiCore{\n'
            f'{specified_wrappers.get("__STRUCTS_EXTRA__", "")}\n'
            'void pybind_setup_pyimgui_structs(pybind11::module_ m)\n'
            '{\n'
            '    pyimgui_setup_runtime(m);\n'
            f'{specified_wrappers.get("__STRUCTS_DEF_EXTRA__", "")}\n'
            f'{template_defs.getvalue()}'
            f'{struct_defs.getvalue()}'
            f'{runtime_defs.getvalue()}'
            '}\n'
            '}}\n'
        ))

    def generate_globals(self):
        global_defs = CodeWriter(1)
        seen_signatures = set()
        for name in sorted(self.parser.functions):
            if name in seen_signatures:
                continue
            if key := specified_wrappers.get(f'_GFUNC_:{name}'):
                global_defs.write(f'{key}\n')
                continue
            for overload in self.parser.functions[name]:
                signature = (name, overload.result, tuple(arg.type for arg in overload.args))
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                global_defs.write(self.make_function_def(overload) + '\n')

        self.out.append((
            self.core_dir / 'globals.h',
            '#pragma once\n'
            '#include "gHeader.h"\n'
            '#include "./enums.h"\n'
            '#include "./runtime.h"\n'
            'namespace mNameSpace{ namespace PyImguiCore{\n'
            'void pybind_setup_pyimgui_globals(pybind11::module_ m);\n'
            '}}\n'
        ))
        self.out.append((
            self.core_dir / 'globals.cpp',
            '#include "./globals.h"\n'
            'namespace mNameSpace{ namespace PyImguiCore{\n'
            f'{specified_wrappers.get("__GLOBAL_EXTRA__", "")}\n'
            'void pybind_setup_pyimgui_globals(pybind11::module_ m)\n'
            '{\n'
            f'{specified_wrappers.get("__GLOBAL_DEF_EXTRA__", "")}\n'
            f'{global_defs.getvalue()}'
            '}\n'
            '}}\n'
        ))

    def flush(self):
        to_remove = set()
        if self.output_dir.is_dir():
            for file in self.output_dir.iterdir():
                if file.is_file() and file.name.endswith('.cpp'):
                    to_remove.add(file)
        for file, data in self.out:
            file.parent.mkdir(parents=True, exist_ok=True)
            to_remove.discard(file)
            old_data = None
            if file.is_file():
                with open(file, 'r', encoding='utf-8') as f:
                    old_data = f.read()
            if old_data != data:
                print(f'Updating {file}...')
                with open(file, 'w', encoding='utf-8') as f:
                    f.write(data)
        for file in to_remove:
            print(f'Removing {file}...')
            os.remove(file)


SUPPORT_VERSIONS = {
    'imgui': 'tags/v1.91.5-docking',
}
AUTO_PULL = False


def _checkout_git_ref(repo_dir, version):
    git_at = ensure_env.ensure_git()
    subprocess.check_call([git_at, 'reset', '--hard', 'HEAD'], cwd=repo_dir)
    subprocess.check_call([git_at, 'fetch', '--tags'], cwd=repo_dir)
    subprocess.check_call([git_at, 'checkout', version], cwd=repo_dir)
    subprocess.check_call([git_at, 'submodule', 'update', '--init', '--recursive'], cwd=repo_dir)


def load_requirements(auto_src_dir, backends):
    auto_src_dir.mkdir(parents=True, exist_ok=True)
    cached_versions = {}
    cached_versions_fp = auto_src_dir / 'versions.json'
    if cached_versions_fp.is_file():
        with open(cached_versions_fp, 'r', encoding='utf-8') as f:
            cached_versions = json.load(f)

    def update_versions():
        with open(cached_versions_fp, 'w', encoding='utf-8') as f:
            json.dump(cached_versions, f, indent=2)

    git_at = ensure_env.ensure_git()
    imgui_dir = auto_src_dir / 'imgui'
    if not imgui_dir.is_dir():
        subprocess.check_call([git_at, 'clone', 'https://github.com/ocornut/imgui.git', imgui_dir], cwd=auto_src_dir)
    if cached_versions.get('imgui') != (imgui_version := SUPPORT_VERSIONS['imgui']):
        _checkout_git_ref(imgui_dir, imgui_version)
        cached_versions['imgui'] = imgui_version
        update_versions()

    stb_dir = auto_src_dir / 'stb'
    if not stb_dir.is_dir():
        subprocess.check_call([git_at, 'clone', 'https://github.com/nothings/stb.git', stb_dir], cwd=auto_src_dir)
    elif AUTO_PULL:
        subprocess.check_call([git_at, 'pull'], cwd=stb_dir)

    detours_dir = auto_src_dir / 'detours'
    if not detours_dir.is_dir():
        subprocess.check_call([git_at, 'clone', 'https://github.com/microsoft/Detours.git', detours_dir], cwd=auto_src_dir)
    elif AUTO_PULL:
        subprocess.check_call([git_at, 'pull'], cwd=detours_dir)

    required('clang')
    libclang_dll = ensure_env.ensure_msys2_file('/clang64/bin/libclang.dll')
    from clang import cindex
    cindex.Config.set_library_file(str(libclang_dll))
    cindex.Config.set_compatibility_check(False)
    return imgui_dir, stb_dir, detours_dir


def pybind11_build(*a, debug=0, **kw):
    ensure_env.ensure_msvc()
    required('pybind11')
    required('setuptools')
    if sys.version_info < (3, 12):
        os.environ['SETUPTOOLS_USE_DISTUTILS'] = 'stdlib'
    from setuptools import Distribution
    from pybind11.setup_helpers import Pybind11Extension, build_ext

    ext = Pybind11Extension(*a, **kw)
    extra = list(getattr(ext, 'extra_compile_args', []) or [])
    for flag in ('/bigobj', '/Zm500', '/std:c++20'):
        if flag not in extra:
            extra.append(flag)
    ext.extra_compile_args = extra

    # Setuptools' inplace copy step does not auto-create the parent package
    # directory, so for dotted module names (e.g. ``pyimgui.dx9``) we make
    # sure ``./pyimgui/`` exists before the build runs. Otherwise the .pyd is
    # silently dropped and downstream packaging (copy_build_outputs, etc.)
    # never sees it.
    module_name = kw.get('name') or (a[0] if a else None)
    if module_name and '.' in module_name:
        parts = module_name.split('.')
        pathlib.Path.cwd().joinpath(*parts[:-1]).mkdir(parents=True, exist_ok=True)

    dist = Distribution({
        'cmdclass': {'build_ext': build_ext},
        'ext_modules': [ext],
    })
    cmd_obj = dist.get_command_obj('build_ext')
    cmd_obj.inplace = 1
    cmd_obj.ensure_finalized()
    cmd_obj.debug = debug
    cmd_obj.run()


def stub_gen(module_name, output_dir, field_stub_types=None, function_return_types=None):
    required('pybind11-stubgen')
    import pybind11_stubgen
    args = pybind11_stubgen.arg_parser().parse_args(['-o', str(output_dir), module_name], namespace=pybind11_stubgen.CLIArgs())
    out_dir, sub_dir = pybind11_stubgen.to_output_and_subdir(
        output_dir=args.output_dir,
        module_name=args.module_name,
        root_suffix=args.root_suffix,
    )
    pybind11_stubgen.run(
        pybind11_stubgen.stub_parser_from_args(args),
        pybind11_stubgen.Printer(invalid_expr_as_ellipses=not args.print_invalid_expressions_as_is),
        args.module_name,
        out_dir,
        sub_dir=sub_dir,
        dry_run=args.dry_run,
        writer=pybind11_stubgen.Writer(stub_ext=args.stub_extension),
    )
    postprocess_stubs(pathlib.Path(output_dir), module_name, field_stub_types or {}, function_return_types or {})


def _patch_class_block(data, class_name, replacements):
    pattern = re.compile(rf'(class {re.escape(class_name)}[^:]*:\n)(.*?)(?=\nclass |\ndef |\Z)', re.S)

    def replace(match):
        body = match.group(2)
        for old, new in replacements.items():
            body = body.replace(old, new)
        return match.group(1) + body

    return pattern.sub(replace, data, count=1)


def _patch_field_stub_types(data, field_stub_types):
    for class_name, fields in field_stub_types.items():
        pattern = re.compile(rf'(class {re.escape(class_name)}[^:]*:\n)(.*?)(?=\nclass |\ndef |\Z)', re.S)

        def replace(match):
            body = match.group(2)
            for field_name, field_type in fields.items():
                body = re.sub(
                    rf'(^    {re.escape(field_name)}: )[^\n]+',
                    rf'\g<1>{field_type}',
                    body,
                    flags=re.M,
                )
                body = re.sub(
                    rf'(def {re.escape(field_name)}\(self\) -> )[^:\n]+:',
                    rf'\g<1>{field_type}:',
                    body,
                )
                body = re.sub(
                    rf'(^    def {re.escape(field_name)}\(self, [^:]+: )typing\.Any(\) -> None:)',
                    rf'\g<1>{field_type}\g<2>',
                    body,
                    flags=re.M,
                )
            return match.group(1) + body

        data = pattern.sub(replace, data, count=1)
    return data


def _patch_function_return_types(data, function_return_types):
    global_returns = function_return_types.get('', {})
    for function_name, return_type in global_returns.items():
        data = re.sub(
            rf'(^def {re.escape(function_name)}\([^\n]*\) -> )[^:\n]+:',
            rf'\g<1>{return_type}:',
            data,
            flags=re.M,
        )
    for class_name, methods in function_return_types.items():
        if not class_name:
            continue
        pattern = re.compile(rf'(class {re.escape(class_name)}[^:]*:\n)(.*?)(?=\nclass |\ndef |\Z)', re.S)

        def replace(match):
            body = match.group(2)
            for method_name, return_type in methods.items():
                body = re.sub(
                    rf'(^    def {re.escape(method_name)}\([^\n]*\) -> )[^:\n]+:',
                    rf'\g<1>{return_type}:',
                    body,
                    flags=re.M,
                )
            return match.group(1) + body

        data = pattern.sub(replace, data, count=1)
    return data


def postprocess_stubs(output_dir, module_name, field_stub_types=None, function_return_types=None):
    imgui_stub = output_dir / module_name / 'imgui' / '__init__.pyi'
    if not imgui_stub.is_file():
        return
    data = imgui_stub.read_text(encoding='utf-8')
    if 'class Pointer' not in data or 'class Array' not in data:
        return
    if '_T = typing.TypeVar("_T")' not in data:
        data = data.replace('from . import ctx\n', 'from . import ctx\n_T = typing.TypeVar("_T")\n')
    data = data.replace('class Array(Pointer):', 'class Array(typing.Generic[_T]):')
    data = data.replace('class ArrayFlat:', 'class ArrayFlat(typing.Generic[_T]):')
    data = data.replace('class Pointer:', 'class Pointer(typing.Generic[_T]):')
    data = _patch_class_block(data, 'Array', {
        'def __getitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex) -> typing.Any:':
            'def __getitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex) -> _T:',
        'def __setitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex, arg1: typing.Any) -> None:':
            'def __setitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex, arg1: _T) -> None:',
    })
    data = _patch_class_block(data, 'ArrayFlat', {
        'def __getitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex) -> typing.Any:':
            'def __getitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex) -> _T:',
        'def __setitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex, arg1: typing.Any) -> None:':
            'def __setitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex, arg1: _T) -> None:',
    })
    data = _patch_class_block(data, 'Pointer', {
        'content: typing.Any': 'content: _T',
        'def __getitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex) -> typing.Any:':
            'def __getitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex) -> _T:',
        'def __setitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex, arg1: typing.Any) -> None:':
            'def __setitem__(self, arg0: typing.SupportsInt | typing.SupportsIndex, arg1: _T) -> None:',
    })
    data = _patch_field_stub_types(data, field_stub_types or {})
    data = _patch_function_return_types(data, function_return_types or {})
    imgui_stub.write_text(data, encoding='utf-8')


def patch_frontend_compat_stubs(output_dir, frontends):
    init_stub = pathlib.Path(output_dir) / 'pyimgui' / '__init__.pyi'
    if not init_stub.is_file():
        return
    data = init_stub.read_text(encoding='utf-8')
    exports = ['gUtils', 'imgui']
    imports = []
    if 'dx9' in frontends:
        exports.extend(['Dx9Inbound', 'Dx9Window', '_Dx9Render'])
        imports.append('from pyimgui.dx9 import Dx9Inbound as Dx9Inbound, Dx9Window as Dx9Window, _Dx9Render as _Dx9Render')
    if 'dx10' in frontends:
        exports.extend(['Dx10Inbound', 'Dx10Render', 'Dx10Window', '_Dx10Render'])
        imports.append('from pyimgui.dx10 import Dx10Inbound as Dx10Inbound, Dx10Window as Dx10Window, _Dx10Render as _Dx10Render')
        imports.append('Dx10Render = _Dx10Render')
    if 'dx11' in frontends:
        exports.extend(['Dx11Inbound', 'Dx11Texture', 'Dx11Window', '_Dx11Render', '_RenderBase'])
        imports.append('from pyimgui.dx11 import Dx11Inbound as Dx11Inbound, Dx11Texture as Dx11Texture, Dx11Window as Dx11Window, _Dx11Render as _Dx11Render, _RenderBase as _RenderBase')
    if 'dx12' in frontends:
        exports.extend(['Dx12Inbound', 'Dx12Render', 'Dx12TextureHelper', 'Dx12Window'])
        imports.append('from pyimgui.dx12 import Dx12Inbound as Dx12Inbound, Dx12Render as Dx12Render, Dx12TextureHelper as Dx12TextureHelper, Dx12Window as Dx12Window')
    if 'gl3' in frontends:
        exports.extend(['Gl3Inbound', 'Gl3Render', 'Gl3Window', '_Gl3Render'])
        imports.append('from pyimgui.gl3 import Gl3Inbound as Gl3Inbound, Gl3Window as Gl3Window, _Gl3Render as _Gl3Render')
        imports.append('Gl3Render = _Gl3Render')
    if 'vk' in frontends:
        exports.extend(['VkInbound', 'VkRender', 'VkWindow', '_VkRender'])
        imports.append('from pyimgui.vk import VkInbound as VkInbound, VkWindow as VkWindow, _VkRender as _VkRender')
        imports.append('VkRender = _VkRender')
    if imports:
        data = re.sub(
            r"__all__: list\[str\] = \[[^\]]*\]",
            f"__all__: list[str] = {exports!r}",
            data,
            count=1,
        )
        insert_at = data.find('__all__: list[str]')
        if insert_at != -1:
            end = data.find('\n', insert_at)
            if end != -1:
                import_text = '\n'.join(imports)
                if import_text not in data:
                    data = data[:end + 1] + import_text + '\n' + data[end + 1:]
    init_stub.write_text(data, encoding='utf-8')


def patch_frontend_module_stubs(output_dir, module_name):
    output_dir = pathlib.Path(output_dir)
    module_parts = module_name.split('.')
    module_key = module_parts[-1]
    flat_stub = output_dir.joinpath(*module_parts).with_suffix('.pyi')
    package_stub = output_dir.joinpath(*module_parts) / '__init__.pyi'
    module_stub = package_stub if package_stub.is_file() else flat_stub
    if not module_stub.is_file():
        return
    if package_stub.is_file() and flat_stub.is_file():
        flat_stub.unlink()
    data = module_stub.read_text(encoding='utf-8')
    if module_key == 'dx9':
        data = re.sub(
            r"__all__: list\[str\] = \[[^\]]*\]",
            "__all__: list[str] = ['Dx9Inbound', 'Dx9Window', '_Dx9Render', '_RenderBase', 'detours', 'inbound']",
            data,
            count=1,
        )
    elif module_key == 'dx10':
        data = re.sub(
            r"__all__: list\[str\] = \[[^\]]*\]",
            "__all__: list[str] = ['Dx10Inbound', 'Dx10Render', 'Dx10Window', '_Dx10Render', '_RenderBase', 'detours', 'inbound']",
            data,
            count=1,
        )
        data = data.replace('Dx10Render = _Dx10Render\n', '')
        data = data.rstrip() + '\nDx10Render = _Dx10Render\n'
    elif module_key == 'dx11':
        data = re.sub(
            r"__all__: list\[str\] = \[[^\]]*\]",
            "__all__: list[str] = ['Dx11Inbound', 'Dx11Texture', 'Dx11Window', '_Dx11Render', '_RenderBase', 'detours', 'inbound']",
            data,
            count=1,
        )
    elif module_key == 'dx12':
        data = re.sub(
            r"__all__: list\[str\] = \[[^\]]*\]",
            "__all__: list[str] = ['Dx12Inbound', 'Dx12Render', 'Dx12TextureHelper', 'Dx12Window', '_RenderBase', 'detours', 'inbound']",
            data,
            count=1,
        )
    elif module_key == 'gl3':
        data = re.sub(
            r"__all__: list\[str\] = \[[^\]]*\]",
            "__all__: list[str] = ['Gl3Inbound', 'Gl3Render', 'Gl3Window', '_Gl3Render', '_RenderBase', 'detours', 'inbound']",
            data,
            count=1,
        )
        data = data.replace('Gl3Render = _Gl3Render\n', '')
        data = data.rstrip() + '\nGl3Render = _Gl3Render\n'
    elif module_key == 'vk':
        data = re.sub(
            r"__all__: list\[str\] = \[[^\]]*\]",
            "__all__: list[str] = ['VkInbound', 'VkRender', 'VkWindow', '_VkRender', '_RenderBase', 'detours', 'inbound']",
            data,
            count=1,
        )
        data = data.replace('VkRender = _VkRender\n', '')
        data = data.rstrip() + '\nVkRender = _VkRender\n'
    module_stub.write_text(data, encoding='utf-8')
    inbound_stub = output_dir.joinpath(*module_parts) / 'inbound.pyi'
    if inbound_stub.is_file():
        inbound_data = inbound_stub.read_text(encoding='utf-8')
        inbound_data = re.sub(r'^    None: typing\.ClassVar\[RenderType\].*\n', '', inbound_data, flags=re.M)
        inbound_stub.write_text(inbound_data, encoding='utf-8')


def cleanup_legacy_frontend_outputs(cwd):
    cwd = pathlib.Path(cwd)
    for legacy_dir in cwd.glob('pyimgui_dx*'):
        if legacy_dir.is_dir():
            shutil.rmtree(legacy_dir)
    for legacy_file in cwd.glob('pyimgui_dx*.*'):
        if legacy_file.is_file():
            legacy_file.unlink()


def copy_build_outputs(cwd, debug=0):
    cwd = pathlib.Path(cwd)
    core_files = sorted(cwd.glob('pyimgui*.pyd'))
    package_dir = cwd / 'pyimgui'
    if not core_files:
        print('copy_build_outputs: no pyimgui*.pyd in cwd, skipping')
        return
    if not package_dir.is_dir():
        print('copy_build_outputs: pyimgui/ package dir is missing, creating empty one')
        package_dir.mkdir(parents=True, exist_ok=True)
    for dst_dir in (cwd.parent.parent / 'nylib', cwd / ('debug' if debug else 'release')):
        dst_dir.mkdir(parents=True, exist_ok=True)
        for core_file in core_files:
            shutil.copy2(core_file, dst_dir / core_file.name)
        dst_package_dir = dst_dir / 'pyimgui'
        if dst_package_dir.is_dir():
            shutil.rmtree(dst_package_dir)
        shutil.copytree(package_dir, dst_package_dir)


def generate(backends, debug=0, with_stubs=True):
    cwd = pathlib.Path(__file__).parent.resolve()
    src_dir = cwd / 'src'
    auto_src_dir = cwd / 'auto_src'
    imgui_dir, stb_dir, detours_dir = load_requirements(auto_src_dir, backends)
    pyimgui_generator = PyImguiGenerator(imgui_dir, auto_src_dir / 'pyimgui', backends)
    pyimgui_srcs = pyimgui_generator.generate()

    old_cwd = pathlib.Path.cwd()
    os.chdir(cwd)
    atexit.register(lambda: os.chdir(old_cwd))
    try:
        cleanup_legacy_frontend_outputs(cwd)
        core_import_lib = cwd / 'pyimgui_core.lib'
        core_compile_args = [
            '/D_AMD64_=1',
            '/DUNICODE',
            '/D_UNICODE',
            '/utf-8',
            '/DIMGUI_API=__declspec(dllexport)',
        ]
        frontend_compile_args = [
            '/D_AMD64_=1',
            '/DUNICODE',
            '/D_UNICODE',
            '/utf-8',
            '/DIMGUI_API=__declspec(dllimport)',
            '/DIMGUI_IMPL_API=',
        ]
        common_include_dirs = sorted(map(str, [
            auto_src_dir / 'pyimgui',
            imgui_dir,
            imgui_dir / 'backends',
            src_dir,
            auto_src_dir,
            stb_dir,
        ]))
        pybind11_build(
            name='pyimgui',
            sources=sorted(map(str, [
                *imgui_dir.glob('*.cpp'),
                *pyimgui_srcs,
                src_dir / 'DllMain.cpp',
                src_dir / 'gHeader.cpp',
                src_dir / 'ImguiCtx.cpp',
                src_dir / 'UnhandledException.cpp',
                src_dir / 'Win32Font.cpp',
            ])),
            include_dirs=common_include_dirs,
            extra_objects=[],
            extra_compile_args=core_compile_args,
            extra_link_args=[f'/IMPLIB:{core_import_lib}'],
            debug=debug,
        )
        frontend_modules = []
        if 'dx9' in backends:
            pybind11_build(
                name='pyimgui.dx9',
                sources=sorted(map(str, [
                    imgui_dir / 'backends' / 'imgui_impl_win32.cpp',
                    imgui_dir / 'backends' / 'imgui_impl_dx9.cpp',
                    *(src_dir / 'frontends' / 'common').glob('*.cpp'),
                    *(src_dir / 'frontends' / 'dx9').glob('*.cpp'),
                    *(f for f in (detours_dir / 'src').glob('*.cpp') if f.name != 'uimports.cpp'),
                    src_dir / 'gHeader.cpp',
                ])),
                include_dirs=common_include_dirs,
                extra_objects=[str(core_import_lib)],
                extra_compile_args=frontend_compile_args,
                libraries=['user32', 'gdi32', 'dwmapi', 'shell32', 'd3d9'],
                debug=debug,
            )
            frontend_modules.append('pyimgui.dx9')
        if 'dx10' in backends:
            pybind11_build(
                name='pyimgui.dx10',
                sources=sorted(map(str, [
                    imgui_dir / 'backends' / 'imgui_impl_win32.cpp',
                    imgui_dir / 'backends' / 'imgui_impl_dx10.cpp',
                    *(src_dir / 'frontends' / 'common').glob('*.cpp'),
                    *(src_dir / 'frontends' / 'dx10').glob('*.cpp'),
                    *(f for f in (detours_dir / 'src').glob('*.cpp') if f.name != 'uimports.cpp'),
                    src_dir / 'gHeader.cpp',
                ])),
                include_dirs=common_include_dirs,
                extra_objects=[str(core_import_lib)],
                extra_compile_args=frontend_compile_args,
                libraries=['user32', 'gdi32', 'dwmapi', 'shell32', 'd3d10', 'dxgi'],
                debug=debug,
            )
            frontend_modules.append('pyimgui.dx10')
        if 'dx11' in backends:
            pybind11_build(
                name='pyimgui.dx11',
                sources=sorted(map(str, [
                    imgui_dir / 'backends' / 'imgui_impl_win32.cpp',
                    imgui_dir / 'backends' / 'imgui_impl_dx11.cpp',
                    *(src_dir / 'frontends' / 'common').glob('*.cpp'),
                    *(f for f in (detours_dir / 'src').glob('*.cpp') if f.name != 'uimports.cpp'),
                    src_dir / 'gHeader.cpp',
                    src_dir / 'Dx11Window.cpp',
                    src_dir / 'Dx11Module.cpp',
                ])),
                include_dirs=common_include_dirs,
                extra_objects=[str(core_import_lib)],
                extra_compile_args=frontend_compile_args,
                libraries=['user32', 'gdi32', 'dwmapi', 'shell32', 'd3d11', 'dxgi'],
                debug=debug,
            )
            frontend_modules.append('pyimgui.dx11')
        if 'dx12' in backends:
            pybind11_build(
                name='pyimgui.dx12',
                sources=sorted(map(str, [
                    imgui_dir / 'backends' / 'imgui_impl_win32.cpp',
                    imgui_dir / 'backends' / 'imgui_impl_dx12.cpp',
                    *(src_dir / 'frontends' / 'common').glob('*.cpp'),
                    *(src_dir / 'frontends' / 'dx12').glob('*.cpp'),
                    *(f for f in (detours_dir / 'src').glob('*.cpp') if f.name != 'uimports.cpp'),
                    src_dir / 'gHeader.cpp',
                ])),
                include_dirs=common_include_dirs,
                extra_objects=[str(core_import_lib)],
                extra_compile_args=frontend_compile_args,
                libraries=['user32', 'gdi32', 'dwmapi', 'shell32', 'd3d12', 'dxgi', 'dxguid'],
                debug=debug,
            )
            frontend_modules.append('pyimgui.dx12')
        if 'gl3' in backends:
            pybind11_build(
                name='pyimgui.gl3',
                sources=sorted(map(str, [
                    imgui_dir / 'backends' / 'imgui_impl_win32.cpp',
                    imgui_dir / 'backends' / 'imgui_impl_opengl3.cpp',
                    *(src_dir / 'frontends' / 'common').glob('*.cpp'),
                    *(src_dir / 'frontends' / 'gl3').glob('*.cpp'),
                    *(f for f in (detours_dir / 'src').glob('*.cpp') if f.name != 'uimports.cpp'),
                    src_dir / 'gHeader.cpp',
                ])),
                include_dirs=common_include_dirs,
                extra_objects=[str(core_import_lib)],
                extra_compile_args=frontend_compile_args,
                libraries=['user32', 'gdi32', 'dwmapi', 'shell32', 'opengl32'],
                debug=debug,
            )
            frontend_modules.append('pyimgui.gl3')
        if 'vk' in backends:
            vulkan_sdk_path = pathlib.Path(ensure_env.ensure_vulkan_sdk())
            vulkan_include_dir = vulkan_sdk_path / 'Include'
            vulkan_lib = vulkan_sdk_path / 'Lib' / 'vulkan-1.lib'
            if not vulkan_include_dir.is_dir():
                raise RuntimeError(f"Vulkan SDK include dir not found: {vulkan_include_dir}")
            if not vulkan_lib.is_file():
                raise RuntimeError(f"Vulkan SDK import lib not found: {vulkan_lib}")
            pybind11_build(
                name='pyimgui.vk',
                sources=sorted(map(str, [
                    imgui_dir / 'backends' / 'imgui_impl_win32.cpp',
                    imgui_dir / 'backends' / 'imgui_impl_vulkan.cpp',
                    *(src_dir / 'frontends' / 'common').glob('*.cpp'),
                    *(src_dir / 'frontends' / 'vk').glob('*.cpp'),
                    *(f for f in (detours_dir / 'src').glob('*.cpp') if f.name != 'uimports.cpp'),
                    src_dir / 'gHeader.cpp',
                ])),
                include_dirs=common_include_dirs + [str(vulkan_include_dir)],
                extra_objects=[str(core_import_lib), str(vulkan_lib)],
                extra_compile_args=frontend_compile_args,
                libraries=['user32', 'gdi32', 'dwmapi', 'shell32'],
                debug=debug,
            )
            frontend_modules.append('pyimgui.vk')
        if with_stubs:
            stub_gen('pyimgui', str(cwd), pyimgui_generator.stub_field_types, pyimgui_generator.stub_function_return_types)
            for frontend_module in frontend_modules:
                stub_gen(frontend_module, str(cwd))
                patch_frontend_module_stubs(cwd, frontend_module)
            patch_frontend_compat_stubs(cwd, {module.rsplit('.', 1)[-1] for module in frontend_modules})
        copy_build_outputs(cwd, debug=debug)
    finally:
        os.chdir(old_cwd)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--skip', action='store_true')
    parser.add_argument('--skip-stubs', action='store_true')
    # Auto-close the post-build demo after this many frames so unattended
    # build invocations always self-terminate. Pass 0 for an interactive
    # session that runs until the user closes the window.
    parser.add_argument('--test-frames', type=int, default=600)
    args = parser.parse_args()

    generate(['win32', 'dx9', 'dx10', 'dx11', 'dx12', 'gl3', 'vk'], debug=args.debug, with_stubs=not args.skip_stubs)
    if not args.skip:
        import pyimgui_test
        pyimgui_test.test(auto_close_frames=args.test_frames)


if __name__ == '__main__':
    main()