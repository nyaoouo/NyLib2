import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

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


def update_generated_files(source_dir, files):
    to_remove = set()
    if source_dir.is_dir():
        for file in source_dir.iterdir():
            if file.is_file() and file.name.endswith('.cpp'):
                to_remove.add(file)
    for file, data in files:
        file.parent.mkdir(parents=True, exist_ok=True)
        to_remove.discard(file)
        old_data = None
        if file.is_file():
            with open(file, 'r', encoding='utf-8') as f:
                old_data = f.read()
        if old_data != data:
            print(f"Updating {file}...")
            with open(file, 'w', encoding='utf-8') as f:
                f.write(data)
    for file in to_remove:
        print(f"Removing {file}...")
        os.remove(file)


def generate_pyimgui(cimgui_dir, output_dir, backends):
    def_dir = cimgui_dir / 'generator' / 'output'
    with open(def_dir / 'structs_and_enums.json', 'r', encoding='utf-8') as f:
        struct_and_enums = json.load(f)
    with open(def_dir / 'definitions.json', 'r', encoding='utf-8') as f:
        func_defs = json.load(f)
    with open(def_dir / 'typedefs_dict.json', 'r', encoding='utf-8') as f:
        typedefs_dict = json.load(f)

    def solve_typedef(t):
        while t in typedefs_dict:
            t_ = typedefs_dict[t]
            if t_.startswith('struct ') or re.search(r"\(\*\)\((.*)\)$", t_):
                return t
            t = t_
        return t

    typedefs_dict = {n: solve_typedef(t) for n, t in typedefs_dict.items() if not (t.startswith('struct ') or re.search(r"\(\*\)\((.*)\)$", t))}

    enum_defs = CodeWriter(0)
    for enum_type, enum_items in struct_and_enums['enums'].items():
        enum_defs.write(f"py::enum_<{enum_type}>(m, \"{enum_type}\")")
        with enum_defs.push_indent():
            for item in enum_items:
                enum_defs.write(f".value(\"{item['name']}\", {item['name']})")
            enum_defs.write(".export_values();")

    def export_template_create(writer, template_name):
        writer.write(f"template <typename T>\n")
        writer.write(f"void pybind_setup_template_cls_{template_name}(py::module &m, const char* type_name) {{")
        with writer.push_indent():
            writer.write(f"\npy::class_<T>(m, type_name, py::dynamic_attr())")
            with writer.push_indent():
                # for field in struct_and_enums['templated_structs'][template_name]:
                #     field_name = field['name']
                #     try:
                #         field_name = field_name[:field_name.index('[')]
                #     except ValueError:
                #         pass
                #     writer.write(f"\n.def_readwrite(\"{field_name}\", &T::{field_name})")
                if s := specified_wrappers.get(f'_TCLS_EXTRA_{template_name}', ''):
                    writer.write('\n' + s)
            writer.write(";\n")
        writer.write("}\n")

    template_defs = CodeWriter(0)
    for template_name in struct_and_enums['templated_structs'].keys():
        export_template_create(template_defs, template_name)

    exported_types = set()
    template_need_export = set()

    def make_func_desc(func):
        if (s := specified_wrappers.get(f"_GFUNC_:{func['ov_cimguiname']}")) is not None:
            return s, set()
        if func.get('isvararg'): return f"/* TODO:varg func {func['ov_cimguiname']}*/", set()
        if any(arg['type'] == 'va_list' for arg in func['argsT']): return f"/* TODO:va_list func {func['ov_cimguiname']}*/", set()

        real_arg_off = nonUDT = func.get("nonUDT", 0)

        if not func.get('stname'):
            func_type = 0  # global function
        elif func.get("constructor"):
            func_type = 11  # class constructor
        elif func.get("destructor"):
            func_type = 12  # class destructor
        elif func.get("is_static_function"):
            func_type = 2  # class static method
        else:
            func_type = 1  # class method

        if nonUDT or func_type == 1:
            func_args = []
            if func_type == 1:
                real_arg_off += 1
                func_args.append((func['stname'] + '&', 'self', None))
            for argt in func['argsT'][real_arg_off:]:
                func_args.append((argt['type'], argt['name'], func.get("defaults", {}).get(argt['name'])))
            func_args = ', '.join(f"{t} {n}" for t, n, _ in func_args)
            has_return = int(func.get('ret', 'void') != 'void')
            call_args = [f"&__out_{i}" for i in range(nonUDT)]
            if func_type == 1: call_args.append("&self")
            call_args.extend(arg['name'] for arg in func['argsT'][real_arg_off:])
            ret_args = []
            if has_return: ret_args.append("__ret")
            ret_args.extend(f"__out_{i}" for i in range(nonUDT))

            # print(func['ov_cimguiname'],real_arg_off, func_args, call_args, ret_args)

            desc = f"[]({func_args}){{"
            for i, argt in enumerate(func['argsT'][:nonUDT]):
                desc += f"{argt['type'][:-1]} __out_{i} = {{}};"
            if has_return:
                desc += "auto __ret = "
            desc += f"{func['ov_cimguiname']}({', '.join(call_args)});"

            if len(ret_args) == 1:
                desc += f"return {ret_args[0]};"
            elif len(ret_args) > 1:
                desc += f"return std::make_tuple({', '.join(ret_args)});"
            desc += "}"
        else:
            desc = f"&{func['ov_cimguiname']}"

        args = ''
        extra_types = set()
        for argt in func['argsT'][real_arg_off:]:
            args += f", py::arg(\"{argt['name']}\")"
            if (d := func.get("defaults", {}).get(argt['name'])) is not None:
                args += f" = {d}"
            t = argt['type'].rstrip('*&')
            if t.startswith("const "):
                t = t[6:]
            elif t.startswith("struct "):
                t = t[7:]
            elif t.startswith("enum "):
                t = t[5:]
            if t in struct_and_enums['structs']:
                extra_types.add(t)
        if nonUDT:
            args += ", py::return_value_policy::move"

        if (ret := func.get('ret', '')).endswith('*') and ret[:-1] in struct_and_enums['structs']:
            args += ", py::return_value_policy::reference"

        match func_type:
            case 0:  # global function
                return f".def(\"{func['funcname']}\", {desc}{args})", extra_types
            case 1:  # class method
                return f".def(\"{func['funcname']}\", {desc}{args})", extra_types
            case 2:  # class static method
                return f".def_static(\"{func['funcname']}\", {desc}{args})", extra_types
            case 11:  # class constructor
                return f".def(py::init({desc}){args})", extra_types
            case 12:  # class destructor
                return None, extra_types

    def export_field(writer, type_name, field):
        field_name = field['name']
        if size := field.get('size'):
            field_name = field_name[:field_name.index('[')]
        if (s := specified_wrappers.get(f'_CLS_FIELD_:{type_name}::{field_name}')) is not None:
            writer.write('\n' + s)
            return
        field_type = field['type'].strip()
        if not field_name and field_type.startswith('union '):
            for line_ in field_type[7:-1].split(';'):
                line = line_.strip()
                if not line: continue
                t, n = line.rsplit(' ', 1)
                export_field(writer, type_name, {'name': n, 'type': t})
            return
        if field_type.startswith('const '):
            field_type = field_type[6:].strip()
        if "template_type" in field:
            _template_base = field_type.split('_', 1)[0]
            template_need_export.add((_template_base, field['type'].rstrip('&*')))
        if m := re.search(r"\(\*\)\((.*)\)$", field_type):
            writer.write(f"\n// {field['name']} {field['type']}")
        elif size:
            # if field['type'].endswith('*'):
            #     writer.write(f"\n// {field['name']}: {field['type']}[{size}] not support")
            # else:
            #     writer.write(f"\n.def_property_readonly(\"{field_name}\", []({type_name}& self) {{ return self.{field_name}; }}) // {field['type']}[{size}]")
            _type = field['type']
            while _type in typedefs_dict:
                _type = typedefs_dict[_type]
            _typeN = _type.strip().replace(' ', '_')
            _typeN = ('p_' + _typeN[:-1]) if _typeN.endswith('*') else _typeN
            template_need_export.add((f"PyArrayWrapper<{_type}>::pybind_setup(m, \"Arr_{_typeN}\");", None))
            writer.write(f"\n.def_property_readonly(\"{field_name}\", []({type_name}& self) {{ return PyArrayWrapper<{field['type']}>(self.{field_name}, {size}); }}) // {field['type']}[{size}]")
        else:
            writer.write(f"\n.def_property(\"{field_name}\", []({type_name}& self) {{ return self.{field_name}; }}, []({type_name}& self, {field_type} value) {{ self.{field_name} = value; }}) // {field['type']}")

    def export_type(writer, type_name):
        if type_name in exported_types: return
        exported_types.add(type_name)
        code = CodeWriter()
        code.write(f"py::class_<{type_name}>(m, \"{type_name}\", py::dynamic_attr())")
        with code.push_indent():
            for field in struct_and_enums['structs'][type_name]:
                export_field(code, type_name, field)
            for func in struct_funcs.get(type_name, []):
                desc, extra_types = make_func_desc(func)
                if desc: code.write('\n' + desc)
                for t in extra_types:
                    if t in struct_and_enums['structs']:
                        export_type(writer, t)
            if s := specified_wrappers.get(f'_CLS_EXTRA_{type_name}', ''):
                template_defs.write('\n' + s)
        writer.write(code.getvalue().rstrip() + '\n;\n')

    struct_funcs = {}
    for overloads in func_defs.values():
        for overload in overloads:
            struct_funcs.setdefault(overload['stname'], []).append(overload)

    cls_defs = CodeWriter(1)
    for keys in struct_and_enums['structs'].keys():
        export_type(cls_defs, keys)
    cls_template_defs = CodeWriter(1)
    for template_name, template_type in sorted(template_need_export):
        if template_type is None:
            cls_template_defs.write(f'\n{template_name};')
            continue
        if template_type.endswith('*'):
            _template_type = 'p_' + template_type[:-1]
        else:
            _template_type = template_type
        cls_template_defs.write(f'\npybind_setup_template_cls_{template_name}<{template_type}>(m, "{template_type}");')

    glob_defs = CodeWriter(1)
    for func in struct_funcs.get('', []):
        desc, extra_types = make_func_desc(func)
        if desc:
            if desc.startswith('/*') or desc.startswith('//'):
                glob_defs.write(desc)
            else:
                glob_defs.write('\nm' + desc + ';')
        # for t in extra_types:
        #     if t in struct_and_enums['structs']:
        #         export_type(cls_defs, t)

    core_dir = output_dir / 'pyimgui_core'
    update_generated_files(output_dir, [
        (
            core_dir / 'enums.h',
            "#pragma once\n"
            "#include \"gHeader.h\"\n"
            "namespace mNameSpace{ namespace PyImguiCore{\n"
            "void pybind_setup_pyimgui_enums(pybind11::module_ m);"
            "}}\n"
        ),
        (
            core_dir / 'enums.cpp',
            "#include \"./enums.h\"\n"
            "namespace mNameSpace{ namespace PyImguiCore{\n"
            f"void pybind_setup_pyimgui_enums(pybind11::module_ m) {{ {enum_defs.getvalue()} }}"
            "}}\n"
        ),
        (
            core_dir / 'structs.h',
            "#pragma once\n"
            "#include \"gHeader.h\"\n"
            "namespace mNameSpace{ namespace PyImguiCore{\n"
            "void pybind_setup_pyimgui_structs(pybind11::module_ m);\n"
            "}}\n"
        ),
        (
            core_dir / 'structs.cpp',
            "#include \"./structs.h\"\n"
            "namespace mNameSpace{ namespace PyImguiCore{\n"
            f"{specified_wrappers.get('__STRUCTS_EXTRA__', '')}\n"
            f'{template_defs.getvalue()}\n'
            f"void pybind_setup_pyimgui_structs(pybind11::module_ m) {{ {cls_template_defs.getvalue()} \n {cls_defs.getvalue()} }}"
            "}}\n"
        ),
        (
            core_dir / 'globals.h',
            "#pragma once\n"
            "#include \"gHeader.h\"\n"
            "namespace mNameSpace{ namespace PyImguiCore{\n"
            "void pybind_setup_pyimgui_globals(pybind11::module_ m);\n"
            "}}\n"
        ),
        (
            core_dir / 'globals.cpp',
            f"#include \"./globals.h\"\n"
            "namespace mNameSpace{ namespace PyImguiCore{\n"
            f"{specified_wrappers.get('__GLOBAL_EXTRA__', '')}\n"
            f"void pybind_setup_pyimgui_globals(pybind11::module_ m) {{ {specified_wrappers.get('__GLOBAL_DEF_EXTRA__', '')};"
            f" {glob_defs.getvalue()} }}"
            "}}\n"
        ),
        (
            output_dir / 'pyimgui.h',
            """#include  "gHeader.h"
#include "./pyimgui_core/enums.h"
#include "./pyimgui_core/structs.h"
#include "./pyimgui_core/globals.h"

#define PYIMGUI_CORE_NAMESPACE mNameSpace::PyImguiCore
namespace mNameSpace{ namespace PyImguiCore{
void pybind_setup_pyimgui_core(pybind11::module_ m);
}}
"""
        ),
        (
            output_dir / 'pyimgui.cpp',
            """#include  "./pyimgui.h"
namespace mNameSpace{ namespace PyImguiCore{
void pybind_setup_pyimgui_core(pybind11::module_ m) {
    pybind_setup_pyimgui_enums(m);
    pybind_setup_pyimgui_structs(m);
    pybind_setup_pyimgui_globals(m);
}
}}
        """
        )
    ])
    return [
        core_dir / 'enums.cpp',
        core_dir / 'structs.cpp',
        core_dir / 'globals.cpp',
        output_dir / 'pyimgui.cpp',
    ]


def load_luajit(luajit_dir):
    if not luajit_dir.is_dir():
        subprocess.check_call([
            ensure_env.ensure_git(), 'clone', 'https://luajit.org/git/luajit.git', luajit_dir
        ], cwd=luajit_dir.parent)
    bin_dir = luajit_dir / 'bin'
    src_dir = luajit_dir / 'src'
    if not (bin_dir / 'luajit.exe').is_file():
        if bin_dir.exists(): shutil.rmtree(bin_dir)
        subprocess.check_call([ensure_env.ensure_msys2_file('/clang64/bin/mingw32-make.exe')], cwd=luajit_dir)
        (bin_dir / 'lua').mkdir(parents=True)
        shutil.copy(src_dir / 'luajit.exe', bin_dir / 'luajit.exe')
        shutil.copy(src_dir / 'lua51.dll', bin_dir / 'lua51.dll')
        shutil.copytree(src_dir / 'jit', bin_dir / 'lua' / 'jit')
    return bin_dir / 'luajit.exe'


def load_requirements(auto_src_dir, backends):
    auto_src_dir.mkdir(parents=True, exist_ok=True)
    cimgui_dir = auto_src_dir / 'cimgui'
    if not cimgui_dir.is_dir():
        subprocess.check_call([ensure_env.ensure_git(), 'clone', 'https://github.com/cimgui/cimgui.git', cimgui_dir], cwd=auto_src_dir)
        subprocess.check_call([ensure_env.ensure_git(), 'submodule', 'update', '--init', '--recursive'], cwd=cimgui_dir)
    if not (auto_src_dir / 'detours').is_dir():
        subprocess.check_call([ensure_env.ensure_git(), 'clone', 'https://github.com/microsoft/Detours.git', auto_src_dir / 'detours'], cwd=auto_src_dir)

    ensure_env.ensure_msys2_file('/clang64/bin/gcc.exe')

    env = os.environ.copy()
    env = {**env, 'PATH': f"{env['PATH']};{pathlib.Path(ensure_env.ensure_msys2_file('/clang64/bin/gcc.exe')).parent}"}

    subprocess.check_call([
        load_luajit(auto_src_dir / 'luajit'),
        './generator.lua',
        'gcc', 'internal noimstrv',
        *backends,
    ], cwd=cimgui_dir / 'generator', env=env)


def pybind11_build(*a, debug=0, **kw):
    required('pybind11')
    if sys.version_info < (3, 12):
        os.environ['SETUPTOOLS_USE_DISTUTILS'] = 'stdlib'
    from setuptools import Distribution
    from pybind11.setup_helpers import Pybind11Extension, build_ext
    dist = Distribution({
        'cmdclass': {'build_ext': build_ext},
        'ext_modules': [Pybind11Extension(*a, **kw), ]
    })
    cmd_obj = dist.get_command_obj('build_ext')
    cmd_obj.inplace = 1
    cmd_obj.ensure_finalized()
    cmd_obj.debug = debug
    cmd_obj.run()


def stub_gen(module_name, output_dir):
    required('pybind11-stubgen')
    import pybind11_stubgen
    args = pybind11_stubgen.arg_parser().parse_args(["-o", str(output_dir), module_name], namespace=pybind11_stubgen.CLIArgs())
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


def generate(backends, debug=False):
    cwd = pathlib.Path(__file__).parent
    src_dir = cwd / 'src'
    auto_src_dir = cwd / 'auto_src'
    cimgui_dir = auto_src_dir / 'cimgui'
    imgui_dir = cimgui_dir / 'imgui'
    detours_dir = auto_src_dir / 'detours'
    load_requirements(auto_src_dir, backends)
    pybind11_build(
        name="pyimgui",
        sources=sorted(map(str, [
            *cimgui_dir.glob('*.cpp'),
            *imgui_dir.glob('*.cpp'),
            *generate_pyimgui(cimgui_dir, auto_src_dir / 'pyimgui', backends),
            *src_dir.glob('*.cpp'),
            *(src_dir / 'mImguiImpl').glob('*.cpp'),
            *(f for f in (detours_dir / 'src').glob('*.cpp') if f.name != 'uimports.cpp'),
            *(imgui_dir / 'backends' / f'imgui_impl_{backend}.cpp' for backend in backends),
        ])),
        include_dirs=sorted(map(str, [
            cimgui_dir,
            cimgui_dir / 'generator' / 'output',
            auto_src_dir / 'pyimgui',
            imgui_dir,
            imgui_dir / 'backends',
            src_dir,
            auto_src_dir,
        ])),
        extra_objects=[],
        extra_compile_args=[
            *(f'/DCIMGUI_USE_{backend.upper()}=1' for backend in backends),
            '/DIMGUI_DISABLE_OBSOLETE_FUNCTIONS=1',
            '/DIMGUI_IMPL_API=extern \"C\"',
            '/D_AMD64_=1',
            '/utf-8',
        ],
        debug=debug,
    )
    stub_gen('pyimgui', str(cwd))

    nylib_path = cwd.parent.parent / 'nylib'
    for file in cwd.glob('pyimgui.*.pyd'):
        shutil.copy(file, nylib_path / file.name)
    if (cwd.parent / 'nylib' / 'pyimgui').is_dir():
        shutil.rmtree(nylib_path / 'pyimgui')
    shutil.copytree(cwd / 'pyimgui', nylib_path / 'pyimgui')


def main():
    generate([
        'win32',
        'dx9',
        'dx10',
        'dx11',
        'dx12',
    ], debug=True)
    import pyimgui_test
    pyimgui_test.test()


if __name__ == '__main__':
    main()
