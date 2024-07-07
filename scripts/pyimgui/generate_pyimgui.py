import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

from nylib.utils.pip import required
from nylib.winutils import ensure_env, msvc
from func_wrappers import wrappers as specified_wrappers

backends = {
    # 'opengl3': [],
    # 'opengl2':[],
    # 'glfw': [],
    # 'sdl2':[],
    'win32': [],
    'dx9': [],
    'dx10': [],
    'dx11': [],
    'dx12': [],
}


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
        ind = ' ' * self.indent_size * self.indent
        self.buf.write('\n'.join(f"{ind}{line}" for line in s.splitlines()) + '\n')

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


def generate_pyimgui(cimgui_dir, output_dir):
    def_dir = cimgui_dir / 'generator' / 'output'
    with open(def_dir / 'structs_and_enums.json', 'r', encoding='utf-8') as f:
        struct_and_enums = json.load(f)
    with open(def_dir / 'definitions.json', 'r', encoding='utf-8') as f:
        func_defs = json.load(f)
    with open(def_dir / 'impl_definitions.json', 'r', encoding='utf-8') as f:
        impl_func_defs = json.load(f)

    res = []

    enum_defs = CodeWriter(0)

    for enum_type, enum_items in struct_and_enums['enums'].items():
        enum_defs.write(f"/*auto enum_{enum_type} = */py::enum_<{enum_type}>(m, \"{enum_type}\")")
        with enum_defs.push_indent():
            for item in enum_items:
                enum_defs.write(f".value(\"{item['name']}\", {item['name']})")
            enum_defs.write(".export_values();")

    exported_types = set()

    def export_field(writer, type_name, field_info):
        field_name = field_info['name']
        if size := field_info.get('size'):
            field_name = field_name[:field_name.index('[')]
        field_type = field_info['type'].strip()
        if not field_name and field_type.startswith('union '):
            for line_ in field_type[7:-1].split(';'):
                line = line_.strip()
                if not line: continue
                t, n = line.rsplit(' ', 1)
                export_field(writer, type_name, {'name': n, 'type': t})
            return
        if field_type.startswith('const '):
            field_type = field_type[6:].strip()
        if m := re.search(r"\(\*\)\((.*)\)$", type_name):
            writer.write(f"// {field_info['name']} {field_info['type']}")
        elif re.search('[*[(<]', field_type):
            writer.write(f"// {field_info['name']} {field_info['type']}")
            # writer.write(f".def_property_readonly(\"{field_name}\", []({type_name}& self) {{ return self.{field_name}; }})")
        elif size:
            writer.write(f".def_property_readonly(\"{field_name}\", []({type_name}& self) {{ return self.{field_name}; }}) // {field_info['type']}[{size}]")
        else:
            writer.write(f".def_property(\"{field_name}\", []({type_name}& self) {{ return self.{field_name}; }}, []({type_name}& self, {field_type} value) {{ self.{field_name} = value; }}) // {field_info['type']}")

    def make_func_desc(func):
        if func['ov_cimguiname'] in specified_wrappers:
            return specified_wrappers[func['ov_cimguiname']], set()
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

    def export_type(writer, type_name, template_type=None):
        if type_name in exported_types: return
        exported_types.add(type_name)
        code = CodeWriter()
        code.write(f"/*auto cls_{type_name} = */py::class_<{type_name}>(m, \"{type_name}\", py::dynamic_attr())")
        with code.push_indent():
            if template_type:
                template_ = type_name.split('_', 1)[0]
                fields = struct_and_enums['templated_structs'][template_]
                process_type = lambda s: re.sub(rf"(?<!\w){struct_and_enums['typenames'][template_]}(?!\w)", template_type, s)
                # funcs = struct_funcs.get(template_, [])
                funcs = []
            else:
                fields = struct_and_enums['structs'][type_name]
                process_type = lambda s: s
                funcs = struct_funcs.get(type_name, [])
            for field in fields:
                field['type'] = process_type(field['type'])
                export_field(code, type_name, field)
            for func in funcs:
                desc, extra_types = make_func_desc(func)
                if desc: code.write(desc)
                for t in extra_types:
                    export_type(writer, t)
            code.write(";")
        writer.write(code.getvalue())

    struct_funcs = {}
    for overloads in func_defs.values():
        for overload in overloads:
            struct_funcs.setdefault(overload['stname'], []).append(overload)

    struct_defs = CodeWriter(1)

    for keys in struct_and_enums['structs'].keys():
        export_type(struct_defs, keys)

    glob_defs = CodeWriter(1)
    for func in struct_funcs.get('', []):
        desc, extra_types = make_func_desc(func)
        if desc:
            if desc.startswith('/*') or desc.startswith('//'):
                glob_defs.write(desc)
            else:
                glob_defs.write('m' + desc + ';')
        for t in extra_types:
            export_type(struct_defs, t)

    # impl_headers = CodeWriter(0)
    # impl_defs = CodeWriter(1)
    # need_libs = set()
    for backend, libs in backends.items():
        # for lib in libs:
        #     need_libs.add(lib)
        res.append(cimgui_dir / 'imgui' / 'backends' / f'imgui_impl_{backend}.cpp')

    # for lib in sorted(need_libs):
    #     impl_headers.write(f"#pragma comment(lib, \"{lib}\")")
    # impl_headers.write("#include <dxgiformat.h> // DXGI_FORMAT")
    #
    # for func in impl_func_defs.values():
    #     for func_ in func:
    #         desc, extra_types = make_func_desc(func_)
    #         if desc:
    #             if desc.startswith('/*') or desc.startswith('//'):
    #                 impl_defs.write(desc)
    #             else:
    #                 impl_defs.write('m' + desc + ';')

    core_dir = output_dir / 'core'
    update_generated_files(output_dir, [
        (
            core_dir / 'gheader.h',
            "#pragma once\n"
            "#define PYBIND11_DETAILED_ERROR_MESSAGES\n"
            "#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS\n"
            "#include <pybind11/pybind11.h>\n"
            "#include \"cimgui.h\"\n"
            "namespace py = pybind11;\n"
        ),
        (
            core_dir / 'enums.h',
            "#pragma once\n"
            "#include \"./gheader.h\"\n"
            "void setup_pyimgui_core_enums(pybind11::module_ m);"
        ),
        (
            core_dir / 'enums.cpp',
            f"#include \"./enums.h\"\n"
            f"void setup_pyimgui_core_enums(pybind11::module_ m) {{ {enum_defs.getvalue()} }}"
        ),
        (
            core_dir / 'structs.h',
            "#pragma once\n"
            "#include \"./gheader.h\"\n"
            "void setup_pyimgui_core_structs(pybind11::module_ m);"
        ),
        (
            core_dir / 'structs.cpp',
            f"#include \"./structs.h\"\n"
            f"void setup_pyimgui_core_structs(pybind11::module_ m) {{ {struct_defs.getvalue()} }}"
        ),
        (
            core_dir / 'globals.h',
            "#pragma once\n"
            "#include \"./gheader.h\"\n"
            "void setup_pyimgui_core_globals(pybind11::module_ m);"
        ),
        (
            core_dir / 'globals.cpp',
            f"#include \"./globals.h\"\n"
            f"{specified_wrappers.get('__GLOBAL_EXTRA__', '')}\n"
            f"void setup_pyimgui_core_globals(pybind11::module_ m) {{ {specified_wrappers.get('__GLOBAL_DEF_EXTRA__', '')};"
            f" {glob_defs.getvalue()} }}"
        ),
        # (
        #     core_dir / 'impl.h',
        #     "#pragma once\n"
        #     "#include \"./gheader.h\"\n"
        #     "#include \"cimgui_impl.h\"\n\n"
        #     "void setup_pyimgui_impl(pybind11::module_ m);"
        # ),
        # (
        #     core_dir / 'impl.cpp',
        #     f"{impl_headers.getvalue()}\n"
        #     f"#include \"./impl.h\"\n"
        #     f"void setup_pyimgui_impl(pybind11::module_ m) {{ {impl_defs.getvalue()} }}"
        # ),
        (
            output_dir / 'pyimgui.h',
            """#include  "./core/gheader.h"
#include "./core/enums.h"
#include "./core/structs.h"
#include "./core/globals.h"
// #include "./core/impl.h"

void setup_pyimgui_core(pybind11::module_ m);
"""
        ),
        (
            output_dir / 'pyimgui.cpp',
            f"""#include  "./pyimgui.h"

    void setup_pyimgui_core(pybind11::module_ m) {{
        setup_pyimgui_core_enums(m);
        setup_pyimgui_core_structs(m);
        setup_pyimgui_core_globals(m);
        // setup_pyimgui_impl(m);
    }}
    """
        )
    ])

    res.append(core_dir / 'enums.cpp')
    res.append(core_dir / 'structs.cpp')
    res.append(core_dir / 'globals.cpp')
    # res.append(core_dir / 'impl.cpp')
    res.append(output_dir / 'pyimgui.cpp')
    return res


def build(*a, debug=0, **kw):
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


def load_src(src_dir):
    src_dir.mkdir(parents=True, exist_ok=True)
    cimgui_dir = src_dir / 'cimgui'
    if not cimgui_dir.is_dir():
        subprocess.check_call([ensure_env.ensure_git(), 'clone', 'https://github.com/cimgui/cimgui.git', cimgui_dir], cwd=src_dir)
        subprocess.check_call([ensure_env.ensure_git(), 'submodule', 'update', '--init', '--recursive'], cwd=cimgui_dir)
    # if not (src_dir / 'glfw').is_dir():
    #     subprocess.check_call([ensure_env.ensure_git(), 'clone', 'https://github.com/glfw/glfw.git', src_dir / 'glfw'], cwd=src_dir)
    if not (src_dir / 'detours').is_dir():
        subprocess.check_call([ensure_env.ensure_git(), 'clone', 'https://github.com/microsoft/Detours.git', src_dir / 'detours'], cwd=src_dir)

    ensure_env.ensure_msys2_file('/clang64/bin/gcc.exe')

    env = os.environ.copy()
    env = {**env, 'PATH': f"{env['PATH']};{pathlib.Path(ensure_env.ensure_msys2_file('/clang64/bin/gcc.exe')).parent}"}

    subprocess.check_call([
        load_luajit(src_dir / 'luajit'),
        './generator.lua',
        'gcc', 'internal noimstrv',
        *backends,
    ], cwd=cimgui_dir / 'generator', env=env)


def test():
    import pyimgui.detours as detours
    print(detours.DetourTransactionBegin)
    import pyimgui.imgui as imgui
    import pyimgui.imgui.ctx as imgui_ctx
    print(imgui.ImDrawFlags_(0).name, imgui.ImDrawFlags_None.value)
    vec = imgui.ImColor(1., 2., 3., 4.)
    print(f"{vec.Value.x=}, {vec.Value.y=}, {vec.Value.z=}, {vec.Value.w=}")
    vec.SetHSV(0.5, 0.5, 0.5)
    print(f"{vec.Value.x=}, {vec.Value.y=}, {vec.Value.z=}, {vec.Value.w=}")

    show_windows = [False, False, False, False, False]
    datas = {
        'test_string': 'Hello, world!',
    }

    def draw_func(wnd):
        if show_windows[0]:
            show_windows[0] = imgui.ShowAboutWindow()
        if show_windows[1]:
            show_windows[1] = imgui.ShowDebugLogWindow()
        if show_windows[2]:
            show_windows[2] = imgui.ShowDemoWindow()
        if show_windows[3]:
            show_windows[3] = imgui.ShowIDStackToolWindow()
        if show_windows[4]:
            show_windows[4] = imgui.ShowMetricsWindow()
        with imgui_ctx.Begin("Hello, world") as (show, window_open):
            if not window_open:
                wnd.Close()
            if show:
                imgui.Text("This is another useful text.")
                imgui.Text(f"{show_windows=}")
                window_size = imgui.GetWindowSize()
                imgui.Text(f"Window size: {window_size.x}, {window_size.y}")
                window_pos = imgui.GetWindowPos()
                imgui.Text(f"Window pos: {window_pos.x}, {window_pos.y}")
                if imgui.CollapsingHeader("Test"):
                    _, wnd.clear_color = imgui.ColorEdit4("Clear color", wnd.clear_color)
                    changed, datas['test_string'] = imgui.InputText("Test string", datas['test_string'])
                    imgui.Text(f"Test string: {datas['test_string']}")
                changed, show_windows[0] = imgui.Checkbox("Show about window", show_windows[0])
                changed, show_windows[1] = imgui.Checkbox("Show debug log window", show_windows[1])
                changed, show_windows[2] = imgui.Checkbox("Show demo window", show_windows[2])
                changed, show_windows[3] = imgui.Checkbox("Show ID stack tool window", show_windows[3])
                changed, show_windows[4] = imgui.Checkbox("Show metrics window", show_windows[4])

    import pyimgui
    pyimgui.Dx11ImguiWindow(draw_func).Serve()


def main(do_build=1, debug=0):
    if do_build:
        cwd = pathlib.Path(__file__).parent
        src_dir = cwd / 'src'
        auto_src_dir = cwd / 'auto_src'
        cimgui_dir = auto_src_dir / 'cimgui'
        imgui_dir = cimgui_dir / 'imgui'
        detours_dir = auto_src_dir / 'detours'
        load_src(auto_src_dir)
        build(
            name="pyimgui",
            sources=sorted(map(str, [
                *cimgui_dir.glob('*.cpp'),
                *imgui_dir.glob('*.cpp'),
                *generate_pyimgui(cimgui_dir, auto_src_dir / 'pyimgui'),
                *src_dir.glob('*.cpp'),
                *(src_dir / 'imgui_impl').glob('*.cpp'),
                *(f for f in (detours_dir / 'src').glob('*.cpp') if f.name != 'uimports.cpp')
            ])),
            include_dirs=sorted(map(str, [
                cimgui_dir,
                cimgui_dir / 'generator' / 'output',
                auto_src_dir / 'pyimgui',
                # glfw_dir / 'include',
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

    test()


if __name__ == '__main__':
    main(1, 1)
