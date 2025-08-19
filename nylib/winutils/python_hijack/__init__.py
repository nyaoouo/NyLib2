import configparser
import os
import pathlib
import shutil
import subprocess
import sys
import sysconfig
import tempfile

DLLMAIN_TEMPLATE = '''
'''


def iter_pe_exported(pe_path):
    from ...utils.pip import required
    required('pefile')
    import pefile
    pe = pefile.PE(pe_path)
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        yield exp.name.decode('utf-8'), exp.address, exp.ordinal
    pe.close()


def create_src(pe_path, dst_dir, default_config=None, template=None, plat_spec='x86_amd64'):
    assert plat_spec in ('x86_amd64', 'x86')
    names = [(name, ordinal) for name, _, ordinal in iter_pe_exported(pe_path)]
    dst = pathlib.Path(dst_dir)
    shutil.rmtree(dst, ignore_errors=True)
    dst.mkdir(parents=True, exist_ok=True)

    addr_var = lambda n: 'pyhijack_val_' + n
    func_asm = lambda n: 'pyhijack_func_' + n

    if template:
        with open(template, 'r', encoding='utf-8') as f:
            dllmain_text = f.read()
    else:
        current_dir = pathlib.Path(sys.executable if getattr(sys, "frozen", False) else __file__).parent
        if (dllmain_template_path := current_dir / 'dllmain.template.cpp').exists():
            dllmain_text = dllmain_template_path.read_text('utf-8')
        else:
            dllmain_text = DLLMAIN_TEMPLATE
    default_config = default_config or {}
    dllmain_text = dllmain_text.replace("/*REPLACE_ORIG_DLL_HERE*/", default_config.get('orig', str(pe_path)).replace('\\', '\\\\'))
    dllmain_text = dllmain_text.replace("/*REPLACE_PY_DLL_HERE*/", default_config.get('python_dll', '').replace('\\', '\\\\'))
    dllmain_text = dllmain_text.replace("/*REPLACE_PY_MAIN_HERE*/", default_config.get('python_main', '').replace('\\', '\\\\'))

    buf = ''
    for name, ordinal in names:
        internal_symbol = func_asm(name)
        # MASM/x86 (C calling convention) decorates symbols with a leading underscore.
        if plat_spec == 'x86':
            internal_symbol = '_' + internal_symbol
        buf += f'#pragma comment(linker, "/EXPORT:{name}={internal_symbol},@{ordinal}")\n'
    buf += '\nextern "C" {\n'
    for name, ordinal in names:
        buf += f'    PVOID {addr_var(name)};\n'
    buf += '}\n'
    dllmain_text = dllmain_text.replace("/*REPLACE_DEF_EXPORT_HERE*/", buf)

    buf = ''
    for name, ordinal in names:
        buf += (f'    {addr_var(name)} = (PVOID)GetProcAddress(hOrig, "{name}");\n'
                f'    if ({addr_var(name)} == NULL) {{\n'
                f'       HANDLE_ERROR(L"GetProcAddress({name}) failed: %d", GetLastError());\n'
                f'    }}\n')

    dllmain_text = dllmain_text.replace("/*REPLACE_SET_EXPORT_HERE*/", buf)

    (dst / 'dllmain.cpp').write_text(dllmain_text, 'utf-8')

    # Generate platform-specific assembly
    if plat_spec == 'x86':
        # x86 assembly syntax
        dllasm_text = '.386\n.model flat, C\n\n.Data\n'
        for name, ordinal in names:
            dllasm_text += f'EXTERN {addr_var(name)}:DWORD\n'
        dllasm_text += '\n.Code\n\n'
        # Then define the procedures
        for name, ordinal in names:
            dllasm_text += (f'{func_asm(name)} PROC C\n'
                            f'    jmp DWORD PTR [{addr_var(name)}]\n'
                            f'{func_asm(name)} ENDP\n'
                            f'PUBLIC {func_asm(name)}\n\n')
        dllasm_text += '\nEND\n'
    else:
        # x64 assembly syntax (original)
        dllasm_text = '.Data\n'
        for name, ordinal in names:
            dllasm_text += f'EXTERN {addr_var(name)}:dq;\n'
        dllasm_text += '\n.Code\n'
        for name, ordinal in names:
            dllasm_text += (f'{func_asm(name)} PROC\n'
                            f'    jmp {addr_var(name)}\n'
                            f'{func_asm(name)} ENDP\n\n')
        dllasm_text += '\nEND\n'

    (dst / 'dllasm.asm').write_text(dllasm_text, 'utf-8')


def hijack(pe_path, build_dir=None, default_config=None, dst_dir=None, template=None, plat_spec='x86_amd64'):
    assert plat_spec in ('x86_amd64', 'x86')

    from .. import msvc, ensure_env
    from ...process import Process

    ensure_env.ensure_msvc()

    need_move_orig = False
    orig_path = pe_path = pathlib.Path(pe_path).absolute()
    dst_dir = pathlib.Path(dst_dir) if dst_dir is not None else pe_path.parent
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst_path = dst_dir / pe_path.name
    if dst_path == orig_path:
        need_move_orig = True
        orig_path = orig_path.with_suffix('.pyHijack' + orig_path.suffix)
    build_env = msvc.load_vcvarsall(plat_spec)

    py_dll = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
    if default_config is None:
        default_config = {}
    default_config = {
                         'orig': str(orig_path),
                         'create_console': '1',  # empty string to hide console
                         'python_dll': Process.current.get_ldr_data(py_dll).FullDllName.value,
                         'python_main': '.\\main.py',
                     } | default_config

    if build_dir is None:
        tmp_dir = tempfile.mkdtemp()
    else:
        tmp_dir = pathlib.Path(build_dir).absolute()
        tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        tmp_dir = pathlib.Path(tmp_dir)
        create_src(pe_path, tmp_dir, default_config, plat_spec=plat_spec, template=template)
        ml = msvc.where('ml64.exe' if plat_spec == 'x86_amd64' else 'ml.exe', plat_spec)
        cl = msvc.where('cl.exe', plat_spec)
        include_path = sysconfig.get_paths()['include']
        libs_path = str(pathlib.Path(include_path).with_name('libs'))

        subprocess.run([
            ml, '/c', '/coff', '/Fo', str(tmp_dir / 'dllasm.obj'), str(tmp_dir / 'dllasm.asm')
        ], cwd=tmp_dir, env=build_env, check=True, shell=True)

        subprocess.run([
            cl,
            '/D_USRDLL', '/D_WINDLL',
            str(tmp_dir / 'dllmain.cpp'), str(tmp_dir / 'dllasm.obj'),
            # '/I', sysconfig.get_paths()['include'], f'/LIBPATH:"{libs_path}"',
            '/link', '/DLL',
            ('/MACHINE:X86' if plat_spec == 'x86' else '/MACHINE:X64'),
            '/OUT:' + str(tmp_dir / 'hijacked.dll')
        ], cwd=tmp_dir, env=build_env, check=True, shell=True)

        if need_move_orig:
            shutil.move(str(pe_path), str(orig_path))
        # (tmp_dir / 'hijacked.dll').rename(dst_path)
        shutil.move(str(tmp_dir / 'hijacked.dll'), str(dst_path))
    finally:
        if build_dir is None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    cgh_path = dst_path.with_name('pyHijack.ini')
    config = configparser.ConfigParser()
    config['Hijack'] = default_config
    config['Python'] = {
        'path': os.pathsep.join(sys.path),
    }
    with open(cgh_path, 'w') as f:
        config.write(f)
