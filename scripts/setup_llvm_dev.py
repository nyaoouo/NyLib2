import hashlib
import os
import pathlib
import shutil
import subprocess

from nylib.winutils import ensure_env, msvc

os.environ['Path'] += r';D:\tool\cmake-3.29.0-windows-x86_64\bin;'


def file_last_modified(path: pathlib.Path) -> int:
    return path.stat().st_mtime_ns


def file_md5(path: pathlib.Path) -> str:
    md5 = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
    return md5.hexdigest()


def main(llvm_path, mode='Debug', tool='msbuild', file_comp='last-modified'):
    os.system('chcp 65001')

    llvm_path = pathlib.Path(llvm_path).resolve()
    tmp_dir = pathlib.Path('.tmp').resolve()
    tmp_dir.mkdir(exist_ok=True)
    git_at = pathlib.Path(ensure_env.ensure_git(tmp_dir))
    cmake_at = pathlib.Path(ensure_env.ensure_cmake(tmp_dir))
    ensure_env.ensure_msvc(tmp_dir)
    cygwin_dir = ensure_env.ensure_cygwin_dir(tmp_dir)

    if not llvm_path.exists():
        subprocess.check_call([
            git_at, 'clone', '-c', 'core.autocrlf=false',
            'https://github.com/llvm/llvm-project.git', llvm_path
        ], cwd=llvm_path.parent)
    else:
        assert (llvm_path / '.git').exists(), f'{llvm_path} is not a git repository'
        # subprocess.check_call(['git', 'pull'], cwd=llvm_path)
    env = msvc.load_vcvarsall('x86_amd64').copy() | {'CC': 'cl', 'CXX': 'cl'}

    if tool == 'msbuild':
        build_path = llvm_path / 'build'
        bin_path = build_path / mode / 'bin'
        dist_path = llvm_path / 'dist' / mode
    elif tool == 'ninja':
        build_path = llvm_path / 'build_ninja'
        bin_path = build_path / mode / 'bin'
        dist_path = llvm_path / 'dist_ninja' / mode
    else:
        raise ValueError(f'Unknown tool: {tool}')

    # if build_path.exists(): shutil.rmtree(build_path)

    if tool == 'msbuild':
        msbuild_at = msvc.where('msbuild.exe', 'x86_amd64')
        if not build_path.exists():
            build_path.mkdir()
            subprocess.check_call([
                cmake_at, '-E', 'env', 'CXXFLAGS=/utf-8', 'CCFLAGS=/utf-8',
                '--', cmake_at, '-G', "Visual Studio 17 2022", '-A', 'x64',
                '-Thost=x64', '-DLLVM_ENABLE_PROJECTS=clang', '..\\llvm'
            ], cwd=build_path, env=env, shell=True)
        subprocess.check_call([msbuild_at, build_path / 'ALL_BUILD.vcxproj', f'/p:Configuration={mode}'], cwd=build_path, env=env, shell=True)
    elif tool == 'ninja':
        ninja_at = msvc.where('ninja.exe', 'x86_amd64')
        if not build_path.exists():
            build_path.mkdir()
            subprocess.check_call([
                cmake_at, '-E', 'env', 'CXXFLAGS=/utf-8', 'CCFLAGS=/utf-8',
                '--', cmake_at, '-GNinja', '-DLLVM_ENABLE_PROJECTS=clang',
                '-DCMAKE_EXE_LINKER_FLAGS=/MAXILKSIZE:0x7FF00000',
                '..\\llvm'
            ], cwd=build_path, env=env, shell=True)
        subprocess.check_call([ninja_at, 'clang'], cwd=build_path, env=env, shell=True)
        subprocess.check_call([ninja_at, 'check-clang'], cwd=build_path, env=env, shell=True)
    else:
        raise ValueError(f'Unknown tool: {tool}')

    if file_comp == 'last-modified':
        comp_func = file_last_modified
    elif file_comp == 'md5':
        comp_func = file_md5
    else:
        raise ValueError(f'Unknown file comparison method: {file_comp}')
    if not dist_path.exists():
        dist_path.mkdir()

    update_count = 0
    for bin_file in bin_path.iterdir():
        dist_file = dist_path / bin_file.relative_to(bin_path)
        if dist_file.exists() and comp_func(bin_file) == comp_func(dist_file): continue
        print(f'Copy {bin_file} to {dist_file}')
        update_count += 1
        shutil.copy2(bin_file, dist_file)

    print(f'Updated {update_count} files')


if __name__ == '__main__':
    main(r'D:\projects\llvm', 'Debug')
