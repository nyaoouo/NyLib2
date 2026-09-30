"""Build a pinned Dumper-7 revision as a test oracle whose output root we control.

CMD: `./.venv/Scripts/python.exe scripts/ue/build_dumper7.py --rev <hash>`.
`--verify <manifest>` checks a previous build without rebuilding.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import difflib
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
CLONE_DIR = REPO_ROOT / ".ignore" / "refs" / "Dumper-7"
BUILD_ROOT = REPO_ROOT / ".ignore" / "refs" / "build"
CONFIG_PATH_TOKEN = "{CONFIG_PATH}"


class RecipeError(Exception):
    """A patch anchor did not match exactly once, or the revision has no recipe."""


class ConfigPathError(Exception):
    """The computed config path fails the absolute/ASCII/length constraints."""


@dataclasses.dataclass
class Edit:
    path: str  # path relative to the exported src/ root
    anchor: str  # LF-normalised text, must match exactly once; may contain CONFIG_PATH_TOKEN
    replacement: str  # LF-normalised replacement text; may contain CONFIG_PATH_TOKEN


@dataclasses.dataclass
class Recipe:
    revision: str  # full 40-char hash
    project: str  # path to the .vcxproj to build, relative to src/
    edits: list[Edit]
    markers: tuple[bytes, ...]  # byte strings present in the DLL only when the guard edits are compiled in


_GUARD_MESSAGE = "Dumper-7: SDKGenerationPath is empty or not absolute, no output will be written."
_INI_KEY = "SDKGenerationPath"


# Recipe for ea0dab35eb8d99162ac94de276cfbbf26d67264a: retarget SDKGenerationPath to a runtime ini value; SetupDumperFolder() refuses to write when it is empty or not absolute.
RECIPES: dict[str, Recipe] = {
    "ea0dab35eb8d99162ac94de276cfbbf26d67264a": Recipe(
        revision="ea0dab35eb8d99162ac94de276cfbbf26d67264a",
        project="Dumper/Dumper.vcxproj",
        edits=[
            Edit(
                path="Dumper/Settings.h",
                anchor='\tinline constexpr const char* GlobalConfigPath = "C:/Dumper-7/Dumper-7.ini";',
                replacement=f'\tinline constexpr const char* GlobalConfigPath = "{CONFIG_PATH_TOKEN}";',
            ),
            Edit(
                path="Dumper/Settings.h",
                anchor='\t\tinline constexpr const char* SDKGenerationPath = "C:/Dumper-7";',
                replacement='\t\tinline std::string SDKGenerationPath = "";',
            ),
            Edit(
                path="Dumper/Settings.cpp",
                anchor=(
                    "\t// Try local Dumper-7.ini\n"
                    "\tconst std::string LocalPath = (fs::current_path() / \"Dumper-7.ini\").string();\n"
                    "\tconst char* ConfigPath = nullptr;\n"
                    "\n"
                    "\tif (fs::exists(LocalPath)) \n"
                    "\t{\n"
                    "\t\tConfigPath = LocalPath.c_str();\n"
                    "\t}\n"
                    "\telse if (fs::exists(GlobalConfigPath)) // Try global path\n"
                    "\t{\n"
                    "\t\tConfigPath = GlobalConfigPath;\n"
                    "\t}\n"
                ),
                replacement=(
                    "\tconst char* ConfigPath = nullptr;\n"
                    "\n"
                    "\tif (fs::exists(GlobalConfigPath))\n"
                    "\t{\n"
                    "\t\tConfigPath = GlobalConfigPath;\n"
                    "\t}\n"
                ),
            ),
            Edit(
                path="Dumper/Settings.cpp",
                anchor=(
                    "\tSDKNamespaceName = SDKNamespace;\n"
                    "\tSleepTimeout = max(GetPrivateProfileIntA(\"Settings\", \"SleepTimeout\", 0, ConfigPath), 0);\n"
                    "}\n"
                ),
                replacement=(
                    "\tSDKNamespaceName = SDKNamespace;\n"
                    "\tSleepTimeout = max(GetPrivateProfileIntA(\"Settings\", \"SleepTimeout\", 0, ConfigPath), 0);\n"
                    "\n"
                    "\tchar SDKGenerationPathBuf[MAX_PATH] = {};\n"
                    f"\tconst DWORD SDKGenerationPathLen = GetPrivateProfileStringA(\"Settings\", \"{_INI_KEY}\", \"\", SDKGenerationPathBuf, sizeof(SDKGenerationPathBuf), ConfigPath);\n"
                    "\tif (SDKGenerationPathLen < sizeof(SDKGenerationPathBuf) - 1)\n"
                    "\t{\n"
                    "\t\tGenerator::SDKGenerationPath = SDKGenerationPathBuf;\n"
                    "\t}\n"
                    "}\n"
                ),
            ),
            Edit(
                path="Dumper/Generator/Private/Generators/Generator.cpp",
                anchor=(
                    "bool Generator::SetupDumperFolder()\n"
                    "{\n"
                    "\ttry\n"
                ),
                replacement=(
                    "bool Generator::SetupDumperFolder()\n"
                    "{\n"
                    "\tconst fs::path Root(Settings::Generator::SDKGenerationPath);\n"
                    "\tif (Root.empty() || !Root.is_absolute())\n"
                    "\t{\n"
                    f"\t\tstd::cerr << \"{_GUARD_MESSAGE}\" << std::endl;\n"
                    "\t\treturn false;\n"
                    "\t}\n"
                    "\n"
                    "\ttry\n"
                ),
            ),
        ],
        markers=(_GUARD_MESSAGE.encode("ascii"), _INI_KEY.encode("ascii")),
    ),
}


def _import_msvc():
    sys.path.insert(0, str(REPO_ROOT))
    from nylib.winutils import msvc

    return msvc


def resolve_revision(rev: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(CLONE_DIR), "rev-parse", "--verify", f"{rev}^{{commit}}"],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
    except subprocess.CalledProcessError:
        return None


def resolve_config_path() -> str:
    captures = os.environ.get("NYLIB_UE_CAPTURES")
    if captures:
        base = pathlib.Path(captures)
        if not base.is_absolute():
            raise ConfigPathError(f"NYLIB_UE_CAPTURES is not absolute: {captures!r}")
    else:
        base = REPO_ROOT / "ue_dumps" / "_captures"
    config_path = (base / "_dumper7" / "Dumper-7.ini").resolve()
    text = str(config_path).replace("\\", "/")
    if not text.isascii():
        raise ConfigPathError(f"config path is not ASCII: {text}")
    if len(text) >= 200:
        raise ConfigPathError(f"config path is {len(text)} chars, must be under 200: {text}")
    return text


def export_source(revision: str, src_dir: pathlib.Path) -> None:
    src_dir.parent.mkdir(parents=True, exist_ok=True)
    if src_dir.exists():
        shutil.rmtree(src_dir)
    zip_bytes = subprocess.check_output(["git", "-C", str(CLONE_DIR), "archive", "--format=zip", revision])
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(src_dir)


def apply_recipe(recipe: Recipe, src_dir: pathlib.Path, config_path: str) -> dict[str, tuple[bytes, bytes]]:
    edits_by_file: dict[str, list[Edit]] = {}
    for edit in recipe.edits:
        edits_by_file.setdefault(edit.path, []).append(edit)

    changes: dict[str, tuple[bytes, bytes]] = {}
    pending_writes: dict[pathlib.Path, bytes] = {}
    for rel_path, edits in edits_by_file.items():
        file_path = src_dir / rel_path
        raw = file_path.read_bytes()
        crlf_count = raw.count(b"\r\n")
        lf_count = raw.count(b"\n")
        if crlf_count not in (0, lf_count):
            raise RecipeError(f"{rel_path}: mixed line endings ({crlf_count} CRLF, {lf_count} LF)")
        crlf = crlf_count > 0
        text = raw.decode("utf-8").replace("\r\n", "\n")
        for edit in edits:
            anchor = edit.anchor.replace(CONFIG_PATH_TOKEN, config_path)
            replacement = edit.replacement.replace(CONFIG_PATH_TOKEN, config_path)
            count = text.count(anchor)
            if count != 1:
                raise RecipeError(f"{rel_path}: anchor matched {count} times (expected 1): {anchor!r}")
            text = text.replace(anchor, replacement, 1)
        patched = text.replace("\n", "\r\n") if crlf else text
        patched_bytes = patched.encode("utf-8")
        changes[rel_path] = (raw, patched_bytes)
        pending_writes[file_path] = patched_bytes

    for file_path, patched_bytes in pending_writes.items():  # write only after every anchor matched
        file_path.write_bytes(patched_bytes)
    return changes


def render_patch(changes: dict[str, tuple[bytes, bytes]]) -> str:
    chunks = []
    for rel_path in sorted(changes):
        before, after = changes[rel_path]
        before_lines = before.decode("utf-8").splitlines(keepends=True)
        after_lines = after.decode("utf-8").splitlines(keepends=True)
        chunks.extend(difflib.unified_diff(
            before_lines, after_lines,
            fromfile=f"a/{rel_path}", tofile=f"b/{rel_path}",
        ))
    return "".join(chunks)


def _pe_is_pe32plus_amd64(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 26 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return False
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
    return machine == 0x8664 and magic == 0x20B  # IMAGE_FILE_MACHINE_AMD64, PE32+


# banned SDK-output roots, matched case-insensitively against data.lower(); ASCII and wide (UTF-16LE) forms
_BANNED_ROOT_ASCII = re.compile(rb"[cd]:[/\\]+dumper-7")
_BANNED_ROOT_UTF16LE = re.compile(rb"[cd]\x00:\x00(?:[/\\]\x00)+d\x00u\x00m\x00p\x00e\x00r\x00-\x007\x00")


def _extract_vc_tools_version(log_path: pathlib.Path, env: dict[str, str]) -> str:
    version = env.get("VCToolsVersion", "")
    if version:
        return version
    match = re.search(r"\\MSVC\\([^\\]+)\\bin\\", log_path.read_text(encoding="utf-8", errors="replace"))
    return match.group(1) if match else ""


def _manifest_error(manifest: object) -> str | None:
    if not isinstance(manifest, dict):
        return "manifest is not a JSON object"
    for key in ("revision", "dll", "dll_sha256", "config_path"):
        value = manifest.get(key)
        if not isinstance(value, str) or not value:
            return f"manifest field {key!r} is missing or not a non-empty string"
    return None


def cmd_build(args: argparse.Namespace) -> int:
    revision = resolve_revision(args.rev)
    if revision is None:
        print(f"error: unknown revision {args.rev!r}", file=sys.stderr)
        return 2
    recipe = RECIPES.get(revision)
    if recipe is None:
        print(f"error: no build recipe for revision {revision}", file=sys.stderr)
        return 2

    try:
        config_path = resolve_config_path()
    except ConfigPathError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rev7 = revision[:7]
    out_dir = BUILD_ROOT / f"Dumper-7-{rev7}"
    src_dir = out_dir / "src"
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "manifest.json"
    manifest_path.unlink(missing_ok=True)  # a failed rebuild must not leave a manifest verifying a stale dll/patch

    export_source(revision, src_dir)

    try:
        changes = apply_recipe(recipe, src_dir, config_path)
    except RecipeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    patch_path = out_dir / f"Dumper-7-{rev7}.patch"
    patch_path.write_text(render_patch(changes), encoding="utf-8", newline="\n")
    patch_sha256 = hashlib.sha256(patch_path.read_bytes()).hexdigest()

    if args.msbuild:
        msbuild = args.msbuild
        env = os.environ.copy()  # do not run a caller-supplied MSBuild inside the VS 18 vcvars env
    else:
        msvc = _import_msvc()
        env = msvc.load_vcvarsall("x64")
        msbuild = msvc.where("MSBuild.exe", "x64")

    vcxproj = src_dir / recipe.project
    int_dir = out_dir / "obj"
    int_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "build.log"

    msbuild_args = [
        msbuild, str(vcxproj),
        "/p:Configuration=Release",
        "/p:Platform=x64",
        f"/p:PlatformToolset={args.toolset}",
        f"/p:OutDir={out_dir}\\",
        f"/p:IntDir={int_dir}\\",
        "/m",
    ]
    print(" ".join(msbuild_args))
    with open(log_path, "w", encoding="utf-8", errors="replace") as log_fh:
        proc = subprocess.run(msbuild_args, cwd=src_dir, env=env, stdout=log_fh, stderr=subprocess.STDOUT)

    if proc.returncode != 0:
        tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-40:]
        print("error: build failed, log tail:", file=sys.stderr)
        print("\n".join(tail), file=sys.stderr)
        return 1

    built_dll = out_dir / "Dumper-7.dll"
    built_pdb = out_dir / "Dumper-7.pdb"
    dll_path = out_dir / f"Dumper-7-{rev7}.dll"
    pdb_path = out_dir / f"Dumper-7-{rev7}.pdb"
    built_dll.replace(dll_path)
    if built_pdb.exists():
        built_pdb.replace(pdb_path)

    manifest = {
        "revision": revision,
        "patch_sha256": patch_sha256,
        "config_path": config_path,
        "toolset": args.toolset,
        "msbuild": str(msbuild),
        "vc_tools_version": _extract_vc_tools_version(log_path, env),
        "dll": dll_path.name,
        "dll_sha256": hashlib.sha256(dll_path.read_bytes()).hexdigest(),
        "built": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


def cmd_verify(manifest_arg: str) -> int:
    manifest_path = pathlib.Path(manifest_arg)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"verify: cannot read manifest {manifest_arg!r}: {exc}")
        return 1
    error = _manifest_error(manifest)
    if error:
        print(f"verify: {error}")
        return 1

    recipe = RECIPES.get(manifest["revision"])
    if recipe is None:
        print(f"verify: no recipe for revision {manifest['revision']!r}")
        return 1

    dll_path = manifest_path.parent / manifest["dll"]
    try:
        data = dll_path.read_bytes()
    except OSError as exc:
        print(f"verify: cannot read dll {dll_path}: {exc}")
        return 1

    config_path = manifest["config_path"]
    try:
        config_path_bytes = config_path.encode("ascii")
    except UnicodeEncodeError:
        print("verify: config_path is not ASCII")
        return 1

    ok = True
    digest = hashlib.sha256(data).hexdigest()
    if digest != manifest["dll_sha256"]:
        print(f"verify: sha256 mismatch: {digest} != {manifest['dll_sha256']}")
        ok = False
    if not _pe_is_pe32plus_amd64(data):
        print("verify: not a PE32+ AMD64 image")
        ok = False
    if config_path_bytes not in data:
        print("verify: config_path not found in dll bytes")
        ok = False
    ini_count = data.count(b"Dumper-7.ini")
    if ini_count != 1:
        print(f"verify: expected exactly one 'Dumper-7.ini' occurrence in dll bytes, found {ini_count}")
        ok = False
    for marker in recipe.markers:
        if marker not in data:
            print(f"verify: guard marker not found in dll bytes: {marker!r}")
            ok = False
    data_lower = data.lower()
    if _BANNED_ROOT_ASCII.search(data_lower) or _BANNED_ROOT_UTF16LE.search(data_lower):
        print("verify: forbidden path pattern found in dll bytes")
        ok = False
    if ok:
        print(f"verify: ok ({dll_path})")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--rev", help="Dumper-7 revision to build (short or full hash)")
    group.add_argument("--verify", metavar="MANIFEST", help="verify a previous build's manifest and DLL")
    parser.add_argument("--toolset", default="v145", help="MSBuild PlatformToolset (default: v145)")
    parser.add_argument("--msbuild", help="override MSBuild.exe path (default: resolved via vcvarsall x64)")
    args = parser.parse_args()

    if args.verify:
        return cmd_verify(args.verify)
    return cmd_build(args)


if __name__ == "__main__":
    sys.exit(main())
