# IDA importer

[Index](index.md) · Code: `scripts/ida/ue_dumper_import.py`

`scripts/ida/ue_dumper_import.py` imports a snapshot into an IDA 9.x database. It uses only the Python standard library, so IDA needs no nylib.

## Run it

1. Open the game's exe, or the snapshot's `image/<exe>` (see [Dump](dump.md#exports)), in IDA 9.x and let auto-analysis finish.
2. File > Script file (Alt+F7) > `scripts/ida/ue_dumper_import.py`. A dialog asks for the snapshot folder and the options; press Import.

Other ways:

- Plugin: copy the file into IDA's `plugins` folder, then Edit > Plugins > UE Dumper Import (Ctrl-Alt-U; the hotkey is not tested yet).
- Batch, without the GUI:

  ```text
  idat -A -S"scripts/ida/ue_dumper_import.py --snapshot <snapshot folder> --types all" <database>
  ```

  Options: `--types all|referenced|none`, `--roots A,B` (with `referenced`), `--no-exec`, `--no-vtables`, `--no-globals`, `--no-core-types`, `--no-enums`, `--no-comments`, `--overwrite`, `--force`, `-v`. Exit codes: 0 done, 1 error, 2 usage, 3 build refused.
- From IDA's Python console, with the script's folder on `sys.path`: `import ue_dumper_import as uei; uei.run(r'<snapshot folder>')`.

## What it applies

- Names: the exec functions of native UFunctions, vtables, and the globals `GObjects`, `GNames`, `GWorld`, `ProcessEvent`, `AppendString`.
- Types: the engine core types, enums, and the classes and structs (all, only those the roots reference, or none).
- Comments: each UFunction's signature and flags on its exec function.

It first checks that the database was built from the snapshot's exe (SHA-256, or PE timestamp and size) and refuses another build unless you confirm (`--force`). A second run keeps what you changed by hand in its names, types and comments, and lists it; `--overwrite` (the dialog's "overwrite what I changed by hand") replaces them.
