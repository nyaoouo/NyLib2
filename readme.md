NyLib
===
> A simple library for Python game debugging.

## How to use
```python
from nylib.winutils.process import enable_privilege, run_admin
from nylib.process import Process


def main():
    process = Process.from_name('notepad.exe') # get the process object by name
    # or just pass the process id
    # process = Process.from_id(1234)
    
    for ldr in process.enum_ldr_data(): # enumerate the loaded modules
        print(ldr.FullDllName.remote_value(process))  # print the full dll name of the module


if __name__ == '__main__':
    run_admin() # run the script as admin if this process is not admin
    enable_privilege() # enable the debug privilege
    main()
```

## hijack/ inject
- use [nylib/winutils/python_hijack](nylib/winutils/python_hijack) for hijacking dlls and run python scripts when the dll is loaded.
- use [nylib/winutils/python_loader](nylib/winutils/python_loader) for injecting python scripts.

## pyimgui
- run [scripts/pyimgui/pyimgui_generate.py](scripts/pyimgui/pyimgui_generate.py) to generate the `pyimgui` module.  
- code example [scripts/pyimgui/pyimgui_test.py](scripts/pyimgui/pyimgui_test.py) 
- for injected esp, use `pyimgui.Dx11Inbound` / `pyimgui.Dx12Inbound`

## hooks
 - see [nylib/hook](nylib/hook) for the hooking functions.

## TODO
- Universal unity game utils
- Universal unreal game utils

## License
[GPL V3](./license.txt)
