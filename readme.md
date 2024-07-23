NyLib
===
> A simple library for Python game debugging.

## How to use
```python
from nylib.winutils.process import enable_privilege, run_admin
from nylib.process import Process
from nylib.winutils.python_loader import run_script


def main():
    process = Process.from_name('notepad.exe') # get the process object by name
    # or just pass the process id
    # process = Process.from_id(1234)
    
    for ldr in process.enum_ldr_data(): # enumerate the loaded modules
        print(ldr.FullDllName.remote_value(process))  # print the full dll name of the module

    # run_script(process, "inject_main.py") # run a script in the target process


if __name__ == '__main__':
    run_admin() # run the script as admin if this process is not admin
    enable_privilege() # enable the debug privilege
    main()
```
