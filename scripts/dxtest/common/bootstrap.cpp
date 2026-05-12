#include <windows.h>

extern "C" __declspec(dllexport) void __stdcall dxtest_bootstrap_touch()
{
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}