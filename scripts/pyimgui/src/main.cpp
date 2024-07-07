#include "./main.h"

#include <dbghelp.h>
#include <iostream>
#pragma comment(lib, "dbghelp.lib")
// Exception handler function
LONG WINAPI MyUnhandledExceptionFilter(EXCEPTION_POINTERS* pExceptionPointers)
{
    HANDLE hDumpFile = CreateFile(_T("MiniDump.dmp"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDumpFile != INVALID_HANDLE_VALUE)
    {
        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = pExceptionPointers;
        mdei.ClientPointers = FALSE;

        MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            hDumpFile,
            MiniDumpWithDataSegs,
            &mdei,
            NULL,
            NULL);

        CloseHandle(hDumpFile);
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

PYBIND11_MODULE(pyimgui, m) {
    SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);

    mImguiImpl::impl_dx9::Dx9ImguiWindow::RegPyCls(m);
    mImguiImpl::impl_dx9::Dx9ImguiInternalWindow::RegPyCls(m);
    mImguiImpl::impl_dx10::Dx10ImguiWindow::RegPyCls(m);
    mImguiImpl::impl_dx10::Dx10ImguiInternalWindow::RegPyCls(m);
    mImguiImpl::impl_dx11::Dx11ImguiWindow::RegPyCls(m);
    mImguiImpl::impl_dx11::Dx11ImguiInternalWindow::RegPyCls(m);
    mImguiImpl::impl_dx12::Dx12ImguiWindow::RegPyCls(m);
    mImguiImpl::impl_dx12::Dx12ImguiInternalWindow::RegPyCls(m);

    pybind_setup_win32(m.def_submodule("win32"));
    setup_pyimgui_core(m.def_submodule("imgui"));
    pybind_setup_detours(m.def_submodule("detours"));
}
