#include "./gHeader.h"
    
#include <dbghelp.h>
#include <iostream>
#pragma comment(lib, "dbghelp.lib")

START_G_UTILS_NAMESPACE
{
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
    void InstallUnhandledExceptionFilter(){
        SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);
    }
}
END_G_UTILS_NAMESPACE