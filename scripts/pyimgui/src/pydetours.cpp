#include "./pydetours.h"

void pybind_setup_detours(pybind11::module_ m)
{
    m.def("DetourTransactionBegin", &DetourTransactionBegin);
    m.def("DetourUpdateThread", [](HANDLE hThread) { 
        if (hThread == NULL) hThread = GetCurrentThread();
        return DetourUpdateThread(hThread);
    }, pybind11::arg("hThread") = NULL);
    m.def("DetourTransactionAbort", &DetourTransactionAbort);
    m.def("DetourTransactionCommit", &DetourTransactionCommit);

    // use ctypes to pass pointers
    m.def("DetourAttach", [](size_t ppPointer,size_t pDetour){
        return DetourAttach((PVOID *)ppPointer, (PVOID)pDetour);
    });
    m.def("DetourDetach", [](size_t ppPointer,size_t pDetour){
        return DetourDetach((PVOID *)ppPointer, (PVOID)pDetour);
    });
}

namespace mDetours
{
    LONG simpleAttach(PVOID *ppPointer, PVOID pDetour)
    {
        LONG error = NO_ERROR;
        if (error = DetourTransactionBegin())
            _throwV_("DetourTransactionBegin failed: {}", error);
        
        try {
            if (error = DetourUpdateThread(GetCurrentThread()))
                _throwV_("DetourUpdateThread failed: {}", error);
            if (error = DetourAttach(ppPointer, pDetour))
                _throwV_("DetourAttach failed: {}", error);
            if (error = DetourTransactionCommit())
                _throwV_("DetourTransactionCommit failed: {}", error);
        } catch (const std::exception &e) {
            LONG error_ = DetourTransactionAbort();
            if (error_)
                _throwV_("DetourTransactionAbort failed: {}", error_);
            throw;
        }
        return error;
    }

    LONG simpleDetach(PVOID *ppPointer, PVOID pDetour)
    {
        LONG error = NO_ERROR;
        if (error = DetourTransactionBegin())
            _throwV_("DetourTransactionBegin failed: %d", error);
        
        try {
            if (error = DetourUpdateThread(GetCurrentThread()))
                _throwV_("DetourUpdateThread failed: %d", error);
            if (error = DetourDetach(ppPointer, pDetour))
                _throwV_("DetourDetach failed: %d", error);
            if (error = DetourTransactionCommit())
                _throwV_("DetourTransactionCommit failed: %d", error);
        } catch (const std::exception &e) {
            LONG error_ = DetourTransactionAbort();
            if (error_)
                _throwV_("DetourTransactionAbort failed: %d", error_);
            throw;
        }
        return error;
    }
}
