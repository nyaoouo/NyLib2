#include "./PyDetours.h"

START_PYDETOURS_NAMESPACE
{
    void pybind_setup_pydetours(pybind11::module_ m)
    {
        m.def("SimpleAttach", [](size_t ppPointer, size_t pDetour)
              { return SimpleAttach((PVOID *)ppPointer, (PVOID)pDetour); });
        m.def("SimpleDetach", [](size_t ppPointer, size_t pDetour)
              { return SimpleDetach((PVOID *)ppPointer, (PVOID)pDetour); });
    }

    LONG SimpleAttach(PVOID *ppPointer, PVOID pDetour)
    {
        LONG error = NO_ERROR;
        if ((error = DetourTransactionBegin()))
            _throwV_("DetourTransactionBegin failed: {}", error);

        try
        {
            if ((error = DetourUpdateThread(GetCurrentThread())))
                _throwV_("DetourUpdateThread failed: {}", error);
            if ((error = DetourAttach(ppPointer, pDetour)))
                _throwV_("DetourAttach failed: {}", error);
            if ((error = DetourTransactionCommit()))
                _throwV_("DetourTransactionCommit failed: {}", error);
        }
        catch (const std::exception &)
        {
            LONG abort_error = DetourTransactionAbort();
            if (abort_error)
                _throwV_("DetourTransactionAbort failed: {}", abort_error);
            throw;
        }
        return error;
    }

    LONG SimpleDetach(PVOID *ppPointer, PVOID pDetour)
    {
        LONG error = NO_ERROR;
        if ((error = DetourTransactionBegin()))
            _throwV_("DetourTransactionBegin failed: {}", error);

        try
        {
            if ((error = DetourUpdateThread(GetCurrentThread())))
                _throwV_("DetourUpdateThread failed: {}", error);
            if ((error = DetourDetach(ppPointer, pDetour)))
                _throwV_("DetourDetach failed: {}", error);
            if ((error = DetourTransactionCommit()))
                _throwV_("DetourTransactionCommit failed: {}", error);
        }
        catch (const std::exception &)
        {
            LONG abort_error = DetourTransactionAbort();
            if (abort_error)
                _throwV_("DetourTransactionAbort failed: {}", abort_error);
            throw;
        }
        return error;
    }
}
END_PYDETOURS_NAMESPACE