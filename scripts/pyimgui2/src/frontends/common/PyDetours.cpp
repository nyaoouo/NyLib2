#include "./PyDetours.h"

#include <malloc.h>
#include <tlhelp32.h>

START_PYDETOURS_NAMESPACE
{
    void pybind_setup_pydetours(pybind11::module_ m)
    {
        m.def("SimpleAttach", [](size_t ppPointer, size_t pDetour)
              { return SimpleAttach((PVOID *)ppPointer, (PVOID)pDetour); });
        m.def("SimpleDetach", [](size_t ppPointer, size_t pDetour)
              { return SimpleDetach((PVOID *)ppPointer, (PVOID)pDetour); });
    }

    // Opens every thread of this process except the calling one; the caller closes the handles.
    static std::vector<HANDLE> OpenOtherThreads()
    {
        std::vector<HANDLE> threads;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return threads;
        DWORD pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
        THREADENTRY32 entry{sizeof(entry)};
        for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry))
        {
            if (entry.dwSize >= offsetof(THREADENTRY32, th32OwnerProcessID) + sizeof(entry.th32OwnerProcessID) &&
                entry.th32OwnerProcessID == pid && entry.th32ThreadID != tid)
            {
                if (HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID))
                    threads.push_back(thread);
            }
            entry.dwSize = sizeof(entry);
        }
        CloseHandle(snapshot);
        return threads;
    }

    // Runs one Detours attach or detach with every other thread suspended (and its IP fixed up) during the commit.
    // Holds the CRT heap lock while threads are suspended; nothing between suspend and resume may take another user-mode lock.
    static LONG RunTransaction(PVOID *ppPointer, PVOID pDetour, bool detach)
    {
        std::vector<HANDLE> threads = OpenOtherThreads();
        const char *step = "DetourTransactionBegin";
        LONG error = DetourTransactionBegin();
        if (!error)
        {
            step = detach ? "DetourDetach" : "DetourAttach";
            if ((error = detach ? DetourDetach(ppPointer, pDetour) : DetourAttach(ppPointer, pDetour)))
                DetourTransactionAbort();
            else
            {
                HANDLE heap = (HANDLE)_get_heap_handle();
                bool locked = heap && HeapLock(heap);
                for (size_t i = 0; locked && !error && i < threads.size(); i++)
                {
                    if (SuspendThread(threads[i]) == (DWORD)-1)
                        continue; // exited since the snapshot
                    step = "DetourUpdateThread";
                    error = DetourUpdateThread(threads[i]);
                    ResumeThread(threads[i]); // drops only our own suspend; Detours keeps its own until commit
                }
                LONG commitError = DetourTransactionCommit(); // aborts and resumes threads on a pending error
                if (!error && commitError)
                {
                    step = "DetourTransactionCommit";
                    error = commitError;
                }
                if (locked)
                    HeapUnlock(heap);
            }
        }
        for (HANDLE thread : threads)
            CloseHandle(thread);
        if (error)
            _throwV_("{} failed: {}", step, error);
        return error;
    }

    LONG SimpleAttach(PVOID *ppPointer, PVOID pDetour)
    {
        return RunTransaction(ppPointer, pDetour, false);
    }

    LONG SimpleDetach(PVOID *ppPointer, PVOID pDetour)
    {
        return RunTransaction(ppPointer, pDetour, true);
    }
}
END_PYDETOURS_NAMESPACE