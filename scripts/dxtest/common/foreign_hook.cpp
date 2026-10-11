#include "foreign_hook.h"

#include "detours/src/detours.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" volatile unsigned long long g_foreign_present_calls = 0;

namespace
{
    typedef HRESULT(__stdcall *PresentFn)(IUnknown *, UINT, UINT);
    PresentFn oForeignPresent = nullptr;

    HRESULT __stdcall ForeignDetourPresent(IUnknown *swap_chain, UINT sync_interval, UINT flags)
    {
        g_foreign_present_calls++;
        return oForeignPresent(swap_chain, sync_interval, flags);
    }

    void **PresentSlot(IUnknown *swap_chain)
    {
        return *reinterpret_cast<void ***>(swap_chain) + 8;
    }

    // Mirrors PyDetours::SimpleAttach (own Detours transaction, so this
    // reproduces a second independent hooker sharing the same target
    // function, the way OBS's statically-linked Detours copy would).
    void InstallDetours(IUnknown *swap_chain)
    {
        oForeignPresent = reinterpret_cast<PresentFn>(*PresentSlot(swap_chain));
        LONG err = DetourTransactionBegin();
        if (err != NO_ERROR)
        {
            std::printf("foreign_hook: DetourTransactionBegin failed: %ld\n", err);
            return;
        }
        DetourUpdateThread(GetCurrentThread());
        err = DetourAttach(&reinterpret_cast<PVOID &>(oForeignPresent), reinterpret_cast<PVOID>(ForeignDetourPresent));
        if (err != NO_ERROR)
        {
            std::printf("foreign_hook: DetourAttach failed: %ld\n", err);
            DetourTransactionAbort();
            return;
        }
        err = DetourTransactionCommit();
        if (err != NO_ERROR)
            std::printf("foreign_hook: DetourTransactionCommit failed: %ld\n", err);
        else
            std::printf("foreign_hook: detours mode installed\n");
    }

    // Shared-vtable slot hook: compare-and-swap the dxgi vtable entry.
    void InstallVtable(IUnknown *swap_chain)
    {
        void **slot = PresentSlot(swap_chain);
        DWORD old_protect = 0;
        if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old_protect))
        {
            std::printf("foreign_hook: VirtualProtect failed: %lu\n", GetLastError());
            return;
        }
        oForeignPresent = reinterpret_cast<PresentFn>(*slot);
        *slot = reinterpret_cast<void *>(ForeignDetourPresent);
        DWORD unused = 0;
        VirtualProtect(slot, sizeof(void *), old_protect, &unused);
        std::printf("foreign_hook: vtable mode installed\n");
    }

    // Per-instance vptr swap: copy a generous run of the swap chain's
    // vtable (no RTTI; a generous back-to-back entry run) and
    // repoint only this object's vptr, leaving the shared dxgi vtable
    // untouched (simulates a tool that proxies the game's object).
    constexpr size_t kVtableCopyEntries = 512;
    void *g_vtable_copy[kVtableCopyEntries];

    void InstallVptrSwap(IUnknown *swap_chain)
    {
        void **original_vtable = *reinterpret_cast<void ***>(swap_chain);
        std::memcpy(g_vtable_copy, original_vtable, sizeof(g_vtable_copy));
        oForeignPresent = reinterpret_cast<PresentFn>(original_vtable[8]);
        g_vtable_copy[8] = reinterpret_cast<void *>(ForeignDetourPresent);
        *reinterpret_cast<void ***>(swap_chain) = g_vtable_copy;
        std::printf("foreign_hook: vptrswap mode installed\n");
    }

    std::string EnvOrEmpty(const char *name)
    {
        char *value = nullptr;
        size_t size = 0;
        std::string result;
        if (_dupenv_s(&value, &size, name) == 0 && value != nullptr)
        {
            result = value;
            free(value);
        }
        return result;
    }
}

namespace dxtest
{
    void ForeignHookTick(IUnknown *swap_chain, double elapsed_seconds)
    {
        static bool initialized = false;
        static bool installed = false;
        static std::string mode;
        static double at_seconds = 0.0;
        if (!initialized)
        {
            initialized = true;
            mode = EnvOrEmpty("DXTEST_FOREIGN");
            std::string at_text = EnvOrEmpty("DXTEST_FOREIGN_AT");
            if (!at_text.empty())
                at_seconds = std::atof(at_text.c_str());
        }
        if (mode.empty() || installed || elapsed_seconds < at_seconds)
            return;
        installed = true;
        if (mode == "detours")
            InstallDetours(swap_chain);
        else if (mode == "vtable")
            InstallVtable(swap_chain);
        else if (mode == "vptrswap")
            InstallVptrSwap(swap_chain);
        else
            std::printf("foreign_hook: unknown DXTEST_FOREIGN=%s\n", mode.c_str());
    }
}
