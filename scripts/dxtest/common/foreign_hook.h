#pragma once

#include <windows.h>
#include <unknwn.h>

namespace dxtest
{
    // Mock third-party hooker (DXTEST_FOREIGN=detours|vtable|vptrswap) that
    // patches the swap chain's Present (vtable slot 8), simulating an
    // overlay tool that coexists with (or chains on top of) the pyimgui
    // inbound hook. A no-op when DXTEST_FOREIGN is unset.
    //
    // Call once per frame with the host's swap chain and elapsed seconds
    // since program start; installs once DXTEST_FOREIGN_AT has elapsed.
    void ForeignHookTick(IUnknown *swap_chain, double elapsed_seconds);
}

// Present call counter seen by the foreign hook, exported like
// g_dxtest_tick so it can be inspected from outside the process too.
extern volatile unsigned long long g_foreign_present_calls;
