#pragma once

#include "../../gHeader.h"

#include <atomic>

#define VTABLE_HOOK_NAMESPACE mNameSpace::VtableHook
#define START_VTABLE_HOOK_NAMESPACE namespace mNameSpace { namespace VtableHook
#define END_VTABLE_HOOK_NAMESPACE }

START_VTABLE_HOOK_NAMESPACE
{
    struct SlotHook
    {
        void **slot = nullptr;
        std::atomic<void *> original{nullptr};
    };

    bool IsImageSlot(void **vtable, size_t index);
    void *PristineImageMethod(void **vtable, size_t index);
    void Install(SlotHook &hook, void **vtable, size_t index, void *detour);

    template <typename T>
    T Original(const SlotHook &hook)
    {
        return reinterpret_cast<T>(hook.original.load(std::memory_order_acquire));
    }
}
END_VTABLE_HOOK_NAMESPACE
