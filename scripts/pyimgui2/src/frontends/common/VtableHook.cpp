#include "./VtableHook.h"
#include "./PyDetours.h"

#include <cstring>

START_VTABLE_HOOK_NAMESPACE
{
    bool IsImageSlot(void **vtable, size_t index)
    {
        if (vtable == nullptr)
            return false;
        void **slot = vtable + index;
        if ((reinterpret_cast<uintptr_t>(slot) & (sizeof(void *) - 1)) != 0)
            return false;
        MEMORY_BASIC_INFORMATION mbi = {};
        return VirtualQuery(slot, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE;
    }

    namespace
    {
        struct ImageFile
        {
            HANDLE file = INVALID_HANDLE_VALUE;
            HANDLE mapping = nullptr;
            const BYTE *view = nullptr;
            size_t size = 0;
            const IMAGE_NT_HEADERS64 *nt = nullptr;
            const IMAGE_SECTION_HEADER *sections = nullptr;

            explicit ImageFile(HMODULE module)
            {
                wchar_t path[MAX_PATH];
                DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
                if (length == 0 || length >= MAX_PATH)
                    return;
                this->file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
                if (this->file == INVALID_HANDLE_VALUE)
                    return;
                LARGE_INTEGER fileSize;
                if (!GetFileSizeEx(this->file, &fileSize) || fileSize.QuadPart <= 0 || static_cast<ULONGLONG>(fileSize.QuadPart) > SIZE_MAX)
                    return;
                this->size = static_cast<size_t>(fileSize.QuadPart);
                this->mapping = CreateFileMappingW(this->file, nullptr, PAGE_READONLY, 0, 0, nullptr);
                if (this->mapping == nullptr)
                    return;
                this->view = static_cast<const BYTE *>(MapViewOfFile(this->mapping, FILE_MAP_READ, 0, 0, 0));
                if (this->view == nullptr || this->size < sizeof(IMAGE_DOS_HEADER))
                    return;
                auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(this->view);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || this->size < sizeof(IMAGE_NT_HEADERS64) ||
                    static_cast<size_t>(dos->e_lfanew) > this->size - sizeof(IMAGE_NT_HEADERS64))
                    return;
                this->nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(this->view + dos->e_lfanew);
                if (this->nt->Signature != IMAGE_NT_SIGNATURE || this->nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
                    this->nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    this->nt = nullptr;
                    return;
                }
                size_t sectionOffset = static_cast<size_t>(dos->e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + this->nt->FileHeader.SizeOfOptionalHeader;
                if (sectionOffset > this->size || this->nt->FileHeader.NumberOfSections > (this->size - sectionOffset) / sizeof(IMAGE_SECTION_HEADER))
                {
                    this->nt = nullptr;
                    return;
                }
                this->sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(this->view + sectionOffset);
            }

            ~ImageFile()
            {
                if (this->view != nullptr)
                    UnmapViewOfFile(this->view);
                if (this->mapping != nullptr)
                    CloseHandle(this->mapping);
                if (this->file != INVALID_HANDLE_VALUE)
                    CloseHandle(this->file);
            }

            const BYTE *AtRva(size_t rva, size_t length) const
            {
                if (this->nt == nullptr)
                    return nullptr;
                if (rva < this->nt->OptionalHeader.SizeOfHeaders && rva <= this->size && length <= this->size - rva)
                    return this->view + rva;
                for (size_t i = 0; i < this->nt->FileHeader.NumberOfSections; i++)
                {
                    const IMAGE_SECTION_HEADER &section = this->sections[i];
                    if (rva < section.VirtualAddress || rva - section.VirtualAddress > section.SizeOfRawData)
                        continue;
                    size_t offsetInSection = rva - section.VirtualAddress;
                    size_t offset = static_cast<size_t>(section.PointerToRawData) + offsetInSection;
                    if (length <= section.SizeOfRawData - offsetInSection && offset <= this->size && length <= this->size - offset)
                        return this->view + offset;
                }
                return nullptr;
            }
        };
    }

    // Returns the native slot target only when its complete Detours overwrite span matches the DLL on disk.
    void *PristineImageMethod(void **vtable, size_t index)
    {
        if (!IsImageSlot(vtable, index))
            return nullptr;
        void **slot = vtable + index;
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(slot, &mbi, sizeof(mbi)) != sizeof(mbi))
            return nullptr;
        HMODULE module = static_cast<HMODULE>(mbi.AllocationBase);
        ImageFile image(module);
        if (image.nt == nullptr)
            return nullptr;
        size_t slotRva = reinterpret_cast<const BYTE *>(slot) - reinterpret_cast<const BYTE *>(module);
        const BYTE *diskSlot = image.AtRva(slotRva, sizeof(uintptr_t));
        if (diskSlot == nullptr)
            return nullptr;
        uintptr_t preferredMethod = 0;
        std::memcpy(&preferredMethod, diskSlot, sizeof(preferredMethod));
        uintptr_t preferredBase = static_cast<uintptr_t>(image.nt->OptionalHeader.ImageBase);
        if (preferredMethod < preferredBase || preferredMethod - preferredBase >= image.nt->OptionalHeader.SizeOfImage)
            return nullptr;
        size_t methodRva = preferredMethod - preferredBase;
        const BYTE *method = reinterpret_cast<const BYTE *>(module) + methodRva;
        size_t span = 0;
        while (span < 5)
        {
            const BYTE *next = static_cast<const BYTE *>(DetourCopyInstruction(nullptr, nullptr, const_cast<BYTE *>(method + span), nullptr, nullptr));
            if (next <= method + span || next - (method + span) > 15 || span + (next - (method + span)) > 32)
                return nullptr;
            span += next - (method + span);
        }
        const BYTE *diskMethod = image.AtRva(methodRva, span);
        if (diskMethod == nullptr || std::memcmp(method, diskMethod, span) != 0)
            return nullptr;
        return const_cast<BYTE *>(method);
    }

    // Installs a process-lifetime hook on a shared image vtable slot.
    void Install(SlotHook &hook, void **vtable, size_t index, void *detour)
    {
        if (vtable == nullptr)
            _throw_("Vtable is unavailable");
        void **slot = vtable + index;
        if (hook.slot == slot)
            return;
        if (hook.slot != nullptr)
            _throw_("Vtable hook is already installed on another slot");
        if (!IsImageSlot(vtable, index))
            _throw_("Vtable slot is not in a committed image");
        DWORD oldProtect = 0;
        if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &oldProtect))
            _throwV_("VirtualProtect on vtable slot failed: {}", GetLastError());
        bool installed = false;
        for (int attempt = 0; attempt < 16; attempt++)
        {
            void *previous = *slot;
            if (previous == detour)
                break;
            hook.original.store(previous, std::memory_order_release);
            if (InterlockedCompareExchangePointer(reinterpret_cast<PVOID volatile *>(slot), detour, previous) == previous)
            {
                installed = true;
                break;
            }
        }
        DWORD unused = 0;
        BOOL restored = VirtualProtect(slot, sizeof(void *), oldProtect, &unused);
        if (!restored)
            _throwV_("Restoring vtable protection failed: {}", GetLastError());
        if (!installed)
            _throw_("Vtable slot changed while installing the hook");
        hook.slot = slot;
    }
}
END_VTABLE_HOOK_NAMESPACE
