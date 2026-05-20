// nylib breakpoint veh backend
// ----------------------------
// In-process VEH-based dispatcher for hardware (DR0..3) and software (INT3 +
// PAGE_GUARD) breakpoints. See
// docs/superpowers/specs/2026-05-19-breakpoint-design.md.
//
// Built standalone (no <Python.h> dependency). CPython is resolved at runtime
// by walking loaded modules for python3X.dll.

#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <utility>

// ---------- diagnostic helpers ----------

static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static bool   g_logFileTried = false;

static HANDLE LogFileHandle()
{
    if (g_logFileTried) return g_logFile;
    g_logFileTried = true;
    wchar_t path[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableW(L"NYLIB_BP_LOG", path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return INVALID_HANDLE_VALUE;
    g_logFile = CreateFileW(path,
                            FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    return g_logFile;
}

static void DbgW(const wchar_t* msg)
{
    OutputDebugStringW(L"[nylib.bp.veh] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
    HANDLE h = LogFileHandle();
    if (h != INVALID_HANDLE_VALUE) {
        char hdr[64];
        int hn = _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
                             "[pid=%lu tid=%lu] ",
                             GetCurrentProcessId(), GetCurrentThreadId());
        DWORD wr;
        if (hn > 0) WriteFile(h, hdr, hn, &wr, nullptr);
        int wl = WideCharToMultiByte(CP_UTF8, 0, msg, -1, nullptr, 0, nullptr, nullptr);
        if (wl > 1) {
            std::string u8((size_t)(wl - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, msg, -1, u8.data(), wl, nullptr, nullptr);
            WriteFile(h, u8.data(), (DWORD)u8.size(), &wr, nullptr);
        }
        WriteFile(h, "\r\n", 2, &wr, nullptr);
        FlushFileBuffers(h);
    }
}

static void DbgFmtW(const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, 1024, _TRUNCATE, fmt, ap);
    va_end(ap);
    DbgW(buf);
}

// ---------- ABI version ----------

#define BP_BACKEND_VERSION 1u

// Flag bits, must mirror BP_E in __init__.py.
#define BPF_EXEC  0x001u
#define BPF_WRITE 0x002u
#define BPF_READ  0x004u
#define BPF_HARD  0x100u
#define BPF_SOFT  0x200u

// Status codes returned by BpLastError().
#define BPERR_OK              0u
#define BPERR_ALLOC           1u
#define BPERR_OOM             2u
#define BPERR_SLOT_EXHAUSTED  3u
#define BPERR_CHUNK_OVERFLOW  4u
#define BPERR_APPLY_FAILED    5u
#define BPERR_BAD_FLAGS       6u

static thread_local uint32_t g_lastBpError = BPERR_OK;

// ---------- BP records (extended in Tasks 7-9) ----------

struct PerThreadSlot {
    DWORD tid;
    int   slotIndex;   // 0..3 = Dr0..Dr3
};

struct ChunkRec {
    uint64_t address;
    uint32_t length;
};

struct Bp {
    uintptr_t handle;
    uint64_t  address;
    uint32_t  size;
    uint32_t  flags;
    void*     callback;     // ctypes CFUNCTYPE thunk
    void*     userData;
    bool      enabled;
    bool      isHard;
    bool      isExec;
    bool      isSoft;
    std::vector<PerThreadSlot> slots;
    std::vector<ChunkRec>      chunks;       // for HARD data BPs (multi-slot splits)
    uint8_t                    origByte;     // SOFT EXEC: byte we overwrote
    std::vector<std::pair<uintptr_t, uint32_t>> guardedPages; // SOFT R/W
};

struct BackendState {
    uint32_t          version;
    CRITICAL_SECTION  lock;
    PVOID             vehHandle;
    bool              shutdown;
    uintptr_t         nextHandle;
    std::unordered_map<uintptr_t, Bp*>     bps;
    std::unordered_map<DWORD, uint8_t>     threadSlotMasks;  // bit i = slot i used on tid
    std::unordered_map<DWORD, Bp*>         stepRearm;        // tid -> BP currently single-stepping for re-arm
};

static CRITICAL_SECTION g_singletonLock;
static bool             g_singletonLockInit = false;
static BackendState*    g_singleton = nullptr;   // only one VehBackend per process

static void EnsureSingletonLock()
{
    if (!g_singletonLockInit) {
        InitializeCriticalSection(&g_singletonLock);
        g_singletonLockInit = true;
    }
}

// ---------- thread / slot helpers ----------

static std::vector<DWORD> SnapshotThreads(DWORD pid)
{
    std::vector<DWORD> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return tids;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) tids.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}

static int AllocSlot(BackendState* st, DWORD tid)
{
    uint8_t& mask = st->threadSlotMasks[tid];
    for (int i = 0; i < 4; ++i) {
        if ((mask & (1u << i)) == 0) {
            mask |= (uint8_t)(1u << i);
            return i;
        }
    }
    return -1;
}

static void FreeSlot(BackendState* st, DWORD tid, int slotIndex)
{
    auto it = st->threadSlotMasks.find(tid);
    if (it == st->threadSlotMasks.end()) return;
    it->second &= (uint8_t)~(1u << slotIndex);
}

// Forward declarations for HW slot helpers defined further down.
static bool ApplyHwExecSlot(DWORD tid, int slotIndex, uint64_t address, bool enable);
static bool ApplyHwDataSlot(DWORD tid, int slotIndex, uint64_t address,
                            uint32_t len, bool isWriteOnly, bool enable);

// Apply a HARD BP to a list of TIDs (claim slots, write DR registers, push
// `(tid, slot)` entries into bp->slots). On any failure for a TID, rolls back
// the slots claimed for THAT TID only and returns false. Slots for earlier
// TIDs in the same call stay applied (caller decides whether to roll back
// further by calling DetachBpFromTids).
//
// Returns true iff every TID succeeded. Sets g_lastBpError on failure.
static bool ApplyBpToTids(BackendState* st, Bp* bp, const std::vector<DWORD>& tids)
{
    bool isWriteOnly = (bp->flags & BPF_WRITE) && !(bp->flags & BPF_READ);
    size_t beforeCount = bp->slots.size();
    for (DWORD t : tids) {
        // Skip TIDs already covered by this BP.
        bool already = false;
        for (auto& s : bp->slots) if (s.tid == t) { already = true; break; }
        if (already) continue;

        size_t perTidStart = bp->slots.size();
        if (bp->isExec) {
            int slot = AllocSlot(st, t);
            if (slot < 0) { g_lastBpError = BPERR_SLOT_EXHAUSTED; goto rollback_tid; }
            if (!ApplyHwExecSlot(t, slot, bp->address, bp->enabled)) {
                FreeSlot(st, t, slot);
                g_lastBpError = BPERR_APPLY_FAILED;
                goto rollback_tid;
            }
            bp->slots.push_back({ t, slot });
        } else {
            for (auto& c : bp->chunks) {
                int slot = AllocSlot(st, t);
                if (slot < 0) { g_lastBpError = BPERR_SLOT_EXHAUSTED; goto rollback_tid; }
                if (!ApplyHwDataSlot(t, slot, c.address, c.length, isWriteOnly, bp->enabled)) {
                    FreeSlot(st, t, slot);
                    g_lastBpError = BPERR_APPLY_FAILED;
                    goto rollback_tid;
                }
                bp->slots.push_back({ t, slot });
            }
        }
        continue;
      rollback_tid:
        // Roll back the slots claimed for THIS TID only, then bail.
        while (bp->slots.size() > perTidStart) {
            auto& s = bp->slots.back();
            if (bp->isExec) ApplyHwExecSlot(s.tid, s.slotIndex, 0, false);
            else            ApplyHwDataSlot(s.tid, s.slotIndex, 0, 1, false, false);
            FreeSlot(st, s.tid, s.slotIndex);
            bp->slots.pop_back();
        }
        // Also roll back slots added by previous TIDs in this very call.
        while (bp->slots.size() > beforeCount) {
            auto& s = bp->slots.back();
            if (bp->isExec) ApplyHwExecSlot(s.tid, s.slotIndex, 0, false);
            else            ApplyHwDataSlot(s.tid, s.slotIndex, 0, 1, false, false);
            FreeSlot(st, s.tid, s.slotIndex);
            bp->slots.pop_back();
        }
        return false;
    }
    return true;
}

// Detach a HARD BP from a list of TIDs: release every slot whose tid is in
// `tids`, leaving slots for other TIDs alone.
static void DetachBpFromTids(BackendState* st, Bp* bp, const std::vector<DWORD>& tids)
{
    std::vector<PerThreadSlot> kept;
    kept.reserve(bp->slots.size());
    for (auto& s : bp->slots) {
        bool drop = false;
        for (DWORD t : tids) if (s.tid == t) { drop = true; break; }
        if (drop) {
            if (bp->isExec) ApplyHwExecSlot(s.tid, s.slotIndex, 0, false);
            else            ApplyHwDataSlot(s.tid, s.slotIndex, 0, 1, false, false);
            FreeSlot(st, s.tid, s.slotIndex);
        } else {
            kept.push_back(s);
        }
    }
    bp->slots = std::move(kept);
}

// Split a [address, address+size) region into 1/2/4/8-aligned chunks. Returns
// false if more than 4 chunks would be needed.
static bool ChunkRegion(uint64_t address, uint32_t size,
                        std::vector<std::pair<uint64_t, uint32_t>>& out)
{
    out.clear();
    uint64_t cur = address;
    uint64_t end = address + size;
    while (cur < end) {
        uint64_t remain = end - cur;
        uint32_t pick = 1;
        if (remain >= 8 && (cur % 8) == 0) pick = 8;
        else if (remain >= 4 && (cur % 4) == 0) pick = 4;
        else if (remain >= 2 && (cur % 2) == 0) pick = 2;
        else pick = 1;
        out.push_back({cur, pick});
        cur += pick;
        if (out.size() > 4) return false;
    }
    return out.size() <= 4;
}

// Apply a HW data (READ or WRITE) BP at `address` with `len` bytes (1/2/4/8).
// isWriteOnly: true -> DR7 RW=01 (write); false -> RW=11 (read/write).
static bool ApplyHwDataSlot(DWORD tid, int slotIndex,
                            uint64_t address, uint32_t len,
                            bool isWriteOnly, bool enable)
{
    bool isSelf = (tid == GetCurrentThreadId());
    HANDLE th;
    if (isSelf) {
        th = GetCurrentThread();
    } else {
        th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                       FALSE, tid);
        if (!th) return false;
        SuspendThread(th);
    }
    bool ok = true;
    do {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(th, &ctx)) { ok = false; break; }
        uint64_t* drs[4] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
        *drs[slotIndex] = enable ? address : 0;
        int enableBit = slotIndex * 2;
        int rwShift   = 16 + slotIndex * 4;
        int lenShift  = 18 + slotIndex * 4;
        ctx.Dr7 &= ~((uint64_t)0x3 << rwShift);
        ctx.Dr7 &= ~((uint64_t)0x3 << lenShift);
        ctx.Dr7 &= ~((uint64_t)0x1 << enableBit);
        if (enable) {
            uint64_t rw = isWriteOnly ? 0x1 : 0x3;     // 01=write, 11=read/write
            // LEN bits: 1->00, 2->01, 4->11, 8->10
            uint64_t lenBits = (len == 1) ? 0 : (len == 2) ? 1 : (len == 4) ? 3 : 2;
            ctx.Dr7 |= (rw      << rwShift);
            ctx.Dr7 |= (lenBits << lenShift);
            ctx.Dr7 |= ((uint64_t)0x1 << enableBit);
        }
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!SetThreadContext(th, &ctx)) { ok = false; break; }
    } while (false);
    if (!isSelf) { ResumeThread(th); CloseHandle(th); }
    return ok;
}

// Encode DR7 + Drn for an EXEC slot (LEN=00, RW=00).
// `enable` = false clears the address + the local-enable bit (leaving RW/LEN
// at 00, which is harmless when disabled).
//
// For the current thread we MUST NOT call SuspendThread (self-suspend
// deadlocks). Get/SetThreadContext on the current thread is safe via the
// pseudo-handle: the kernel snapshots / restores around the syscall and any
// modifications to DR* take effect on the next instruction we execute.
static bool ApplyHwExecSlot(DWORD tid, int slotIndex, uint64_t address, bool enable)
{
    bool isSelf = (tid == GetCurrentThreadId());
    HANDLE th;
    if (isSelf) {
        th = GetCurrentThread();  // pseudo-handle, do not Close
    } else {
        th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                       FALSE, tid);
        if (!th) {
            DbgFmtW(L"OpenThread(%lu) failed (%lu)", tid, GetLastError());
            return false;
        }
        SuspendThread(th);
    }
    bool ok = true;
    do {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(th, &ctx)) {
            DbgFmtW(L"GetThreadContext(tid=%lu) failed (%lu)", tid, GetLastError());
            ok = false; break;
        }
        uint64_t* drs[4] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
        *drs[slotIndex] = enable ? address : 0;
        int enableBit = slotIndex * 2;        // L0,L1,L2,L3 in bits 0,2,4,6
        int rwShift   = 16 + slotIndex * 4;
        int lenShift  = 18 + slotIndex * 4;
        ctx.Dr7 &= ~((uint64_t)0x3 << rwShift);
        ctx.Dr7 &= ~((uint64_t)0x3 << lenShift);
        ctx.Dr7 &= ~((uint64_t)0x1 << enableBit);
        if (enable) {
            ctx.Dr7 |= ((uint64_t)0x1 << enableBit);
        }
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!SetThreadContext(th, &ctx)) {
            DbgFmtW(L"SetThreadContext(tid=%lu) failed (%lu)", tid, GetLastError());
            ok = false; break;
        }
    } while (false);
    if (!isSelf) {
        ResumeThread(th);
        CloseHandle(th);
    }
    return ok;
}

// ---------- SOFT path helpers ----------

// Write `byte` at `addr` after temporarily ensuring PAGE_EXECUTE_READWRITE.
// Returns true on success.
static bool WriteByteRWX(uint64_t addr, uint8_t byte)
{
    DWORD old = 0;
    if (!VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old)) {
        DbgFmtW(L"VirtualProtect(RWX) failed @ %llx (%lu)",
                (unsigned long long)addr, GetLastError());
        return false;
    }
    __try {
        *(uint8_t*)addr = byte;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        VirtualProtect((LPVOID)addr, 1, old, &old);
        return false;
    }
    VirtualProtect((LPVOID)addr, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)addr, 1);
    return true;
}

// Read the byte at `addr` (under PAGE_READONLY at minimum). Returns true and
// fills *out on success.
static bool ReadByteAny(uint64_t addr, uint8_t* out)
{
    DWORD old = 0;
    bool changed = false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) return false;
    if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
        if (!VirtualProtect((LPVOID)addr, 1, PAGE_READONLY, &old)) return false;
        changed = true;
    }
    bool ok = true;
    __try { *out = *(uint8_t*)addr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    if (changed) VirtualProtect((LPVOID)addr, 1, old, &old);
    return ok;
}

// Enumerate the pages spanning [address, address+size) and apply PAGE_GUARD,
// recording original protections so we can restore.
static bool ApplyPageGuard(uint64_t address, uint32_t size,
                           std::vector<std::pair<uintptr_t, uint32_t>>& outPages)
{
    SYSTEM_INFO si; GetSystemInfo(&si);
    uintptr_t pageSize = si.dwPageSize;
    uintptr_t start = (uintptr_t)(address & ~(pageSize - 1));
    uintptr_t end   = (uintptr_t)((address + size + pageSize - 1) & ~(pageSize - 1));
    for (uintptr_t p = start; p < end; p += pageSize) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi)) == 0) return false;
        DWORD oldProt = 0;
        DWORD newProt = mbi.Protect | PAGE_GUARD;
        if (!VirtualProtect((LPVOID)p, 1, newProt, &oldProt)) {
            DbgFmtW(L"VirtualProtect(GUARD) failed @ %p (%lu)",
                    (void*)p, GetLastError());
            return false;
        }
        outPages.push_back({p, (uint32_t)oldProt});
    }
    return true;
}

static void RemovePageGuard(const std::vector<std::pair<uintptr_t, uint32_t>>& pages)
{
    DWORD old = 0;
    for (auto& pp : pages) {
        VirtualProtect((LPVOID)pp.first, 1, pp.second, &old);
    }
}

static void ReapplyPageGuard(const std::vector<std::pair<uintptr_t, uint32_t>>& pages)
{
    DWORD old = 0;
    for (auto& pp : pages) {
        VirtualProtect((LPVOID)pp.first, 1, pp.second | PAGE_GUARD, &old);
    }
}

// ---------- VEH dispatch ----------

using TrampolineFn = void (__cdecl*)(uint64_t /*bp_handle*/, uint32_t /*flags*/,
                                     uint64_t /*frm*/, uint64_t /*context_addr*/);

static LONG CALLBACK VehDispatch(PEXCEPTION_POINTERS p)
{
    __try {
        BackendState* st = g_singleton;
        if (st == nullptr || st->shutdown) return EXCEPTION_CONTINUE_SEARCH;
        DWORD code = p->ExceptionRecord->ExceptionCode;
        DWORD tid  = GetCurrentThreadId();

        // ----- EXCEPTION_SINGLE_STEP: HW BP hit OR SOFT re-arm step -----
        if (code == EXCEPTION_SINGLE_STEP) {
            // First, check if we're in a SOFT re-arm single-step for this thread.
            Bp* rearmBp = nullptr;
            EnterCriticalSection(&st->lock);
            auto rit = st->stepRearm.find(tid);
            if (rit != st->stepRearm.end()) {
                rearmBp = rit->second;
                st->stepRearm.erase(rit);
            }
            LeaveCriticalSection(&st->lock);
            if (rearmBp) {
                // Re-apply SOFT trap.
                if (rearmBp->isExec) {
                    WriteByteRWX(rearmBp->address, 0xCC);
                } else {
                    ReapplyPageGuard(rearmBp->guardedPages);
                }
                // TF auto-cleared by the SINGLE_STEP delivery; nothing to do.
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            // Otherwise: HW DR breakpoint match.
            uint64_t dr6 = p->ContextRecord->Dr6;
            int slotIndex = -1;
            for (int i = 0; i < 4; ++i) {
                if (dr6 & ((uint64_t)1u << i)) { slotIndex = i; break; }
            }
            if (slotIndex < 0) return EXCEPTION_CONTINUE_SEARCH;

            uint64_t* drs[4] = {
                &p->ContextRecord->Dr0, &p->ContextRecord->Dr1,
                &p->ContextRecord->Dr2, &p->ContextRecord->Dr3,
            };
            uint64_t hitAddr = *drs[slotIndex];

            EnterCriticalSection(&st->lock);
            Bp* match = nullptr;
            bool matchIsExec = false;
            for (auto& kv : st->bps) {
                Bp* bp = kv.second;
                if (!bp->enabled || !bp->isHard) continue;
                if (bp->isExec) {
                    if (bp->address == hitAddr) { match = bp; matchIsExec = true; break; }
                } else {
                    for (auto& c : bp->chunks) {
                        if (c.address == hitAddr) { match = bp; matchIsExec = false; break; }
                    }
                    if (match) break;
                }
            }
            LeaveCriticalSection(&st->lock);
            if (!match) return EXCEPTION_CONTINUE_SEARCH;

            p->ContextRecord->Dr6 &= ~((uint64_t)1u << slotIndex);
            p->ContextRecord->EFlags |= 0x10000;   // RF

            uint64_t frm = 0;
            if (matchIsExec) {
                __try { frm = *reinterpret_cast<uint64_t*>(p->ContextRecord->Rsp); }
                __except (EXCEPTION_EXECUTE_HANDLER) { frm = 0; }
            } else {
                frm = p->ContextRecord->Rip;
            }
            TrampolineFn fn = reinterpret_cast<TrampolineFn>(match->callback);
            fn((uint64_t)match->handle, match->flags, frm,
               reinterpret_cast<uint64_t>(p->ContextRecord));
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // ----- EXCEPTION_BREAKPOINT (INT3): SOFT EXEC hit -----
        if (code == EXCEPTION_BREAKPOINT) {
            uint64_t hitAddr = p->ContextRecord->Rip;  // INT3 is 1-byte; RIP points AT INT3+1
            // Some kernels deliver Rip already pointing at the INT3 byte; handle both.
            uint64_t cand1 = hitAddr;
            uint64_t cand2 = hitAddr - 1;
            EnterCriticalSection(&st->lock);
            Bp* match = nullptr;
            uint64_t matchedAt = 0;
            for (auto& kv : st->bps) {
                Bp* bp = kv.second;
                if (!bp->enabled || !bp->isSoft || !bp->isExec) continue;
                if (bp->address == cand1) { match = bp; matchedAt = cand1; break; }
                if (bp->address == cand2) { match = bp; matchedAt = cand2; break; }
            }
            LeaveCriticalSection(&st->lock);
            if (!match) return EXCEPTION_CONTINUE_SEARCH;

            // Restore the original byte and rewind Rip so the original
            // instruction executes; set TF + queue re-arm.
            WriteByteRWX(matchedAt, match->origByte);
            p->ContextRecord->Rip = matchedAt;
            p->ContextRecord->EFlags |= 0x100;   // TF
            EnterCriticalSection(&st->lock);
            st->stepRearm[tid] = match;
            LeaveCriticalSection(&st->lock);

            uint64_t frm = 0;
            __try { frm = *reinterpret_cast<uint64_t*>(p->ContextRecord->Rsp); }
            __except (EXCEPTION_EXECUTE_HANDLER) { frm = 0; }

            TrampolineFn fn = reinterpret_cast<TrampolineFn>(match->callback);
            fn((uint64_t)match->handle, match->flags, frm,
               reinterpret_cast<uint64_t>(p->ContextRecord));
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // ----- EXCEPTION_GUARD_PAGE: SOFT R/W hit -----
        if (code == EXCEPTION_GUARD_PAGE) {
            // ExceptionInformation[0] = access type (0=r, 1=w, 8=execute),
            // ExceptionInformation[1] = faulting address.
            uint64_t faultAddr = (uint64_t)p->ExceptionRecord->ExceptionInformation[1];
            EnterCriticalSection(&st->lock);
            Bp* match = nullptr;
            for (auto& kv : st->bps) {
                Bp* bp = kv.second;
                if (!bp->enabled || !bp->isSoft || bp->isExec) continue;
                if (faultAddr >= bp->address && faultAddr < bp->address + bp->size) {
                    match = bp; break;
                }
                // PAGE_GUARD may also fire on adjacent pages we covered; check
                // if the faulting page is one of ours.
                for (auto& pp : bp->guardedPages) {
                    if (faultAddr >= pp.first && faultAddr < pp.first + 0x1000) {
                        match = bp; break;
                    }
                }
                if (match) break;
            }
            LeaveCriticalSection(&st->lock);
            if (!match) return EXCEPTION_CONTINUE_SEARCH;

            // OS already cleared PAGE_GUARD for this hit; queue re-arm via TF.
            p->ContextRecord->EFlags |= 0x100;   // TF
            EnterCriticalSection(&st->lock);
            st->stepRearm[tid] = match;
            LeaveCriticalSection(&st->lock);

            uint64_t frm = p->ContextRecord->Rip;
            TrampolineFn fn = reinterpret_cast<TrampolineFn>(match->callback);
            fn((uint64_t)match->handle, match->flags, frm,
               reinterpret_cast<uint64_t>(p->ContextRecord));
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgW(L"VehDispatch faulted; continuing search");
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

// ---------- exports ----------

extern "C" __declspec(dllexport) uintptr_t BpBackendInit(uint32_t version)
{
    if (version != BP_BACKEND_VERSION) {
        DbgFmtW(L"BpBackendInit: version mismatch (got %u, want %u)", version, BP_BACKEND_VERSION);
        return 0;
    }
    EnsureSingletonLock();
    EnterCriticalSection(&g_singletonLock);
    if (g_singleton != nullptr) {
        DbgW(L"BpBackendInit: singleton already alive, returning existing handle");
        BackendState* existing = g_singleton;
        LeaveCriticalSection(&g_singletonLock);
        return reinterpret_cast<uintptr_t>(existing);
    }
    BackendState* st = new BackendState();
    st->version = version;
    InitializeCriticalSection(&st->lock);
    st->shutdown = false;
    st->nextHandle = 1;
    st->vehHandle = AddVectoredExceptionHandler(1 /* first */, &VehDispatch);
    if (st->vehHandle == nullptr) {
        DbgFmtW(L"BpBackendInit: AddVectoredExceptionHandler failed (%lu)", GetLastError());
        DeleteCriticalSection(&st->lock);
        delete st;
        LeaveCriticalSection(&g_singletonLock);
        return 0;
    }
    g_singleton = st;
    LeaveCriticalSection(&g_singletonLock);
    DbgFmtW(L"BpBackendInit: ok handle=%p", (void*)st);
    return reinterpret_cast<uintptr_t>(st);
}

extern "C" __declspec(dllexport) uint32_t BpBackendShutdown(uintptr_t handle)
{
    EnsureSingletonLock();
    EnterCriticalSection(&g_singletonLock);
    BackendState* st = reinterpret_cast<BackendState*>(handle);
    if (st == nullptr || st != g_singleton) {
        LeaveCriticalSection(&g_singletonLock);
        return 1;
    }
    st->shutdown = true;
    if (st->vehHandle) {
        RemoveVectoredExceptionHandler(st->vehHandle);
        st->vehHandle = nullptr;
    }
    // Free any leftover BP records (caller should have uninstalled them, but
    // be defensive in case of abnormal teardown).
    for (auto& kv : st->bps) delete kv.second;
    st->bps.clear();
    DeleteCriticalSection(&st->lock);
    g_singleton = nullptr;
    delete st;
    LeaveCriticalSection(&g_singletonLock);
    DbgW(L"BpBackendShutdown: ok");
    return 0;
}

extern "C" __declspec(dllexport) uintptr_t BpInstall(
    uintptr_t backend, uint64_t address, uint32_t size, uint32_t flags,
    void* callback, void* user_data, uint32_t* tids, uint32_t tid_count)
{
    g_lastBpError = BPERR_OK;
    BackendState* st = reinterpret_cast<BackendState*>(backend);
    if (!st || st->shutdown) { g_lastBpError = BPERR_BAD_FLAGS; return 0; }

    bool wantExec  = (flags & BPF_EXEC) != 0;
    bool wantWrite = (flags & BPF_WRITE) != 0;
    bool wantRead  = (flags & BPF_READ) != 0;
    bool wantSoft  = (flags & BPF_SOFT) != 0;

    if (wantExec && size != 1) {
        DbgW(L"BpInstall: EXEC requires size=1");
        g_lastBpError = BPERR_BAD_FLAGS;
        return 0;
    }
    if (!wantExec && !wantWrite && !wantRead) {
        g_lastBpError = BPERR_BAD_FLAGS;
        return 0;
    }

    // ---- SOFT path: no DR registers; same per-process trap -----
    if (wantSoft) {
        EnterCriticalSection(&st->lock);
        Bp* bp = new Bp();
        bp->handle   = st->nextHandle++;
        bp->address  = address;
        bp->size     = size;
        bp->flags    = flags;
        bp->callback = callback;
        bp->userData = user_data;
        bp->enabled  = true;
        bp->isHard   = false;
        bp->isExec   = wantExec;
        bp->isSoft   = true;
        if (wantExec) {
            uint8_t orig = 0;
            if (!ReadByteAny(address, &orig)) {
                delete bp;
                LeaveCriticalSection(&st->lock);
                g_lastBpError = BPERR_APPLY_FAILED;
                return 0;
            }
            bp->origByte = orig;
            if (!WriteByteRWX(address, 0xCC)) {
                delete bp;
                LeaveCriticalSection(&st->lock);
                g_lastBpError = BPERR_APPLY_FAILED;
                return 0;
            }
        } else {
            if (!ApplyPageGuard(address, size, bp->guardedPages)) {
                RemovePageGuard(bp->guardedPages);
                delete bp;
                LeaveCriticalSection(&st->lock);
                g_lastBpError = BPERR_APPLY_FAILED;
                return 0;
            }
        }
        uintptr_t h = bp->handle;
        st->bps[h] = bp;
        LeaveCriticalSection(&st->lock);
        DbgFmtW(L"BpInstall: SOFT ok handle=%llu addr=%llx size=%u",
                (unsigned long long)h, (unsigned long long)address, size);
        return h;
    }

    std::vector<DWORD> targetTids;
    if (tids && tid_count) {
        targetTids.assign(tids, tids + tid_count);
    } else {
        targetTids = SnapshotThreads(GetCurrentProcessId());
    }
    if (targetTids.empty()) {
        DbgW(L"BpInstall: no target threads");
        g_lastBpError = BPERR_APPLY_FAILED;
        return 0;
    }

    // For HARD data BPs, split into 1/2/4/8-aligned chunks.
    std::vector<std::pair<uint64_t, uint32_t>> chunks;
    if (!wantExec) {
        if (!ChunkRegion(address, size, chunks)) {
            DbgFmtW(L"BpInstall: region size=%u splits into >4 chunks", size);
            g_lastBpError = BPERR_CHUNK_OVERFLOW;
            return 0;
        }
    }

    EnterCriticalSection(&st->lock);
    Bp* bp = new Bp();
    bp->handle   = st->nextHandle++;
    bp->address  = address;
    bp->size     = size;
    bp->flags    = flags;
    bp->callback = callback;
    bp->userData = user_data;
    bp->enabled  = true;
    bp->isHard   = true;
    bp->isExec   = wantExec;
    bp->isSoft   = false;
    if (!wantExec) {
        for (auto& c : chunks) bp->chunks.push_back({c.first, c.second});
    }

    if (!ApplyBpToTids(st, bp, targetTids)) {
        delete bp;
        LeaveCriticalSection(&st->lock);
        DbgW(L"BpInstall: rolled back");
        return 0;
    }
    uintptr_t h = bp->handle;
    st->bps[h] = bp;
    LeaveCriticalSection(&st->lock);
    DbgFmtW(L"BpInstall: ok handle=%llu addr=%llx tids=%zu chunks=%zu",
            (unsigned long long)h, (unsigned long long)address,
            targetTids.size(), bp->chunks.size());
    return h;
}

// Attach an existing HARD BP to additional TIDs.
// Returns 0 on success, non-zero status on failure (see BpLastError too).
extern "C" __declspec(dllexport) uint32_t BpAttachTids(
    uintptr_t backend, uintptr_t handle,
    uint32_t* tids, uint32_t tid_count)
{
    g_lastBpError = BPERR_OK;
    BackendState* st = reinterpret_cast<BackendState*>(backend);
    if (!st || st->shutdown) { g_lastBpError = BPERR_BAD_FLAGS; return 1; }
    if (!tids || tid_count == 0) return 0;
    EnterCriticalSection(&st->lock);
    auto it = st->bps.find(handle);
    if (it == st->bps.end()) { LeaveCriticalSection(&st->lock); return 2; }
    Bp* bp = it->second;
    if (!bp->isHard) {
        LeaveCriticalSection(&st->lock);
        g_lastBpError = BPERR_BAD_FLAGS;
        return 3;  // SOFT BPs are per-process; no per-TID attach
    }
    std::vector<DWORD> ts(tids, tids + tid_count);
    bool ok = ApplyBpToTids(st, bp, ts);
    LeaveCriticalSection(&st->lock);
    return ok ? 0 : 4;
}

extern "C" __declspec(dllexport) uint32_t BpDetachTids(
    uintptr_t backend, uintptr_t handle,
    uint32_t* tids, uint32_t tid_count)
{
    BackendState* st = reinterpret_cast<BackendState*>(backend);
    if (!st || st->shutdown) return 1;
    if (!tids || tid_count == 0) return 0;
    EnterCriticalSection(&st->lock);
    auto it = st->bps.find(handle);
    if (it == st->bps.end()) { LeaveCriticalSection(&st->lock); return 2; }
    Bp* bp = it->second;
    if (!bp->isHard) { LeaveCriticalSection(&st->lock); return 3; }
    std::vector<DWORD> ts(tids, tids + tid_count);
    DetachBpFromTids(st, bp, ts);
    LeaveCriticalSection(&st->lock);
    return 0;
}

// Fill `out_tids` with at most `cap` unique TIDs currently carrying this BP.
// Returns the actual count (may exceed `cap`, in which case the caller should
// re-call with a larger buffer).
extern "C" __declspec(dllexport) uint32_t BpListTids(
    uintptr_t backend, uintptr_t handle,
    uint32_t* out_tids, uint32_t cap)
{
    BackendState* st = reinterpret_cast<BackendState*>(backend);
    if (!st) return 0;
    EnterCriticalSection(&st->lock);
    auto it = st->bps.find(handle);
    if (it == st->bps.end()) { LeaveCriticalSection(&st->lock); return 0; }
    Bp* bp = it->second;
    std::vector<DWORD> uniq;
    for (auto& s : bp->slots) {
        bool seen = false;
        for (DWORD u : uniq) if (u == s.tid) { seen = true; break; }
        if (!seen) uniq.push_back(s.tid);
    }
    uint32_t n = (uint32_t)uniq.size();
    uint32_t toCopy = (n < cap) ? n : cap;
    for (uint32_t i = 0; i < toCopy; ++i) out_tids[i] = uniq[i];
    LeaveCriticalSection(&st->lock);
    return n;
}

// Snapshot the current process's TIDs; useful for callers driving refresh.
extern "C" __declspec(dllexport) uint32_t BpSnapshotTids(
    uintptr_t backend, uint32_t* out_tids, uint32_t cap)
{
    (void)backend;
    auto tids = SnapshotThreads(GetCurrentProcessId());
    uint32_t n = (uint32_t)tids.size();
    uint32_t toCopy = (n < cap) ? n : cap;
    for (uint32_t i = 0; i < toCopy; ++i) out_tids[i] = tids[i];
    return n;
}

extern "C" __declspec(dllexport) uint32_t BpUninstall(uintptr_t backend, uintptr_t handle)
{
    BackendState* st = reinterpret_cast<BackendState*>(backend);
    if (!st) return 1;
    EnterCriticalSection(&st->lock);
    auto it = st->bps.find(handle);
    if (it == st->bps.end()) { LeaveCriticalSection(&st->lock); return 2; }
    Bp* bp = it->second;
    if (bp->isHard) {
        if (bp->isExec) {
            for (auto& s : bp->slots) {
                ApplyHwExecSlot(s.tid, s.slotIndex, 0, false);
                FreeSlot(st, s.tid, s.slotIndex);
            }
        } else {
            for (auto& s : bp->slots) {
                ApplyHwDataSlot(s.tid, s.slotIndex, 0, 1, false, false);
                FreeSlot(st, s.tid, s.slotIndex);
            }
        }
    } else if (bp->isSoft) {
        if (bp->isExec) {
            WriteByteRWX(bp->address, bp->origByte);
        } else {
            RemovePageGuard(bp->guardedPages);
        }
    }
    st->bps.erase(it);
    delete bp;
    LeaveCriticalSection(&st->lock);
    return 0;
}

extern "C" __declspec(dllexport) uint32_t BpEnable(uintptr_t backend, uintptr_t handle, uint32_t enabled)
{
    BackendState* st = reinterpret_cast<BackendState*>(backend);
    if (!st) return 1;
    EnterCriticalSection(&st->lock);
    auto it = st->bps.find(handle);
    if (it == st->bps.end()) { LeaveCriticalSection(&st->lock); return 2; }
    Bp* bp = it->second;
    bool prev = bp->enabled;
    bp->enabled = (enabled != 0);
    if (bp->isSoft) {
        if (bp->enabled && !prev) {
            if (bp->isExec) WriteByteRWX(bp->address, 0xCC);
            else            ReapplyPageGuard(bp->guardedPages);
        } else if (!bp->enabled && prev) {
            if (bp->isExec) WriteByteRWX(bp->address, bp->origByte);
            else            RemovePageGuard(bp->guardedPages);
        }
    }
    if (bp->isHard) {
        bool isWriteOnly = (bp->flags & BPF_WRITE) && !(bp->flags & BPF_READ);
        if (bp->isExec) {
            for (auto& s : bp->slots) {
                ApplyHwExecSlot(s.tid, s.slotIndex, bp->address, bp->enabled);
            }
        } else {
            // Slot order matches chunk order; recover (chunkAddr, chunkLen)
            // by indexing modulo chunks.size().
            size_t nChunks = bp->chunks.size();
            for (size_t i = 0; i < bp->slots.size(); ++i) {
                auto& s = bp->slots[i];
                auto& c = bp->chunks[i % nChunks];
                ApplyHwDataSlot(s.tid, s.slotIndex,
                                bp->enabled ? c.address : 0, c.length,
                                isWriteOnly, bp->enabled);
            }
        }
    }
    LeaveCriticalSection(&st->lock);
    return 0;
}

extern "C" __declspec(dllexport) uint32_t BpSlotsFree(uintptr_t backend, uint32_t tid)
{
    (void)backend; (void)tid;
    return 4;
}

extern "C" __declspec(dllexport) uint32_t BpLastError()
{
    return g_lastBpError;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_DETACH && g_singleton != nullptr) {
        BpBackendShutdown(reinterpret_cast<uintptr_t>(g_singleton));
    }
    return TRUE;
}
