// nylib breakpoint debugger backend
// ---------------------------------
// In-process debugger-thread dispatcher. A worker thread calls
// DebugActiveProcess(GetCurrentProcessId()) and runs the standard
// WaitForDebugEvent / ContinueDebugEvent loop. Every other thread in the
// process becomes a debuggee; when a HW DR / INT3 / PAGE_GUARD trap fires,
// the kernel suspends the trapping thread and delivers the event to our
// worker, which dispatches to a Python callback under the GIL.
//
// Compared with the VEH backend this gives two wins for free:
//   1. CREATE_THREAD_DEBUG_EVENT lets us auto-apply DR settings to newly
//      spawned threads (no RtlUserThreadStart hook needed).
//   2. The trapping thread is suspended by the kernel during dispatch, so
//      we don't have to play games with EFLAGS.RF / single-step to re-arm.
//
// Limitations:
//   * Coexistence with another in-process debugger or DR-using VEH is
//     undefined; only one backend should be active at a time.
//   * DebugActiveProcessStop is called on shutdown; if that fails the host
//     stays in "being debugged" state until process exit.
//
// Exports the same nine-function ABI as the VEH backend
// (BpBackendInit/Shutdown/Install/Uninstall/Enable/SlotsFree/LastError +
//  BpAttachTids/BpDetachTids/BpListTids/BpSnapshotTids).

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

// ---------- diagnostic helpers (DbgView + optional file via NYLIB_BP_LOG) ----------

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
    OutputDebugStringW(L"[nylib.bp.dbg] ");
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

// ---------- ABI ----------

#define BP_BACKEND_VERSION 1u
#define BPF_EXEC  0x001u
#define BPF_WRITE 0x002u
#define BPF_READ  0x004u
#define BPF_HARD  0x100u
#define BPF_SOFT  0x200u

#define BPERR_OK              0u
#define BPERR_ALLOC           1u
#define BPERR_OOM             2u
#define BPERR_SLOT_EXHAUSTED  3u
#define BPERR_CHUNK_OVERFLOW  4u
#define BPERR_APPLY_FAILED    5u
#define BPERR_BAD_FLAGS       6u

static thread_local uint32_t g_lastBpError = BPERR_OK;

// ---------- BP records ----------

struct PerThreadSlot { DWORD tid; int slotIndex; };
struct ChunkRec     { uint64_t address; uint32_t length; };

struct Bp {
    uintptr_t handle;
    uint64_t  address;
    uint32_t  size;
    uint32_t  flags;
    void*     callback;
    void*     userData;
    bool      enabled;
    bool      isHard;
    bool      isExec;
    bool      isSoft;
    std::vector<PerThreadSlot> slots;
    std::vector<ChunkRec>      chunks;
    uint8_t                    origByte;
    std::vector<std::pair<uintptr_t, uint32_t>> guardedPages;
};

struct DbgState {
    uint32_t          version;
    CRITICAL_SECTION  lock;
    HANDLE            worker;
    DWORD             workerTid;
    HANDLE            startedEvent;
    HANDLE            stopEvent;
    bool              shutdown;
    bool              started_ok;
    uintptr_t         nextHandle;
    std::unordered_map<uintptr_t, Bp*> bps;
    std::unordered_map<DWORD, uint8_t> threadSlotMasks;
    std::unordered_map<DWORD, Bp*>     stepRearm;
};

static CRITICAL_SECTION g_singletonLock;
static bool             g_singletonLockInit = false;
static DbgState*        g_singleton = nullptr;

static void EnsureSingletonLock()
{
    if (!g_singletonLockInit) {
        InitializeCriticalSection(&g_singletonLock);
        g_singletonLockInit = true;
    }
}

// ---------- slot helpers ----------

static int AllocSlot(DbgState* st, DWORD tid)
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

static void FreeSlot(DbgState* st, DWORD tid, int slotIndex)
{
    auto it = st->threadSlotMasks.find(tid);
    if (it == st->threadSlotMasks.end()) return;
    it->second &= (uint8_t)~(1u << slotIndex);
}

// Open / suspend / GetCtx / SetCtx / Resume — for the debugger backend the
// trapping thread is already suspended when the event is delivered, but for
// applying DR slots from install / attach paths we still need the standard
// suspend dance for non-current threads.
static bool ApplyHwExecSlot(DWORD tid, int slotIndex, uint64_t address, bool enable)
{
    bool isSelf = (tid == GetCurrentThreadId());
    HANDLE th;
    if (isSelf) {
        th = GetCurrentThread();
    } else {
        th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                        FALSE, tid);
        if (!th) { DbgFmtW(L"OpenThread(%lu) failed (%lu)", tid, GetLastError()); return false; }
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
        if (enable) ctx.Dr7 |= ((uint64_t)0x1 << enableBit);
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!SetThreadContext(th, &ctx)) { ok = false; break; }
    } while (false);
    if (!isSelf) { ResumeThread(th); CloseHandle(th); }
    return ok;
}

static bool ApplyHwDataSlot(DWORD tid, int slotIndex, uint64_t address,
                            uint32_t len, bool isWriteOnly, bool enable)
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
            uint64_t rw = isWriteOnly ? 0x1 : 0x3;
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

static bool ApplyBpToTids(DbgState* st, Bp* bp, const std::vector<DWORD>& tids)
{
    size_t beforeCount = bp->slots.size();
    bool isWriteOnly = (bp->flags & BPF_WRITE) && !(bp->flags & BPF_READ);
    for (DWORD t : tids) {
        bool already = false;
        for (auto& s : bp->slots) if (s.tid == t) { already = true; break; }
        if (already) continue;
        size_t perTidStart = bp->slots.size();
        if (bp->isExec) {
            int slot = AllocSlot(st, t);
            if (slot < 0) { g_lastBpError = BPERR_SLOT_EXHAUSTED; goto rollback; }
            if (!ApplyHwExecSlot(t, slot, bp->address, bp->enabled)) {
                FreeSlot(st, t, slot);
                g_lastBpError = BPERR_APPLY_FAILED;
                goto rollback;
            }
            bp->slots.push_back({ t, slot });
        } else {
            for (auto& c : bp->chunks) {
                int slot = AllocSlot(st, t);
                if (slot < 0) { g_lastBpError = BPERR_SLOT_EXHAUSTED; goto rollback; }
                if (!ApplyHwDataSlot(t, slot, c.address, c.length, isWriteOnly, bp->enabled)) {
                    FreeSlot(st, t, slot);
                    g_lastBpError = BPERR_APPLY_FAILED;
                    goto rollback;
                }
                bp->slots.push_back({ t, slot });
            }
        }
        continue;
      rollback:
        while (bp->slots.size() > perTidStart) {
            auto& s = bp->slots.back();
            if (bp->isExec) ApplyHwExecSlot(s.tid, s.slotIndex, 0, false);
            else            ApplyHwDataSlot(s.tid, s.slotIndex, 0, 1, false, false);
            FreeSlot(st, s.tid, s.slotIndex);
            bp->slots.pop_back();
        }
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

static void DetachBpFromTids(DbgState* st, Bp* bp, const std::vector<DWORD>& tids)
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

static bool ChunkRegion(uint64_t address, uint32_t size,
                        std::vector<std::pair<uint64_t, uint32_t>>& out)
{
    out.clear();
    uint64_t cur = address, end = address + size;
    while (cur < end) {
        uint64_t remain = end - cur;
        uint32_t pick = 1;
        if      (remain >= 8 && (cur % 8) == 0) pick = 8;
        else if (remain >= 4 && (cur % 4) == 0) pick = 4;
        else if (remain >= 2 && (cur % 2) == 0) pick = 2;
        out.push_back({cur, pick});
        cur += pick;
        if (out.size() > 4) return false;
    }
    return out.size() <= 4;
}

static std::vector<DWORD> SnapshotThreads(DWORD pid)
{
    std::vector<DWORD> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return tids;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(snap, &te)) {
        do { if (te.th32OwnerProcessID == pid) tids.push_back(te.th32ThreadID); }
        while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}

// ---------- SOFT helpers ----------

static bool WriteByteRWX(uint64_t addr, uint8_t byte)
{
    DWORD old = 0;
    if (!VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    __try { *(uint8_t*)addr = byte; }
    __except (EXCEPTION_EXECUTE_HANDLER) { VirtualProtect((LPVOID)addr, 1, old, &old); return false; }
    VirtualProtect((LPVOID)addr, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)addr, 1);
    return true;
}

static bool ReadByteAny(uint64_t addr, uint8_t* out)
{
    DWORD old = 0; bool changed = false;
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
        if (!VirtualProtect((LPVOID)p, 1, mbi.Protect | PAGE_GUARD, &oldProt)) return false;
        outPages.push_back({p, (uint32_t)oldProt});
    }
    return true;
}

static void RemovePageGuard(const std::vector<std::pair<uintptr_t, uint32_t>>& pages)
{
    DWORD old = 0;
    for (auto& pp : pages) VirtualProtect((LPVOID)pp.first, 1, pp.second, &old);
}

static void ReapplyPageGuard(const std::vector<std::pair<uintptr_t, uint32_t>>& pages)
{
    DWORD old = 0;
    for (auto& pp : pages) VirtualProtect((LPVOID)pp.first, 1, pp.second | PAGE_GUARD, &old);
}

// ---------- dispatch (runs on debugger worker thread) ----------

using TrampolineFn = void (__cdecl*)(uint64_t, uint32_t, uint64_t, uint64_t);

// Returns DBG_CONTINUE if we consumed the event, DBG_EXCEPTION_NOT_HANDLED if not.
static DWORD HandleException(DbgState* st, const DEBUG_EVENT& ev)
{
    const EXCEPTION_DEBUG_INFO& edi = ev.u.Exception;
    DWORD code = edi.ExceptionRecord.ExceptionCode;
    DWORD tid  = ev.dwThreadId;

    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!th) {
        DbgFmtW(L"HandleException: OpenThread(%lu) failed (%lu)", tid, GetLastError());
        return DBG_EXCEPTION_NOT_HANDLED;
    }
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(th, &ctx)) {
        DbgFmtW(L"GetThreadContext(%lu) failed (%lu)", tid, GetLastError());
        CloseHandle(th);
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    auto dispatchCallback = [&](Bp* match, uint64_t frm) {
        TrampolineFn fn = reinterpret_cast<TrampolineFn>(match->callback);
        fn((uint64_t)match->handle, match->flags, frm,
           reinterpret_cast<uint64_t>(&ctx));
    };

    DWORD ret = DBG_EXCEPTION_NOT_HANDLED;

    if (code == EXCEPTION_SINGLE_STEP) {
        // SOFT re-arm step first.
        Bp* rearm = nullptr;
        EnterCriticalSection(&st->lock);
        auto rit = st->stepRearm.find(tid);
        if (rit != st->stepRearm.end()) { rearm = rit->second; st->stepRearm.erase(rit); }
        LeaveCriticalSection(&st->lock);
        if (rearm) {
            if (rearm->isExec) WriteByteRWX(rearm->address, 0xCC);
            else               ReapplyPageGuard(rearm->guardedPages);
            ret = DBG_CONTINUE;
            goto done;
        }

        // HW DR match.
        uint64_t dr6 = ctx.Dr6;
        int slotIndex = -1;
        for (int i = 0; i < 4; ++i) if (dr6 & ((uint64_t)1u << i)) { slotIndex = i; break; }
        if (slotIndex < 0) goto done;
        uint64_t* drs[4] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
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
                for (auto& c : bp->chunks) if (c.address == hitAddr) { match = bp; matchIsExec = false; break; }
                if (match) break;
            }
        }
        LeaveCriticalSection(&st->lock);
        if (!match) goto done;

        ctx.Dr6 &= ~((uint64_t)1u << slotIndex);
        ctx.EFlags |= 0x10000;   // RF

        uint64_t frm = 0;
        if (matchIsExec) {
            __try { frm = *reinterpret_cast<uint64_t*>(ctx.Rsp); }
            __except (EXCEPTION_EXECUTE_HANDLER) { frm = 0; }
        } else {
            frm = ctx.Rip;
        }
        dispatchCallback(match, frm);
        ret = DBG_CONTINUE;
        goto done;
    }

    if (code == EXCEPTION_BREAKPOINT) {
        uint64_t cand1 = ctx.Rip;
        uint64_t cand2 = ctx.Rip - 1;
        EnterCriticalSection(&st->lock);
        Bp* match = nullptr; uint64_t matchedAt = 0;
        for (auto& kv : st->bps) {
            Bp* bp = kv.second;
            if (!bp->enabled || !bp->isSoft || !bp->isExec) continue;
            if (bp->address == cand1) { match = bp; matchedAt = cand1; break; }
            if (bp->address == cand2) { match = bp; matchedAt = cand2; break; }
        }
        LeaveCriticalSection(&st->lock);
        if (!match) goto done;

        WriteByteRWX(matchedAt, match->origByte);
        ctx.Rip = matchedAt;
        ctx.EFlags |= 0x100;     // TF
        EnterCriticalSection(&st->lock);
        st->stepRearm[tid] = match;
        LeaveCriticalSection(&st->lock);

        uint64_t frm = 0;
        __try { frm = *reinterpret_cast<uint64_t*>(ctx.Rsp); }
        __except (EXCEPTION_EXECUTE_HANDLER) { frm = 0; }
        dispatchCallback(match, frm);
        ret = DBG_CONTINUE;
        goto done;
    }

    if (code == EXCEPTION_GUARD_PAGE) {
        uint64_t faultAddr = (uint64_t)edi.ExceptionRecord.ExceptionInformation[1];
        EnterCriticalSection(&st->lock);
        Bp* match = nullptr;
        for (auto& kv : st->bps) {
            Bp* bp = kv.second;
            if (!bp->enabled || !bp->isSoft || bp->isExec) continue;
            if (faultAddr >= bp->address && faultAddr < bp->address + bp->size) { match = bp; break; }
            for (auto& pp : bp->guardedPages) if (faultAddr >= pp.first && faultAddr < pp.first + 0x1000) { match = bp; break; }
            if (match) break;
        }
        LeaveCriticalSection(&st->lock);
        if (!match) goto done;

        ctx.EFlags |= 0x100;     // TF
        EnterCriticalSection(&st->lock);
        st->stepRearm[tid] = match;
        LeaveCriticalSection(&st->lock);

        dispatchCallback(match, ctx.Rip);
        ret = DBG_CONTINUE;
        goto done;
    }

  done:
    if (ret == DBG_CONTINUE) {
        ctx.ContextFlags = CONTEXT_ALL;
        if (!SetThreadContext(th, &ctx)) {
            DbgFmtW(L"SetThreadContext(%lu) failed (%lu)", tid, GetLastError());
        }
    }
    CloseHandle(th);
    return ret;
}

// CREATE_THREAD_DEBUG_EVENT: auto-apply HARD BPs whose targetTids was None
// (we approximate this by re-attaching every HARD BP that already has at
// least one slot — i.e. it was installed with tids=None or with an explicit
// list that didn't include the new tid; the latter is intentional skip).
//
// Implementation: walk the BP table, and for each HARD BP that doesn't yet
// have a slot for this TID, attach if the BP was "process-wide" at install
// (stored implicitly: install snapshotted all live TIDs, so if at install
// time slots covered every then-live TID, treat it as process-wide).
//
// Simpler heuristic for v1: attach EVERY HARD BP to the new thread.
static void HandleNewThread(DbgState* st, DWORD newTid)
{
    EnterCriticalSection(&st->lock);
    std::vector<DWORD> oneTid = { newTid };
    for (auto& kv : st->bps) {
        Bp* bp = kv.second;
        if (!bp->isHard) continue;
        ApplyBpToTids(st, bp, oneTid);
    }
    LeaveCriticalSection(&st->lock);
    DbgFmtW(L"new thread %lu - auto-attached HARD BPs", newTid);
}

static void HandleThreadExit(DbgState* st, DWORD deadTid)
{
    EnterCriticalSection(&st->lock);
    std::vector<DWORD> oneTid = { deadTid };
    for (auto& kv : st->bps) {
        Bp* bp = kv.second;
        DetachBpFromTids(st, bp, oneTid);
    }
    st->threadSlotMasks.erase(deadTid);
    st->stepRearm.erase(deadTid);
    LeaveCriticalSection(&st->lock);
}

static DWORD WINAPI DebuggerWorker(LPVOID lp)
{
    DbgState* st = (DbgState*)lp;
    st->workerTid = GetCurrentThreadId();

    // Make ourselves a debugger of the current process.
    if (!DebugActiveProcess(GetCurrentProcessId())) {
        DbgFmtW(L"DebugActiveProcess(self) failed (%lu)", GetLastError());
        st->started_ok = false;
        SetEvent(st->startedEvent);
        return 1;
    }
    DebugSetProcessKillOnExit(FALSE);
    st->started_ok = true;
    SetEvent(st->startedEvent);
    DbgW(L"DebuggerWorker: attached as in-process debugger");

    DEBUG_EVENT ev;
    while (!st->shutdown) {
        // Use a short timeout so we notice shutdown promptly.
        if (!WaitForDebugEvent(&ev, 100)) {
            DWORD ge = GetLastError();
            if (ge == ERROR_SEM_TIMEOUT) continue;
            DbgFmtW(L"WaitForDebugEvent error %lu - exiting", ge);
            break;
        }
        DWORD continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        switch (ev.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT:
                continueStatus = HandleException(st, ev);
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                HandleNewThread(st, ev.dwThreadId);
                continueStatus = DBG_CONTINUE;
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                HandleThreadExit(st, ev.dwThreadId);
                continueStatus = DBG_CONTINUE;
                break;
            case CREATE_PROCESS_DEBUG_EVENT:
                if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
                continueStatus = DBG_CONTINUE;
                break;
            case LOAD_DLL_DEBUG_EVENT:
                if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
                continueStatus = DBG_CONTINUE;
                break;
            default:
                continueStatus = DBG_CONTINUE;
                break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);
    }

    DebugActiveProcessStop(GetCurrentProcessId());
    DbgW(L"DebuggerWorker: detached");
    return 0;
}

// ---------- exports ----------

extern "C" __declspec(dllexport) uintptr_t BpBackendInit(uint32_t version)
{
    if (version != BP_BACKEND_VERSION) return 0;
    EnsureSingletonLock();
    EnterCriticalSection(&g_singletonLock);
    if (g_singleton) {
        DbgState* existing = g_singleton;
        LeaveCriticalSection(&g_singletonLock);
        return reinterpret_cast<uintptr_t>(existing);
    }
    DbgState* st = new DbgState();
    st->version = version;
    InitializeCriticalSection(&st->lock);
    st->shutdown = false;
    st->started_ok = false;
    st->nextHandle = 1;
    st->startedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    st->stopEvent    = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    st->worker = CreateThread(nullptr, 0, DebuggerWorker, st, 0, &st->workerTid);
    if (!st->worker) {
        DbgFmtW(L"CreateThread(worker) failed (%lu)", GetLastError());
        CloseHandle(st->startedEvent); CloseHandle(st->stopEvent);
        DeleteCriticalSection(&st->lock);
        delete st;
        LeaveCriticalSection(&g_singletonLock);
        return 0;
    }
    // wait up to 3s for worker to call DebugActiveProcess
    WaitForSingleObject(st->startedEvent, 3000);
    if (!st->started_ok) {
        DbgW(L"DebuggerWorker did not start cleanly");
        st->shutdown = true;
        WaitForSingleObject(st->worker, 2000);
        CloseHandle(st->worker);
        CloseHandle(st->startedEvent); CloseHandle(st->stopEvent);
        DeleteCriticalSection(&st->lock);
        delete st;
        LeaveCriticalSection(&g_singletonLock);
        return 0;
    }
    g_singleton = st;
    LeaveCriticalSection(&g_singletonLock);
    DbgFmtW(L"BpBackendInit(dbg): ok handle=%p", (void*)st);
    return reinterpret_cast<uintptr_t>(st);
}

extern "C" __declspec(dllexport) uint32_t BpBackendShutdown(uintptr_t handle)
{
    EnsureSingletonLock();
    EnterCriticalSection(&g_singletonLock);
    DbgState* st = reinterpret_cast<DbgState*>(handle);
    if (!st || st != g_singleton) { LeaveCriticalSection(&g_singletonLock); return 1; }
    st->shutdown = true;
    // Worker thread polls st->shutdown with a 100ms WaitForDebugEvent timeout.
    if (st->worker) {
        WaitForSingleObject(st->worker, 5000);
        CloseHandle(st->worker);
        st->worker = nullptr;
    }
    if (st->startedEvent) { CloseHandle(st->startedEvent); st->startedEvent = nullptr; }
    if (st->stopEvent)    { CloseHandle(st->stopEvent);    st->stopEvent = nullptr; }
    for (auto& kv : st->bps) delete kv.second;
    st->bps.clear();
    DeleteCriticalSection(&st->lock);
    g_singleton = nullptr;
    delete st;
    LeaveCriticalSection(&g_singletonLock);
    return 0;
}

extern "C" __declspec(dllexport) uintptr_t BpInstall(
    uintptr_t backend, uint64_t address, uint32_t size, uint32_t flags,
    void* callback, void* user_data, uint32_t* tids, uint32_t tid_count)
{
    g_lastBpError = BPERR_OK;
    DbgState* st = reinterpret_cast<DbgState*>(backend);
    if (!st || st->shutdown) { g_lastBpError = BPERR_BAD_FLAGS; return 0; }

    bool wantExec  = (flags & BPF_EXEC) != 0;
    bool wantWrite = (flags & BPF_WRITE) != 0;
    bool wantRead  = (flags & BPF_READ) != 0;
    bool wantSoft  = (flags & BPF_SOFT) != 0;

    if (wantExec && size != 1) { g_lastBpError = BPERR_BAD_FLAGS; return 0; }
    if (!wantExec && !wantWrite && !wantRead) { g_lastBpError = BPERR_BAD_FLAGS; return 0; }

    if (wantSoft) {
        EnterCriticalSection(&st->lock);
        Bp* bp = new Bp();
        bp->handle   = st->nextHandle++;
        bp->address  = address; bp->size = size; bp->flags = flags;
        bp->callback = callback; bp->userData = user_data;
        bp->enabled  = true; bp->isHard = false; bp->isExec = wantExec; bp->isSoft = true;
        if (wantExec) {
            uint8_t orig = 0;
            if (!ReadByteAny(address, &orig)) { delete bp; LeaveCriticalSection(&st->lock); g_lastBpError = BPERR_APPLY_FAILED; return 0; }
            bp->origByte = orig;
            if (!WriteByteRWX(address, 0xCC)) { delete bp; LeaveCriticalSection(&st->lock); g_lastBpError = BPERR_APPLY_FAILED; return 0; }
        } else {
            if (!ApplyPageGuard(address, size, bp->guardedPages)) {
                RemovePageGuard(bp->guardedPages); delete bp;
                LeaveCriticalSection(&st->lock); g_lastBpError = BPERR_APPLY_FAILED; return 0;
            }
        }
        uintptr_t h = bp->handle;
        st->bps[h] = bp;
        LeaveCriticalSection(&st->lock);
        return h;
    }

    std::vector<DWORD> targetTids;
    if (tids && tid_count) targetTids.assign(tids, tids + tid_count);
    else                   targetTids = SnapshotThreads(GetCurrentProcessId());
    // Exclude the debugger worker thread - it must not be a debuggee target.
    targetTids.erase(std::remove(targetTids.begin(), targetTids.end(), st->workerTid),
                     targetTids.end());
    if (targetTids.empty()) { g_lastBpError = BPERR_APPLY_FAILED; return 0; }

    std::vector<std::pair<uint64_t, uint32_t>> chunks;
    if (!wantExec) {
        if (!ChunkRegion(address, size, chunks)) { g_lastBpError = BPERR_CHUNK_OVERFLOW; return 0; }
    }

    EnterCriticalSection(&st->lock);
    Bp* bp = new Bp();
    bp->handle   = st->nextHandle++;
    bp->address  = address; bp->size = size; bp->flags = flags;
    bp->callback = callback; bp->userData = user_data;
    bp->enabled  = true; bp->isHard = true; bp->isExec = wantExec; bp->isSoft = false;
    if (!wantExec) for (auto& c : chunks) bp->chunks.push_back({c.first, c.second});
    if (!ApplyBpToTids(st, bp, targetTids)) {
        delete bp; LeaveCriticalSection(&st->lock); return 0;
    }
    uintptr_t h = bp->handle;
    st->bps[h] = bp;
    LeaveCriticalSection(&st->lock);
    return h;
}

extern "C" __declspec(dllexport) uint32_t BpUninstall(uintptr_t backend, uintptr_t handle)
{
    DbgState* st = reinterpret_cast<DbgState*>(backend);
    if (!st) return 1;
    EnterCriticalSection(&st->lock);
    auto it = st->bps.find(handle);
    if (it == st->bps.end()) { LeaveCriticalSection(&st->lock); return 2; }
    Bp* bp = it->second;
    if (bp->isHard) {
        for (auto& s : bp->slots) {
            if (bp->isExec) ApplyHwExecSlot(s.tid, s.slotIndex, 0, false);
            else            ApplyHwDataSlot(s.tid, s.slotIndex, 0, 1, false, false);
            FreeSlot(st, s.tid, s.slotIndex);
        }
    } else if (bp->isSoft) {
        if (bp->isExec) WriteByteRWX(bp->address, bp->origByte);
        else            RemovePageGuard(bp->guardedPages);
    }
    st->bps.erase(it);
    delete bp;
    LeaveCriticalSection(&st->lock);
    return 0;
}

extern "C" __declspec(dllexport) uint32_t BpEnable(uintptr_t backend, uintptr_t handle, uint32_t enabled)
{
    DbgState* st = reinterpret_cast<DbgState*>(backend);
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
            for (auto& s : bp->slots) ApplyHwExecSlot(s.tid, s.slotIndex, bp->address, bp->enabled);
        } else {
            size_t n = bp->chunks.size();
            for (size_t i = 0; i < bp->slots.size(); ++i) {
                auto& s = bp->slots[i];
                auto& c = bp->chunks[i % n];
                ApplyHwDataSlot(s.tid, s.slotIndex, bp->enabled ? c.address : 0, c.length, isWriteOnly, bp->enabled);
            }
        }
    }
    LeaveCriticalSection(&st->lock);
    return 0;
}

extern "C" __declspec(dllexport) uint32_t BpSlotsFree(uintptr_t backend, uint32_t tid)
{
    DbgState* st = reinterpret_cast<DbgState*>(backend);
    if (!st) return 4;
    EnterCriticalSection(&st->lock);
    uint32_t free_count = 4;
    if (tid != 0xFFFFFFFF) {
        auto it = st->threadSlotMasks.find(tid);
        if (it != st->threadSlotMasks.end()) {
            uint8_t m = it->second;
            free_count = 0;
            for (int i = 0; i < 4; ++i) if ((m & (1u << i)) == 0) free_count++;
        }
    } else {
        for (auto& kv : st->threadSlotMasks) {
            uint8_t m = kv.second;
            uint32_t fr = 0;
            for (int i = 0; i < 4; ++i) if ((m & (1u << i)) == 0) fr++;
            if (fr < free_count) free_count = fr;
        }
    }
    LeaveCriticalSection(&st->lock);
    return free_count;
}

extern "C" __declspec(dllexport) uint32_t BpLastError() { return g_lastBpError; }

extern "C" __declspec(dllexport) uint32_t BpAttachTids(
    uintptr_t backend, uintptr_t handle, uint32_t* tids, uint32_t n)
{
    g_lastBpError = BPERR_OK;
    DbgState* st = reinterpret_cast<DbgState*>(backend);
    if (!st || st->shutdown) { g_lastBpError = BPERR_BAD_FLAGS; return 1; }
    if (!tids || n == 0) return 0;
    EnterCriticalSection(&st->lock);
    auto it = st->bps.find(handle);
    if (it == st->bps.end()) { LeaveCriticalSection(&st->lock); return 2; }
    Bp* bp = it->second;
    if (!bp->isHard) { LeaveCriticalSection(&st->lock); g_lastBpError = BPERR_BAD_FLAGS; return 3; }
    std::vector<DWORD> ts(tids, tids + n);
    ts.erase(std::remove(ts.begin(), ts.end(), st->workerTid), ts.end());
    bool ok = ApplyBpToTids(st, bp, ts);
    LeaveCriticalSection(&st->lock);
    return ok ? 0 : 4;
}

extern "C" __declspec(dllexport) uint32_t BpDetachTids(
    uintptr_t backend, uintptr_t handle, uint32_t* tids, uint32_t n)
{
    DbgState* st = reinterpret_cast<DbgState*>(backend);
    if (!st || st->shutdown) return 1;
    if (!tids || n == 0) return 0;
    EnterCriticalSection(&st->lock);
    auto it = st->bps.find(handle);
    if (it == st->bps.end()) { LeaveCriticalSection(&st->lock); return 2; }
    Bp* bp = it->second;
    if (!bp->isHard) { LeaveCriticalSection(&st->lock); return 3; }
    std::vector<DWORD> ts(tids, tids + n);
    DetachBpFromTids(st, bp, ts);
    LeaveCriticalSection(&st->lock);
    return 0;
}

extern "C" __declspec(dllexport) uint32_t BpListTids(
    uintptr_t backend, uintptr_t handle, uint32_t* out, uint32_t cap)
{
    DbgState* st = reinterpret_cast<DbgState*>(backend);
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
    uint32_t to = (n < cap) ? n : cap;
    for (uint32_t i = 0; i < to; ++i) out[i] = uniq[i];
    LeaveCriticalSection(&st->lock);
    return n;
}

extern "C" __declspec(dllexport) uint32_t BpSnapshotTids(
    uintptr_t backend, uint32_t* out, uint32_t cap)
{
    DbgState* st = reinterpret_cast<DbgState*>(backend);
    auto tids = SnapshotThreads(GetCurrentProcessId());
    // Exclude the debugger thread from the snapshot if we can identify it.
    if (st) {
        tids.erase(std::remove(tids.begin(), tids.end(), st->workerTid), tids.end());
    }
    uint32_t n = (uint32_t)tids.size();
    uint32_t to = (n < cap) ? n : cap;
    for (uint32_t i = 0; i < to; ++i) out[i] = tids[i];
    return n;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_DETACH && g_singleton != nullptr) {
        BpBackendShutdown(reinterpret_cast<uintptr_t>(g_singleton));
    }
    return TRUE;
}
