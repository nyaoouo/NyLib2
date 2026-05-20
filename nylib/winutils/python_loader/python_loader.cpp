// nylib python_loader
// ---------------------
// In-process Python interpreter loader for a remote Win32 process.
//
// Capabilities:
//   * Initialises CPython via the PyConfig API so it works in PyInstaller
//     bundles (caller passes home + module search paths explicitly).
//   * Allows multiple LoadPython calls in the same target process; the
//     interpreter is kept alive between calls and reused (script runs
//     under PyGILState_Ensure / Release).
//   * Accepts either an on-disk script path (pyMain) or a pre-loaded UTF-8
//     source buffer (pyCode), so the caller can ship a self-extracting
//     packed payload without writing to the target's filesystem.
//   * Redirects sys.stdout/sys.stderr to CONOUT$ from inside Python (so
//     the redirect actually targets python.dll's CRT) when createConsole
//     is requested.
//   * Logs each phase via OutputDebugStringW. DebugView (sysinternals)
//     shows the trace even if the console is broken.
//
// ABI:
//   The struct laid out below is what nylib/winutils/python_loader/__init__.py
//   writes into the target process. Fields are appended; never reordered.

#include <stddef.h>
#include <stdint.h>
#include <stdexcept>
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <io.h>
#include <fcntl.h>
#include <cstdio>

// PyConfig / PyStatus / PyPreConfig minimal forward declarations.
// We do NOT include <Python.h>: the loader is built without the CPython
// headers so it can be compiled standalone and against any 3.x ABI. We
// resolve symbols dynamically and rely on the documented binary layout
// of PyConfig / PyStatus for Python 3.8+.

extern "C" {

typedef struct {
    int _type;
    const char *func;
    const char *err_msg;
    int exitcode;
} PyStatus;

// PyConfig is a private CPython structure whose layout drifts between
// 3.11..3.14. We never read or write fields directly - the binding only
// passes the address to PyConfig_InitPythonConfig / Py_InitializeFromConfig
// / PyConfig_Clear. All we need is a buffer large enough to hold any
// reasonable PyConfig (currently <1 KiB on x64) and aligned for pointer
// fields. We allocate 8 KiB to leave generous slack for future CPython
// growth.
struct alignas(16) PyConfigBlob {
    char _opaque[8192];
};

}  // extern "C"

// ---------- diagnostic helpers ----------

// File logging: enabled when env var NYLIB_PYLOADER_LOG points at a path.
// Useful when DebugView isn't available; tail -f on the path to follow the
// loader's progress from the host.
static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static bool   g_logFileTried = false;

static HANDLE LogFileHandle()
{
    if (g_logFileTried) return g_logFile;
    g_logFileTried = true;
    wchar_t path[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableW(L"NYLIB_PYLOADER_LOG", path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return INVALID_HANDLE_VALUE;
    g_logFile = CreateFileW(path,
                            FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr,
                            OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    return g_logFile;
}

static void DbgW(const wchar_t* msg)
{
    OutputDebugStringW(L"[nylib.python_loader] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");

    HANDLE h = LogFileHandle();
    if (h != INVALID_HANDLE_VALUE) {
        // Append "pid=N tid=N msg\r\n" as UTF-8.
        char header[64];
        int hn = _snprintf_s(header, sizeof(header), _TRUNCATE,
                             "[pid=%lu tid=%lu] ",
                             GetCurrentProcessId(), GetCurrentThreadId());
        DWORD written;
        if (hn > 0) WriteFile(h, header, (DWORD)hn, &written, nullptr);
        int wlen = WideCharToMultiByte(CP_UTF8, 0, msg, -1, nullptr, 0, nullptr, nullptr);
        if (wlen > 1) {
            std::string utf8(static_cast<size_t>(wlen - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, msg, -1, utf8.data(), wlen, nullptr, nullptr);
            WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
        }
        WriteFile(h, "\r\n", 2, &written, nullptr);
        FlushFileBuffers(h);
    }
}

static void DbgFmtW(const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, 1024, _TRUNCATE, fmt, ap);
    va_end(ap);
    DbgW(buf);
}

static std::string WideToUtf8(const wchar_t* w)
{
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Escape a UTF-8 string into a Python raw-string-friendly literal.
// We emit `"...."` (a normal double-quoted string) with backslashes and
// double quotes escaped and embedded newlines escaped to \n. Suitable for
// any single-line string literal expression.
static std::string PyEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "\\x%02x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// ---------- ABI: extended PyLoaderConfig ----------
//
// version=1 is the layout below. The Python side writes this struct via
// nylib.process.write_*; field order must match exactly.

#pragma pack(push, 8)
typedef struct {
    uint32_t version;       // = 1
    uint32_t flags;         // bit0 createConsole, bit1 reuseInterpreter,
                            // bit2 pyCodeIsUtf8 (else read pyMain from disk),
                            // bit3 finalizeAfter (legacy Py_Finalize on exit)
    wchar_t* pyDll;         // path to python3XX.dll  (required)
    wchar_t* pyHome;        // PyConfig.home; may be NULL
    wchar_t* pyPaths;       // pathsep-separated extra sys.path entries; may be NULL
    wchar_t* pyMain;        // script path used as __file__; required if !pyCode
    char*    pyCode;        // UTF-8 Python source to run; may be NULL
    uint32_t pyCodeLen;     // length of pyCode in bytes; 0 = strlen
    uint32_t reserved;      // alignment
    wchar_t* logPath;       // optional path for the loader's own log file
                            // (overrides the NYLIB_PYLOADER_LOG env var)
    uint64_t reserved2;     // future use
} PyLoaderConfig;
#pragma pack(pop)

#define PLF_CREATE_CONSOLE     0x00000001u
#define PLF_REUSE_INTERPRETER  0x00000002u
#define PLF_HAS_CODE           0x00000004u
#define PLF_FINALIZE_AFTER     0x00000008u
#define PLF_SKIP_INIT_DEBUG    0x00000010u  // return without touching Python (debug)

// ---------- resolved Python C API symbols ----------

struct PyApi {
    HMODULE      hPython = nullptr;
    std::wstring pyDllPath;

    // Init
    PyStatus  (*PyConfig_InitPythonConfig)(PyConfigBlob*) = nullptr;
    PyStatus  (*PyConfig_InitIsolatedConfig)(PyConfigBlob*) = nullptr;
    void      (*PyConfig_Clear)(PyConfigBlob*) = nullptr;
    PyStatus  (*PyConfig_SetString)(PyConfigBlob*, wchar_t** target, const wchar_t* value) = nullptr;
    PyStatus  (*PyConfig_SetBytesString)(PyConfigBlob*, wchar_t** target, const char* value) = nullptr;
    PyStatus  (*PyConfig_Read)(PyConfigBlob*) = nullptr;
    PyStatus  (*Py_InitializeFromConfig)(const PyConfigBlob*) = nullptr;
    void      (*Py_Initialize)() = nullptr;
    int       (*Py_IsInitialized)() = nullptr;
    void      (*Py_Finalize)() = nullptr;
    int       (*PyStatus_Exception)(PyStatus) = nullptr;
    int       (*PyStatus_IsError)(PyStatus) = nullptr;

    // module_search_paths handling (PyConfig has a list field; we use the
    // simpler approach of running Python code post-init to extend sys.path).

    // Eval
    int       (*PyRun_SimpleString)(const char*) = nullptr;
    int       (*PyRun_SimpleStringFlags)(const char*, void*) = nullptr;

    // GIL
    int       (*PyGILState_Ensure)() = nullptr;
    void      (*PyGILState_Release)(int) = nullptr;
    void*     (*PyEval_SaveThread)() = nullptr;
    void      (*PyEval_RestoreThread)(void*) = nullptr;

    void Reset() { *this = PyApi(); }
};

static PyApi g_api;
static bool  g_initialized = false;
static CRITICAL_SECTION g_lock;
static bool  g_lockInit = false;

static void EnsureLock()
{
    if (!g_lockInit) {
        InitializeCriticalSection(&g_lock);
        g_lockInit = true;
    }
}

struct ScopedLock {
    ScopedLock()  { EnsureLock(); EnterCriticalSection(&g_lock); }
    ~ScopedLock() { LeaveCriticalSection(&g_lock); }
};

template <typename FnPtr>
static bool BindOptional(HMODULE m, const char* name, FnPtr& out)
{
    out = reinterpret_cast<FnPtr>(GetProcAddress(m, name));
    return out != nullptr;
}

template <typename FnPtr>
static bool BindRequired(HMODULE m, const char* name, FnPtr& out, std::string& err)
{
    if (BindOptional(m, name, out)) return true;
    err = std::string("missing symbol: ") + name;
    return false;
}

static bool LoadPythonModule(const wchar_t* pyDll, std::string& err)
{
    if (g_api.hPython != nullptr && g_api.pyDllPath == pyDll) return true;

    HMODULE m = LoadLibraryW(pyDll);
    if (m == nullptr) {
        DWORD ge = GetLastError();
        DbgFmtW(L"LoadLibraryW(%s) failed: %lu", pyDll, ge);
        err = "LoadLibraryW failed for python dll (GetLastError above)";
        return false;
    }
    DbgFmtW(L"Loaded python dll: %s  base=%p", pyDll, (void*)m);

    PyApi api;
    api.hPython   = m;
    api.pyDllPath = pyDll;

    // Init / shutdown. PyConfig_* are bound optionally because we don't
    // call them in the current code path (see InitializeInterpreter's note
    // on why Py_InitializeFromConfig is avoided), but keeping the binds
    // makes it trivial to switch back if a future CPython fixes the
    // injection regression.
    BindOptional(m, "PyConfig_InitPythonConfig", api.PyConfig_InitPythonConfig);
    BindOptional(m, "PyConfig_InitIsolatedConfig", api.PyConfig_InitIsolatedConfig);
    BindOptional(m, "PyConfig_Clear",            api.PyConfig_Clear);
    BindOptional(m, "PyConfig_SetString",        api.PyConfig_SetString);
    BindOptional(m, "PyConfig_SetBytesString",   api.PyConfig_SetBytesString);
    BindOptional(m, "PyConfig_Read",             api.PyConfig_Read);
    BindOptional(m, "Py_InitializeFromConfig",   api.Py_InitializeFromConfig);
    BindOptional(m, "PyStatus_Exception",        api.PyStatus_Exception);
    BindOptional(m, "PyStatus_IsError",          api.PyStatus_IsError);

    if (!BindRequired(m, "Py_Initialize",          api.Py_Initialize, err)) return false;
    if (!BindRequired(m, "Py_IsInitialized",       api.Py_IsInitialized, err)) return false;
    if (!BindRequired(m, "Py_Finalize",            api.Py_Finalize, err)) return false;

    if (!BindRequired(m, "PyRun_SimpleString",     api.PyRun_SimpleString, err)) return false;
    BindOptional(m, "PyRun_SimpleStringFlags",     api.PyRun_SimpleStringFlags);

    if (!BindRequired(m, "PyGILState_Ensure",      api.PyGILState_Ensure, err)) return false;
    if (!BindRequired(m, "PyGILState_Release",     api.PyGILState_Release, err)) return false;
    if (!BindRequired(m, "PyEval_SaveThread",      api.PyEval_SaveThread, err)) return false;
    if (!BindRequired(m, "PyEval_RestoreThread",   api.PyEval_RestoreThread, err)) return false;

    g_api = api;
    DbgW(L"Python API symbols bound");
    return true;
}

// ---------- script source loading ----------

static bool ReadFileUtf8(const wchar_t* path, std::string& out, std::string& err)
{
    // _wfopen so non-ASCII paths work.
    FILE* fp = nullptr;
    errno_t e = _wfopen_s(&fp, path, L"rb");
    if (e != 0 || fp == nullptr) {
        err = "failed to open script file";
        return false;
    }
    std::ostringstream ss;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        ss.write(buf, static_cast<std::streamsize>(n));
    }
    fclose(fp);
    out = ss.str();
    // Strip a UTF-8 BOM if present so PyRun_SimpleString doesn't see it as
    // an identifier.
    if (out.size() >= 3 &&
        (unsigned char)out[0] == 0xEF &&
        (unsigned char)out[1] == 0xBB &&
        (unsigned char)out[2] == 0xBF) {
        out.erase(0, 3);
    }
    return true;
}

// ---------- console redirect ----------

static void AttachConsole_NoCRTRedirect()
{
    // Allocating the console is enough to make CONOUT$ openable from inside
    // python.dll. We deliberately do NOT freopen on the loader's CRT - that
    // would only redirect *our* stdio, not python.dll's.
    if (GetConsoleWindow() == nullptr) {
        if (!AllocConsole()) {
            DWORD ge = GetLastError();
            DbgFmtW(L"AllocConsole failed: %lu", ge);
        } else {
            DbgW(L"AllocConsole ok");
        }
    } else {
        DbgW(L"AllocConsole skipped: console already attached");
    }
}

// ---------- init code generator ----------

// Build the bootstrap Python source that runs immediately after
// Py_InitializeFromConfig. Responsible for:
//   * Setting __main__.__file__ to pyMain.
//   * Redirecting sys.stdout / sys.stderr to CONOUT$ when a console was
//     allocated.
//   * Extending sys.path with pyPaths entries and dirname(__file__).
//   * Installing a faulthandler so segfaults surface in the debug console.
static std::string BuildInitCode(const PyLoaderConfig* cfg)
{
    std::string esc_file  = PyEscape(WideToUtf8(cfg->pyMain ? cfg->pyMain : L""));
    std::string esc_paths = PyEscape(WideToUtf8(cfg->pyPaths ? cfg->pyPaths : L""));

    std::ostringstream os;
    os <<
        "import sys, os, os.path\n"
        "try:\n"
        "    import faulthandler; faulthandler.enable()\n"
        "except Exception:\n"
        "    pass\n";

    if (cfg->flags & PLF_CREATE_CONSOLE) {
        os <<
        "try:\n"
        "    import io\n"
        "    _conout = io.open('CONOUT$', 'wt', encoding='utf-8', buffering=1)\n"
        "    sys.stdout = sys.stderr = _conout\n"
        "    try:\n"
        "        sys.stdin = io.open('CONIN$', 'rt', encoding='utf-8')\n"
        "    except Exception:\n"
        "        pass\n"
        "except Exception as _e:\n"
        "    import ctypes; ctypes.windll.kernel32.OutputDebugStringW("
        "    'nylib.python_loader: console redirect failed: ' + repr(_e))\n";
    }

    os <<
        "def _ny_parse_path(paths):\n"
        "    if not paths: return\n"
        "    if isinstance(paths, str):\n"
        "        paths = paths.split(os.pathsep)\n"
        "    for p in paths:\n"
        "        if p and p not in sys.path:\n"
        "            sys.path.append(p)\n"
        "_ny_parse_path(\"" << esc_paths << "\")\n"
        "_ny_main_file = \"" << esc_file << "\"\n"
        "if _ny_main_file:\n"
        "    _ny_parse_path(os.path.dirname(_ny_main_file))\n"
        "    try:\n"
        "        import __main__\n"
        "        __main__.__file__ = _ny_main_file\n"
        "    except Exception:\n"
        "        pass\n";

    return os.str();
}

// SEH wrappers around CPython init calls. Must live in functions with no
// C++ objects requiring unwind (MSVC error C2712 otherwise). Return 0 on
// success or the SEH exception code on failure.
static DWORD SehWrappedInit(PyConfigBlob* blob, PyStatus* out)
{
    __try {
        *out = g_api.Py_InitializeFromConfig(blob);
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static DWORD SehWrappedSimpleInit()
{
    __try {
        g_api.Py_Initialize();
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

// ---------- initialization ----------

static bool InitializeInterpreter(const PyLoaderConfig* cfg, std::string& err)
{
    if (g_initialized && g_api.Py_IsInitialized && g_api.Py_IsInitialized()) {
        DbgW(L"InitializeInterpreter: already initialized; skipping");
        return true;
    }

    if (!LoadPythonModule(cfg->pyDll, err)) return false;

    // Best-effort PyConfig fields. We can't write the entire PyConfig
    // safely from outside CPython headers, but PyConfig_SetString /
    // PyConfig_SetBytesString cover the fields we care about by *target
    // pointer*, which is positional within PyConfig. To avoid binding
    // against a CPython-version-specific PyConfig layout, we instead set
    // these things from Python after init via _ny_init code.
    //
    // The one knob we DO want at the PyConfig level is `home`, because it
    // changes how Python locates its stdlib. CPython exposes it as the
    // first wchar_t* in PyConfig after the various ints. The cleanest
    // cross-version approach is to use the documented helpers via
    // env-vars instead.
    // Setting PYTHONHOME/PYTHONPATH lets the in-process CPython find its
    // stdlib without relying on argv[0]/registry heuristics. The pyPaths
    // entries get added to sys.path after init too (see BuildInitCode) for
    // belt-and-braces semantics.
    //
    // NOTE: passing an *empty* PYTHONHOME would make Py_InitializeFromConfig
    // hit a NULL deref in 3.13+, so we only set the var when non-empty.
    if (cfg->pyHome && *cfg->pyHome) {
        SetEnvironmentVariableW(L"PYTHONHOME", cfg->pyHome);
        DbgFmtW(L"PYTHONHOME set to %s", cfg->pyHome);
    }
    if (cfg->pyPaths && *cfg->pyPaths) {
        SetEnvironmentVariableW(L"PYTHONPATH", cfg->pyPaths);
        DbgFmtW(L"PYTHONPATH set to %s", cfg->pyPaths);
    }
    // Avoid Python writing user site config files into someone else's process.
    SetEnvironmentVariableW(L"PYTHONNOUSERSITE", L"1");
    SetEnvironmentVariableW(L"PYTHONUTF8", L"1");
    // Don't let Python install its signal handlers - they're meant for a
    // host that owns Ctrl-C, not an injected guest.
    SetEnvironmentVariableW(L"PYTHONDONTWRITEBYTECODE", L"1");

    // Use bare Py_Initialize rather than Py_InitializeFromConfig.
    //
    // Py_InitializeFromConfig segfaults (STATUS_ACCESS_VIOLATION) when
    // called from a remote-thread context against a python.dll that was
    // LoadLibrary'd into a foreign process. We confirmed it:
    //   * happens with PyConfig_InitPythonConfig AND PyConfig_InitIsolatedConfig;
    //   * happens whether we run on the inbound remote thread or on a
    //     freshly-spawned worker thread (so it's not just a TLS slot issue);
    //   * does NOT happen in a standalone exe that LoadLibrary's the same
    //     python.dll and calls Py_InitializeFromConfig from main().
    //
    // The bare Py_Initialize() takes a different internal path (no parse_argv,
    // no signal handlers install, simpler PathConfig discovery) and reliably
    // returns. PYTHONHOME and PYTHONPATH env vars (set above) still drive
    // stdlib discovery the way callers expect.
    DbgW(L"Calling Py_Initialize");
    DWORD seh_code = SehWrappedSimpleInit();
    if (seh_code != 0) {
        DbgFmtW(L"Py_Initialize raised SEH exception 0x%08lx", seh_code);
        err = "Py_Initialize raised SEH";
        return false;
    }
    DbgW(L"Py_Initialize returned");

    DbgW(L"Checking Py_IsInitialized");
    if (!g_api.Py_IsInitialized()) {
        DbgW(L"Py_IsInitialized returned 0 after init");
        err = "Py_IsInitialized returned 0";
        return false;
    }
    DbgW(L"Py_IsInitialized returned 1");

    // RunUserScript handles per-call bootstrap + script execution under
    // PyGILState_Ensure, so InitializeInterpreter does NOT run the
    // bootstrap itself - it just leaves the interpreter alive with the
    // GIL released, ready for any thread to acquire it.

    // Release the GIL now so subsequent calls on a *different* worker
    // thread can PyGILState_Ensure cleanly. If we left the GIL held by
    // the dying worker, the next call would deadlock waiting for it.
    DbgW(L"Saving thread state to release GIL");
    void* save = g_api.PyEval_SaveThread();
    (void)save;  // we never re-restore explicitly; PyGILState_Ensure takes care of it

    g_initialized = true;
    return true;
}

// ---------- single-shot run on an already-initialised interpreter ----------

static bool RunUserScript(const PyLoaderConfig* cfg, std::string& err)
{
    if (!g_initialized) {
        err = "interpreter not initialized";
        return false;
    }

    std::string source;
    if ((cfg->flags & PLF_HAS_CODE) && cfg->pyCode) {
        size_t n = cfg->pyCodeLen ? cfg->pyCodeLen : strlen(cfg->pyCode);
        source.assign(cfg->pyCode, cfg->pyCode + n);
        DbgFmtW(L"RunUserScript: in-memory source, %zu bytes", source.size());
    } else if (cfg->pyMain) {
        if (!ReadFileUtf8(cfg->pyMain, source, err)) return false;
        DbgFmtW(L"RunUserScript: read %s (%zu bytes)", cfg->pyMain, source.size());
    } else {
        err = "no script source (pyCode or pyMain required)";
        return false;
    }

    // The bootstrap init code runs every call so __file__ and sys.path
    // reflect *this* invocation, not the first one.
    std::string init = BuildInitCode(cfg);

    int gilState = g_api.PyGILState_Ensure();
    int rc1 = g_api.PyRun_SimpleString(init.c_str());
    int rc2 = g_api.PyRun_SimpleString(source.c_str());
    g_api.PyGILState_Release(gilState);

    if (rc1 != 0) DbgFmtW(L"per-call init code rc=%d", rc1);
    if (rc2 != 0) {
        DbgFmtW(L"user script rc=%d", rc2);
        err = "user script raised an unhandled exception";
        return false;
    }
    return true;
}

// ---------- worker thread plumbing ----------
//
// Python uses thread-local storage (PEP 3121 + __declspec(thread)). When
// python.dll is LoadLibrary'd post-startup, only threads created AFTER
// the load get TLS slots allocated for the DLL. The remote thread that
// CreateRemoteThread spawned to run LoadPython already exists by then,
// so calling Py_InitializeFromConfig on it segfaults inside the TLS
// access path (we observed STATUS_ACCESS_VIOLATION 0xc0000005).
//
// The fix: load python.dll first on the remote thread (cheap, no TLS
// touch), then spawn a worker thread that runs everything Python-related.
// That worker is born *after* python.dll exists and gets a real TLS slot.

struct WorkerArgs {
    const PyLoaderConfig* cfg;
    uint32_t              rc;     // out
};

static DWORD WINAPI WorkerEntry(LPVOID raw)
{
    WorkerArgs* args = static_cast<WorkerArgs*>(raw);
    const PyLoaderConfig* cfg = args->cfg;
    std::string err;

    if (!InitializeInterpreter(cfg, err)) {
        DbgFmtW(L"Worker: InitializeInterpreter failed: %S", err.c_str());
        args->rc = 0xE0000002u;
        return 0;
    }
    if (!RunUserScript(cfg, err)) {
        DbgFmtW(L"Worker: RunUserScript failed: %S", err.c_str());
        args->rc = 0xE0000003u;
        return 0;
    }
    if (cfg->flags & PLF_FINALIZE_AFTER) {
        DbgW(L"Worker: PLF_FINALIZE_AFTER -> Py_Finalize");
        g_api.Py_Finalize();
        g_initialized = false;
    }
    args->rc = 0;
    return 0;
}

// ---------- exported entry points ----------

extern "C" __declspec(dllexport)
uint32_t LoadPython(PyLoaderConfig* cfg)
{
    ScopedLock lk;
    if (cfg == nullptr) {
        DbgW(L"LoadPython called with NULL config");
        return 0xE0000001u;
    }
    if (cfg->logPath && *cfg->logPath) {
        SetEnvironmentVariableW(L"NYLIB_PYLOADER_LOG", cfg->logPath);
        // Force re-open of the log file on the new path.
        if (g_logFile != INVALID_HANDLE_VALUE) {
            CloseHandle(g_logFile);
            g_logFile = INVALID_HANDLE_VALUE;
        }
        g_logFileTried = false;
    }
    DbgFmtW(L"LoadPython entry: version=%u flags=0x%08x", cfg->version, cfg->flags);
    if (cfg->pyDll)   DbgFmtW(L"  pyDll  = %s", cfg->pyDll);
    if (cfg->pyHome)  DbgFmtW(L"  pyHome = %s", cfg->pyHome);
    if (cfg->pyPaths) DbgFmtW(L"  pyPaths(len=%zu)", wcslen(cfg->pyPaths));
    if (cfg->pyMain)  DbgFmtW(L"  pyMain = %s", cfg->pyMain);
    if (cfg->pyCode)  DbgFmtW(L"  pyCode(%u bytes)", (unsigned)cfg->pyCodeLen);

    if (cfg->flags & PLF_SKIP_INIT_DEBUG) {
        DbgW(L"PLF_SKIP_INIT_DEBUG: returning without initializing Python");
        return 0xC0DE0000u;
    }

    if (cfg->flags & PLF_CREATE_CONSOLE) AttachConsole_NoCRTRedirect();

    // Load python.dll on THIS thread before we spawn the Python-running
    // worker. LoadLibrary is the cheap part; it doesn't touch python's
    // __declspec(thread) slots, but it does cause Windows to allocate
    // TLS for any thread created AFTER this point. The worker we spawn
    // below is created after this, so its TLS is fully wired.
    std::string err_load;
    if (!LoadPythonModule(cfg->pyDll, err_load)) {
        DbgFmtW(L"LoadPythonModule failed on entry thread: %S", err_load.c_str());
        return 0xE0000004u;
    }

    WorkerArgs args = { cfg, 0xFFFFFFFFu };
    HANDLE h = CreateThread(nullptr, 0, WorkerEntry, &args, 0, nullptr);
    if (h == nullptr) {
        DbgFmtW(L"CreateThread for worker failed: %lu", GetLastError());
        return 0xE0000005u;
    }
    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);

    DbgFmtW(L"LoadPython done rc=0x%08x", args.rc);
    return args.rc;
}

// Convenience: run a script on an already-initialised interpreter without
// the InitializeInterpreter branch. Intended for callers that want to be
// explicit about reuse.
extern "C" __declspec(dllexport)
uint32_t RunPython(PyLoaderConfig* cfg)
{
    // Convenience wrapper - same worker-thread plumbing as LoadPython so
    // RunPython is also safe when invoked from a thread that pre-existed
    // the python.dll load.
    return LoadPython(cfg);
}

extern "C" __declspec(dllexport)
uint32_t FinalizePython()
{
    ScopedLock lk;
    if (!g_initialized) return 0;
    DbgW(L"FinalizePython: calling Py_Finalize");
    g_api.Py_Finalize();
    g_initialized = false;
    return 0;
}

extern "C" __declspec(dllexport)
uint32_t IsPythonInitialized()
{
    return g_initialized && g_api.Py_IsInitialized && g_api.Py_IsInitialized() ? 1 : 0;
}

// ---------- dllmain ----------

BOOL APIENTRY DllMain(HMODULE, DWORD reason, PVOID)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        EnsureLock();
        DbgW(L"DllMain: DLL_PROCESS_ATTACH");
        break;
    case DLL_PROCESS_DETACH:
        DbgW(L"DllMain: DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}
