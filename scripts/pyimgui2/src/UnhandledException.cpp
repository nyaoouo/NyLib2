#include "./UnhandledException.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include <Windows.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

START_G_UTILS_NAMESPACE
{
    namespace
    {
        // `g_write_dump` is the opt-in switch; `g_flags` holds the most recent
        // MINIDUMP_TYPE bitmask. We keep them separate so that `g_flags == 0`
        // (i.e. MiniDumpNormal) remains a valid configured value.
        std::atomic<bool>     g_write_dump{false};
        std::atomic<uint32_t> g_flags{0};

        std::mutex g_path_lock;
        std::string g_path = "./CrashDump.dmp";

        // Python-state dump arm; independent of the native minidump arm.
        std::atomic<bool> g_write_py_dump{false};
        std::mutex g_py_path_lock;
        std::string g_py_path = "./CrashDump.pystack.txt";

        std::atomic<bool> g_installed{false};

        void SnapshotPath(char* out, size_t out_len)
        {
            std::lock_guard<std::mutex> lock(g_path_lock);
            const std::string& src = g_path;
            size_t n = src.size();
            if (n >= out_len) n = out_len - 1;
            std::memcpy(out, src.data(), n);
            out[n] = '\0';
        }

        void SnapshotPyPath(char* out, size_t out_len)
        {
            std::lock_guard<std::mutex> lock(g_py_path_lock);
            const std::string& src = g_py_path;
            size_t n = src.size();
            if (n >= out_len) n = out_len - 1;
            std::memcpy(out, src.data(), n);
            out[n] = '\0';
        }

        // Inline Python script. Runs in a fresh dict (not __main__) so its
        // helper bindings don't pollute the user's namespace. Reads
        // `_dump_path`, `_exc_code`, `_exc_addr`, `_self_tid` from its own
        // globals (injected by the C++ caller). Stays stdlib-only.
        static const char* kPyDumpScript = R"PY(
import sys, threading, os
try:
    _f = open(_dump_path, 'w', encoding='utf-8', errors='replace')
except Exception as _e:
    sys.stderr.write('[pyimgui] failed to open py-dump %r: %r\n' % (_dump_path, _e))
else:
    with _f:
        _f.write('# pyimgui python state dump\n')
        _f.write('# pid=%d  exc=0x%08x@0x%x\n' % (os.getpid(), _exc_code & 0xFFFFFFFF, _exc_addr))
        _f.write('# crash-filter is dumping from tid=%d (its frames are this dumper, not the real fault site)\n' % _self_tid)
        try:
            _tname = {t.ident: t.name for t in threading.enumerate()}
        except Exception:
            _tname = {}
        _frames = sys._current_frames()
        _seen_modules = {}
        for _tid, _frame in sorted(_frames.items()):
            _nm = _tname.get(_tid, '<unknown>')
            _marker = '  [CRASH-FILTER THREAD]' if _tid == _self_tid else ''
            _f.write('\n=== Thread tid=%d  name=%r%s ===\n' % (_tid, _nm, _marker))
            _cur = _frame
            _depth = 0
            while _cur is not None:
                _co = _cur.f_code
                try:
                    _modname = _cur.f_globals.get('__name__', '?')
                except Exception:
                    _modname = '?'
                _f.write('  [%d] File "%s", line %d, in %s    (module %s)\n'
                         % (_depth, _co.co_filename, _cur.f_lineno, _co.co_name, _modname))
                try:
                    _items = list(_cur.f_locals.items())
                except Exception as _e:
                    _items = []
                    _f.write('        <f_locals error: %r>\n' % (_e,))
                for _k, _v in _items:
                    try:
                        _r = repr(_v)
                    except Exception as _e:
                        _r = '<repr failed: %r>' % (_e,)
                    if len(_r) > 200:
                        _r = _r[:200] + '...'
                    _f.write('        local %s = %s\n' % (_k, _r))
                try:
                    if _modname not in _seen_modules and _modname != '?':
                        _seen_modules[_modname] = sorted(_cur.f_globals.keys())
                except Exception:
                    pass
                _cur = _cur.f_back
                _depth += 1
        if _seen_modules:
            _f.write('\n# globals keys (per module seen on any stack):\n')
            for _m, _keys in sorted(_seen_modules.items()):
                _f.write('  %s: %r\n' % (_m, _keys))
        _f.write('\n# end of pyimgui python state dump\n')
)PY";

        // SEH-wrapped Python excursion. Must NOT contain C++ stack objects
        // with destructors so that `__try/__except` is legal under /EHsc.
        static void DumpPythonStateSEH(const char* path, DWORD exc_code, PVOID exc_addr) noexcept
        {
            __try
            {
                if (!Py_IsInitialized())
                    return;

                PyGILState_STATE gstate = PyGILState_Ensure();

                // Run in a fresh dict (with __builtins__) so the dump script's
                // helper variables don't leak into the user's __main__ module.
                PyObject* run_dict = PyDict_New();
                if (run_dict)
                {
                    PyObject* builtins = PyEval_GetBuiltins(); // borrowed
                    if (builtins)
                        PyDict_SetItemString(run_dict, "__builtins__", builtins);

                    PyObject* pypath = PyUnicode_FromString(path);
                    PyObject* pycode = PyLong_FromUnsignedLong((unsigned long)exc_code);
                    PyObject* pyaddr = PyLong_FromUnsignedLongLong((unsigned long long)(uintptr_t)exc_addr);
                    PyObject* pytid  = PyLong_FromUnsignedLong((unsigned long)GetCurrentThreadId());

                    if (pypath && pycode && pyaddr && pytid)
                    {
                        PyDict_SetItemString(run_dict, "_dump_path", pypath);
                        PyDict_SetItemString(run_dict, "_exc_code",  pycode);
                        PyDict_SetItemString(run_dict, "_exc_addr",  pyaddr);
                        PyDict_SetItemString(run_dict, "_self_tid", pytid);

                        PyObject* result = PyRun_String(kPyDumpScript, Py_file_input,
                                                        run_dict, run_dict);
                        if (result) Py_DECREF(result);
                        if (PyErr_Occurred())
                        {
                            PyErr_Print();
                            PyErr_Clear();
                        }
                    }

                    Py_XDECREF(pypath);
                    Py_XDECREF(pycode);
                    Py_XDECREF(pyaddr);
                    Py_XDECREF(pytid);
                    Py_DECREF(run_dict);
                }

                PyGILState_Release(gstate);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Secondary fault inside the Python dump; swallow so the native
                // minidump arm still gets to run.
            }
        }

        LONG WINAPI MyUnhandledExceptionFilter(EXCEPTION_POINTERS* pExceptionPointers)
        {
            DWORD  exc_code = (pExceptionPointers && pExceptionPointers->ExceptionRecord)
                                  ? pExceptionPointers->ExceptionRecord->ExceptionCode
                                  : 0UL;
            PVOID  exc_addr = (pExceptionPointers && pExceptionPointers->ExceptionRecord)
                                  ? pExceptionPointers->ExceptionRecord->ExceptionAddress
                                  : nullptr;

            const bool do_native = g_write_dump.load(std::memory_order_relaxed);
            const bool do_python = g_write_py_dump.load(std::memory_order_relaxed);

            std::fprintf(stderr,
                         "\n[pyimgui] unhandled exception 0x%08lx at 0x%p\n",
                         exc_code, exc_addr);
            std::fflush(stderr);

            // ---- Python state dump (runs first; the GIL excursion is the
            // riskiest step and the SEH guard inside DumpPythonStateSEH will
            // catch any secondary fault before we proceed to the minidump).
            if (do_python)
            {
                char py_path[MAX_PATH * 2];
                SnapshotPyPath(py_path, sizeof(py_path));
                std::fprintf(stderr,
                             "[pyimgui] writing python state dump to %s\n",
                             py_path);
                std::fflush(stderr);
                DumpPythonStateSEH(py_path, exc_code, exc_addr);
            }

            // ---- Native minidump.
            if (do_native)
            {
                uint32_t flags = g_flags.load(std::memory_order_relaxed);
                char path[MAX_PATH * 2];
                SnapshotPath(path, sizeof(path));

                std::fprintf(stderr,
                             "[pyimgui] writing minidump to %s\n", path);
                std::fflush(stderr);

                HANDLE hDumpFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hDumpFile != INVALID_HANDLE_VALUE)
                {
                    MINIDUMP_EXCEPTION_INFORMATION mdei;
                    mdei.ThreadId = GetCurrentThreadId();
                    mdei.ExceptionPointers = pExceptionPointers;
                    mdei.ClientPointers = FALSE;

                    BOOL ok = MiniDumpWriteDump(
                        GetCurrentProcess(),
                        GetCurrentProcessId(),
                        hDumpFile,
                        (MINIDUMP_TYPE)flags,
                        &mdei,
                        NULL,
                        NULL);

                    CloseHandle(hDumpFile);

                    if (!ok)
                    {
                        std::fprintf(stderr,
                                     "[pyimgui] MiniDumpWriteDump failed: 0x%08lx\n",
                                     GetLastError());
                        std::fflush(stderr);
                    }
                }
                else
                {
                    std::fprintf(stderr,
                                 "[pyimgui] CreateFile for crash dump failed: 0x%08lx\n",
                                 GetLastError());
                    std::fflush(stderr);
                }
            }
            else if (!do_python)
            {
                std::fprintf(stderr,
                             "[pyimgui] (no minidump / no python dump configured)\n");
                std::fflush(stderr);
            }

            // Let the OS handle the exception normally afterwards (process exits
            // with the original exception code; Windows Error Reporting may also
            // run). Using EXCEPTION_EXECUTE_HANDLER would swallow the exit code.
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    void SetupUnhandledExceptionFilter(bool write_dump,
                                       uint32_t flags,
                                       const std::string& path,
                                       bool write_py_dump,
                                       const std::string& py_dump_path)
    {
        {
            std::lock_guard<std::mutex> lock(g_path_lock);
            g_path = path.empty() ? std::string("./CrashDump.dmp") : path;
        }
        {
            std::lock_guard<std::mutex> lock(g_py_path_lock);
            g_py_path = py_dump_path.empty() ? std::string("./CrashDump.pystack.txt") : py_dump_path;
        }
        g_flags.store(flags, std::memory_order_relaxed);
        g_write_dump.store(write_dump, std::memory_order_relaxed);
        g_write_py_dump.store(write_py_dump, std::memory_order_relaxed);

        // Idempotent: SetUnhandledExceptionFilter returns the previous handler
        // and we don't care about it.
        if (!g_installed.exchange(true, std::memory_order_acq_rel))
        {
            SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);
        }
    }

    void pybind_setup_UnhandledException(py::module_ m)
    {
        py::enum_<MINIDUMP_TYPE>(m, "MINIDUMP_TYPE", py::arithmetic(),
                                 "Bitmask flags controlling MiniDumpWriteDump output. "
                                 "OR values together when passing to setup_unhandle_exception_filter.")
            .value("MiniDumpNormal",                         MiniDumpNormal)
            .value("MiniDumpWithDataSegs",                   MiniDumpWithDataSegs)
            .value("MiniDumpWithFullMemory",                 MiniDumpWithFullMemory)
            .value("MiniDumpWithHandleData",                 MiniDumpWithHandleData)
            .value("MiniDumpFilterMemory",                   MiniDumpFilterMemory)
            .value("MiniDumpScanMemory",                     MiniDumpScanMemory)
            .value("MiniDumpWithUnloadedModules",            MiniDumpWithUnloadedModules)
            .value("MiniDumpWithIndirectlyReferencedMemory", MiniDumpWithIndirectlyReferencedMemory)
            .value("MiniDumpFilterModulePaths",              MiniDumpFilterModulePaths)
            .value("MiniDumpWithProcessThreadData",          MiniDumpWithProcessThreadData)
            .value("MiniDumpWithPrivateReadWriteMemory",     MiniDumpWithPrivateReadWriteMemory)
            .value("MiniDumpWithoutOptionalData",            MiniDumpWithoutOptionalData)
            .value("MiniDumpWithFullMemoryInfo",             MiniDumpWithFullMemoryInfo)
            .value("MiniDumpWithThreadInfo",                 MiniDumpWithThreadInfo)
            .value("MiniDumpWithCodeSegs",                   MiniDumpWithCodeSegs)
            .value("MiniDumpWithoutAuxiliaryState",          MiniDumpWithoutAuxiliaryState)
            .value("MiniDumpWithFullAuxiliaryState",         MiniDumpWithFullAuxiliaryState)
            .value("MiniDumpWithPrivateWriteCopyMemory",     MiniDumpWithPrivateWriteCopyMemory)
            .value("MiniDumpIgnoreInaccessibleMemory",       MiniDumpIgnoreInaccessibleMemory)
            .value("MiniDumpWithTokenInformation",           MiniDumpWithTokenInformation)
            .value("MiniDumpWithModuleHeaders",              MiniDumpWithModuleHeaders)
            .value("MiniDumpFilterTriage",                   MiniDumpFilterTriage)
            .value("MiniDumpWithAvxXStateContext",           MiniDumpWithAvxXStateContext)
            .value("MiniDumpWithIptTrace",                   MiniDumpWithIptTrace)
            .value("MiniDumpScanInaccessiblePartialPages",   MiniDumpScanInaccessiblePartialPages)
            .value("MiniDumpValidTypeFlags",                 MiniDumpValidTypeFlags)
            .export_values();

        m.def("setup_unhandle_exception_filter",
              [](py::object flag, const std::string& path, py::object py_dump)
              {
                  bool write_dump = !flag.is_none();
                  uint32_t flags = 0;
                  if (write_dump)
                  {
                      // Accept int, MINIDUMP_TYPE, or any arithmetic combination
                      // thereof (pybind11's `py::arithmetic()` enums implement
                      // __index__).
                      flags = py::cast<uint32_t>(flag.attr("__index__")());
                  }

                  bool write_py_dump = !py_dump.is_none();
                  std::string py_dump_path = "./CrashDump.pystack.txt";
                  if (write_py_dump)
                  {
                      // Accept any str-able value; common case is a path string.
                      py_dump_path = py::cast<std::string>(py::str(py_dump));
                  }

                  SetupUnhandledExceptionFilter(write_dump, flags, path,
                                                write_py_dump, py_dump_path);
              },
              py::arg("flag") = py::none(),
              py::arg("path") = std::string("./CrashDump.dmp"),
              py::arg("py_dump") = py::none(),
              "Install (or reconfigure) the process-wide unhandled exception filter.\n"
              "\n"
              "flag: bitmask of MINIDUMP_TYPE values, or None to disable minidump\n"
              "  writing (the default). When None the filter still runs and prints the\n"
              "  exception code/address to stderr but does NOT write a dump file. Any\n"
              "  integer is accepted, including 0 (MiniDumpNormal).\n"
              "path: file path to write the native minidump to. Ignored when flag is None.\n"
              "py_dump: file path to write a best-effort Python state snapshot to on\n"
              "  crash, or None (default) to disable. When enabled, the filter acquires\n"
              "  the GIL inside an SEH __try guard and writes a text file containing,\n"
              "  for every Python thread, its frame stack with locals (truncated reprs)\n"
              "  and the keys of each module's globals. A secondary fault during this\n"
              "  excursion is swallowed; the native minidump still runs afterwards.\n"
              "\n"
              "Safe to call multiple times; later calls update the stored values.");
    }
}
END_G_UTILS_NAMESPACE
