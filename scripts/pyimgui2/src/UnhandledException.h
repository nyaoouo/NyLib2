#pragma once
#include "./gHeader.h"

#include <cstdint>
#include <string>

#include <dbghelp.h>

START_G_UTILS_NAMESPACE
{
    // Install (or re-configure) the process-wide unhandled exception filter.
    //
    // Native minidump arm (`write_dump` + `flags` + `path`):
    //   * `write_dump == false` (opt-in default) — the filter prints the
    //     exception code/address to stderr but does NOT call
    //     `MiniDumpWriteDump`. `flags`/`path` are stored but unused.
    //   * `write_dump == true` — minidump is written to `path` using `flags`
    //     as the `MINIDUMP_TYPE` bitmask. `flags == 0` is a valid mask
    //     (`MiniDumpNormal`).
    //
    // Python state dump arm (`write_py_dump` + `py_dump_path`):
    //   * `write_py_dump == false` (opt-in default) — Python state is not
    //     dumped.
    //   * `write_py_dump == true` — best-effort: acquire the GIL inside an
    //     SEH __try guard, run a small inline Python script that snapshots
    //     every thread's frame stack + locals + module globals keys, and
    //     write the result as text to `py_dump_path`. A secondary crash
    //     inside this excursion is swallowed; the native minidump still
    //     runs afterwards.
    //
    // Both arms are independent: you can enable either, both, or neither.
    //
    // Calling more than once just updates the stored state; the underlying
    // `SetUnhandledExceptionFilter` install is idempotent.
    void SetupUnhandledExceptionFilter(bool write_dump,
                                       uint32_t flags,
                                       const std::string& path,
                                       bool write_py_dump,
                                       const std::string& py_dump_path);

    // Bind `setup_unhandle_exception_filter(flag, path)` and the
    // `MINIDUMP_TYPE` enum onto `m` (intended to be the top-level pyimgui
    // module so users can `from pyimgui import setup_unhandle_exception_filter,
    // MINIDUMP_TYPE`).
    void pybind_setup_UnhandledException(py::module_ m);
}
END_G_UTILS_NAMESPACE
