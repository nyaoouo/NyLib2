"""PyInstaller hook for ``nylib.winutils.sign``.

The package ships a cross-certificate bundle ``MSCVStore.p7b`` (a PKCS#7 of the
Microsoft kernel-mode code-signing cross-certificates). ``nylib.winutils.sign``
reads it at runtime via ``BUNDLED_CROSS_CERT_STORE`` (a ``__file__``-relative
path) to provide driver-mode signing without the caller supplying a ``/ac``
file. This hook makes sure the data file is collected into the frozen bundle at
the matching package-relative location so that lookup keeps working.

Unlike the ``.dll`` hooks in this directory, ``.p7b`` is a plain data file (not
excluded from the wheel), so it is added through the ``datas`` channel.
"""

from __future__ import annotations

import os
import pathlib

from PyInstaller.utils.hooks import (  # type: ignore[import-not-found]
    get_module_file_attribute,
    logger,
)

datas: list[tuple[str, str]] = []
binaries: list[tuple[str, str]] = []
hiddenimports: list[str] = []


def _collect() -> None:
    try:
        init_py = pathlib.Path(get_module_file_attribute("nylib.winutils.sign"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("hook-nylib.winutils.sign: cannot locate package (%s)", exc)
        return

    pkg_dir = init_py.parent
    dest = os.path.join("nylib", "winutils", "sign")

    bundle = pkg_dir / "MSCVStore.p7b"
    if bundle.is_file():
        datas.append((str(bundle), dest))
    else:
        logger.warning(
            "hook-nylib.winutils.sign: %s is missing; driver-mode signing will "
            "require an explicit /ac certificate at runtime",
            bundle,
        )


_collect()
