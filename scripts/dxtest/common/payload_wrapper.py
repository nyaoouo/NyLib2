"""Fixed python_main for `inject.py --payload`: runs a scratch payload and
turns its outcome into a verdict marker. Stdlib only.

Env: DXTEST_PAYLOAD = absolute path to the scratch payload to run;
DXTEST_OUT = the backend's out dir (markers/ lives under it).
"""
from __future__ import annotations

import os
import runpy
import sys
import traceback

_payload = os.environ["DXTEST_PAYLOAD"]
_payload_dir = os.path.dirname(_payload)
if _payload_dir and _payload_dir not in sys.path:
    sys.path.insert(0, _payload_dir)


def _mark_ok() -> None:
    out_dir = os.environ.get("DXTEST_OUT", os.getcwd())
    markers_dir = os.path.join(out_dir, "markers")
    os.makedirs(markers_dir, exist_ok=True)
    text = f"{_payload}\nPROBE_MODE={os.environ.get('PROBE_MODE', '')}\n"
    with open(os.path.join(markers_dir, "payload_ok.txt"), "w", encoding="utf-8") as f:
        f.write(text)


try:
    runpy.run_path(_payload, run_name="__main__")
except BaseException:
    traceback.print_exc()
    sys.stderr.flush()
    os._exit(3)

_mark_ok()
