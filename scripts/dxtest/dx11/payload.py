from __future__ import annotations

import time

from common.payload_common import configure_imports, keep_alive, mark

configure_imports()

import pyimgui.imgui as imgui
from pyimgui.dx11 import Dx11Inbound


mark("payload_started")


def draw(renderer):
    mark("payload_drawn")
    imgui.Begin("pyimgui2 dx11 inbound")
    imgui.Text("DX11 inbound render ok")
    imgui.Text(f"isInLogic={renderer.isInLogic}")
    imgui.End()


renderer = Dx11Inbound(draw)
for attempt in range(50):
    try:
        renderer.Attach()
        mark("payload_attached")
        break
    except Exception as exc:
        mark("payload_attach_retry", repr(exc))
        time.sleep(0.2)
else:
    raise RuntimeError("failed to attach DX11 inbound renderer")

keep_alive()
renderer.Detach()