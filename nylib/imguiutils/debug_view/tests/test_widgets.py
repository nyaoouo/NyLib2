from __future__ import annotations

import pytest

from nylib.imguiutils.debug_view.widgets import use_state, current_state


class _Sentinel:
    pass


def test_use_state_sets_and_resets_contextvar():
    a = _Sentinel()
    b = _Sentinel()
    with use_state(a):
        assert current_state() is a
        with use_state(b):
            assert current_state() is b
        assert current_state() is a
    with pytest.raises(LookupError):
        current_state()
