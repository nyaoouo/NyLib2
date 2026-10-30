import importlib

from . import icons
from .alerts import Alerts
from .file_dialog import FileDialog
from .icons import install_icon
from .message_box import MessageBox
from .utils import BeginFullScreenBackGround, Inspector, PushDisabledButtonStyle
from .window_manager import WindowManager, window_manager

_LAZY_DEBUG_VIEW = ('DebugViewState', 'render_debug_view')


def __getattr__(name):
    """Load the debug view on first use; a frozen app that needs it imports `nylib.imguiutils.debug_view`."""
    if name in _LAZY_DEBUG_VIEW:
        value = globals()[name] = getattr(importlib.import_module('.debug_view', __name__), name)
        return value
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')


def __dir__():
    return sorted({*globals(), *_LAZY_DEBUG_VIEW})
