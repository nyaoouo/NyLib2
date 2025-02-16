import threading

from .handles import Handles


class Delegate:
    def __init__(self, sub_thread=False):
        self.callbacks = {}
        self.handles = Handles()
        self.sub_thread = sub_thread

    def add(self, callback):
        handle = self.handles.get()
        self.callbacks[handle] = callback
        return handle

    def remove(self, handle):
        self.handles.free(handle)
        self.callbacks.pop(handle, None)

    def __call__(self, *args, **kwargs):
        to_call = list(self.callbacks.values())
        if self.sub_thread:
            for callback in to_call:
                threading.Thread(target=callback, args=args, kwargs=kwargs, daemon=True).start()
        else:
            for callback in to_call:
                callback(*args, **kwargs)
