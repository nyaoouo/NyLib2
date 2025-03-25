import itertools
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


class GroupDelegate:
    class _SubDelegate:
        def __init__(self, parent, key):
            self.parent = parent
            self.key = key

        def add(self, callback):
            return self.parent.add(self.key, callback)

        def remove(self, handle):
            self.parent.remove(self.key, handle)

        def __call__(self, *args, **kwargs):
            self.parent(self.key, *args, **kwargs)

    Any = type('Any_t', (), {})()

    def __init__(self, sub_thread=False):
        self.callbacks = {}
        self.handles = Handles()
        self.sub_thread = sub_thread

    def add(self, key, callback):
        handle = self.handles.get()
        self.callbacks.setdefault(key, {})[handle] = callback
        return handle

    def remove(self, key, handle):
        self.handles.free(handle)
        (cb := self.callbacks.get(key, {})).pop(handle, None)
        if not cb:
            self.callbacks.pop(key, None)

    def __call__(self, key, *args, **kwargs):
        to_call = list(itertools.chain(self.callbacks.get(key, {}).values(), self.callbacks.get(GroupDelegate.Any, {}).values()))
        if self.sub_thread:
            for callback in to_call:
                threading.Thread(target=callback, args=args, kwargs=kwargs, daemon=True).start()
        else:
            for callback in to_call:
                callback(*args, **kwargs)

    def __getitem__(self, key):
        return self._SubDelegate(self, key)
