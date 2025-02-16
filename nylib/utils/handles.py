class Handles:
    def __init__(self):
        self.free_handles = []
        self.counter = 0

    def get(self):
        if self.free_handles:
            return self.free_handles.pop()
        self.counter += 1
        return self.counter

    def free(self, handle):
        if not self.is_valid(handle):
            raise ValueError(f"Invalid handle: {handle}")
        if handle == self.counter:
            self.counter -= 1
        else:
            self.free_handles.append(handle)

    def is_valid(self, handle):
        return 0 < handle <= self.counter and handle not in self.free_handles
