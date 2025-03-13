import pathlib
import shutil
import tempfile


class TmpFileWritter:
    def __init__(self, file_path, *a, tmp_file_path=None, **kw):
        self.a = a
        self.kw = kw

        self.file_path = file_path
        self.file = None

        self.tmp_file_path = tmp_file_path
        self.tmp_file = None

    def __enter__(self):
        if self.tmp_file_path:
            self.tmp_file = open(self.tmp_file_path, *self.a, **self.kw)
        else:
            self.tmp_file = tempfile.NamedTemporaryFile(*self.a, delete=False, **self.kw)
            self.tmp_file_path = self.tmp_file.name
        return self.tmp_file

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.tmp_file.close()
        file_path = pathlib.Path(self.file_path)
        tmp_file_path = pathlib.Path(self.tmp_file_path)
        if exc_type:
            if tmp_file_path.exists():
                tmp_file_path.unlink()
            return False
        bak_file_path = None
        if file_path.exists():
            n = 1
            while (bak_file_path := file_path.with_suffix(f'.bak{n}')).exists():
                n += 1
            shutil.move(file_path, bak_file_path)
        shutil.move(tmp_file_path, file_path)
        if bak_file_path: bak_file_path.unlink()
