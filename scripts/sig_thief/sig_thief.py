import shutil
import struct

from nylib.utils.pip import required


# ... just for fun, cant bypass any check

def get_pe_security_dir_entry_offset(pe_file_path):
    required("pefile")
    import pefile
    pe = pefile.PE(pe_file_path, fast_load=True)
    return pe.OPTIONAL_HEADER.__file_offset__ + pe.OPTIONAL_HEADER.sizeof() + 4 * 8  # IMAGE_DIRECTORY_ENTRY_SECURITY = 4


def get_cert(pe_file_path):
    offset = get_pe_security_dir_entry_offset(pe_file_path)
    with open(pe_file_path, 'rb') as f:
        f.seek(offset, 0)
        rva, size = struct.unpack_from("II", f.read(8))
        f.seek(rva, 0)
        return f.read(size)


def set_cert(src, dst, cert):
    offset = get_pe_security_dir_entry_offset(src)
    shutil.copy2(src, dst)
    with open(dst, 'wb') as d:
        d.seek(0, 2)
        size = d.tell()
        d.write(cert)

        d.seek(offset, 0)
        d.write(struct.pack("<II", size, len(cert)))
