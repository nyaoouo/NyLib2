"""`python -m nylib.ue` entry point (I4)."""
import sys

from .cli import main

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, 'reconfigure'):
        _stream.reconfigure(errors='backslashreplace')

raise SystemExit(main())
