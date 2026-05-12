from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKENDS = ("dx9", "dx11", "dx12")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=10)
    args = parser.parse_args()

    failed: list[str] = []
    for backend in BACKENDS:
        result = subprocess.run([sys.executable, str(ROOT / "inject.py"), backend, "--seconds", str(args.seconds)])
        if result.returncode != 0:
            failed.append(backend)
    if failed:
        print("failed:", ", ".join(failed))
        raise SystemExit(1)


if __name__ == "__main__":
    main()