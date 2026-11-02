"""Testlerin ortak yardımcıları."""
import os
import shutil
from pathlib import Path


def find_bash():
    """Windows'ta PATH'teki bash çoğunlukla WSL yönlendirmesidir; betikler Git Bash ile çalışır."""
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432")):
            candidate = Path(base or "") / "Git" / "bin" / "bash.exe"
            if base and candidate.exists():
                return str(candidate)
    return shutil.which("bash")
