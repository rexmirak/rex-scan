import os
import shutil
from pathlib import Path


def check_tool(name: str) -> bool:
    """Return True if `name` is on PATH."""
    return shutil.which(name) is not None


def ensure_output_path(path: str) -> Path:
    p = Path(path).expanduser()
    if p.is_dir():
        return p
    parent = p.parent
    parent.mkdir(parents=True, exist_ok=True)
    return p


def default_desktop_path(target: str) -> Path:
    home = Path.home()
    desktop = home / "Desktop"
    desktop.mkdir(parents=True, exist_ok=True)
    fname = f"{target}_scan"
    return desktop / fname
