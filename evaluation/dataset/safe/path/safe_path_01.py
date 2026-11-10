from pathlib import Path

def read_user_file(base_dir: str, filename: str) -> str:
    # Safe implementation: canonicalize and verify path stays within base_dir
    base = Path(base_dir).resolve()
    target = (base / filename).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise PermissionError("Path traversal attempt detected")
    with target.open("r", encoding="utf-8") as f:
        return f.read()

