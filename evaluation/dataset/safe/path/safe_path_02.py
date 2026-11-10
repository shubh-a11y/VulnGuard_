import os

def fetch_document(doc_folder: str, relative_name: str) -> str:
    # Safe implementation: commonpath boundary check
    base = os.path.abspath(doc_folder)
    candidate = os.path.abspath(os.path.join(base, relative_name))
    if os.path.commonpath([base, candidate]) != base:
        raise PermissionError("Access outside designated document directory")
    with open(candidate, "r", encoding="utf-8") as f:
        return f.read()

