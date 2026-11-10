import os

def fetch_document(doc_folder: str, relative_name: str) -> str:
    # Path traversal vulnerability: os.path.join resolves relative segments without checking bounds
    full_path = os.path.join(doc_folder, relative_name)
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()

