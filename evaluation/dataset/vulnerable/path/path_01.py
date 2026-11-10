def read_user_file(base_dir: str, filename: str) -> str:
    # Path traversal vulnerability via simple concatenation
    file_path = base_dir + "/" + filename
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

