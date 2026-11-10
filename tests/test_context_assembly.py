"""Context assembly must feed the Red Agent the callee/class surface it needs."""

from __future__ import annotations

from vulnguard.data.context_gatherer import gather_context

PROCESSOR = (
    "from database import Database\n"
    "\n"
    "class DataProcessor:\n"
    "    def __init__(self):\n"
    "        self.db = Database()\n"
    "\n"
    "    def process(self, data):\n"
    "        transformed = data.strip().lower()\n"
    "        self.db.update_user_status(transformed)\n"
)

PROCESS_FUNCTION = (
    "    def process(self, data):\n"
    "        transformed = data.strip().lower()\n"
    "        self.db.update_user_status(transformed)\n"
)

DATABASE = (
    "class Database:\n"
    "    def update_user_status(self, value):\n"
    "        pass\n"
)


def _write(tmp_path):
    (tmp_path / "database.py").write_text(DATABASE, encoding="utf-8")
    target = tmp_path / "processor.py"
    target.write_text(PROCESSOR, encoding="utf-8")
    return target


def test_parser_payload_enriches_imports_and_callees(tmp_path):
    target = _write(tmp_path)

    ctx = gather_context(
        PROCESS_FUNCTION,
        file_path=target,
        repo_root=tmp_path,
        language="python",
        known_imports=["from database import Database"],
        known_callees=["self.db.update_user_status", "data.strip"],
    )

    assert ctx.imports == ["from database import Database"]
    # The method target lives in another module; the parser-provided callee
    # name lets the resolver pull its signature in.
    assert any("update_user_status" in sig for sig in ctx.callee_signatures)
    assert any("DataProcessor" in item for item in ctx.class_context)
    assert ctx.token_count > 0


def test_prompt_exposes_enclosing_class_and_callee_signatures(tmp_path):
    target = _write(tmp_path)

    ctx = gather_context(
        PROCESS_FUNCTION,
        file_path=target,
        repo_root=tmp_path,
        language="python",
        known_imports=["from database import Database"],
        known_callees=["self.db.update_user_status"],
    )
    text = ctx.to_prompt_text()

    assert "=== ENCLOSING CLASS ===" in text
    assert "class DataProcessor:" in text
    assert "=== CALLEES ===" in text
    assert "update_user_status" in text


def test_context_stays_function_scoped(tmp_path):
    target = _write(tmp_path)

    ctx = gather_context(
        PROCESS_FUNCTION,
        file_path=target,
        repo_root=tmp_path,
        language="python",
    )

    # Other functions in the file are not dumped wholesale into the bundle.
    assert "def update_user_status" not in "\n".join(ctx.type_definitions)
    assert "class DataProcessor:" in "\n".join(ctx.class_context)
