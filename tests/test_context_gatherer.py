"""
Tests for the context gatherer module.

Validates import extraction, circular import protection, dynamic import
detection, FFI detection, and token budget enforcement.
"""

import pytest
from pathlib import Path

from vulnguard.data.context_gatherer import (
    ContextBundle,
    gather_context,
    _extract_imports,
    _extract_type_defs,
    _extract_macros,
    _enforce_token_budget,
)


class TestImportExtraction:
    def test_c_includes(self):
        code = '#include <stdio.h>\n#include "myheader.h"\nint main() {}'
        imports = _extract_imports(code, "c")
        assert len(imports) == 2
        assert any("stdio.h" in i for i in imports)
        assert any("myheader.h" in i for i in imports)

    def test_python_imports(self):
        code = "import os\nfrom pathlib import Path\nimport sys, json"
        imports = _extract_imports(code, "python")
        assert len(imports) >= 2
        assert any("os" in i for i in imports)
        assert any("pathlib" in i for i in imports)

    def test_java_imports(self):
        code = "import java.util.List;\nimport com.example.MyClass;"
        imports = _extract_imports(code, "java")
        assert len(imports) == 2

    def test_javascript_imports(self):
        code = "import foo from 'bar';\nconst x = require('lodash');"
        imports = _extract_imports(code, "javascript")
        assert len(imports) >= 1

    def test_unknown_language_returns_empty(self):
        imports = _extract_imports("some code", "rust")
        assert imports == []


class TestTypeDefs:
    def test_struct_extraction(self):
        code = "struct Point {\n    int x;\n    int y;\n};"
        types = _extract_type_defs(code)
        assert len(types) == 1
        assert "Point" in types[0]

    def test_class_extraction(self):
        code = "class MyClass {\npublic:\n    void foo();\n};"
        types = _extract_type_defs(code)
        assert len(types) == 1
        assert "MyClass" in types[0]

    def test_no_types_returns_empty(self):
        code = "int main() { return 0; }"
        types = _extract_type_defs(code)
        assert types == []


class TestMacroExtraction:
    def test_basic_defines(self):
        code = "#define MAX 100\n#define MIN(a,b) ((a)<(b)?(a):(b))"
        macros = _extract_macros(code)
        assert len(macros) == 2
        assert any("MAX" in m for m in macros)

    def test_no_macros(self):
        code = "int x = 0;"
        macros = _extract_macros(code)
        assert macros == []


class TestDynamicImportDetection:
    """Test EC-6.2: Dynamic import warning."""

    def test_python_importlib(self):
        code = "module = importlib.import_module('mymod')"
        ctx = gather_context(code, language="python")
        assert any("DYNAMIC_IMPORT" in w for w in ctx.warnings)

    def test_java_class_forname(self):
        code = 'Class<?> cls = Class.forName("com.example.Foo");'
        ctx = gather_context(code, language="java")
        assert any("DYNAMIC_IMPORT" in w for w in ctx.warnings)

    def test_no_dynamic_import(self):
        code = "import os\nx = os.path.join('a', 'b')"
        ctx = gather_context(code, language="python")
        assert not any("DYNAMIC_IMPORT" in w for w in ctx.warnings)


class TestFFIDetection:
    """Test EC-6.3: FFI detection."""

    def test_ctypes_detection(self):
        code = "lib = ctypes.CDLL('./libfoo.so')"
        ctx = gather_context(code, language="python")
        assert any("FFI" in w for w in ctx.warnings)

    def test_jni_detection(self):
        code = "JNIEXPORT void JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)"
        ctx = gather_context(code, language="c")
        assert any("FFI" in w for w in ctx.warnings)


class TestTokenBudget:
    """Test EC-6.4: Token budget enforcement."""

    def test_truncation_when_over_budget(self):
        ctx = ContextBundle(
            imports=["import x"] * 10,
            type_definitions=["struct A { int x; };"] * 50,
            caller_signatures=["void foo();"] * 100,
            callee_signatures=["void bar();"] * 100,
            macro_definitions=["#define X 1"] * 100,
            global_variables=["int g;"] * 100,
        )
        _enforce_token_budget(ctx, budget=50)  # Very small budget
        assert ctx.truncated is True

    def test_no_truncation_when_under_budget(self):
        ctx = ContextBundle(imports=["import os"])
        _enforce_token_budget(ctx, budget=10000)
        assert ctx.truncated is False


class TestContextBundle:
    def test_to_prompt_text(self):
        ctx = ContextBundle(
            imports=["#include <stdio.h>"],
            warnings=["DYNAMIC_IMPORT_DETECTED: test"],
        )
        text = ctx.to_prompt_text()
        assert "IMPORTS" in text
        assert "stdio.h" in text
        assert "WARNINGS" in text

    def test_to_dict_roundtrip(self):
        ctx = ContextBundle(imports=["import os"], warnings=["test warning"])
        d = ctx.to_dict()
        ctx2 = ContextBundle(**d)
        assert ctx2.imports == ctx.imports
        assert ctx2.warnings == ctx.warnings
