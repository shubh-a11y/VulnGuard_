import pytest

from vulnguard.data.parser import detect_language, parse_file, validate_syntax


@pytest.mark.parametrize(
    ("filename", "language", "source", "expected"),
    [
        ("app.py", "python", "import os\n\ndef run(value):\n    return clean(value)\n", "run"),
        ("app.c", "c", "#include <stdio.h>\nint run(int value) { return clean(value); }\n", "run"),
        ("app.cpp", "cpp", "#include <string>\nint run(int value) { return clean(value); }\n", "run"),
        (
            "App.java",
            "java",
            "import java.util.List; class App { int run(int value) { return clean(value); } }",
            "run",
        ),
        (
            "app.js",
            "javascript",
            "import { clean } from './clean.js'; function run(value) { return clean(value); }",
            "run",
        ),
    ],
)
def test_parse_supported_language(filename, language, source, expected):
    units = parse_file(filename, source)

    assert detect_language(filename) == language
    assert any(unit.function_name == expected for unit in units)
    assert any("clean" in callee for unit in units for callee in unit.callees)
    assert all(unit.language == language for unit in units)


def test_javascript_arrow_function():
    units = parse_file("app.js", "const run = (value) => clean(value);")
    assert [unit.function_name for unit in units] == ["run"]


def test_class_name_is_preserved():
    units = parse_file("app.py", "class Service:\n    def run(self):\n        return 1\n")
    assert units[0].class_name == "Service"


def test_syntax_validation_is_language_aware():
    assert validate_syntax("int main(void) { return 0; }", "c")[0] is True
    valid, error = validate_syntax("def broken(:\n    pass", "python")
    assert valid is False
    assert "Syntax error" in error
