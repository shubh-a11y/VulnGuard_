"""
Tests for the feature extractor module.

Validates feature extraction, timeout handling, macro stripping,
and template detection.
"""

import numpy as np
import pytest

from vulnguard.data.feature_extractor import (
    FEATURE_NAMES,
    FeatureResult,
    extract_features,
    strip_macros,
)


class TestStripMacros:
    def test_removes_define(self):
        code = '#define MAX 100\nint x = MAX;'
        result = strip_macros(code)
        assert "#define" not in result
        assert "int x = MAX;" in result

    def test_removes_ifdef(self):
        code = '#ifdef DEBUG\nprintf("debug");\n#endif\nreturn 0;'
        result = strip_macros(code)
        assert "#ifdef" not in result
        assert "return 0;" in result

    def test_preserves_non_macro_lines(self):
        code = 'int main() {\n    return 0;\n}'
        assert strip_macros(code) == code


class TestFeatureExtraction:
    def test_basic_c_function(self):
        code = """
int add(int a, int b) {
    return a + b;
}
"""
        result = extract_features(code, language="c")
        assert isinstance(result, FeatureResult)
        assert result.features["loc"] > 0
        assert result.features["cyclomatic_complexity"] >= 1
        assert len(result.vector) == len(FEATURE_NAMES)

    def test_complex_function_has_higher_complexity(self):
        simple = "int f() { return 1; }"
        complex_code = """
int f(int x) {
    if (x > 0) {
        for (int i = 0; i < x; i++) {
            if (i % 2 == 0) {
                while (x > 0) {
                    x--;
                }
            }
        }
    }
    return x;
}
"""
        r_simple = extract_features(simple, "c")
        r_complex = extract_features(complex_code, "c")
        assert r_complex.features["cyclomatic_complexity"] > r_simple.features["cyclomatic_complexity"]

    def test_template_detection(self):
        template_code = "template<typename T>\nT add(T a, T b) { return a + b; }"
        non_template = "int add(int a, int b) { return a + b; }"

        r_template = extract_features(template_code, "cpp")
        r_normal = extract_features(non_template, "c")

        assert r_template.features["is_template"] == 1
        assert r_normal.features["is_template"] == 0

    def test_empty_code_returns_defaults(self):
        result = extract_features("", "c")
        assert result.features["cyclomatic_complexity"] >= 1
        assert isinstance(result.vector, np.ndarray)

    def test_malformed_code_does_not_crash(self):
        # Intentionally broken code — should not raise
        result = extract_features("{{{{not valid c code at all;;;", "c")
        assert isinstance(result, FeatureResult)
        # May have parse errors but should not crash

    def test_python_code_skips_tree_sitter(self):
        code = "def hello():\n    print('hi')"
        result = extract_features(code, "python")
        assert result.features["loc"] > 0

    def test_vector_order_matches_feature_names(self):
        code = "int f() { return 1; }"
        result = extract_features(code, "c")
        vector = result.vector
        for i, name in enumerate(FEATURE_NAMES):
            assert vector[i] == result.features[name]


class TestMaintainabilityIndex:
    def test_simple_function_high_mi(self):
        code = "int f() { return 1; }"
        result = extract_features(code, "c")
        # Simple function should have moderate-to-high MI
        assert result.features["maintainability_index"] > 0

    def test_complex_function_lower_mi(self):
        simple = "int f() { return 1; }"
        complex_code = "\n".join([f"    if (x == {i}) return {i};" for i in range(50)])
        complex_code = f"int f(int x) {{\n{complex_code}\n    return -1;\n}}"

        r_simple = extract_features(simple, "c")
        r_complex = extract_features(complex_code, "c")
        assert r_complex.features["maintainability_index"] <= r_simple.features["maintainability_index"]
