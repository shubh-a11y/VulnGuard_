import os
from types import SimpleNamespace

import pytest

import vulnguard.llm_runtime as llm_runtime


def test_litellm_environment_uses_normalized_local_tokenizers(monkeypatch, tmp_path):
    monkeypatch.setattr(llm_runtime, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm_runtime, "_PREPARED", False)
    monkeypatch.delenv("CUSTOM_TIKTOKEN_CACHE_DIR", raising=False)
    monkeypatch.delenv("TIKTOKEN_CACHE_DIR", raising=False)
    monkeypatch.delenv("LITELLM_LOCAL_MODEL_COST_MAP", raising=False)

    llm_runtime._prepare_litellm_environment()

    cache_files = list(tmp_path.iterdir())
    assert cache_files
    assert all(b"\r\n" not in path.read_bytes() for path in cache_files)
    assert os.environ["CUSTOM_TIKTOKEN_CACHE_DIR"] == str(tmp_path)
    assert os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"


def test_usage_log_records_and_aggregates_metadata(tmp_path, monkeypatch):
    usage_log = tmp_path / "usage.jsonl"
    monkeypatch.setattr(llm_runtime, "_USAGE_LOG", usage_log)
    monkeypatch.setattr(llm_runtime, "_estimate_standard_token_cost", lambda *_: None)
    response = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=120, completion_tokens=30, total_tokens=150),
        _hidden_params={"response_cost": 0.00125},
    )

    llm_runtime._record_usage(response, "gemini/gemini-3.8-flash", latency_ms=250.0)
    summary = llm_runtime.usage_summary()

    assert summary == [
        {
            "provider": "gemini",
            "model": "gemini-3.8-flash",
            "calls": 1,
            "input_tokens": 120,
            "output_tokens": 30,
            "total_tokens": 150,
            "estimated_cost_usd": 0.00125,
            "avg_latency_ms": 250.0,
        }
    ]
    assert "prompt" not in usage_log.read_text()


def test_usage_includes_reasoning_tokens_in_output_and_cost(tmp_path, monkeypatch):
    usage_log = tmp_path / "usage.jsonl"
    monkeypatch.setattr(llm_runtime, "_USAGE_LOG", usage_log)
    monkeypatch.setattr(
        llm_runtime,
        "_estimate_standard_token_cost",
        lambda _model, input_tokens, output_tokens: input_tokens * 0.001 + output_tokens * 0.002,
    )
    response = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=0, total_tokens=150),
        _hidden_params={"response_cost": 0.001},
    )

    llm_runtime._record_usage(response, "gemini/gemini-3.8-flash")
    summary = llm_runtime.usage_summary()

    assert summary[0]["output_tokens"] == 50
    assert summary[0]["estimated_cost_usd"] == 0.2


def test_response_text_rejects_empty_model_content():
    response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None))])

    with pytest.raises(ValueError, match="empty content"):
        llm_runtime.response_text(response)
