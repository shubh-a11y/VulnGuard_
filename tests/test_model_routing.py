import pytest
from vulnguard.config import ModelRoutingConfig

class TestModelRouting:
    def test_high_risk_routing(self):
        config = ModelRoutingConfig(
            high_risk_threshold=80,
            high_risk_provider="gemini",
            high_risk_model="gemini-3.1-pro",
            medium_risk_provider="gemini",
            medium_risk_model="gemini-3.6-flash"
        )
        provider, model = config.get_model_for_score(85.0)
        assert provider == "gemini"
        assert model == "gemini-3.1-pro"

    def test_medium_risk_routing(self):
        config = ModelRoutingConfig(
            high_risk_threshold=80,
            high_risk_provider="gemini",
            high_risk_model="gemini-3.1-pro",
            medium_risk_provider="gemini",
            medium_risk_model="gemini-3.6-flash"
        )
        provider, model = config.get_model_for_score(65.0)
        assert provider == "gemini"
        assert model == "gemini-3.6-flash"
        
    def test_threshold_boundary(self):
        config = ModelRoutingConfig(
            high_risk_threshold=80,
            high_risk_provider="anthropic",
            high_risk_model="claude-3.5-sonnet",
            medium_risk_provider="openai",
            medium_risk_model="gpt-4o-mini"
        )
        # Exactly on threshold should be high risk
        p_high, m_high = config.get_model_for_score(80.0)
        assert p_high == "anthropic"
        assert m_high == "claude-3.5-sonnet"
        
        # Just below threshold should be medium risk
        p_mid, m_mid = config.get_model_for_score(79.9)
        assert p_mid == "openai"
        assert m_mid == "gpt-4o-mini"
