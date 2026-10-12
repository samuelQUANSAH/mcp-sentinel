"""Unit tests for PII and API secret detection and scrubbing engine."""

from mcp_sentinel.security.pii_redactor import PIIRedactor, _luhn_checksum_valid


def test_luhn_checksum_valid():
    # Valid Visa test number
    assert _luhn_checksum_valid("4532015112830366") is True
    # Invalid card number
    assert _luhn_checksum_valid("4532015112830367") is False


def test_redact_ssn():
    redactor = PIIRedactor()
    raw = "User SSN is 123-45-6789 in the system."
    clean, entities = redactor.redact_text(raw)
    assert "[REDACTED_SSN]" in clean
    assert "123-45-6789" not in clean
    assert "SSN" in entities


def test_redact_email_and_phone():
    redactor = PIIRedactor()
    raw = "Contact support@enterprise.com or call 415-555-0199 for help."
    clean, entities = redactor.redact_text(raw)
    assert "[REDACTED_EMAIL]" in clean
    assert "[REDACTED_PHONE]" in clean
    assert "EMAIL" in entities
    assert "PHONE" in entities


def test_redact_api_secrets():
    redactor = PIIRedactor()
    raw = "Keys: sk-live-1234567890abcdef1234567890 and AKIAIOSFODNN7EXAMPLE and ghp_0123456789abcdefghijklmnopqrstuvwxyz"
    clean, entities = redactor.redact_text(raw)
    assert "[REDACTED_OPENAI_KEY]" in clean
    assert "[REDACTED_AWS_KEY]" in clean
    assert "[REDACTED_GITHUB_TOKEN]" in clean
    assert "OPENAI_KEY" in entities
    assert "AWS_KEY" in entities
    assert "GITHUB_TOKEN" in entities


def test_redact_nested_dict():
    redactor = PIIRedactor()
    payload = {
        "user": {
            "name": "Alice",
            "email": "alice@secure.org",
            "ssn": "987-65-4321",
        },
        "metadata": ["note 1", "Token: sk-proj-1234567890abcdef1234567890"],
    }
    cleaned, entities = redactor.redact_value(payload)
    assert cleaned["user"]["email"] == "[REDACTED_EMAIL]"
    assert cleaned["user"]["ssn"] == "[REDACTED_SSN]"
    assert "[REDACTED_OPENAI_KEY]" in cleaned["metadata"][1]
    assert "EMAIL" in entities
    assert "SSN" in entities
    assert "OPENAI_KEY" in entities
