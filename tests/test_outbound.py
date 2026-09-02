from agentbastion.outbound import PiiRedactor, _luhn_ok


def test_redacts_email_and_ssn():
    red = PiiRedactor()
    out, findings = red.redact("Contact jane@acme.com, SSN 123-45-6789.")
    assert "jane@acme.com" not in out
    assert "123-45-6789" not in out
    kinds = {f.kind for f in findings}
    assert "EMAIL" in kinds and "SSN" in kinds


def test_redacts_valid_credit_card_only():
    red = PiiRedactor()
    # 4111 1111 1111 1111 is a valid Luhn test card
    out, findings = red.redact("card 4111 1111 1111 1111 please")
    assert "<REDACTED:CREDIT_CARD>" in out
    assert any(f.kind == "CREDIT_CARD" for f in findings)


def test_ignores_invalid_card_number():
    red = PiiRedactor()
    # random 16 digits that fail Luhn - should NOT redact as a card
    out, findings = red.redact("order 1234567812345678 shipped")
    assert not any(f.kind == "CREDIT_CARD" for f in findings)


def test_redacts_secrets():
    red = PiiRedactor()
    out, findings = red.redact("key sk-ant-api03-ABCdef1234567890XYZlongtoken here")
    assert any(f.kind == "API_KEY" for f in findings)
    assert "sk-ant" not in out


def test_clean_text_untouched():
    red = PiiRedactor()
    out, findings = red.redact("Your order shipped and will arrive Tuesday.")
    assert findings == []
    assert out == "Your order shipped and will arrive Tuesday."


def test_luhn():
    assert _luhn_ok("4111111111111111")
    assert not _luhn_ok("1234567812345678")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("outbound: ok")
