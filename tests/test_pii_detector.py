from aegis_core.pii_detector import PiiDetector


def test_redacts_email():
    result = PiiDetector().scan("Contactez-moi à jean.dupont@example.com pour plus d'infos.")
    assert result.redacted is True
    assert "EMAIL_MASQUÉ" in result.redacted_text
    assert "jean.dupont@example.com" not in result.redacted_text
    assert "EMAIL" in result.categories


def test_redacts_phone_number():
    result = PiiDetector().scan("Vous pouvez m'appeler au 06 12 34 56 78 avant 18h.")
    assert result.redacted is True
    assert "TELEPHONE_MASQUÉ" in result.redacted_text
    assert "06 12 34 56 78" not in result.redacted_text


def test_redacts_iban():
    result = PiiDetector().scan("Merci de virer sur FR7630006000011234567890189.")
    assert result.redacted is True
    assert "IBAN_MASQUÉ" in result.redacted_text


def test_redacts_credit_card_number():
    result = PiiDetector().scan("Ma carte est la 4539 1488 0343 6467, merci de la débiter.")
    assert result.redacted is True
    assert "CARTE_BANCAIRE_MASQUÉ" in result.redacted_text


def test_redacts_api_key():
    result = PiiDetector().scan("Voici ma clé pour le test : sk-abcdEFGH12345678901234567890")
    assert result.redacted is True
    assert "CLE_API_MASQUÉ" in result.redacted_text


def test_leaves_clean_text_untouched():
    text = "Merci pour votre commande, elle sera livrée sous 3 jours."
    result = PiiDetector().scan(text)
    assert result.redacted is False
    assert result.redacted_text == text
    assert result.categories == ()
    assert result.count == 0


def test_counts_multiple_distinct_hits():
    result = PiiDetector().scan("Contact : a@b.com ou c@d.com, tel 06 12 34 56 78.")
    assert result.count == 3
    assert set(result.categories) == {"EMAIL", "TELEPHONE"}
