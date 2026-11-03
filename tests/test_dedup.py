import pytest

from bbpipeline.dedup import (
    DEFAULT_SIMILARITY_THRESHOLD,
    FindingDeduplicator,
    cosine_similarity,
    embed,
)


def test_embed_is_deterministic():
    vector_a = embed("SQL Injection in user id parameter")
    vector_b = embed("SQL Injection in user id parameter")

    assert vector_a == vector_b


def test_embed_returns_vector_of_configured_dim():
    vector = embed("XSS in search field", dim=64)

    assert len(vector) == 64
    assert all(isinstance(v, float) for v in vector)


def test_cosine_similarity_identical_vectors_is_one():
    vector = embed("Stored XSS in search field")

    assert cosine_similarity(vector, vector) == pytest.approx(1.0)


def test_cosine_similarity_disjoint_vectors_is_low():
    vector_a = embed("SSRF via image proxy endpoint")
    vector_b = embed("SQL injection in login form database")

    assert cosine_similarity(vector_a, vector_b) < 0.85


def test_duplicate_detected_above_threshold(tmp_path):
    deduplicator = FindingDeduplicator(threshold=DEFAULT_SIMILARITY_THRESHOLD, storage_path=tmp_path / "dedup.json")

    deduplicator.add("Stored XSS in the search field", finding_id=1)
    is_duplicate, similarity, match = deduplicator.check_duplicate("Stored XSS in the search field")

    assert is_duplicate is True
    assert similarity == pytest.approx(1.0)
    assert match is not None
    assert match.text == "Stored XSS in the search field"


def test_deduplicator_persists_entries_to_disk(tmp_path):
    deduplicator = FindingDeduplicator(threshold=DEFAULT_SIMILARITY_THRESHOLD, storage_path=tmp_path / "dedup.json")
    deduplicator.add("Stored XSS in the search field", finding_id=1)

    reloaded = FindingDeduplicator(threshold=DEFAULT_SIMILARITY_THRESHOLD, storage_path=tmp_path / "dedup.json")
    is_duplicate, _, _ = reloaded.check_duplicate("Stored XSS in the search field")

    assert is_duplicate is True


def test_similar_but_not_identical_findings_are_detected(tmp_path):
    deduplicator = FindingDeduplicator(threshold=0.8, storage_path=tmp_path / "dedup.json")

    deduplicator.add("SQL Injection via user id parameter")
    is_duplicate, similarity, _ = deduplicator.check_duplicate("SQL Injection in user id parameter")

    assert is_duplicate is True
    assert similarity > 0.5


def test_no_duplicate_when_similarity_is_below_threshold(tmp_path):
    deduplicator = FindingDeduplicator(threshold=DEFAULT_SIMILARITY_THRESHOLD, storage_path=tmp_path / "dedup.json")

    deduplicator.add("SSRF via image proxy endpoint")
    is_duplicate, similarity, _ = deduplicator.check_duplicate("SQL injection in login form database")

    assert is_duplicate is False
    assert similarity < DEFAULT_SIMILARITY_THRESHOLD


def test_custom_threshold_changes_detection(tmp_path):
    deduplicator = FindingDeduplicator(threshold=0.99, storage_path=tmp_path / "dedup.json")

    deduplicator.add("Stored XSS in the search field")
    is_duplicate, _, _ = deduplicator.check_duplicate("Stored XSS in the search field")

    # Con umbral muy alto, el hallazgo identico sigue siendo duplicado (sim=1.0)
    assert is_duplicate is True


def test_semantic_security_embedder_synonym_recognition():
    # Sinónimos semánticos que no comparten palabras exactas:
    v_xss1 = embed("Cross-site scripting in search parameter")
    v_xss2 = embed("Reflected XSS on query input")
    sim_xss = cosine_similarity(v_xss1, v_xss2)

    # Deben tener alta similitud semántica (> 0.60)
    assert sim_xss > 0.60

    # Vulnerabilidad distinta (SQLi)
    v_sqli = embed("SQL injection in user login database")
    sim_diff = cosine_similarity(v_xss1, v_sqli)

    # Debe ser marcadamente baja (< 0.25)
    assert sim_diff < 0.25


def test_deduplicator_catches_semantic_synonym_duplicates(tmp_path):
    dedup = FindingDeduplicator(threshold=0.60, storage_path=tmp_path / "semantic_dedup.json")
    dedup.add("Cross-site scripting in search parameter", finding_id=101)

    # Entrada con vocabulario equivalente pero diferente (XSS vs Cross-site scripting)
    is_dup, sim, match = dedup.check_duplicate("Reflected XSS on query input")

    assert is_dup is True
    assert sim > 0.60
    assert match is not None
    assert match.finding_id == 101


def test_semantic_contrast_between_different_vulnerabilities():
    v_rce = embed("Remote code execution via command injection")
    v_ssrf = embed("Server-side request forgery in webhook url")
    v_idor = embed("Insecure direct object reference on user profile")

    # Clases disjuntas deben arrojar similitud baja
    assert cosine_similarity(v_rce, v_ssrf) < 0.30
    assert cosine_similarity(v_rce, v_idor) < 0.30
    assert cosine_similarity(v_ssrf, v_idor) < 0.30
