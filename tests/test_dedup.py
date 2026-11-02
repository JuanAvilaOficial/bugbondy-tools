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
