"""Módulo de deduplicación de hallazgos mediante similitud vectorial (embeddings).

Implementa un indice vectorial local de hallazgos previos (TF embeddings
deterministas basados en hashing de tokens) y un gate de deduplicacion que
detecta hallazgos semanticamente equivalentes antes de aceptar uno nuevo.
Los vectores persisten en disco (state/vector-index/dedup.json).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SIMILARITY_THRESHOLD = 0.85
DEFAULT_EMBEDDING_DIM = 512
DEDUP_STORAGE_VERSION = 1


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_]+", text.lower())


def _hash_token(token: str, dim: int) -> int:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return int(digest, 16) % dim


def embed(text: str, dim: int = DEFAULT_EMBEDDING_DIM) -> list[float]:
    """Embedding determinista: frecuencia normalizada de tokens hasheados."""
    tokens = _tokenize(text)
    vector = [0.0] * dim
    frequencies: dict[int, float] = {}
    for token in tokens:
        index = _hash_token(token, dim)
        frequencies[index] = frequencies.get(index, 0.0) + 1.0

    total = sum(frequencies.values()) or 1.0
    for index, count in frequencies.items():
        vector[index] = count / total
    return vector


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Similitud coseno entre dos vectores (0.0 - 1.0)."""
    dot_product = sum(x * y for x, y in zip(a, b, strict=False))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot_product / (norm_a * norm_b)


@dataclass
class StoredFindingVector:
    finding_id: int | None
    text: str
    vector: list[float]


class FindingDeduplicator:
    """Detecta hallazgos duplicados mediante similitud vectorial con persistencia."""

    def __init__(
        self,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        dim: int = DEFAULT_EMBEDDING_DIM,
        storage_path: str | Path | None = None,
    ) -> None:
        self.threshold = threshold
        self.dim = dim
        self.storage_path = Path(storage_path) if storage_path is not None else Path("state/vector-index/dedup.json")
        self._entries: list[StoredFindingVector] = []
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            entries = data.get("entries") or []
            self._entries = [
                StoredFindingVector(finding_id=entry.get("finding_id"), text=entry.get("text") or "", vector=list(entry.get("vector") or []))
                for entry in entries
            ]
        except (OSError, json.JSONDecodeError, ValueError):
            self._entries = []

    def _save(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": DEDUP_STORAGE_VERSION,
            "entries": [
                {"finding_id": entry.finding_id, "text": entry.text, "vector": entry.vector}
                for entry in self._entries
            ],
        }
        self.storage_path.write_text(json.dumps(payload), encoding="utf-8")

    def add(self, text: str, finding_id: int | None = None) -> StoredFindingVector:
        entry = StoredFindingVector(finding_id=finding_id, text=text, vector=embed(text, self.dim))
        self._entries.append(entry)
        self._save()
        return entry

    def check_duplicate(self, text: str) -> tuple[bool, float, StoredFindingVector | None]:
        """Compara un hallazgo contra el indice persistido; retorna (es_duplicado, similitud, mejor_coincidente)."""
        vector = embed(text, self.dim)
        best_match: StoredFindingVector | None = None
        best_similarity = 0.0

        for entry in self._entries:
            similarity = cosine_similarity(vector, entry.vector)
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = entry

        is_duplicate = best_match is not None and best_similarity >= self.threshold
        return is_duplicate, best_similarity, best_match
