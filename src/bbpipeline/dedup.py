"""Módulo de deduplicación de hallazgos mediante similitud vectorial (embeddings).

Implementa:
1. Embeddings semánticos especializados en el dominio de seguridad (ontología
   canónica de vulnerabilidades + embeddings densos de subpalabras/n-gramas).
2. Soporte pluggable para FastEmbed / Transformers y API Embeddings (OpenAI / Ollama).
3. Índice vectorial local con persistencia en disco (state/vector-index/dedup.json).
4. Gate de deduplicación que detecta hallazgos semánticamente equivalentes
   (ej. "Cross-site scripting" vs "Reflected XSS").
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

DEFAULT_SIMILARITY_THRESHOLD = 0.65
DEFAULT_EMBEDDING_DIM = 512
DEDUP_STORAGE_VERSION = 1

# Ontología de conceptos de vulnerabilidades y sinónimos para el embedding semántico
VULNERABILITY_ONTOLOGY: list[tuple[str, str, float]] = [
    # Patrón regex, Concepto semántico canónico, Peso
    (r"\b(cross[-\s]?site\s+scripting|xss)\b", "concept_vuln_xss", 10.0),
    (r"\b(reflected\s+(cross[-\s]?site\s+scripting|xss))\b", "concept_vuln_xss_reflected", 12.0),
    (r"\b(stored\s+(cross[-\s]?site\s+scripting|xss)|persistent\s+xss)\b", "concept_vuln_xss_stored", 12.0),
    (r"\b(dom[-\s]?(based)?\s*xss)\b", "concept_vuln_xss_dom", 12.0),
    (r"\b(sql\s*injection|sqli|blind\s+sql)\b", "concept_vuln_sqli", 10.0),
    (r"\b(remote\s+code\s+execution|command\s+injection|rce|os\s+command)\b", "concept_vuln_rce", 10.0),
    (r"\b(server[-\s]?side\s+request\s+forgery|ssrf)\b", "concept_vuln_ssrf", 10.0),
    (r"\b(insecure\s+direct\s+object\s+reference|idor|bola|broken\s+object\s+level)\b", "concept_vuln_idor", 10.0),
    (r"\b(cross[-\s]?site\s+request\s+forgery|csrf)\b", "concept_vuln_csrf", 10.0),
    (r"\b(local\s+file\s+inclusion|lfi|directory\s+traversal|path\s+traversal)\b", "concept_vuln_path_traversal", 10.0),
    (r"\b(remote\s+file\s+inclusion|rfi)\b", "concept_vuln_rfi", 10.0),
    (r"\b(open\s+redirect|unvalidated\s+redirect)\b", "concept_vuln_open_redirect", 10.0),
    (r"\b(authentication\s+bypass|auth\s+bypass|broken\s+authentication)\b", "concept_vuln_auth_bypass", 10.0),
    (r"\b(privilege\s+escalation|privesc)\b", "concept_vuln_privesc", 10.0),
    (r"\b(information\s+disclosure|sensitive\s+data\s+exposure|data\s+leak)\b", "concept_vuln_info_disclosure", 10.0),
    (r"\b(cors\s+misconfiguration|cross[-\s]?origin\s+resource)\b", "concept_vuln_cors", 10.0),
    (r"\b(subdomain\s+takeover)\b", "concept_vuln_subdomain_takeover", 10.0),
    (r"\b(prototype\s+pollution)\b", "concept_vuln_prototype_pollution", 10.0),
    (r"\b(xml\s+external\s+entity|xxe)\b", "concept_vuln_xxe", 10.0),
]

CONTEXT_ONTOLOGY: list[tuple[str, str, float]] = [
    (r"\b(search|query|q|input|field|param|parameter)\b", "context_input_param", 3.0),
    (r"\b(login|signin|auth|session|token|cookie|header)\b", "context_auth_token", 3.0),
    (r"\b(upload|file|filename|attachment)\b", "context_file_upload", 3.0),
    (r"\b(api|v1|v2|endpoint|route|json|graphql)\b", "context_api_endpoint", 2.0),
    (r"\b(admin|dashboard|management|panel)\b", "context_admin_area", 2.0),
]


class BaseEmbedder(ABC):
    """Interfaz base para modelos de embedding."""

    @abstractmethod
    def embed(self, text: str, dim: int = DEFAULT_EMBEDDING_DIM) -> list[float]:
        """Calcula el vector de embedding normalizado (L2 = 1.0) para el texto."""


class SemanticSecurityEmbedder(BaseEmbedder):
    """Embedder semántico de dominio de seguridad con canonicalización ontológica y subpalabras."""

    def __init__(self, dim: int = DEFAULT_EMBEDDING_DIM) -> None:
        self.dim = dim

    def _canonicalize(self, text: str) -> list[tuple[str, float]]:
        t = text.lower().strip()
        items: list[tuple[str, float]] = []

        # 1. Detección de conceptos de vulnerabilidades (ontología)
        for pattern, concept, weight in VULNERABILITY_ONTOLOGY:
            if re.search(pattern, t):
                items.append((concept, weight))

        # 2. Detección de contexto (parámetro, auth, endpoint)
        for pattern, concept, weight in CONTEXT_ONTOLOGY:
            if re.search(pattern, t):
                items.append((concept, weight))

        # 3. Descomposición léxica y n-gramas de subpalabras (FastText style)
        words = re.findall(r"[a-z0-9_]+", t)
        for w in words:
            items.append((w, 0.8))
            if len(w) >= 4:
                for n in range(3, min(6, len(w))):
                    for i in range(len(w) - n + 1):
                        items.append((w[i : i + n], 0.2))

        return items

    def embed(self, text: str, dim: int | None = None) -> list[float]:
        d = dim if dim is not None else self.dim
        items = self._canonicalize(text)
        if not items:
            return [0.0] * d

        vec = [0.0] * d
        for token, weight in items:
            # Hash criptográfico estable con proyección de signo alternada
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            h = int(digest, 16)
            index = h % d
            sign = 1.0 if ((h >> 16) & 1) else -1.0
            vec[index] += sign * weight

        # Normalización unitaria (L2 norm)
        norm = math.sqrt(sum(x * x for x in vec))
        if norm == 0.0:
            return [0.0] * d
        return [x / norm for x in vec]


class FastEmbedEmbedder(BaseEmbedder):
    """Embedder basado en transformadores locales ONNX con FastEmbed."""

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        try:
            from fastembed import TextEmbedding

            self._model = TextEmbedding(model_name=model_name)
        except ImportError as e:
            raise ImportError(
                "fastembed no esta instalado. Instálelo con: uv add fastembed"
            ) from e

    def embed(self, text: str, dim: int = DEFAULT_EMBEDDING_DIM) -> list[float]:
        embeddings = list(self._model.embed([text]))
        raw_vec = [float(x) for x in embeddings[0]]
        norm = math.sqrt(sum(x * x for x in raw_vec))
        if norm == 0.0:
            return [0.0] * len(raw_vec)
        return [x / norm for x in raw_vec]


class APIEmbedder(BaseEmbedder):
    """Embedder mediante servicio HTTP compatible con OpenAI / Ollama."""

    def __init__(
        self,
        endpoint_url: str,
        api_key: str | None = None,
        model: str = "text-embedding-3-small",
        timeout: float = 10.0,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def embed(self, text: str, dim: int = DEFAULT_EMBEDDING_DIM) -> list[float]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {"input": text, "model": self.model}
        response = httpx.post(self.endpoint_url, json=payload, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        raw_vec = data["data"][0]["embedding"]
        norm = math.sqrt(sum(x * x for x in raw_vec))
        if norm == 0.0:
            return [0.0] * len(raw_vec)
        return [float(x) / norm for x in raw_vec]


_DEFAULT_EMBEDDER = SemanticSecurityEmbedder()


def get_embedder(provider: str = "semantic", **kwargs: Any) -> BaseEmbedder:
    """Fábrica de embedders: semantic | fastembed | api."""
    if provider == "semantic":
        return SemanticSecurityEmbedder(**kwargs)
    if provider == "fastembed":
        return FastEmbedEmbedder(**kwargs)
    if provider == "api":
        return APIEmbedder(**kwargs)
    raise ValueError(f"Proveedor de embedding desconocido: {provider}")


def embed(
    text: str,
    dim: int = DEFAULT_EMBEDDING_DIM,
    embedder: BaseEmbedder | None = None,
) -> list[float]:
    """Genera vector de embedding semántico normalizado."""
    active_embedder = embedder if embedder is not None else _DEFAULT_EMBEDDER
    return active_embedder.embed(text, dim=dim)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Similitud coseno entre dos vectores (0.0 - 1.0)."""
    dot_product = sum(x * y for x, y in zip(a, b, strict=False))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    val = dot_product / (norm_a * norm_b)
    return max(0.0, min(1.0, float(val)))


@dataclass
class StoredFindingVector:
    finding_id: int | None
    text: str
    vector: list[float]


class FindingDeduplicator:
    """Detecta hallazgos duplicados mediante similitud semántica con persistencia en disco."""

    def __init__(
        self,
        threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        dim: int = DEFAULT_EMBEDDING_DIM,
        storage_path: str | Path | None = None,
        embedder: BaseEmbedder | None = None,
    ) -> None:
        self.threshold = threshold
        self.dim = dim
        self.storage_path = (
            Path(storage_path) if storage_path is not None else Path("state/vector-index/dedup.json")
        )
        self.embedder = embedder if embedder is not None else _DEFAULT_EMBEDDER
        self._entries: list[StoredFindingVector] = []
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            entries = data.get("entries") or []
            self._entries = [
                StoredFindingVector(
                    finding_id=entry.get("finding_id"),
                    text=entry.get("text") or "",
                    vector=list(entry.get("vector") or []),
                )
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
        entry = StoredFindingVector(
            finding_id=finding_id,
            text=text,
            vector=self.embedder.embed(text, self.dim),
        )
        self._entries.append(entry)
        self._save()
        return entry

    def check_duplicate(self, text: str) -> tuple[bool, float, StoredFindingVector | None]:
        """Compara un hallazgo contra el índice persistido; retorna (es_duplicado, similitud, mejor_coincidente)."""
        vector = self.embedder.embed(text, self.dim)
        best_match: StoredFindingVector | None = None
        best_similarity = 0.0

        for entry in self._entries:
            similarity = cosine_similarity(vector, entry.vector)
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = entry

        is_duplicate = best_match is not None and best_similarity >= self.threshold
        return is_duplicate, best_similarity, best_match
