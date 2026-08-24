"""Immutable graph indexes over one retained checked document."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


@dataclass(frozen=True)
class CheckedIndex:
    """Read-only stable-ID tables built from an already checked same-read model."""

    document: Mapping[str, Any]
    profile: str
    semantic_fingerprint: str
    semantic_projection: bytes
    source_sha256: str
    declarations: Mapping[str, Mapping[str, Any]]
    components: Mapping[str, Mapping[str, Any]]
    discriminants: Mapping[str, Mapping[str, Any]]
    entities: Mapping[str, Mapping[str, Any]]
    enum_literals: Mapping[str, Mapping[str, Any]]
    generic_actuals: Mapping[str, Mapping[str, Any]]
    variants: Mapping[str, Mapping[str, Any]]


def index_checked(checked: Any) -> CheckedIndex:
    document = _freeze(checked.document)

    def table(name: str) -> Mapping[str, Mapping[str, Any]]:
        return MappingProxyType({item["stable_id"]: item for item in document[name]})

    return CheckedIndex(
        document=document,
        profile=checked.profile,
        semantic_fingerprint=checked.semantic_fingerprint,
        semantic_projection=checked.semantic_projection,
        source_sha256=checked.source_sha256,
        declarations=table("declarations"),
        components=table("components"),
        discriminants=table("discriminants"),
        entities=table("entities"),
        enum_literals=table("enum_literals"),
        generic_actuals=table("generic_actuals"),
        variants=table("variants"),
    )


__all__ = ["CheckedIndex", "index_checked"]
