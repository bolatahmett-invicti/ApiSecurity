"""Elixir scanner: Phoenix, Plug."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class ElixirScanner(BaseScanner):
    """Elixir scanner supporting Phoenix and Plug frameworks."""

    @property
    def language(self) -> Language:
        return Language.ELIXIR

    @property
    def extensions(self) -> Set[str]:
        return {".ex", ".exs"}

    @property
    def comment_prefixes(self) -> tuple:
        return ("#",)

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== PHOENIX =====================
            PatternDef(
                regex=r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\'],\s+\w+Controller',
                framework="Phoenix",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'resources\s+["\']([^"\']+)["\'],\s+\w+Controller',
                framework="Phoenix",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="resources",
            ),
            PatternDef(
                regex=r'scope\s+["\']([^"\']+)["\']',
                framework="Phoenix",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="scope",
            ),
            PatternDef(
                regex=r'pipe_through\s+:(\w+)',
                framework="Phoenix",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="pipe_through",
            ),
            PatternDef(
                regex=r'live\s+["\']([^"\']+)["\'],\s+\w+Live',
                framework="Phoenix",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="LiveView",
            ),

            # ===================== PLUG =====================
            PatternDef(
                regex=r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\']',
                framework="Plug",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'match\s+["\']([^"\']+)["\']',
                framework="Plug",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'forward\s+["\']([^"\']+)["\']',
                framework="Plug",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="forward",
            ),
        ]
