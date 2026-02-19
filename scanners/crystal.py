"""Crystal scanner: Kemal, Lucky, Amber, Grip, Marten."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class CrystalScanner(BaseScanner):
    """Crystal scanner supporting Amber, Grip, Kemal, Lucky, and Marten."""

    @property
    def language(self) -> Language:
        return Language.CRYSTAL

    @property
    def extensions(self) -> Set[str]:
        return {".cr"}

    @property
    def comment_prefixes(self) -> tuple:
        return ("#",)

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== KEMAL =====================
            PatternDef(
                regex=r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\'].*\bdo\b',
                framework="Kemal",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'Kemal\.run',
                framework="Kemal",
                kind=EndpointKind.ENTRY,
                label="Kemal.run",
            ),

            # ===================== LUCKY =====================
            PatternDef(
                regex=r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\']',
                framework="Lucky",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'resources\s+:(\w+),\s+\w+',
                framework="Lucky",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="resources",
            ),

            # ===================== AMBER =====================
            PatternDef(
                regex=r'routes\s+:\w+,\s+(\w+Router)',
                framework="Amber",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="routes",
            ),
            PatternDef(
                regex=r'Amber::Server\.start',
                framework="Amber",
                kind=EndpointKind.ENTRY,
                label="Amber::Server",
            ),

            # ===================== GRIP =====================
            PatternDef(
                regex=r'def\s+(get|post|put|delete|patch)\s+["\']([^"\']+)["\']',
                framework="Grip",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),

            # ===================== MARTEN =====================
            PatternDef(
                regex=r'path\s+["\']([^"\']+)["\'],\s+\w+',
                framework="Marten",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'Marten\.setup',
                framework="Marten",
                kind=EndpointKind.ENTRY,
                label="Marten.setup",
            ),
        ]
