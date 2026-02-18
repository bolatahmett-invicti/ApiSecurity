"""Ruby scanner: Rails, Sinatra, Hanami."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class RubyScanner(BaseScanner):
    """Ruby scanner supporting Rails, Sinatra, and Hanami frameworks."""

    @property
    def language(self) -> Language:
        return Language.RUBY

    @property
    def extensions(self) -> Set[str]:
        return {".rb"}

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== RAILS =====================
            PatternDef(
                regex=r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\']',
                framework="Rails",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'resources\s+:(\w+)',
                framework="Rails",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="resources",
            ),
            PatternDef(
                regex=r'resource\s+:(\w+)',
                framework="Rails",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="resource",
            ),
            PatternDef(
                regex=r'namespace\s+:(\w+)',
                framework="Rails",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="namespace",
            ),
            PatternDef(
                regex=r'scope\s+["\']([^"\']+)["\']',
                framework="Rails",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="scope",
            ),
            PatternDef(
                regex=r'root\s+["\']([^"\']+)["\']',
                framework="Rails",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="root",
            ),
            PatternDef(
                regex=r'match\s+["\']([^"\']+)["\'](?:.*?via:\s*:(\w+))?',
                framework="Rails",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                method_group=2,
            ),

            # ===================== SINATRA =====================
            PatternDef(
                regex=r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\'].*\bdo\b',
                framework="Sinatra",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),

            # ===================== HANAMI =====================
            PatternDef(
                regex=r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\'],\s*to:',
                framework="Hanami",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'slice\s*\(\s*:(\w+)',
                framework="Hanami",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="slice",
            ),
        ]
