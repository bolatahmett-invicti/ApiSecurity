"""Scala scanner: Akka HTTP, Play Framework, Scalatra."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class ScalaScanner(BaseScanner):
    """Scala scanner supporting Akka HTTP, Play Framework, and Scalatra."""

    @property
    def language(self) -> Language:
        return Language.SCALA

    @property
    def extensions(self) -> Set[str]:
        return {".scala"}

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== PLAY FRAMEWORK =====================
            PatternDef(
                regex=r'^(GET|POST|PUT|DELETE|PATCH)\s+(/[^\s]+)',
                framework="Play Framework",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),

            # ===================== AKKA HTTP =====================
            PatternDef(
                regex=r'\bpath\s*\(\s*["\']([^"\']+)["\']',
                framework="Akka HTTP",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'pathPrefix\s*\(\s*["\']([^"\']+)["\']',
                framework="Akka HTTP",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="pathPrefix",
            ),
            PatternDef(
                regex=r'\b(get|post|put|delete|patch|head|options)\s*\{',
                framework="Akka HTTP",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
            ),
            PatternDef(
                regex=r'path\s*!\s*["\']([^"\']+)["\']',
                framework="Akka HTTP",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'Http\s*\(\s*\)\s*\.bindAndHandle',
                framework="Akka HTTP",
                kind=EndpointKind.ENTRY,
                label="Http().bindAndHandle",
            ),

            # ===================== SCALATRA =====================
            PatternDef(
                regex=r'\b(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                framework="Scalatra",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'extends\s+ScalatraServlet',
                framework="Scalatra",
                kind=EndpointKind.CONFIG,
                label="ScalatraServlet",
            ),
        ]
