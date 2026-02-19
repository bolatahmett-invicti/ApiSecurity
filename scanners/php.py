"""PHP scanner: Laravel, Symfony."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class PHPScanner(BaseScanner):
    """PHP scanner supporting Laravel and Symfony frameworks."""

    @property
    def language(self) -> Language:
        return Language.PHP

    @property
    def extensions(self) -> Set[str]:
        return {".php"}

    @property
    def comment_prefixes(self) -> tuple:
        return ("//", "#", "*")

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== LARAVEL =====================
            PatternDef(
                regex=r'Route::(get|post|put|patch|delete|any)\s*\(\s*["\']([^"\']+)["\']',
                framework="Laravel",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'Route::resource\s*\(\s*["\']([^"\']+)["\']',
                framework="Laravel",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="resource",
            ),
            PatternDef(
                regex=r'Route::apiResource\s*\(\s*["\']([^"\']+)["\']',
                framework="Laravel",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="apiResource",
            ),
            PatternDef(
                regex=r'Route::group\s*\(\s*\[',
                framework="Laravel",
                kind=EndpointKind.CONFIG,
                label="Route::group",
            ),
            PatternDef(
                regex=r'->prefix\s*\(\s*["\']([^"\']+)["\']',
                framework="Laravel",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="prefix",
            ),
            PatternDef(
                regex=r'Route::controller\s*\(\s*\w+::class\s*\)->group',
                framework="Laravel",
                kind=EndpointKind.CONFIG,
                label="Route::controller",
            ),

            # ===================== SYMFONY =====================
            PatternDef(
                regex=r'#\[Route\s*\(\s*["\']([^"\']+)["\'](?:[^)]*methods:\s*\[([^\]]+)\])?',
                framework="Symfony",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                method_group=2,
            ),
            PatternDef(
                regex=r'@Route\s*\(\s*["\']([^"\']+)["\'](?:[^)]*methods\s*=\s*\{([^}]+)\})?',
                framework="Symfony",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                method_group=2,
            ),
            PatternDef(
                regex=r'#\[Get\s*\(\s*["\']([^"\']+)["\']',
                framework="Symfony",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="GET",
            ),
            PatternDef(
                regex=r'#\[Post\s*\(\s*["\']([^"\']+)["\']',
                framework="Symfony",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="POST",
            ),
        ]
