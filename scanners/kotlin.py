"""Kotlin scanner: Ktor, Spring."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class KotlinScanner(BaseScanner):
    """Kotlin scanner supporting Ktor and Spring frameworks."""

    @property
    def language(self) -> Language:
        return Language.KOTLIN

    @property
    def extensions(self) -> Set[str]:
        return {".kt", ".kts"}

    @property
    def comment_prefixes(self) -> tuple:
        return ("//", "*")

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== KTOR =====================
            PatternDef(
                regex=r'\b(get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']',
                framework="Ktor",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'route\s*\(\s*["\']([^"\']+)["\']',
                framework="Ktor",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="route group",
            ),
            PatternDef(
                regex=r'routing\s*\{',
                framework="Ktor",
                kind=EndpointKind.CONFIG,
                label="routing {}",
            ),
            PatternDef(
                regex=r'embeddedServer\s*\(',
                framework="Ktor",
                kind=EndpointKind.ENTRY,
                label="embeddedServer",
            ),

            # ===================== SPRING (KOTLIN) =====================
            PatternDef(
                regex=r'@GetMapping\s*(?:\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\'])?',
                framework="Spring",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="GET",
            ),
            PatternDef(
                regex=r'@PostMapping\s*(?:\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\'])?',
                framework="Spring",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="POST",
            ),
            PatternDef(
                regex=r'@PutMapping\s*(?:\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\'])?',
                framework="Spring",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="PUT",
            ),
            PatternDef(
                regex=r'@DeleteMapping\s*(?:\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\'])?',
                framework="Spring",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="DELETE",
            ),
            PatternDef(
                regex=r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
                framework="Spring",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'@RestController',
                framework="Spring",
                kind=EndpointKind.CONFIG,
                label="@RestController",
            ),
        ]
