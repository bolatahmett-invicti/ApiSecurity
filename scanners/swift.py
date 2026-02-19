"""Swift scanner: Vapor, Hummingbird, Kitura."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class SwiftScanner(BaseScanner):
    """Swift scanner supporting Vapor, Hummingbird, and Kitura frameworks."""

    @property
    def language(self) -> Language:
        return Language.SWIFT

    @property
    def extensions(self) -> Set[str]:
        return {".swift"}

    @property
    def comment_prefixes(self) -> tuple:
        return ("//", "*")

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== VAPOR =====================
            PatternDef(
                regex=r'app\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                framework="Vapor",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'routes\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                framework="Vapor",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'app\.grouped\s*\(\s*["\']([^"\']+)["\']',
                framework="Vapor",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="grouped",
            ),
            PatternDef(
                regex=r'app\.on\s*\(\s*\.(get|post|put|patch|delete)',
                framework="Vapor",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
            ),

            # ===================== HUMMINGBIRD =====================
            PatternDef(
                regex=r'router\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                framework="Hummingbird",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'router\.add\s*\(\s*["\']([^"\']+)["\'],\s*method:\s*\.(get|post|put|patch|delete)',
                framework="Hummingbird",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                method_group=2,
            ),
            PatternDef(
                regex=r'HBApplication\s*\(',
                framework="Hummingbird",
                kind=EndpointKind.ENTRY,
                label="HBApplication",
            ),

            # ===================== KITURA =====================
            PatternDef(
                regex=r'router\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
                framework="Kitura",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'Kitura\.addHTTPServer\s*\(',
                framework="Kitura",
                kind=EndpointKind.ENTRY,
                label="Kitura.addHTTPServer",
            ),
            PatternDef(
                regex=r'router\.all\s*\(\s*["\']([^"\']+)["\']',
                framework="Kitura",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="ANY",
            ),
        ]
