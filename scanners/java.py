"""Java scanner: Spring, Vert.x, Armeria, JSP/Servlet, Play Framework."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class JavaScanner(BaseScanner):
    """Java scanner for Spring Boot and other frameworks."""

    @property
    def language(self) -> Language:
        return Language.JAVA

    @property
    def extensions(self) -> Set[str]:
        return {".java"}

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            PatternDef(
                regex=r'@RestController',
                framework="Spring",
                kind=EndpointKind.CONFIG,
                label="@RestController",
            ),
            PatternDef(
                regex=r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
                framework="Spring",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
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
                regex=r'@PatchMapping\s*(?:\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\'])?',
                framework="Spring",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="PATCH",
            ),

            # ===================== VERT.X =====================
            PatternDef(
                regex=r'router\.(get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']',
                framework="Vert.x",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'router\.route\s*\(\s*["\']([^"\']+)["\']',
                framework="Vert.x",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'\.method\s*\(\s*HttpMethod\.(GET|POST|PUT|DELETE|PATCH)\s*\)',
                framework="Vert.x",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
            ),

            # ===================== ARMERIA =====================
            PatternDef(
                regex=r'@(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="Armeria",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'\.service\s*\(\s*["\']([^"\']+)["\']',
                framework="Armeria",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'Server\.builder\s*\(',
                framework="Armeria",
                kind=EndpointKind.CONFIG,
                label="Armeria Server",
            ),

            # ===================== JSP / SERVLET =====================
            PatternDef(
                regex=r'<url-pattern>\s*([^<]+)\s*</url-pattern>',
                framework="JSP/Servlet",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'@WebServlet\s*\(\s*["\']([^"\']+)["\']',
                framework="JSP/Servlet",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),

            # ===================== PLAY FRAMEWORK (Java) =====================
            PatternDef(
                regex=r'^(GET|POST|PUT|DELETE|PATCH)\s+(/[^\s]+)',
                framework="Play Framework",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
        ]
