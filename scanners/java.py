"""Java scanner: Spring, Vert.x, Armeria, JSP/Servlet, Play Framework, JAX-RS."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef, Endpoint


class JavaScanner(BaseScanner):
    """Java scanner for Spring Boot and other frameworks."""

    @property
    def language(self) -> Language:
        return Language.JAVA

    @property
    def extensions(self) -> Set[str]:
        return {".java"}

    @property
    def comment_prefixes(self) -> tuple:
        return ("//", "*")

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

            # ===================== JAX-RS =====================
            PatternDef(
                regex=r'@Path\s*\(\s*["\']([^"\']+)["\']',
                framework="JAX-RS",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b(?!\s*\()',
                framework="JAX-RS",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
            ),
        ]

    def scan_file(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Scan file with deep Spring controller parsing + pattern fallback."""
        results = []
        results.extend(self._deep_scan_controllers(file_path, content, lines))
        results.extend(self.scan_with_patterns(file_path, content, lines))
        return results

    def _combine_routes(self, base_route: str, method_route: str) -> str:
        """Combine class-level base route with method-level route.

        In Spring MVC, method-level routes are always relative to the class
        @RequestMapping prefix — even when the method route starts with '/'.
        """
        base = base_route.strip('/') if base_route else ""
        method = method_route.strip('/') if method_route else ""

        if base and method:
            return f"/{base}/{method}"
        elif base:
            return f"/{base}"
        elif method:
            return f"/{method}"
        else:
            return "/"

    def _deep_scan_controllers(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Find Spring @RestController/@Controller classes and combine class-level
        @RequestMapping prefix with method-level @GetMapping/@PostMapping etc."""
        results = []

        # Match @RestController or @Controller before a class declaration
        class_re = re.compile(
            r'@(?:Rest)?Controller\b.*?(?:\bclass\s+(\w+))',
            re.DOTALL,
        )

        verb_map = {
            'GetMapping': 'GET',
            'PostMapping': 'POST',
            'PutMapping': 'PUT',
            'DeleteMapping': 'DELETE',
            'PatchMapping': 'PATCH',
        }

        for class_match in class_re.finditer(content):
            class_name = class_match.group(1) or "Unknown"
            class_ann_start = class_match.start()
            class_body_keyword_end = class_match.end()

            # Look back up to 500 chars before the annotation for @RequestMapping
            lookback_start = max(0, class_ann_start - 500)
            preceding = content[lookback_start:class_ann_start]

            # Also check within the annotation block itself (common pattern)
            annotation_block = content[class_ann_start:class_body_keyword_end]

            class_prefix = ""
            rm_match = re.search(
                r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
                preceding + annotation_block,
            )
            if rm_match:
                class_prefix = rm_match.group(1)

            # Brace-match the class body
            brace_start = content.find('{', class_body_keyword_end)
            if brace_start == -1:
                continue

            depth = 1
            pos = brace_start + 1
            while depth > 0 and pos < len(content):
                if content[pos] == '{':
                    depth += 1
                elif content[pos] == '}':
                    depth -= 1
                pos += 1
            brace_end = pos

            class_body = content[brace_start:brace_end]
            class_body_start_line = content[:brace_start].count('\n')

            # Find each HTTP verb mapping annotation inside the class body
            for verb_attr, http_method in verb_map.items():
                verb_re = re.compile(
                    rf'@{verb_attr}\s*(?:\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\'](?:[^)]*))?\s*\)',
                )
                # Also match @GetMapping without parentheses
                verb_bare_re = re.compile(rf'@{verb_attr}(?!\s*\()')

                for vm in list(verb_re.finditer(class_body)) + list(verb_bare_re.finditer(class_body)):
                    groups = vm.groups() if hasattr(vm, 'groups') else ()
                    method_route = (groups[0] if groups and groups[0] is not None else "")
                    full_route = self._combine_routes(class_prefix, method_route)

                    verb_pos = vm.start()
                    line_num = class_body_start_line + class_body[:verb_pos].count('\n') + 1

                    results.append(Endpoint(
                        file_path=str(file_path),
                        line_number=line_num,
                        language=self.language,
                        framework="Spring",
                        kind=EndpointKind.ENDPOINT,
                        method=http_method,
                        route=full_route,
                        raw_match=vm.group(0)[:150],
                        context=self.get_context(lines, line_num - 1),
                        metadata={
                            "controller": class_name,
                            "class_route": class_prefix,
                            "method_route": method_route,
                        },
                    ))

        return results
