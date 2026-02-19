"""Spec scanner: OpenAPI/Swagger (.json/.yaml) and GraphQL schema files."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef, Endpoint


class SpecScanner(BaseScanner):
    """
    Static Specification File Scanner:
    - OpenAPI/Swagger (.json, .yaml, .yml)
    - GraphQL Schema (.graphql, .gql)
    """

    @property
    def language(self) -> Language:
        return Language.UNKNOWN

    @property
    def extensions(self) -> Set[str]:
        return {".json", ".yaml", ".yml", ".graphql", ".gql"}

    @property
    def patterns(self) -> List[PatternDef]:
        # Patterns not used - we do deep parsing instead
        return []

    def scan_file(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Override to use spec-specific parsing."""
        ext = file_path.suffix.lower()

        if ext in {".json", ".yaml", ".yml"}:
            return self._scan_openapi(file_path, content, lines)
        elif ext in {".graphql", ".gql"}:
            return self._scan_graphql(file_path, content, lines)

        return []

    def _scan_openapi(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """
        Parse OpenAPI/Swagger specs.

        Detection: Look for 'openapi:', 'swagger:', or 'paths:' keywords
        Extraction: Parse paths section and extract routes + methods
        """
        results = []

        # Detection: Check if this is actually an OpenAPI/Swagger file
        is_openapi = False
        content_lower = content.lower()

        if any(kw in content_lower for kw in ['"openapi":', "'openapi':", 'openapi:', '"swagger":', "'swagger':", 'swagger:', '"paths":', "'paths':", 'paths:']):
            is_openapi = True

        if not is_openapi:
            return []

        # Parse based on file extension
        ext = file_path.suffix.lower()

        try:
            if ext == ".json":
                # Parse JSON
                spec = json.loads(content)
            elif ext in {".yaml", ".yml"}:
                # Try PyYAML if available, otherwise use simple text parsing
                try:
                    import yaml
                    spec = yaml.safe_load(content)
                except ImportError:
                    # Fallback: Simple text-based parsing for YAML
                    return self._scan_openapi_text(file_path, content, lines)
            else:
                return []

            # Resolve local-file $ref references before processing paths
            spec = self._resolve_refs(spec, file_path.parent)

            # Extract paths section
            if not isinstance(spec, dict) or "paths" not in spec:
                return []

            paths = spec.get("paths", {})

            for route, path_obj in paths.items():
                if not isinstance(path_obj, dict):
                    continue

                # Find line number for this route
                line_num = self._find_line_number(content, lines, route)

                # Extract HTTP methods
                http_methods = []
                for method in ["get", "post", "put", "delete", "patch", "head", "options", "trace"]:
                    if method in path_obj:
                        http_methods.append(method.upper())

                # If no methods found, create a generic entry
                if not http_methods:
                    http_methods = ["ANY"]

                # Create an endpoint for each method
                for method in http_methods:
                    results.append(Endpoint(
                        file_path=str(file_path),
                        line_number=line_num,
                        language=Language.UNKNOWN,
                        framework="OpenAPI-Spec",
                        kind=EndpointKind.ENDPOINT,
                        method=method,
                        route=route,
                        raw_match=f"{method} {route}",
                        context=self.get_context(lines, line_num - 1) if line_num > 0 else [],
                        metadata={"source": "openapi", "spec_file": str(file_path)},
                    ))

        except (json.JSONDecodeError, Exception):
            # If parsing fails, try text-based fallback
            return self._scan_openapi_text(file_path, content, lines)

        return results

    def _scan_openapi_text(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """
        Fallback text-based OpenAPI parser for when YAML library is not available.
        Uses regex to extract paths.
        """
        results = []

        # Pattern to match path definitions in YAML
        # Matches: /api/users: or "/api/users":
        path_pattern = r'^\s*["\']?(/[^"\':\s]*)["\']?\s*:\s*$'

        # Pattern to match HTTP methods
        method_pattern = r'^\s*(get|post|put|delete|patch|head|options|trace)\s*:\s*$'

        current_path = None

        for i, line in enumerate(lines):
            # Check for path definition
            path_match = re.match(path_pattern, line, re.IGNORECASE)
            if path_match:
                current_path = path_match.group(1)
                continue

            # Check for method under current path
            if current_path:
                method_match = re.match(method_pattern, line, re.IGNORECASE)
                if method_match:
                    method = method_match.group(1).upper()

                    results.append(Endpoint(
                        file_path=str(file_path),
                        line_number=i + 1,
                        language=Language.UNKNOWN,
                        framework="OpenAPI-Spec",
                        kind=EndpointKind.ENDPOINT,
                        method=method,
                        route=current_path,
                        raw_match=f"{method} {current_path}",
                        context=self.get_context(lines, i),
                        metadata={"source": "openapi", "spec_file": str(file_path)},
                    ))

        return results

    def _scan_graphql(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """
        Parse GraphQL schema files.

        Detection: Look for 'type Query' or 'type Mutation'
        Extraction: Extract field names from these blocks
        """
        results = []

        # Detection
        if not re.search(r'\btype\s+(Query|Mutation)\b', content, re.IGNORECASE):
            return []

        # Extract Query fields
        query_pattern = r'type\s+Query\s*\{([^}]+)\}'
        for match in re.finditer(query_pattern, content, re.DOTALL | re.IGNORECASE):
            block = match.group(1)
            block_start = match.start()
            line_offset = content[:block_start].count('\n')

            # Extract field names: fieldName(...): ReturnType or fieldName: ReturnType
            field_pattern = r'^\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*'

            for field_match in re.finditer(field_pattern, block, re.MULTILINE):
                field_name = field_match.group(1)
                field_line = line_offset + block[:field_match.start()].count('\n') + 1

                results.append(Endpoint(
                    file_path=str(file_path),
                    line_number=field_line,
                    language=Language.UNKNOWN,
                    framework="GraphQL-Schema",
                    kind=EndpointKind.ENDPOINT,
                    method="QUERY",
                    route=f"Query.{field_name}",
                    raw_match=field_match.group(0),
                    context=self.get_context(lines, field_line - 1),
                    metadata={"source": "graphql", "operation": "query", "field": field_name},
                ))

        # Extract Mutation fields
        mutation_pattern = r'type\s+Mutation\s*\{([^}]+)\}'
        for match in re.finditer(mutation_pattern, content, re.DOTALL | re.IGNORECASE):
            block = match.group(1)
            block_start = match.start()
            line_offset = content[:block_start].count('\n')

            field_pattern = r'^\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*'

            for field_match in re.finditer(field_pattern, block, re.MULTILINE):
                field_name = field_match.group(1)
                field_line = line_offset + block[:field_match.start()].count('\n') + 1

                results.append(Endpoint(
                    file_path=str(file_path),
                    line_number=field_line,
                    language=Language.UNKNOWN,
                    framework="GraphQL-Schema",
                    kind=EndpointKind.ENDPOINT,
                    method="MUTATION",
                    route=f"Mutation.{field_name}",
                    raw_match=field_match.group(0),
                    context=self.get_context(lines, field_line - 1),
                    metadata={"source": "graphql", "operation": "mutation", "field": field_name},
                ))

        return results

    def _resolve_refs(self, spec: object, base_dir: Path) -> object:
        """Recursively resolve local-file $ref values (not fragment or HTTP refs)."""
        if isinstance(spec, dict):
            if '$ref' in spec:
                ref = spec['$ref']
                if not ref.startswith('#') and not ref.startswith('http'):
                    ref_path = ref.split('#')[0]
                    ref_file = base_dir / ref_path
                    if ref_file.exists() and ref_file.suffix.lower() in {'.json', '.yaml', '.yml'}:
                        try:
                            raw = ref_file.read_text(encoding='utf-8')
                            if ref_file.suffix.lower() == '.json':
                                return self._resolve_refs(json.loads(raw), ref_file.parent)
                            else:
                                import yaml
                                return self._resolve_refs(yaml.safe_load(raw), ref_file.parent)
                        except Exception:
                            pass
            return {k: self._resolve_refs(v, base_dir) for k, v in spec.items()}
        elif isinstance(spec, list):
            return [self._resolve_refs(item, base_dir) for item in spec]
        return spec

    def _find_line_number(self, content: str, lines: List[str], route: str) -> int:
        """Find the line number where a route is defined."""
        # Try to find the route string in the content
        pattern = re.escape(route)
        match = re.search(pattern, content)
        if match:
            return content[:match.start()].count('\n') + 1
        return 1
