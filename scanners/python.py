"""Python scanner: Flask, FastAPI, Django, Sanic, Tornado, MCP, Legacy."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set

from .base import (
    BaseScanner, Language, EndpointKind, PatternDef, Endpoint
)


class PythonScanner(BaseScanner):
    """
    Python scanner with HYBRID detection:
    - Legacy/Custom: WSGI, Gevent, frontend handlers, OpenAPIRouter, argparse workers
    - Modern: Flask, FastAPI, Django
    - MCP: Model Context Protocol tools/resources
    """

    @property
    def language(self) -> Language:
        return Language.PYTHON

    @property
    def extensions(self) -> Set[str]:
        return {".py"}

    @property
    def comment_prefixes(self) -> tuple:
        return ("#",)

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== FLASK =====================
            PatternDef(
                regex=r'@(?:app|blueprint|bp)\.route\s*\(\s*["\']([^"\']+)["\'](?:.*?methods\s*=\s*\[([^\]]+)\])?',
                framework="Flask",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                method_group=2,
            ),
            PatternDef(
                regex=r'@(?:app|blueprint|bp)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="Flask",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),

            # ===================== FASTAPI =====================
            PatternDef(
                regex=r'@(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
                framework="FastAPI",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'APIRouter\s*\(\s*(?:prefix\s*=\s*)?["\']([^"\']+)["\']',
                framework="FastAPI",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                label="APIRouter",
            ),

            # ===================== DJANGO =====================
            PatternDef(
                regex=r'path\s*\(\s*["\']([^"\']+)["\']',
                framework="Django",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'url\s*\(\s*r?["\']([^"\']+)["\']',
                framework="Django",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),

            # ===================== LEGACY/CUSTOM (CRITICAL) =====================
            # WSGI/Gevent Server
            PatternDef(
                regex=r'gevent\.pywsgi\.WSGIServer|from\s+gevent\.pywsgi\s+import\s+WSGIServer',
                framework="Gevent-WSGI",
                kind=EndpointKind.ENTRY,
                label="WSGI Server Entry",
            ),
            PatternDef(
                regex=r'WSGIServer\s*\(\s*\(?["\']?([^"\')\s,]*)["\']?,?\s*(\d+)?\)?',
                framework="Gevent-WSGI",
                kind=EndpointKind.ENTRY,
                route_group=1,
                label="WSGI Server",
            ),
            # OpenAPIRouter
            PatternDef(
                regex=r'OpenAPIRouter\s*\(',
                framework="OpenAPI-Custom",
                kind=EndpointKind.ENDPOINT,
                label="OpenAPIRouter",
            ),
            PatternDef(
                regex=r'\.add_api_route\s*\(\s*["\']([^"\']+)["\']',
                framework="OpenAPI-Custom",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            # Manual route registration
            PatternDef(
                regex=r'\.add_route\s*\(\s*["\'](\w+)["\'],\s*["\']([^"\']+)["\']',
                framework="Custom-Router",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'\.add_url_rule\s*\(\s*["\']([^"\']+)["\']',
                framework="Flask-Manual",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            # Argparse Workers
            PatternDef(
                regex=r'add_argument\s*\(\s*["\']--kind["\']',
                framework="Worker-CLI",
                kind=EndpointKind.WORKER,
                label="Worker --kind",
            ),
            PatternDef(
                regex=r'add_argument\s*\(\s*["\']--conf["\']',
                framework="Worker-CLI",
                kind=EndpointKind.WORKER,
                label="Worker --conf",
            ),
            PatternDef(
                regex=r'add_argument\s*\(\s*["\']--worker["\']',
                framework="Worker-CLI",
                kind=EndpointKind.WORKER,
                label="Worker --worker",
            ),
            # Celery
            PatternDef(
                regex=r'@(?:app|celery)\.task(?:\s*\(\s*(?:name\s*=\s*)?["\']([^"\']+)["\'])?',
                framework="Celery",
                kind=EndpointKind.WORKER,
                route_group=1,
                label="Celery Task",
            ),
            # Other WSGI servers
            PatternDef(
                regex=r'waitress\.serve\s*\(',
                framework="Waitress",
                kind=EndpointKind.ENTRY,
                label="Waitress Server",
            ),
            PatternDef(
                regex=r'uvicorn\.run\s*\(',
                framework="Uvicorn",
                kind=EndpointKind.ENTRY,
                label="Uvicorn ASGI",
            ),
            PatternDef(
                regex=r'gunicorn',
                framework="Gunicorn",
                kind=EndpointKind.ENTRY,
                label="Gunicorn",
            ),

            # ===================== MCP (Model Context Protocol) =====================
            PatternDef(
                regex=r'@(?:server|mcp)\.tool\s*\(\s*\)\s*(?:async\s+)?def\s+(\w+)',
                framework="MCP",
                kind=EndpointKind.TOOL,
                route_group=1,
            ),
            PatternDef(
                regex=r'@(?:server|mcp)\.tool\s*\(\s*(?:name\s*=\s*)?["\']([^"\']+)["\']',
                framework="MCP",
                kind=EndpointKind.TOOL,
                route_group=1,
            ),
            PatternDef(
                regex=r'@(?:server|mcp)\.list_tools\s*\(\s*\)',
                framework="MCP",
                kind=EndpointKind.TOOL,
                label="list_tools",
            ),
            PatternDef(
                regex=r'@(?:server|mcp)\.call_tool\s*\(\s*\)',
                framework="MCP",
                kind=EndpointKind.TOOL,
                label="call_tool",
            ),
            PatternDef(
                regex=r'Tool\s*\(\s*name\s*=\s*["\']([^"\']+)["\']',
                framework="MCP",
                kind=EndpointKind.TOOL,
                route_group=1,
            ),
            PatternDef(
                regex=r'@(?:server|mcp)\.resource\s*\(\s*["\']([^"\']+)["\']',
                framework="MCP",
                kind=EndpointKind.RESOURCE,
                route_group=1,
            ),
            PatternDef(
                regex=r'@(?:server|mcp)\.list_resources\s*\(\s*\)',
                framework="MCP",
                kind=EndpointKind.RESOURCE,
                label="list_resources",
            ),
            PatternDef(
                regex=r'Resource\s*\(\s*uri\s*=\s*["\']([^"\']+)["\']',
                framework="MCP",
                kind=EndpointKind.RESOURCE,
                route_group=1,
            ),

            # ===================== SANIC =====================
            PatternDef(
                regex=r'@(?:app|bp|blueprint)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="Sanic",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'@(?:app|bp|blueprint)\.route\s*\(\s*["\']([^"\']+)["\'](?:.*?methods\s*=\s*\[([^\]]+)\])?',
                framework="Sanic",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                method_group=2,
            ),
            PatternDef(
                regex=r'Blueprint\s*\(\s*["\']([^"\']+)["\']',
                framework="Sanic",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="Blueprint",
            ),

            # ===================== TORNADO =====================
            PatternDef(
                regex=r'tornado\.web\.Application\s*\(\s*\[',
                framework="Tornado",
                kind=EndpointKind.ENTRY,
                label="Tornado App",
            ),
            PatternDef(
                regex=r'\(\s*r?["\']([^"\']+)["\'],\s*\w+Handler\s*\)',
                framework="Tornado",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'class\s+(\w*Handler)\s*\(\s*tornado\.web\.RequestHandler\s*\)',
                framework="Tornado",
                kind=EndpointKind.HANDLER,
                route_group=1,
            ),

            # ===================== STARLETTE =====================
            PatternDef(
                regex=r'Route\s*\(\s*["\']([^"\']+)["\']',
                framework="Starlette",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'Mount\s*\(\s*["\']([^"\']+)["\']',
                framework="Starlette",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="Mount",
            ),

            # ===================== BOTTLE =====================
            PatternDef(
                regex=r'@(?:app|bottle)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="Bottle",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'@(?:app|bottle)\.route\s*\(\s*["\']([^"\']+)["\']',
                framework="Bottle",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),

            # ===================== QUART =====================
            PatternDef(
                regex=r'from\s+quart\s+import',
                framework="Quart",
                kind=EndpointKind.CONFIG,
                label="Quart app",
            ),

            # ===================== HEALTH/INFRA =====================
            PatternDef(
                regex=r'["\']/?health(?:z|check)?["\']',
                framework="Health",
                kind=EndpointKind.ENDPOINT,
                label="/health",
            ),
            PatternDef(
                regex=r'["\']/?metrics["\']',
                framework="Prometheus",
                kind=EndpointKind.ENDPOINT,
                label="/metrics",
            ),
        ]

    def scan_with_heuristics(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Python-specific heuristic rules."""
        results = []
        path_str = str(file_path).lower().replace('\\', '/')

        # HEURISTIC 1: Files in frontend/ or handlers/ folders with class definitions
        handler_folders = ['frontend/', 'handlers/', 'views/', 'api/', 'endpoints/', 'controllers/']
        is_handler_file = any(folder in path_str for folder in handler_folders)

        if is_handler_file:
            # Look for class definitions that could be handlers
            for match in re.finditer(r'class\s+(\w+)\s*(?:\([^)]*\))?:', content):
                class_name = match.group(1)
                line_num = content[:match.start()].count('\n') + 1

                # Derive route from path
                route = f"/{file_path.stem}/{class_name}"
                for folder in handler_folders:
                    if folder in path_str:
                        idx = path_str.find(folder)
                        route = "/" + path_str[idx:].replace('.py', '').replace('/', '.') + f".{class_name}"
                        break

                results.append(Endpoint(
                    file_path=str(file_path),
                    line_number=line_num,
                    language=self.language,
                    framework="Legacy-Handler",
                    kind=EndpointKind.HANDLER,
                    method="HANDLER",
                    route=route,
                    raw_match=match.group(0),
                    context=self.get_context(lines, line_num - 1),
                    metadata={"heuristic": "frontend_class"},
                ))

            # Also look for HTTP method functions
            for match in re.finditer(r'def\s+(get|post|put|delete|patch|head|options)\s*\(\s*self', content, re.IGNORECASE):
                method = match.group(1).upper()
                line_num = content[:match.start()].count('\n') + 1

                results.append(Endpoint(
                    file_path=str(file_path),
                    line_number=line_num,
                    language=self.language,
                    framework="Legacy-Handler",
                    kind=EndpointKind.HANDLER,
                    method=method,
                    route=f"/{file_path.stem}",
                    raw_match=match.group(0),
                    context=self.get_context(lines, line_num - 1),
                    metadata={"heuristic": "http_method"},
                ))

        # HEURISTIC 2: Custom router class definitions
        for match in re.finditer(r'class\s+(\w*(?:Router|Handler|Controller|Endpoint|View|API)\w*)\s*(?:\([^)]*\))?:', content):
            class_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1

            results.append(Endpoint(
                file_path=str(file_path),
                line_number=line_num,
                language=self.language,
                framework="Custom-Class",
                kind=EndpointKind.HANDLER,
                method="CLASS",
                route=class_name,
                raw_match=match.group(0),
                context=self.get_context(lines, line_num - 1),
                metadata={"heuristic": "router_class"},
            ))

        # HEURISTIC 3: API path strings
        for match in re.finditer(r'["\']/?api/v\d+/([a-z_][a-z0-9_/{}]*)["\']', content, re.IGNORECASE):
            route = f"/api/v1/{match.group(1)}"
            line_num = content[:match.start()].count('\n') + 1

            results.append(Endpoint(
                file_path=str(file_path),
                line_number=line_num,
                language=self.language,
                framework="Dynamic-Route",
                kind=EndpointKind.ENDPOINT,
                method="ANY",
                route=route,
                raw_match=match.group(0),
                context=self.get_context(lines, line_num - 1),
                metadata={"heuristic": "api_path"},
            ))

        # HEURISTIC 4: Blueprint registration
        for match in re.finditer(r'register_blueprint\s*\(\s*(\w+)(?:\s*,\s*url_prefix\s*=\s*["\']([^"\']+)["\'])?', content):
            name = match.group(1)
            prefix = match.group(2) or f"/{name}"
            line_num = content[:match.start()].count('\n') + 1

            results.append(Endpoint(
                file_path=str(file_path),
                line_number=line_num,
                language=self.language,
                framework="Flask-Blueprint",
                kind=EndpointKind.CONFIG,
                method="BLUEPRINT",
                route=prefix,
                raw_match=match.group(0),
                context=self.get_context(lines, line_num - 1),
                metadata={"blueprint": name},
            ))

        # HEURISTIC 5: FastAPI include_router() prefix tracking
        # Detect: app.include_router(routerVar, prefix="/api/v1")
        include_re = re.compile(
            r'include_router\s*\(\s*(\w+)\s*(?:,[^)]*prefix\s*=\s*["\']([^"\']+)["\'])?',
        )
        router_method_re = re.compile(
            r'@(\w+)\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )

        prefixes: dict = {}
        for m in include_re.finditer(content):
            if m.group(2):
                prefixes[m.group(1)] = m.group(2)

        for m in router_method_re.finditer(content):
            var = m.group(1)
            if var not in prefixes:
                continue
            method = m.group(2).upper()
            path = m.group(3)
            prefix = prefixes[var]
            full_route = prefix.rstrip('/') + '/' + path.lstrip('/')
            line_num = content[:m.start()].count('\n') + 1
            results.append(Endpoint(
                file_path=str(file_path),
                line_number=line_num,
                language=self.language,
                framework="FastAPI",
                kind=EndpointKind.ENDPOINT,
                method=method,
                route=full_route,
                raw_match=m.group(0)[:150],
                context=self.get_context(lines, line_num - 1),
                metadata={"router_prefix": prefix},
            ))

        return results
