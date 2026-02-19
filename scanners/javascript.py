"""JavaScript/TypeScript scanner: Express, NestJS, Fastify, Koa, NuxtJS, Restify, TanStack, Hapi, Hono."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef, Endpoint


class JavaScriptScanner(BaseScanner):
    """JavaScript/TypeScript scanner."""

    @property
    def language(self) -> Language:
        return Language.JAVASCRIPT

    @property
    def extensions(self) -> Set[str]:
        return {".js", ".ts", ".mjs", ".jsx", ".tsx"}

    @property
    def comment_prefixes(self) -> tuple:
        return ("//", "*")

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            PatternDef(
                regex=r'(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Express",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'@(Get|Post|Put|Delete|Patch)\s*\(\s*["\'\`]?([^"\'\`\)]*)["\'\`]?\s*\)',
                framework="NestJS",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'@Controller\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]\s*\)',
                framework="NestJS",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="Controller",
            ),

            # ===================== FASTIFY =====================
            PatternDef(
                regex=r'(?:fastify|app|server)\.(get|post|put|delete|patch|head|options)\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Fastify",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'fastify\.register\s*\([^,]+,\s*\{\s*prefix:\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Fastify",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="prefix",
            ),
            PatternDef(
                regex=r'\.route\s*\(\s*\{\s*method:\s*["\'\`](GET|POST|PUT|DELETE|PATCH)["\'\`]\s*,\s*url:\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Fastify",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),

            # ===================== KOA =====================
            PatternDef(
                regex=r'router\.(get|post|put|delete|patch|all)\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Koa",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'new Router\s*\(\s*\{\s*prefix:\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Koa",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="Router prefix",
            ),
            PatternDef(
                regex=r'new KoaRouter\s*\(',
                framework="Koa",
                kind=EndpointKind.CONFIG,
                label="KoaRouter",
            ),

            # ===================== NUXTJS =====================
            PatternDef(
                regex=r'export\s+default\s+defineEventHandler',
                framework="NuxtJS",
                kind=EndpointKind.ENDPOINT,
                label="defineEventHandler",
            ),
            PatternDef(
                regex=r'defineEventHandler\s*\(',
                framework="NuxtJS",
                kind=EndpointKind.ENDPOINT,
                label="Event Handler",
            ),
            PatternDef(
                regex=r'eventHandler\s*\(',
                framework="NuxtJS",
                kind=EndpointKind.ENDPOINT,
                label="eventHandler",
            ),

            # ===================== RESTIFY =====================
            PatternDef(
                regex=r'(?:server|app)\.(get|post|put|patch|del|head|opts)\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Restify",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'restify\.createServer\s*\(',
                framework="Restify",
                kind=EndpointKind.CONFIG,
                label="Restify Server",
            ),

            # ===================== TANSTACK ROUTER =====================
            PatternDef(
                regex=r'createRoute\s*\(\s*\{[^}]*path:\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="TanStack Router",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'new Route\s*\(\s*\{[^}]*path:\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="TanStack Router",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'createRootRoute\s*\(',
                framework="TanStack Router",
                kind=EndpointKind.CONFIG,
                label="Root Route",
            ),

            # ===================== HAPI =====================
            PatternDef(
                regex=r'server\.route\s*\(\s*\{[^}]*path:\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Hapi",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'server\.route\s*\(\s*\{[^}]*method:\s*["\'\`](GET|POST|PUT|DELETE|PATCH)["\'\`]',
                framework="Hapi",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
            ),

            # ===================== HONO =====================
            PatternDef(
                regex=r'(?:app|hono)\.(get|post|put|delete|patch|all)\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]',
                framework="Hono",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
        ]

    def scan_with_heuristics(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Detect Express app.use('/prefix', router) sub-router mounts."""
        results = []

        # app.use('/prefix', routerVar) or server.use('/prefix', routerVar)
        use_re = re.compile(
            r'(?:app|server|router)\s*\.\s*use\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]\s*,\s*(\w+)',
        )
        # routerVar.get('/path', ...) etc.
        method_re = re.compile(
            r'(\w+)\s*\.\s*(get|post|put|delete|patch|all)\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]',
            re.IGNORECASE,
        )

        mounts: dict = {}
        for m in use_re.finditer(content):
            mounts[m.group(2)] = m.group(1)

        for m in method_re.finditer(content):
            var = m.group(1)
            if var not in mounts:
                continue
            method = m.group(2).upper()
            path = m.group(3)
            prefix = mounts[var]
            full_route = prefix.rstrip('/') + '/' + path.lstrip('/')
            line_num = content[:m.start()].count('\n') + 1
            results.append(Endpoint(
                file_path=str(file_path),
                line_number=line_num,
                language=self.language,
                framework="Express",
                kind=EndpointKind.ENDPOINT,
                method=method,
                route=full_route,
                raw_match=m.group(0)[:150],
                context=self.get_context(lines, line_num - 1),
                metadata={"mount_prefix": prefix},
            ))

        return results
