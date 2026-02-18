"""JavaScript/TypeScript scanner: Express, NestJS, Fastify, Koa, NuxtJS, Restify, TanStack."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class JavaScriptScanner(BaseScanner):
    """JavaScript/TypeScript scanner."""

    @property
    def language(self) -> Language:
        return Language.JAVASCRIPT

    @property
    def extensions(self) -> Set[str]:
        return {".js", ".ts", ".mjs", ".jsx", ".tsx"}

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
        ]
