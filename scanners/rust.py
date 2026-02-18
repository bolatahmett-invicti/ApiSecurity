"""Rust scanner: Actix Web, Axum, Rocket, Tide, Warp, Gotham, Loco."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class RustScanner(BaseScanner):
    """Rust scanner supporting major web frameworks."""

    @property
    def language(self) -> Language:
        return Language.RUST

    @property
    def extensions(self) -> Set[str]:
        return {".rs"}

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            # ===================== ACTIX WEB =====================
            PatternDef(
                regex=r'#\[(get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']',
                framework="Actix Web",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'web::(get|post|put|delete|patch)\s*\(',
                framework="Actix Web",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                label="web method",
            ),
            PatternDef(
                regex=r'\.route\s*\(\s*["\']([^"\']+)["\'],\s*web::(get|post|put|delete|patch)',
                framework="Actix Web",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                method_group=2,
            ),
            PatternDef(
                regex=r'web::scope\s*\(\s*["\']([^"\']+)["\']',
                framework="Actix Web",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="scope",
            ),

            # ===================== AXUM =====================
            PatternDef(
                regex=r'\.route\s*\(\s*["\']([^"\']+)["\']',
                framework="Axum",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'Router::new\s*\(',
                framework="Axum",
                kind=EndpointKind.CONFIG,
                label="Router::new",
            ),
            PatternDef(
                regex=r'routing::(get|post|put|delete|patch)\s*\(',
                framework="Axum",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
            ),

            # ===================== ROCKET =====================
            PatternDef(
                regex=r'#\[route\s*\(\s*(GET|POST|PUT|DELETE|PATCH)\s*,\s*path\s*=\s*["\']([^"\']+)["\']',
                framework="Rocket",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'#\[(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="Rocket",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'rocket::build\s*\(',
                framework="Rocket",
                kind=EndpointKind.CONFIG,
                label="rocket::build",
            ),

            # ===================== TIDE =====================
            PatternDef(
                regex=r'app\.at\s*\(\s*["\']([^"\']+)["\']',
                framework="Tide",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'tide::new\s*\(',
                framework="Tide",
                kind=EndpointKind.CONFIG,
                label="tide::new",
            ),

            # ===================== WARP =====================
            PatternDef(
                regex=r'warp::path\s*!\s*\(([^)]+)\)',
                framework="Warp",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'warp::path\s*\(\s*["\']([^"\']+)["\']',
                framework="Warp",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'warp::(get|post|put|delete|patch)\s*\(',
                framework="Warp",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
            ),

            # ===================== GOTHAM =====================
            PatternDef(
                regex=r'route\.request\s*\(\s*vec!\s*\[([^\]]+)\]',
                framework="Gotham",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'build_simple_router\s*\(',
                framework="Gotham",
                kind=EndpointKind.CONFIG,
                label="build_simple_router",
            ),

            # ===================== LOCO =====================
            PatternDef(
                regex=r'router\.add\s*\(\s*["\']([^"\']+)["\']',
                framework="Loco",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'#\[controller\]',
                framework="Loco",
                kind=EndpointKind.CONFIG,
                label="#[controller]",
            ),
        ]
