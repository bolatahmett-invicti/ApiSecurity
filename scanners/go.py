"""Go scanner: net/http, Gin, Echo, Fiber, Beego, Chi, Gorilla Mux, fasthttp, go-zero."""
from __future__ import annotations

from typing import List, Set

from .base import BaseScanner, Language, EndpointKind, PatternDef


class GoScanner(BaseScanner):
    """Go scanner supporting multiple frameworks."""

    @property
    def language(self) -> Language:
        return Language.GO

    @property
    def extensions(self) -> Set[str]:
        return {".go"}

    @property
    def patterns(self) -> List[PatternDef]:
        return [
            PatternDef(
                regex=r'http\.HandleFunc\s*\(\s*["`]([^"`]+)["`]',
                framework="net/http",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'http\.Handle\s*\(\s*["`]([^"`]+)["`]',
                framework="net/http",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'(?:router|r|g|engine)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["`]([^"`]+)["`]',
                framework="Gin",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'(?:e|echo)\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["`]([^"`]+)["`]',
                framework="Echo",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'(?:app|fiber)\.(Get|Post|Put|Delete|Patch)\s*\(\s*["`]([^"`]+)["`]',
                framework="Fiber",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),

            # ===================== BEEGO =====================
            PatternDef(
                regex=r'beego\.Router\s*\(\s*["`]([^"`]+)["`]',
                framework="Beego",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'(?:beego|ns)\.(Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*["`]([^"`]+)["`]',
                framework="Beego",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'web\.Router\s*\(\s*["`]([^"`]+)["`]',
                framework="Beego",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),

            # ===================== CHI =====================
            PatternDef(
                regex=r'(?:r|router|mux)\.(Get|Post|Put|Delete|Patch|Head|Options|Connect|Trace)\s*\(\s*["`]([^"`]+)["`]',
                framework="Chi",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'chi\.NewRouter\s*\(',
                framework="Chi",
                kind=EndpointKind.CONFIG,
                label="chi.NewRouter",
            ),
            PatternDef(
                regex=r'(?:r|router)\.Route\s*\(\s*["`]([^"`]+)["`]',
                framework="Chi",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="Route group",
            ),

            # ===================== GORILLA MUX =====================
            PatternDef(
                regex=r'mux\.NewRouter\s*\(',
                framework="Gorilla Mux",
                kind=EndpointKind.CONFIG,
                label="mux.NewRouter",
            ),
            PatternDef(
                regex=r'\.HandleFunc\s*\(\s*["`]([^"`]+)["`]',
                framework="Gorilla Mux",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'\.Path\s*\(\s*["`]([^"`]+)["`]\s*\)\.Methods\s*\(\s*["`](GET|POST|PUT|DELETE|PATCH)["`]',
                framework="Gorilla Mux",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
                method_group=2,
            ),
            PatternDef(
                regex=r'\.PathPrefix\s*\(\s*["`]([^"`]+)["`]',
                framework="Gorilla Mux",
                kind=EndpointKind.CONFIG,
                route_group=1,
                label="PathPrefix",
            ),

            # ===================== FASTHTTP / FASTHTTPROUTER =====================
            PatternDef(
                regex=r'fasthttp\.ListenAndServe\s*\(',
                framework="fasthttp",
                kind=EndpointKind.ENTRY,
                label="fasthttp Server",
            ),
            PatternDef(
                regex=r'(?:router|r)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["`]([^"`]+)["`]',
                framework="fasthttp",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'fasthttp\.MethodGet|fasthttp\.MethodPost',
                framework="fasthttp",
                kind=EndpointKind.CONFIG,
                label="fasthttp method",
            ),

            # ===================== GO-ZERO =====================
            PatternDef(
                regex=r'@handler\s+(\w+)',
                framework="go-zero",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'(get|post|put|delete|patch)\s+(/[/\w:.-]*)',
                framework="go-zero",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'@server\s*\(',
                framework="go-zero",
                kind=EndpointKind.CONFIG,
                label="@server",
            ),
        ]
