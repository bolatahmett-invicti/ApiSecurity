#!/usr/bin/env python3
"""
Universal Polyglot API Scanner v3.1 - WITH SPEC SCANNING
==========================================================
A unified, pattern-based API discovery tool supporting multiple languages,
frameworks, and now STATIC SPECIFICATION FILES.

Supported Languages:
  - Python (Legacy/Custom + Modern Frameworks + MCP)
  - .NET/C# (Controllers + Minimal API + Config)
  - Go/Golang (Standard lib + Gin + Echo + Fiber)
  - Java (Spring Boot annotations)
  - JavaScript/TypeScript (Express + Fastify + NestJS + MCP)
  - OpenAPI/Swagger (.json, .yaml, .yml)
  - GraphQL Schema (.graphql, .gql)

Author: Principal Security Engineer
Usage: python main.py [OPTIONS] <path>
"""

import sys
import os
import re
import json
import argparse
import tempfile
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional, NamedTuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# =============================================================================
# DEPENDENCY CHECK
# =============================================================================
REQUIRED = {"rich": "rich>=13.7.0", "git": "gitpython>=3.1.40", "dotenv": "python-dotenv>=1.0.0"}

def check_deps():
    missing = []
    for mod, pkg in REQUIRED.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"\nMissing: pip install {' '.join(missing)}\n")
        sys.exit(1)

check_deps()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from dotenv import load_dotenv
import git

load_dotenv()
console = Console()

# =============================================================================
# CONFIGURATION - STRICT IGNORE PATTERNS
# =============================================================================
IGNORE_DIRS: Set[str] = {
    # Version control
    ".git", ".svn", ".hg", ".bzr",
    # Dependencies
    "node_modules", "bower_components", "jspm_packages",
    # Python
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", ".nox",
    "venv", ".venv", "env", ".env", "virtualenv", ".virtualenv",
    "site-packages", ".eggs", "dist", "build", "egg-info",
    # .NET
    "bin", "obj", ".vs", "packages", "TestResults", "artifacts",
    # Java
    "target", ".gradle", ".idea", ".settings",
    # Go
    "vendor",
    # JavaScript
    ".next", ".nuxt", "coverage", ".cache", ".parcel-cache",
    # IDE/OS
    ".vscode", ".DS_Store",
    # Docs
    "docs", "doc", "_site",
}

# =============================================================================
# DATA MODELS
# =============================================================================
class Language(Enum):
    PYTHON = "Python"
    DOTNET = "C#/.NET"
    GO = "Go"
    JAVA = "Java"
    JAVASCRIPT = "JavaScript"
    TYPESCRIPT = "TypeScript"
    UNKNOWN = "Unknown"

class EndpointKind(Enum):
    ENDPOINT = "Endpoint"
    TOOL = "Tool"
    RESOURCE = "Resource"
    WORKER = "Worker"
    HANDLER = "Handler"
    CONFIG = "Config"
    ENTRY = "Entry"

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AuthStatus(Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    UNKNOWN = "UNKNOWN"

class PatternDef(NamedTuple):
    """Definition of a detection pattern."""
    regex: str
    framework: str
    kind: EndpointKind
    method_group: Optional[int] = None  # Regex group for HTTP method
    route_group: Optional[int] = None   # Regex group for route/name
    label: Optional[str] = None         # Custom label for display

@dataclass
class Endpoint:
    """Represents a discovered API endpoint."""
    file_path: str
    line_number: int
    language: Language
    framework: str
    kind: EndpointKind
    method: str
    route: str
    raw_match: str
    context: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.INFO
    auth_status: AuthStatus = AuthStatus.UNKNOWN
    risk_reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "language": self.language.value,
            "framework": self.framework,
            "kind": self.kind.value,
            "method": self.method,
            "route": self.route,
            "raw_match": self.raw_match,
            "risk_level": self.risk_level.value,
            "auth_status": self.auth_status.value,
            "risk_reasons": self.risk_reasons,
            "metadata": self.metadata,
        }

# =============================================================================
# BASE SCANNER (Abstract)
# =============================================================================
class BaseScanner(ABC):
    """
    Abstract base class for all language-specific scanners.
    Each scanner implements patterns and heuristic rules.
    """
    
    def __init__(self):
        self.endpoints: List[Endpoint] = []
        self.stats = {"files_scanned": 0, "endpoints_found": 0}
    
    @property
    @abstractmethod
    def language(self) -> Language:
        """The primary language this scanner handles."""
        pass
    
    @property
    @abstractmethod
    def extensions(self) -> Set[str]:
        """File extensions this scanner processes."""
        pass
    
    @property
    @abstractmethod
    def patterns(self) -> List[PatternDef]:
        """List of regex patterns for detection."""
        pass
    
    def get_context(self, lines: List[str], line_num: int, size: int = 3) -> List[str]:
        """Extract context lines around a match."""
        start = max(0, line_num - size)
        end = min(len(lines), line_num + size + 1)
        return lines[start:end]
    
    def scan_with_patterns(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Scan content using defined patterns."""
        results = []
        
        for pattern_def in self.patterns:
            try:
                for match in re.finditer(pattern_def.regex, content, re.MULTILINE | re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    groups = match.groups()
                    
                    # Extract method and route from specified groups
                    method = "ANY"
                    route = pattern_def.label or pattern_def.framework
                    
                    if pattern_def.method_group is not None and len(groups) >= pattern_def.method_group:
                        method = (groups[pattern_def.method_group - 1] or "ANY").upper()
                    
                    if pattern_def.route_group is not None and len(groups) >= pattern_def.route_group:
                        route = groups[pattern_def.route_group - 1] or route
                    
                    results.append(Endpoint(
                        file_path=str(file_path),
                        line_number=line_num,
                        language=self.language,
                        framework=pattern_def.framework,
                        kind=pattern_def.kind,
                        method=method,
                        route=route,
                        raw_match=match.group(0)[:150],
                        context=self.get_context(lines, line_num - 1),
                    ))
            except re.error:
                continue
        
        return results
    
    def scan_with_heuristics(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Override in subclasses for language-specific heuristic rules."""
        return []
    
    def scan_file(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Scan a file using both patterns and heuristics."""
        results = []
        results.extend(self.scan_with_patterns(file_path, content, lines))
        results.extend(self.scan_with_heuristics(file_path, content, lines))
        return results

# =============================================================================
# PYTHON SCANNER (Legacy + Modern + MCP)
# =============================================================================
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
        
        return results

# =============================================================================
# .NET / C# SCANNER (STATEFUL DEEP CONTROLLER PARSING)
# =============================================================================
class DotNetScanner(BaseScanner):
    """
    .NET/C# scanner with STATEFUL DEEP CONTROLLER PARSING.
    """
    
    @property
    def language(self) -> Language:
        return Language.DOTNET
    
    @property
    def extensions(self) -> Set[str]:
        return {".cs"}
    
    @property
    def patterns(self) -> List[PatternDef]:
        # Minimal API patterns only - Controllers handled by _deep_scan_controllers
        return [
            PatternDef(
                regex=r'app\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="MinimalAPI",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'endpoints\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="MinimalAPI",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'\.MapHealthChecks\s*\(\s*["\']([^"\']+)["\']',
                framework="ASP.NET",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'\.MapHub<\w+>\s*\(\s*["\']([^"\']+)["\']',
                framework="SignalR",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'\.MapGrpcService<(\w+)>',
                framework="gRPC",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
        ]
    
    def scan_file(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Override to use deep controller scanning as PRIMARY method."""
        results = []
        
        # PRIMARY: Deep scan for Controllers with proper route combination
        results.extend(self._deep_scan_controllers(file_path, content, lines))
        
        # SECONDARY: Minimal API patterns for .NET 6+
        results.extend(self.scan_with_patterns(file_path, content, lines))
        
        return results
    
    def _deep_scan_controllers(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """
        STATEFUL REGEX PARSING for .NET Controllers.
        Supports:
        - Standard: public class XController : ControllerBase
        - Generated: public abstract class XControllerBase : Microsoft.AspNetCore.Mvc.Controller
        """
        results = []
        
        # Extended pattern to match both standard and fully-qualified controller base classes
        controller_pattern = r'public\s+(?:abstract\s+)?class\s+(\w+)\s*:\s*(?:Microsoft\.AspNetCore\.Mvc\.)?(Controller|ControllerBase|ApiController|ODataController)'
        
        for class_match in re.finditer(controller_pattern, content, re.MULTILINE):
            controller_name = class_match.group(1)
            class_start_pos = class_match.start()
            class_end_pos = class_match.end()
            
            lookback_start = max(0, class_start_pos - 500)
            preceding_text = content[lookback_start:class_start_pos]
            
            base_route = ""
            
            # Support both [Route("...")] and [Microsoft.AspNetCore.Mvc.Route("...")]
            route_match = re.search(r'\[(?:Microsoft\.AspNetCore\.Mvc\.)?Route\s*\(\s*["\']([^"\']+)["\']\s*\)\]', preceding_text)
            if route_match:
                base_route = route_match.group(1)
            
            if "[controller]" in base_route.lower():
                ctrl_short_name = controller_name
                if ctrl_short_name.endswith("Controller"):
                    ctrl_short_name = ctrl_short_name[:-10]
                ctrl_short_name = ctrl_short_name.lower()
                
                base_route = re.sub(r'\[controller\]', ctrl_short_name, base_route, flags=re.IGNORECASE)
            
            brace_start = content.find('{', class_end_pos)
            if brace_start == -1:
                continue
            
            brace_depth = 1
            brace_end = brace_start + 1
            while brace_depth > 0 and brace_end < len(content):
                if content[brace_end] == '{':
                    brace_depth += 1
                elif content[brace_end] == '}':
                    brace_depth -= 1
                brace_end += 1
            
            class_body = content[brace_start:brace_end]
            class_body_start_line = content[:brace_start].count('\n')
            
            http_verbs = [
                ('HttpGet', 'GET'),
                ('HttpPost', 'POST'),
                ('HttpPut', 'PUT'),
                ('HttpDelete', 'DELETE'),
                ('HttpPatch', 'PATCH'),
                ('HttpHead', 'HEAD'),
                ('HttpOptions', 'OPTIONS'),
            ]
            
            for verb_attr, http_method in http_verbs:
                # Pattern 1: Standard format [HttpGet("route")] or [HttpGet]
                # Pattern 2: Fully-qualified [Microsoft.AspNetCore.Mvc.HttpGet, Microsoft.AspNetCore.Mvc.Route("route")]
                # Pattern 3: Inline combined [Microsoft.AspNetCore.Mvc.HttpPost, Microsoft.AspNetCore.Mvc.Route("scans")]
                patterns = [
                    # Standard: [HttpGet("route")] or [HttpGet]
                    rf'\[{verb_attr}(?:\s*\(\s*["\']([^"\']*)["\']\s*\)|\s*\(\s*\))?\s*\]',
                    # Fully qualified with optional route in same attribute
                    rf'\[Microsoft\.AspNetCore\.Mvc\.{verb_attr}(?:\s*\(\s*["\']([^"\']*)["\']\s*\))?\s*(?:,\s*Microsoft\.AspNetCore\.Mvc\.Route\s*\(\s*["\']([^"\']+)["\']\s*\))?\s*\]',
                ]
                
                for pattern in patterns:
                    for verb_match in re.finditer(pattern, class_body, re.IGNORECASE):
                        # Extract route from match groups
                        groups = verb_match.groups()
                        method_route = ""
                        for g in groups:
                            if g:
                                method_route = g
                                break
                    
                        verb_pos = verb_match.start()
                        line_num = class_body_start_line + class_body[:verb_pos].count('\n') + 1
                        
                        method_context_start = max(0, verb_pos - 300)
                        method_preceding = class_body[method_context_start:verb_pos]
                        
                        # Support both [Route("...")] and [Microsoft.AspNetCore.Mvc.Route("...")]
                        method_route_attr = re.search(r'\[(?:Microsoft\.AspNetCore\.Mvc\.)?Route\s*\(\s*["\']([^"\']+)["\']\s*\)\]', method_preceding)
                        if method_route_attr and not method_route:
                            method_route = method_route_attr.group(1)
                        
                        method_following = class_body[verb_pos:verb_pos + 500]
                        action_name = "Unknown"
                        
                        sig_pattern = r'(?:public|private|protected)\s+(?:async\s+)?(?:virtual\s+)?(?:override\s+)?(?:Task<)?(?:IActionResult|ActionResult(?:<[^>]+>)?|[\w<>\[\]]+)>?\s+(\w+)\s*\('
                        sig_match = re.search(sig_pattern, method_following)
                        if sig_match:
                            action_name = sig_match.group(1)
                        
                        if "[action]" in method_route.lower():
                            method_route = re.sub(r'\[action\]', action_name.lower(), method_route, flags=re.IGNORECASE)
                        
                        full_route = self._combine_routes(base_route, method_route)
                        
                        if not full_route or full_route == "/":
                            if base_route:
                                full_route = "/" + base_route.strip('/')
                            else:
                                ctrl_short = controller_name.replace("Controller", "").lower()
                                full_route = f"/api/{ctrl_short}"
                        
                        auth_status = AuthStatus.UNKNOWN
                        
                        auth_context_start = max(0, verb_pos - 200)
                        auth_context_end = min(len(class_body), verb_pos + 200)
                        auth_context = class_body[auth_context_start:auth_context_end]
                        
                        if re.search(r'\[Authorize', auth_context, re.IGNORECASE):
                            auth_status = AuthStatus.PRIVATE
                        if re.search(r'\[Authorize', preceding_text, re.IGNORECASE):
                            auth_status = AuthStatus.PRIVATE
                        
                        if re.search(r'\[AllowAnonymous\]', auth_context, re.IGNORECASE):
                            auth_status = AuthStatus.PUBLIC
                        
                        results.append(Endpoint(
                            file_path=str(file_path),
                            line_number=line_num,
                            language=self.language,
                            framework="ASP.NET",
                            kind=EndpointKind.ENDPOINT,
                            method=http_method,
                            route=full_route,
                            raw_match=verb_match.group(0),
                            context=self.get_context(lines, line_num - 1),
                            auth_status=auth_status,
                            metadata={
                                "controller": controller_name,
                                "action": action_name,
                                "base_route": base_route,
                                "method_route": method_route,
                            },
                        ))
        
        return results
    
    def _combine_routes(self, base_route: str, method_route: str) -> str:
        """Combine class-level base route with method-level route."""
        base = base_route.strip('/') if base_route else ""
        method = method_route.strip('/') if method_route else ""
        
        if method_route:
            if method_route.startswith("~/"):
                return "/" + method_route[2:].lstrip('/')
            if method_route.startswith("/"):
                return method_route
        
        if base and method:
            return f"/{base}/{method}"
        elif base:
            return f"/{base}"
        elif method:
            return f"/{method}"
        else:
            return "/"
    
    def scan_with_heuristics(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """No additional heuristics - deep scanning handles all controller patterns."""
        return []

# =============================================================================
# GO SCANNER (Standard lib + Gin + Echo + Fiber)
# =============================================================================
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
        ]

# =============================================================================
# JAVA SCANNER (Spring Boot)
# =============================================================================
class JavaScanner(BaseScanner):
    """Java scanner for Spring Boot."""
    
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
        ]

# =============================================================================
# JAVASCRIPT/TYPESCRIPT SCANNER
# =============================================================================
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
        ]

# =============================================================================
# SPEC SCANNER (OpenAPI/Swagger + GraphQL) *** NEW ***
# =============================================================================
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
    
    def _find_line_number(self, content: str, lines: List[str], route: str) -> int:
        """Find the line number where a route is defined."""
        # Try to find the route string in the content
        pattern = re.escape(route)
        match = re.search(pattern, content)
        if match:
            return content[:match.start()].count('\n') + 1
        return 1

# =============================================================================
# ENRICHMENT ENGINE
# =============================================================================
class Enricher:
    """Enriches endpoints with risk analysis."""
    
    SENSITIVE = {
        "auth": [r'\bpassword\b', r'\btoken\b', r'\bsecret\b', r'\bauth\b', r'\bjwt\b', r'\bapi.?key\b'],
        "pii": [r'\bssn\b', r'\bemail\b', r'\bphone\b', r'\bcredit.?card\b', r'\baddress\b'],
        "financial": [r'\bpayment\b', r'\btransaction\b', r'\bbilling\b', r'\bcharge\b'],
        "admin": [r'\badmin\b', r'\broot\b', r'\binternal\b', r'\bdebug\b'],
    }
    
    AUTH_PATTERNS = [r'\[Authorize', r'@login_required', r'@auth', r'AuthGuard', r'@PreAuthorize', r'@Secured']
    PUBLIC_PATTERNS = [r'/health', r'/ping', r'/public', r'/docs', r'\[AllowAnonymous\]']
    
    def enrich(self, ep: Endpoint) -> Endpoint:
        text = ' '.join(ep.context + [ep.route, ep.raw_match]).lower()
        
        # Auth status
        if ep.auth_status == AuthStatus.UNKNOWN:
            for p in self.AUTH_PATTERNS:
                if re.search(p, text, re.IGNORECASE):
                    ep.auth_status = AuthStatus.PRIVATE
                    break
            for p in self.PUBLIC_PATTERNS:
                if re.search(p, text, re.IGNORECASE):
                    ep.auth_status = AuthStatus.PUBLIC
                    break
        
        # Risk scoring
        score = 0
        reasons = []
        
        for category, patterns in self.SENSITIVE.items():
            for p in patterns:
                if re.search(p, text, re.IGNORECASE):
                    if category == "admin":
                        score += 5
                    elif category == "pii":
                        score += 4
                    else:
                        score += 3
                    reasons.append(f"{category}: {p}")
        
        if ep.method in ["DELETE", "PUT", "PATCH"]:
            score += 1
            reasons.append(f"Mutation: {ep.method}")
        
        if ep.auth_status == AuthStatus.UNKNOWN:
            score += 1
            reasons.append("Shadow API")
        
        if ep.auth_status == AuthStatus.PUBLIC and score > 2:
            score += 2
            reasons.append("Sensitive PUBLIC")
        
        ep.risk_reasons = reasons
        if score >= 8:
            ep.risk_level = RiskLevel.CRITICAL
        elif score >= 5:
            ep.risk_level = RiskLevel.HIGH
        elif score >= 3:
            ep.risk_level = RiskLevel.MEDIUM
        elif score >= 1:
            ep.risk_level = RiskLevel.LOW
        
        return ep

# =============================================================================
# SCANNER ORCHESTRATOR
# =============================================================================
class PolyglotScanner:
    """
    Universal Polyglot Scanner orchestrator.
    Coordinates all language-specific scanners.
    """
    
    def __init__(self, target_path: str):
        self.target = Path(target_path)
        self.scanners: Dict[str, BaseScanner] = {
            ".py": PythonScanner(),
            ".cs": DotNetScanner(),
            ".go": GoScanner(),
            ".java": JavaScanner(),
            ".js": JavaScriptScanner(),
            ".ts": JavaScriptScanner(),
            ".jsx": JavaScriptScanner(),
            ".tsx": JavaScriptScanner(),
            ".mjs": JavaScriptScanner(),
            # ADD SPEC SCANNER
            ".json": SpecScanner(),
            ".yaml": SpecScanner(),
            ".yml": SpecScanner(),
            ".graphql": SpecScanner(),
            ".gql": SpecScanner(),
        }
        self.enricher = Enricher()
        self.endpoints: List[Endpoint] = []
        self.stats = {"files_scanned": 0, "files_skipped": 0, "by_language": {}}
    
    def should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored."""
        for part in path.parts:
            if part in IGNORE_DIRS:
                return True
        return False
    
    def scan(self, progress_cb=None) -> List[Endpoint]:
        """Scan the target directory."""
        self.endpoints = []
        all_files = []
        
        # Collect files
        for root, dirs, files in os.walk(self.target):
            # CRITICAL: Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            
            for f in files:
                fp = Path(root) / f
                if self.should_ignore(fp):
                    self.stats["files_skipped"] += 1
                    continue
                
                ext = fp.suffix.lower()
                if ext in self.scanners:
                    all_files.append(fp)
                else:
                    self.stats["files_skipped"] += 1
        
        # Scan files
        for i, fp in enumerate(all_files):
            if progress_cb:
                progress_cb(i + 1, len(all_files), fp)
            
            try:
                with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                
                ext = fp.suffix.lower()
                scanner = self.scanners.get(ext)
                if scanner:
                    found = scanner.scan_file(fp, content, lines)
                    for ep in found:
                        ep = self.enricher.enrich(ep)
                        self.endpoints.append(ep)
                    
                    lang = scanner.language.value
                    self.stats["by_language"][lang] = self.stats["by_language"].get(lang, 0) + len(found)
                
                self.stats["files_scanned"] += 1
            except Exception:
                continue
        
        # Deduplicate
        seen = set()
        unique = []
        for ep in self.endpoints:
            key = (ep.file_path, ep.line_number, ep.route, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        self.endpoints = unique
        return self.endpoints
    
    def summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        by_risk = {}
        by_auth = {}
        by_framework = {}
        by_kind = {}
        
        for ep in self.endpoints:
            by_risk[ep.risk_level.value] = by_risk.get(ep.risk_level.value, 0) + 1
            by_auth[ep.auth_status.value] = by_auth.get(ep.auth_status.value, 0) + 1
            by_framework[ep.framework] = by_framework.get(ep.framework, 0) + 1
            by_kind[ep.kind.value] = by_kind.get(ep.kind.value, 0) + 1
        
        return {
            "total": len(self.endpoints),
            "files_scanned": self.stats["files_scanned"],
            "files_skipped": self.stats["files_skipped"],
            "by_language": self.stats["by_language"],
            "by_risk": by_risk,
            "by_auth": by_auth,
            "by_framework": by_framework,
            "by_kind": by_kind,
            "shadow_apis": len([e for e in self.endpoints if e.auth_status == AuthStatus.UNKNOWN]),
            "critical": len([e for e in self.endpoints if e.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]),
        }

# =============================================================================
# OUTPUT FORMATTERS
# =============================================================================
def fmt_risk(r: RiskLevel) -> str:
    colors = {RiskLevel.CRITICAL: "bold red", RiskLevel.HIGH: "red", RiskLevel.MEDIUM: "yellow", RiskLevel.LOW: "cyan", RiskLevel.INFO: "dim"}
    return f"[{colors.get(r, 'white')}]{r.value}[/{colors.get(r, 'white')}]"

def fmt_auth(a: AuthStatus) -> str:
    colors = {AuthStatus.PUBLIC: "red", AuthStatus.PRIVATE: "green", AuthStatus.UNKNOWN: "yellow"}
    return f"[{colors.get(a, 'white')}]{a.value}[/{colors.get(a, 'white')}]"

def make_table(endpoints: List[Endpoint]) -> Table:
    t = Table(title="🔍 Discovered API Endpoints", box=box.ROUNDED, header_style="bold magenta")
    t.add_column("#", style="dim", width=4)
    t.add_column("Language", style="blue", width=12)
    t.add_column("Framework", style="cyan", width=16)
    t.add_column("Type", width=10)
    t.add_column("Method", width=8)
    t.add_column("Route/Name", max_width=40)
    t.add_column("Auth", width=10)
    t.add_column("Risk", width=10)
    t.add_column("File:Line", style="dim", max_width=30)
    
    for i, ep in enumerate(endpoints[:100], 1):
        route = ep.route[:37] + "..." if len(ep.route) > 40 else ep.route
        loc = f"{Path(ep.file_path).name}:{ep.line_number}"
        t.add_row(
            str(i), ep.language.value, ep.framework, ep.kind.value,
            ep.method, route, fmt_auth(ep.auth_status), fmt_risk(ep.risk_level), loc
        )
    
    if len(endpoints) > 100:
        t.add_row("...", "...", "...", "...", "...", f"... +{len(endpoints) - 100} more", "", "", "")
    
    return t

def make_summary(s: Dict[str, Any]) -> Panel:
    txt = f"""
[bold cyan]📊 Scan Summary[/bold cyan]

[bold]Total Endpoints:[/bold] {s['total']}
[bold]Files Scanned:[/bold] {s['files_scanned']} | Skipped: {s['files_skipped']}

[bold cyan]By Language:[/bold cyan]
""" + "\n".join([f"  • {lang}: {count}" for lang, count in s['by_language'].items() if count > 0])

    txt += f"""

[bold cyan]By Risk:[/bold cyan]
  • Critical: {s['by_risk'].get('CRITICAL', 0)}
  • High: {s['by_risk'].get('HIGH', 0)}
  • Medium: {s['by_risk'].get('MEDIUM', 0)}
  • Low: {s['by_risk'].get('LOW', 0)}

[bold cyan]Auth Status:[/bold cyan]
  • Public: {s['by_auth'].get('PUBLIC', 0)}
  • Private: {s['by_auth'].get('PRIVATE', 0)}
  • Shadow APIs: {s['by_auth'].get('UNKNOWN', 0)}

[bold cyan]By Type:[/bold cyan]
""" + "\n".join([f"  • {k}: {v}" for k, v in sorted(s['by_kind'].items(), key=lambda x: -x[1])[:6]])
    
    return Panel(txt, title="📈 Analysis Results", border_style="cyan")

# =============================================================================
# OPENAPI 3.0 GENERATOR
# =============================================================================
def generate_openapi_spec(endpoints: List[Endpoint], target: str, service_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate an OpenAPI 3.0 specification from discovered endpoints.
    
    This enables integration with DAST tools like Invicti/Netsparker/Burp Suite
    by converting shadow APIs into a scannable format.
    
    Args:
        endpoints: List of discovered endpoints
        target: Source directory or URL that was scanned
        service_name: Optional microservice identifier (e.g., "payment-service")
    """
    
    # Determine title based on service name
    if service_name:
        title = f"API Scan Results: {service_name}"
        description = f"APIs discovered from {service_name} ({target})"
    else:
        title = "Auto-Discovered APIs"
        description = f"APIs automatically discovered by Universal Polyglot API Scanner from: {target}"
    
    # Initialize OpenAPI 3.0 structure
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": title,
            "version": "1.0",
            "description": description,
            "x-generated-by": "Universal Polyglot API Scanner v3.1",
            "x-generated-at": datetime.now().isoformat(),
            **({
                "x-service-name": service_name,
            } if service_name else {}),
        },
        "paths": {},
        "components": {
            "schemas": {},
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                },
                "apiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
        }
    }
    
    # Group endpoints by route
    routes: Dict[str, List[Endpoint]] = {}
    for ep in endpoints:
        # Skip non-endpoint types (workers, configs, etc.)
        if ep.kind not in [EndpointKind.ENDPOINT, EndpointKind.TOOL, EndpointKind.RESOURCE, EndpointKind.HANDLER]:
            continue
        
        # Skip heuristic-based class detections that are not real HTTP endpoints
        # These are class names detected by naming convention, not actual routes
        if ep.framework in ["Custom-Class", "Legacy-Handler"]:
            # Only include if it looks like a real route (contains / after the first char)
            if ep.method in ["CLASS", "HANDLER"] or "/" not in ep.route[1:] if len(ep.route) > 1 else True:
                continue
        
        # Skip routes that are just class names (PascalCase without path separators)
        # e.g., "/APIException", "/AgentsApiHandler" are not real endpoints
        if ep.route and re.match(r'^/?[A-Z][a-zA-Z0-9]*$', ep.route):
            continue
        
        # Normalize route
        route = ep.route
        if not route or route == "/":
            continue
        
        # Ensure route starts with /
        if not route.startswith("/"):
            route = "/" + route
        
        # Convert common parameter patterns to OpenAPI format
        # Python/FastAPI: {param} -> {param} (already correct)
        # Express: :param -> {param}
        # .NET: {param} -> {param} (already correct)
        route = re.sub(r':([a-zA-Z_][a-zA-Z0-9_]*)', r'{\1}', route)
        
        if route not in routes:
            routes[route] = []
        routes[route].append(ep)
    
    # Build paths object
    for route, eps in sorted(routes.items()):
        path_item: Dict[str, Any] = {}
        
        # Extract path parameters from route
        path_params = re.findall(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}', route)
        
        for ep in eps:
            # Determine HTTP method
            method = ep.method.lower()
            if method in ["any", "handler", "class", "blueprint", "query", "mutation"]:
                # Default to GET for unknown methods
                # For GraphQL, use POST as it's the standard
                if method in ["query", "mutation"]:
                    method = "post"
                else:
                    method = "get"
            
            # Skip invalid methods
            if method not in ["get", "post", "put", "delete", "patch", "head", "options", "trace"]:
                method = "get"
            
            # Skip if method already exists for this path
            if method in path_item:
                continue
            
            # Build operation object
            operation: Dict[str, Any] = {
                "summary": f"{ep.framework} endpoint",
                "description": f"Discovered from [{Path(ep.file_path).name}]:{ep.line_number}\n\nFramework: {ep.framework}\nLanguage: {ep.language.value}\nRisk Level: {ep.risk_level.value}\nAuth Status: {ep.auth_status.value}",
                "operationId": _generate_operation_id(route, method, ep),
                "tags": [ep.framework, ep.language.value],
                "responses": {
                    "200": {
                        "description": "Successful response"
                    },
                    "400": {
                        "description": "Bad request"
                    },
                    "401": {
                        "description": "Unauthorized"
                    },
                    "404": {
                        "description": "Not found"
                    },
                    "500": {
                        "description": "Internal server error"
                    }
                },
                "x-source-file": ep.file_path,
                "x-source-line": ep.line_number,
                "x-risk-level": ep.risk_level.value,
                "x-auth-status": ep.auth_status.value,
            }
            
            # Add risk reasons if any
            if ep.risk_reasons:
                operation["x-risk-reasons"] = ep.risk_reasons
            
            # Add security requirement based on auth status
            if ep.auth_status == AuthStatus.PRIVATE:
                operation["security"] = [{"bearerAuth": []}, {"apiKeyAuth": []}]
            elif ep.auth_status == AuthStatus.PUBLIC:
                operation["security"] = []  # No security required
            
            # Add path parameters
            if path_params:
                operation["parameters"] = []
                for param in path_params:
                    operation["parameters"].append({
                        "name": param,
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string"
                        },
                        "description": f"Path parameter: {param}"
                    })
            
            # Add request body for mutation methods
            if method in ["post", "put", "patch"]:
                operation["requestBody"] = {
                    "description": "Request body",
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object"
                            }
                        }
                    }
                }
            
            path_item[method] = operation
        
        if path_item:
            spec["paths"][route] = path_item
    
    return spec


def _generate_operation_id(route: str, method: str, ep: Endpoint) -> str:
    """
    Generate a unique operation ID for the endpoint.
    """
    # Clean route for operation ID
    clean_route = route.replace("/", "_").replace("{", "").replace("}", "")
    clean_route = re.sub(r'[^a-zA-Z0-9_]', '', clean_route)
    clean_route = clean_route.strip("_")
    
    if not clean_route:
        clean_route = "root"
    
    return f"{method}_{clean_route}"


def export_openapi(endpoints: List[Endpoint], target: str, output_file: str, service_name: Optional[str] = None) -> None:
    """
    Export endpoints to an OpenAPI 3.0 specification file.
    
    Args:
        endpoints: List of discovered endpoints
        target: Source directory or URL that was scanned  
        output_file: Path to write the OpenAPI spec
        service_name: Optional microservice identifier for enterprise deployments
    """
    spec = generate_openapi_spec(endpoints, target, service_name)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(spec, f, indent=2)
    
    # Print summary
    path_count = len(spec["paths"])
    operation_count = sum(len(methods) for methods in spec["paths"].values())
    
    console.print(f"\n[green]✓ OpenAPI 3.0 spec exported: {output_file}[/green]")
    console.print(f"  • Paths: {path_count}")
    console.print(f"  • Operations: {operation_count}")
    console.print(f"  • Ready for import into Invicti/Burp Suite/DAST tools")


# =============================================================================
# GIT HELPER
# =============================================================================
def clone_repo(url: str) -> str:
    tmp = tempfile.mkdtemp(prefix="polyglot_scan_")
    console.print(f"[cyan]Cloning: {url}[/cyan]")
    git.Repo.clone_from(url, tmp, depth=1)
    console.print(f"[green]✓ Cloned[/green]")
    return tmp

# =============================================================================
# MAIN CLI
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="Universal Polyglot API Scanner v3.1")
    parser.add_argument("target", help="Directory or Git URL to scan")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--export-openapi", metavar="FILE", nargs="?", const="AUTO", 
                        help="Export OpenAPI 3.0 spec for DAST tools. If no filename given, auto-generates based on service name.")
    parser.add_argument("--service-name", "-s", metavar="NAME",
                        help="Microservice identifier (e.g., 'payment-service'). Used in OpenAPI title and output filename.")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    
    console.print(Panel.fit(
        "[bold cyan]🛡️ Universal Polyglot API Scanner v3.1[/bold cyan]\n"
        "[dim]Python | C#/.NET | Go | Java | JavaScript/TypeScript | OpenAPI | GraphQL[/dim]",
        border_style="cyan"
    ))
    
    target = args.target
    tmp = None
    
    try:
        if target.startswith(("http://", "https://", "git@")):
            tmp = clone_repo(target)
            target = tmp
        elif not os.path.exists(target):
            console.print(f"[red]Error: {target} not found[/red]")
            sys.exit(1)
        
        scanner = PolyglotScanner(target)
        console.print("\n[bold cyan]▶ Scanning...[/bold cyan]")
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.percentage:>3.0f}%"), console=console) as prog:
            task = prog.add_task("[cyan]Scanning", total=100)
            def cb(cur, tot, fp):
                prog.update(task, completed=(cur / tot) * 100, description=f"[cyan]{Path(fp).name[:25]}")
            endpoints = scanner.scan(progress_cb=cb)
        
        summary = scanner.summary()
        console.print(f"\n[green]✓ Found {len(endpoints)} endpoints[/green]")
        console.print("\n" + "=" * 70)
        console.print(make_summary(summary))
        console.print()
        
        if endpoints:
            risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4}
            endpoints.sort(key=lambda e: risk_order.get(e.risk_level, 5))
            console.print(make_table(endpoints))
            
            critical = [e for e in endpoints if e.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
            if critical:
                console.print("\n[bold red]⚠️ HIGH PRIORITY[/bold red]")
                for e in critical[:10]:
                    console.print(f"  • [{e.risk_level.value}] {e.language.value} {e.method} {e.route}")
                    for r in e.risk_reasons[:2]:
                        console.print(f"    └─ {r}")
            
            shadow = [e for e in endpoints if e.auth_status == AuthStatus.UNKNOWN]
            if shadow:
                console.print(f"\n[bold yellow]👻 Shadow APIs: {len(shadow)}[/bold yellow]")
        
        if args.output:
            data = {
                "timestamp": datetime.now().isoformat(),
                "target": args.target,
                "summary": summary,
                "endpoints": [e.to_dict() for e in endpoints]
            }
            with open(args.output, 'w') as f:
                json.dump(data, f, indent=2)
            console.print(f"\n[green]✓ Saved: {args.output}[/green]")
        
        # Export OpenAPI 3.0 specification for DAST integration
        if args.export_openapi:
            # Determine output filename
            if args.export_openapi == "AUTO":
                # Auto-generate filename based on service name or target
                if args.service_name:
                    openapi_file = f"{args.service_name}-openapi.json"
                else:
                    # Use target directory name
                    target_name = os.path.basename(os.path.normpath(args.target)).replace(" ", "-").lower()
                    openapi_file = f"{target_name}-openapi.json"
            else:
                openapi_file = args.export_openapi
            
            export_openapi(endpoints, args.target, openapi_file, args.service_name)
            
            # Print service context for microservices environments
            if args.service_name:
                console.print(f"  • Service: [cyan]{args.service_name}[/cyan]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)
    finally:
        if tmp and os.path.exists(tmp):
            shutil.rmtree(tmp, ignore_errors=True)
    
    console.print("\n[bold green]✓ Complete![/bold green]")

if __name__ == "__main__":
    main()