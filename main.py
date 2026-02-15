#!/usr/bin/env python3
"""
Universal Polyglot API Scanner v4.0 - PRODUCTION READY
=======================================================
Enterprise-grade, pattern-based API discovery tool supporting multiple languages,
frameworks, and static specification files.

Features:
  - Multi-language support (Python, C#, Go, Java, JS/TS)
  - Static spec parsing (OpenAPI, GraphQL)
  - Parallel processing for large codebases
  - Incremental scanning with baseline support
  - Policy engine for compliance rules
  - Multiple output formats (JSON, SARIF, JUnit)
  - Audit logging and metrics
  - CI/CD integration ready

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
import logging
import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional, NamedTuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# =============================================================================
# VERSION
# =============================================================================
__version__ = "4.0.0"

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
# LOGGING CONFIGURATION
# =============================================================================
def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure structured logging for the scanner."""
    logger = logging.getLogger("api_scanner")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with structured format
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # Only warnings and errors to console
    console_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

# =============================================================================
# CONFIGURATION SYSTEM
# =============================================================================
@dataclass
class ScannerConfig:
    """
    Scanner configuration with sensible defaults.
    Can be loaded from environment variables, config file, or CLI args.
    """
    # Scanning options
    ignore_dirs: Set[str] = field(default_factory=set)
    max_file_size_mb: int = 10
    timeout_seconds: int = 300
    parallel_workers: int = 4
    enable_heuristics: bool = True
    
    # Risk thresholds
    risk_threshold: str = "LOW"  # Minimum risk level to report
    fail_on_critical: bool = False  # Exit with error if critical findings
    
    # Output options
    output_format: str = "json"  # json, sarif, junit
    verbose: bool = False
    
    # Incremental scanning
    enable_incremental: bool = False
    baseline_file: str = ".api-scan-baseline.json"
    
    # Policy
    policy_file: Optional[str] = None
    
    # Audit & Metrics
    audit_log_file: Optional[str] = None
    metrics_enabled: bool = False
    
    def __post_init__(self):
        """Apply default ignore dirs if not set."""
        if not self.ignore_dirs:
            self.ignore_dirs = DEFAULT_IGNORE_DIRS.copy()
    
    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """Load configuration from environment variables."""
        return cls(
            max_file_size_mb=int(os.getenv("SCANNER_MAX_FILE_SIZE", 10)),
            timeout_seconds=int(os.getenv("SCANNER_TIMEOUT", 300)),
            parallel_workers=int(os.getenv("SCANNER_WORKERS", 4)),
            enable_heuristics=os.getenv("SCANNER_HEURISTICS", "true").lower() == "true",
            risk_threshold=os.getenv("SCANNER_RISK_THRESHOLD", "LOW"),
            fail_on_critical=os.getenv("SCANNER_FAIL_ON_CRITICAL", "false").lower() == "true",
            output_format=os.getenv("SCANNER_OUTPUT_FORMAT", "json"),
            verbose=os.getenv("SCANNER_VERBOSE", "false").lower() == "true",
            enable_incremental=os.getenv("SCANNER_INCREMENTAL", "false").lower() == "true",
            baseline_file=os.getenv("SCANNER_BASELINE_FILE", ".api-scan-baseline.json"),
            policy_file=os.getenv("SCANNER_POLICY_FILE"),
            audit_log_file=os.getenv("SCANNER_AUDIT_LOG"),
            metrics_enabled=os.getenv("SCANNER_METRICS", "false").lower() == "true",
        )
    
    @classmethod
    def from_file(cls, path: str) -> "ScannerConfig":
        """Load configuration from JSON or YAML file."""
        with open(path, 'r') as f:
            if path.endswith(('.yaml', '.yml')):
                try:
                    import yaml
                    data = yaml.safe_load(f)
                except ImportError:
                    raise RuntimeError("PyYAML required for YAML config files: pip install pyyaml")
            else:
                data = json.load(f)
        
        # Convert ignore_dirs list to set if present
        if 'ignore_dirs' in data and isinstance(data['ignore_dirs'], list):
            data['ignore_dirs'] = set(data['ignore_dirs'])
        
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "max_file_size_mb": self.max_file_size_mb,
            "timeout_seconds": self.timeout_seconds,
            "parallel_workers": self.parallel_workers,
            "enable_heuristics": self.enable_heuristics,
            "risk_threshold": self.risk_threshold,
            "fail_on_critical": self.fail_on_critical,
            "output_format": self.output_format,
            "enable_incremental": self.enable_incremental,
            "policy_file": self.policy_file,
            "metrics_enabled": self.metrics_enabled,
        }

# =============================================================================
# CONFIGURATION - STRICT IGNORE PATTERNS
# =============================================================================
DEFAULT_IGNORE_DIRS: Set[str] = {
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

# Alias for backward compatibility
IGNORE_DIRS = DEFAULT_IGNORE_DIRS

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
        - ASP.NET Core: public class XController : ControllerBase
        - ASP.NET Web API 2: public class XController : ApiController (System.Web.Http)
        - Generated: public abstract class XControllerBase : Microsoft.AspNetCore.Mvc.Controller
        """
        results = []
        
        # Detect if this is ASP.NET Web API 2 (System.Web.Http) or ASP.NET Core
        is_webapi2 = "System.Web.Http" in content or "using System.Web.Http;" in content
        
        # Extended pattern to match both standard and fully-qualified controller base classes
        controller_pattern = r'public\s+(?:abstract\s+)?class\s+(\w+)\s*:\s*(?:Microsoft\.AspNetCore\.Mvc\.)?(Controller|ControllerBase|ApiController|ODataController|InvictiApiController|\w+ApiController|\w+Controller)'
        
        for class_match in re.finditer(controller_pattern, content, re.MULTILINE):
            controller_name = class_match.group(1)
            base_class = class_match.group(2)
            class_start_pos = class_match.start()
            class_end_pos = class_match.end()
            
            # Skip if it's just a class ending with Controller but not inheriting from a controller base
            if base_class not in ('Controller', 'ControllerBase', 'ApiController', 'ODataController') and not base_class.endswith('ApiController') and not base_class.endswith('Controller'):
                continue
            
            lookback_start = max(0, class_start_pos - 500)
            preceding_text = content[lookback_start:class_start_pos]
            
            base_route = ""
            
            # Support both [Route("...")] and [Microsoft.AspNetCore.Mvc.Route("...")]
            route_match = re.search(r'\[(?:Microsoft\.AspNetCore\.Mvc\.)?Route\s*\(\s*["\']([^"\']+)["\']\s*\)\]', preceding_text)
            if route_match:
                base_route = route_match.group(1)
            
            # ASP.NET Web API 2: Support [RoutePrefix("api/1.0/discovery")]
            route_prefix_match = re.search(r'\[RoutePrefix\s*\(\s*["\']([^"\']+)["\']\s*\)\]', preceding_text)
            if route_prefix_match:
                base_route = route_prefix_match.group(1)
            
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
                # Pattern 4: ASP.NET Web API 2: [HttpGet] standalone (route comes from separate [Route] attribute)
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
                        
                        # ASP.NET Web API 2 & Core: Support [Route("...")] attribute for method-level routes
                        method_route_attr = re.search(r'\[(?:Microsoft\.AspNetCore\.Mvc\.)?Route\s*\(\s*["\']([^"\']+)["\']\s*\)\]', method_preceding)
                        if method_route_attr and not method_route:
                            method_route = method_route_attr.group(1)
                        
                        # Also check for [Route] after the verb attribute (common in Web API 2)
                        method_following_block = class_body[verb_pos:verb_pos + 500]
                        # Look for [Route("...")] between verb and method signature
                        route_after_verb = re.search(r'\]\s*\[Route\s*\(\s*["\']([^"\']+)["\']\s*\)\]', method_following_block)
                        if route_after_verb and not method_route:
                            method_route = route_after_verb.group(1)
                        
                        method_following = class_body[verb_pos:verb_pos + 1000]  # Extended for parameter extraction
                        action_name = "Unknown"
                        
                        # Support both ASP.NET Core and Web API 2 return types.
                        # Core: IActionResult, ActionResult<T>, Task<IActionResult>
                        # Web API 2: IHttpActionResult, HttpResponseMessage, Task<HttpResponseMessage>
                        sig_pattern = r'(?:public|private|protected)\s+(?:async\s+)?(?:virtual\s+)?(?:override\s+)?(?:Task<)?(?:IActionResult|ActionResult(?:<[^>]+>)?|IHttpActionResult|HttpResponseMessage|[\w<>\[\]]+)>?\s+(\w+)\s*\('
                        sig_match = re.search(sig_pattern, method_following)
                        if sig_match:
                            action_name = sig_match.group(1)
                        
                        # Extract method parameters for payload discovery
                        method_params = self._extract_method_parameters(method_following)
                        
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
                        
                        # Check for authorization attributes (both Core and Web API 2)
                        if re.search(r'\[Authorize', auth_context, re.IGNORECASE):
                            auth_status = AuthStatus.PRIVATE
                        if re.search(r'\[Authorize', preceding_text, re.IGNORECASE):
                            auth_status = AuthStatus.PRIVATE
                        if re.search(r'\[ApiAuthorize', auth_context, re.IGNORECASE):  # Invicti custom auth
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
                                "parameters": method_params.get("parameters", []),
                                "request_body": method_params.get("request_body"),
                                "response_type": method_params.get("response_type"),
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
    
    def _extract_method_parameters(self, method_body: str) -> Dict[str, Any]:
        """
        Extract method parameters including request body DTOs, query params, and route params.
        Returns a dict with 'parameters' and 'request_body' info.
        """
        result = {
            "parameters": [],
            "request_body": None,
            "response_type": None
        }
        
        # Pattern to match method signature with parameters
        # Handles: public async Task<IHttpActionResult> Create(CreateUserDto model, int page = 1)
        sig_pattern = r'(?:public|private|protected)\s+(?:async\s+)?(?:virtual\s+)?(?:override\s+)?(?:Task<)?(?:IActionResult|ActionResult(?:<([^>]+)>)?|IHttpActionResult|HttpResponseMessage|([A-Z]\w+))>?\s+\w+\s*\(([^)]*)\)'
        
        sig_match = re.search(sig_pattern, method_body, re.DOTALL)
        if not sig_match:
            return result
        
        # Extract response type if present (from ActionResult<T> or return type)
        response_type = sig_match.group(1) or sig_match.group(2)
        if response_type and response_type not in ('IActionResult', 'IHttpActionResult', 'HttpResponseMessage', 'Task'):
            result["response_type"] = response_type
        
        params_str = sig_match.group(3)
        if not params_str or not params_str.strip():
            return result
        
        # Parse individual parameters
        # Handle complex generic types like Dictionary<string, object>
        params = self._split_parameters(params_str)
        
        for param in params:
            param = param.strip()
            if not param:
                continue
            
            param_info = self._parse_parameter(param)
            if param_info:
                # Determine if it's a body parameter or query/route parameter
                if param_info.get("is_body"):
                    result["request_body"] = param_info
                else:
                    result["parameters"].append(param_info)
        
        return result
    
    def _split_parameters(self, params_str: str) -> List[str]:
        """Split parameter string handling nested generics."""
        params = []
        current = ""
        depth = 0
        
        for char in params_str:
            if char == '<':
                depth += 1
                current += char
            elif char == '>':
                depth -= 1
                current += char
            elif char == ',' and depth == 0:
                params.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            params.append(current.strip())
        
        return params
    
    def _parse_parameter(self, param: str) -> Optional[Dict[str, Any]]:
        """Parse a single parameter and determine its source and type."""
        # Check for attribute annotations
        from_body = bool(re.search(r'\[FromBody\]', param, re.IGNORECASE))
        from_query = bool(re.search(r'\[FromQuery\]', param, re.IGNORECASE))
        from_route = bool(re.search(r'\[FromRoute\]', param, re.IGNORECASE))
        from_uri = bool(re.search(r'\[FromUri\]', param, re.IGNORECASE))  # Web API 2
        
        # Remove attributes for type parsing
        clean_param = re.sub(r'\[[^\]]+\]\s*', '', param).strip()
        
        # Parse type and name: "CreateUserDto model" or "int page = 1"
        # Handle nullable types: "int? page"
        type_pattern = r'^([\w<>,\[\]\?\.]+)\s+(\w+)(?:\s*=\s*(.+))?$'
        match = re.match(type_pattern, clean_param)
        
        if not match:
            return None
        
        param_type = match.group(1)
        param_name = match.group(2)
        default_value = match.group(3)
        
        # Determine if this is a complex type (likely request body)
        is_complex_type = self._is_complex_type(param_type)
        
        # In Web API 2, complex types without [FromUri] are body by default
        # Simple types are query params by default
        is_body = from_body or (is_complex_type and not from_query and not from_route and not from_uri)
        
        param_info = {
            "name": param_name,
            "type": param_type,
            "is_body": is_body,
            "is_query": from_query or from_uri or (not is_complex_type and not from_body and not from_route),
            "is_route": from_route,
            "required": default_value is None,
            "default": default_value,
            "schema": self._type_to_schema(param_type)
        }
        
        return param_info
    
    def _is_complex_type(self, type_name: str) -> bool:
        """Check if a type is a complex type (DTO/Model) vs primitive."""
        # Simple/primitive types
        simple_types = {
            'int', 'long', 'short', 'byte', 'float', 'double', 'decimal',
            'bool', 'boolean', 'string', 'char', 'guid', 'datetime',
            'int32', 'int64', 'int16', 'uint', 'uint32', 'uint64',
            'timespan', 'datetimeoffset', 'object', 'dynamic'
        }
        
        # Remove nullable indicator and array brackets
        clean_type = type_name.lower().replace('?', '').replace('[]', '')
        
        # Check for collections of simple types
        if re.match(r'^(list|ienumerable|icollection|array)<', clean_type):
            inner = re.search(r'<(.+)>', clean_type)
            if inner:
                return self._is_complex_type(inner.group(1))
        
        return clean_type not in simple_types
    
    def _type_to_schema(self, type_name: str) -> Dict[str, Any]:
        """Convert C# type to OpenAPI schema."""
        type_lower = type_name.lower().replace('?', '')
        
        # Handle nullable
        nullable = '?' in type_name
        
        # Integer types
        if type_lower in ('int', 'int32', 'short', 'int16', 'byte'):
            schema = {"type": "integer", "format": "int32"}
        elif type_lower in ('long', 'int64'):
            schema = {"type": "integer", "format": "int64"}
        # Floating point
        elif type_lower in ('float', 'single'):
            schema = {"type": "number", "format": "float"}
        elif type_lower in ('double', 'decimal'):
            schema = {"type": "number", "format": "double"}
        # Boolean
        elif type_lower in ('bool', 'boolean'):
            schema = {"type": "boolean"}
        # String types
        elif type_lower == 'string':
            schema = {"type": "string"}
        elif type_lower == 'guid':
            schema = {"type": "string", "format": "uuid"}
        elif type_lower in ('datetime', 'datetimeoffset'):
            schema = {"type": "string", "format": "date-time"}
        elif type_lower == 'timespan':
            schema = {"type": "string", "format": "duration"}
        # Arrays
        elif type_lower.endswith('[]'):
            inner_type = type_name[:-2]
            schema = {"type": "array", "items": self._type_to_schema(inner_type)}
        # Generic collections
        elif re.match(r'^(list|ienumerable|icollection|array)<', type_lower):
            inner = re.search(r'<(.+)>', type_name)
            if inner:
                schema = {"type": "array", "items": self._type_to_schema(inner.group(1))}
            else:
                schema = {"type": "array", "items": {"type": "object"}}
        # Complex types - reference to schema
        else:
            schema = {"$ref": f"#/components/schemas/{type_name}"}
        
        if nullable:
            schema["nullable"] = True
        
        return schema


# =============================================================================
# DTO/MODEL SCHEMA EXTRACTOR
# =============================================================================
class DtoSchemaExtractor:
    """
    Extract DTO/Model class definitions and convert to OpenAPI schemas.
    Parses C# class files to build component schemas.
    """
    
    def __init__(self):
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self._files_content: Dict[str, str] = {}
        self._processed_types: Set[str] = set()
    
    def index_files(self, target_path: Path, ignore_dirs: Set[str]):
        """Index all C# files for DTO lookup."""
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            
            for f in files:
                if f.endswith('.cs'):
                    fp = Path(root) / f
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as file:
                            self._files_content[str(fp)] = file.read()
                    except IOError:
                        continue
    
    def extract_schema(self, type_name: str) -> Optional[Dict[str, Any]]:
        """Extract schema for a DTO type by searching through indexed files."""
        # Clean type name
        clean_name = type_name.split('.')[-1].replace('?', '').replace('[]', '')
        
        # Skip if already processed
        if clean_name in self._processed_types:
            return self.schemas.get(clean_name)
        
        self._processed_types.add(clean_name)
        
        # Search for class definition
        for file_path, content in self._files_content.items():
            schema = self._extract_class_schema(clean_name, content)
            if schema:
                self.schemas[clean_name] = schema
                return schema
        
        return None
    
    def _extract_class_schema(self, class_name: str, content: str) -> Optional[Dict[str, Any]]:
        """Extract schema from a class definition."""
        # Pattern to find class/record definition
        # Handles: public class CreateUserDto, public record UserModel, public class UserDto : BaseDto
        class_pattern = rf'(?:public|internal)\s+(?:partial\s+)?(?:class|record|struct)\s+{re.escape(class_name)}(?:\s*<[^>]+>)?(?:\s*:\s*[^{{]+)?\s*\{{'
        
        match = re.search(class_pattern, content, re.IGNORECASE)
        if not match:
            return None
        
        # Find the class body
        class_start = match.end() - 1  # Start at opening brace
        brace_depth = 1
        class_end = class_start + 1
        
        while brace_depth > 0 and class_end < len(content):
            if content[class_end] == '{':
                brace_depth += 1
            elif content[class_end] == '}':
                brace_depth -= 1
            class_end += 1
        
        class_body = content[class_start:class_end]
        
        # Extract properties
        properties = {}
        required = []
        
        # Pattern for properties:
        # public string Name { get; set; }
        # public int? Age { get; set; }
        # [Required] public string Email { get; set; }
        # [JsonProperty("user_name")] public string UserName { get; set; }
        prop_pattern = r'(?:\[([^\]]+)\]\s*)*(?:public|internal)\s+([\w<>,\[\]\?\.]+)\s+(\w+)\s*\{\s*get;'
        
        for prop_match in re.finditer(prop_pattern, class_body):
            attributes = prop_match.group(1) or ""
            prop_type = prop_match.group(2)
            prop_name = prop_match.group(3)
            
            # Skip backing fields or internal properties
            if prop_name.startswith('_'):
                continue
            
            # Check for JsonProperty name override
            json_name = prop_name
            json_prop_match = re.search(r'JsonProperty\s*\(\s*["\']([^"\']+)["\']', attributes)
            if json_prop_match:
                json_name = json_prop_match.group(1)
            
            # Convert to camelCase for JSON (common convention)
            json_key = json_name[0].lower() + json_name[1:] if json_name else json_name
            
            # Build property schema
            prop_schema = self._type_to_openapi_schema(prop_type)
            
            # Add description from XML comments if available (simplified)
            properties[json_key] = prop_schema
            
            # Check if required
            if 'Required' in attributes or ('?' not in prop_type and not self._is_nullable_reference(prop_type)):
                # Only mark as required if has [Required] attribute
                if 'Required' in attributes:
                    required.append(json_key)
            
            # Check for nested complex types and extract them
            if '$ref' in prop_schema or (prop_schema.get('type') == 'array' and '$ref' in prop_schema.get('items', {})):
                nested_type = prop_type.replace('?', '').replace('[]', '')
                # Extract generic type
                generic_match = re.search(r'<(.+)>', nested_type)
                if generic_match:
                    nested_type = generic_match.group(1)
                
                if nested_type not in self._processed_types:
                    self.extract_schema(nested_type)
        
        schema = {
            "type": "object",
            "properties": properties
        }
        
        if required:
            schema["required"] = required
        
        return schema if properties else None
    
    def _type_to_openapi_schema(self, type_name: str) -> Dict[str, Any]:
        """Convert C# type to OpenAPI schema."""
        type_lower = type_name.lower().replace('?', '')
        nullable = '?' in type_name
        
        # Integer types
        if type_lower in ('int', 'int32', 'short', 'int16', 'byte'):
            schema = {"type": "integer", "format": "int32"}
        elif type_lower in ('long', 'int64'):
            schema = {"type": "integer", "format": "int64"}
        # Floating point
        elif type_lower in ('float', 'single'):
            schema = {"type": "number", "format": "float"}
        elif type_lower in ('double', 'decimal'):
            schema = {"type": "number", "format": "double"}
        # Boolean
        elif type_lower in ('bool', 'boolean'):
            schema = {"type": "boolean"}
        # String types
        elif type_lower == 'string':
            schema = {"type": "string"}
        elif type_lower == 'guid':
            schema = {"type": "string", "format": "uuid"}
        elif type_lower in ('datetime', 'datetimeoffset'):
            schema = {"type": "string", "format": "date-time"}
        elif type_lower == 'timespan':
            schema = {"type": "string", "format": "duration"}
        elif type_lower == 'object':
            schema = {"type": "object"}
        # Arrays
        elif type_lower.endswith('[]'):
            inner_type = type_name[:-2]
            schema = {"type": "array", "items": self._type_to_openapi_schema(inner_type)}
        # Generic collections
        elif re.match(r'^(list|ienumerable|icollection|ilist|array|hashset)<', type_lower):
            inner = re.search(r'<(.+)>', type_name)
            if inner:
                schema = {"type": "array", "items": self._type_to_openapi_schema(inner.group(1))}
            else:
                schema = {"type": "array", "items": {"type": "object"}}
        # Dictionary types
        elif re.match(r'^(dictionary|idictionary|concurrentdictionary)<', type_lower):
            schema = {"type": "object", "additionalProperties": True}
        # Complex types - reference to schema
        else:
            clean_type = type_name.split('.')[-1].replace('?', '').replace('[]', '')
            # Remove generic part for reference
            clean_type = re.sub(r'<.+>', '', clean_type)
            schema = {"$ref": f"#/components/schemas/{clean_type}"}
        
        if nullable and '$ref' not in schema:
            schema["nullable"] = True
        
        return schema
    
    def _is_nullable_reference(self, type_name: str) -> bool:
        """Check if type is a nullable reference type."""
        simple_types = {'int', 'long', 'short', 'byte', 'float', 'double', 'decimal', 
                       'bool', 'boolean', 'char', 'guid', 'datetime', 'timespan'}
        return type_name.lower() not in simple_types


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
# POLICY ENGINE - Enterprise Compliance
# =============================================================================
@dataclass
class SecurityPolicy:
    """Security policy rule definition."""
    name: str
    description: str
    severity: RiskLevel
    condition: str  # Python expression evaluated against endpoint
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "condition": self.condition,
        }


class PolicyEngine:
    """
    Evaluate endpoints against security policies for compliance.
    Supports custom policies loaded from YAML/JSON files.
    """
    
    DEFAULT_POLICIES = [
        SecurityPolicy(
            name="no-public-admin",
            description="Admin endpoints must not be public",
            severity=RiskLevel.CRITICAL,
            condition="'admin' in ep.route.lower() and ep.auth_status == AuthStatus.PUBLIC"
        ),
        SecurityPolicy(
            name="no-shadow-mutation",
            description="Mutation endpoints must have explicit authentication",
            severity=RiskLevel.HIGH,
            condition="ep.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and ep.auth_status == AuthStatus.UNKNOWN"
        ),
        SecurityPolicy(
            name="no-sensitive-public",
            description="Sensitive data endpoints must be private",
            severity=RiskLevel.CRITICAL,
            condition="any(kw in ep.route.lower() for kw in ['password', 'token', 'secret', 'key', 'credential']) and ep.auth_status == AuthStatus.PUBLIC"
        ),
        SecurityPolicy(
            name="no-debug-endpoints",
            description="Debug endpoints should not exist in production",
            severity=RiskLevel.HIGH,
            condition="any(kw in ep.route.lower() for kw in ['debug', 'test', 'swagger', 'graphql-playground'])"
        ),
        SecurityPolicy(
            name="auth-coverage",
            description="All non-health endpoints should have auth info",
            severity=RiskLevel.MEDIUM,
            condition="ep.auth_status == AuthStatus.UNKNOWN and not any(kw in ep.route.lower() for kw in ['health', 'ping', 'ready', 'live', 'metrics'])"
        ),
    ]
    
    def __init__(self, policies: Optional[List[SecurityPolicy]] = None):
        self.policies = policies if policies is not None else self.DEFAULT_POLICIES
        self._violations: List[Dict[str, Any]] = []
    
    def evaluate(self, endpoints: List[Endpoint]) -> List[Dict[str, Any]]:
        """
        Evaluate all endpoints against defined policies.
        Returns list of policy violations.
        """
        self._violations = []
        
        for ep in endpoints:
            for policy in self.policies:
                try:
                    # Create safe evaluation context
                    context = {
                        "ep": ep,
                        "AuthStatus": AuthStatus,
                        "RiskLevel": RiskLevel,
                        "any": any,
                        "all": all,
                        "len": len,
                    }
                    
                    if eval(policy.condition, {"__builtins__": {}}, context):
                        self._violations.append({
                            "policy": policy.name,
                            "description": policy.description,
                            "severity": policy.severity.value,
                            "endpoint": {
                                "route": ep.route,
                                "method": ep.method,
                                "file": ep.file_path,
                                "line": ep.line_number,
                                "auth_status": ep.auth_status.value,
                            }
                        })
                        logger.warning(f"Policy violation: {policy.name} - {ep.method} {ep.route}")
                except Exception as e:
                    logger.debug(f"Policy evaluation error for {policy.name}: {e}")
                    continue
        
        return self._violations
    
    @property
    def violations(self) -> List[Dict[str, Any]]:
        return self._violations
    
    @property
    def critical_count(self) -> int:
        return len([v for v in self._violations if v["severity"] == "CRITICAL"])
    
    @property
    def high_count(self) -> int:
        return len([v for v in self._violations if v["severity"] == "HIGH"])
    
    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        """Load policies from YAML or JSON file."""
        with open(path, 'r') as f:
            if path.endswith(('.yaml', '.yml')):
                try:
                    import yaml
                    data = yaml.safe_load(f)
                except ImportError:
                    raise RuntimeError("PyYAML required for policy files: pip install pyyaml")
            else:
                data = json.load(f)
        
        policies = []
        for p in data.get("policies", []):
            severity = RiskLevel[p.get("severity", "MEDIUM").upper()]
            policies.append(SecurityPolicy(
                name=p["name"],
                description=p.get("description", ""),
                severity=severity,
                condition=p["condition"],
            ))
        
        return cls(policies)

# =============================================================================
# OUTPUT FORMATTERS - CI/CD Integration
# =============================================================================
class OutputFormatter(ABC):
    """Base class for output formatters."""
    
    @abstractmethod
    def format(self, endpoints: List[Endpoint], summary: Dict[str, Any], 
               violations: Optional[List[Dict]] = None) -> str:
        """Format scan results."""
        pass
    
    @abstractmethod
    def file_extension(self) -> str:
        """Return file extension for this format."""
        pass


class SARIFFormatter(OutputFormatter):
    """
    SARIF format for GitHub Security tab and other SAST tools.
    Static Analysis Results Interchange Format (SARIF) v2.1.0
    """
    
    def format(self, endpoints: List[Endpoint], summary: Dict[str, Any],
               violations: Optional[List[Dict]] = None) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Universal Polyglot API Scanner",
                        "version": __version__,
                        "informationUri": "https://github.com/your-org/api-scanner",
                        "rules": self._generate_rules()
                    }
                },
                "results": self._generate_results(endpoints, violations or []),
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(tz=None).isoformat() + "Z"
                }]
            }]
        }
        return json.dumps(sarif, indent=2)
    
    def _generate_rules(self) -> List[Dict[str, Any]]:
        """Generate SARIF rule definitions."""
        return [
            {
                "id": "API001",
                "name": "ShadowAPI",
                "shortDescription": {"text": "Shadow API detected without authentication info"},
                "fullDescription": {"text": "An API endpoint was discovered that lacks explicit authentication configuration."},
                "defaultConfiguration": {"level": "warning"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
            },
            {
                "id": "API002",
                "name": "HighRiskEndpoint",
                "shortDescription": {"text": "High risk endpoint detected"},
                "fullDescription": {"text": "An API endpoint with critical or high risk characteristics was detected."},
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://owasp.org/API-Security/"
            },
            {
                "id": "API003",
                "name": "PublicSensitiveEndpoint",
                "shortDescription": {"text": "Sensitive endpoint is publicly accessible"},
                "fullDescription": {"text": "An endpoint handling sensitive data is marked as public."},
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
            },
            {
                "id": "API004",
                "name": "PolicyViolation",
                "shortDescription": {"text": "Security policy violation"},
                "fullDescription": {"text": "The endpoint violates a defined security policy."},
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://owasp.org/API-Security/"
            },
        ]
    
    def _generate_results(self, endpoints: List[Endpoint], violations: List[Dict]) -> List[Dict]:
        """Generate SARIF results from endpoints and violations."""
        results = []
        
        # High risk endpoints
        for ep in endpoints:
            if ep.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                results.append({
                    "ruleId": "API002",
                    "level": "error" if ep.risk_level == RiskLevel.CRITICAL else "warning",
                    "message": {
                        "text": f"High risk endpoint: {ep.method} {ep.route}. Reasons: {', '.join(ep.risk_reasons)}"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": ep.file_path.replace("\\", "/")},
                            "region": {"startLine": ep.line_number}
                        }
                    }],
                    "properties": {
                        "framework": ep.framework,
                        "authStatus": ep.auth_status.value,
                        "riskReasons": ep.risk_reasons
                    }
                })
            
            # Shadow APIs
            if ep.auth_status == AuthStatus.UNKNOWN:
                results.append({
                    "ruleId": "API001",
                    "level": "warning",
                    "message": {
                        "text": f"Shadow API: {ep.method} {ep.route} has no explicit authentication configuration"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": ep.file_path.replace("\\", "/")},
                            "region": {"startLine": ep.line_number}
                        }
                    }]
                })
        
        # Policy violations
        for violation in violations:
            results.append({
                "ruleId": "API004",
                "level": "error" if violation["severity"] == "CRITICAL" else "warning",
                "message": {
                    "text": f"Policy '{violation['policy']}': {violation['description']}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": violation["endpoint"]["file"].replace("\\", "/")},
                        "region": {"startLine": violation["endpoint"]["line"]}
                    }
                }]
            })
        
        return results
    
    def file_extension(self) -> str:
        return ".sarif"


class JUnitFormatter(OutputFormatter):
    """JUnit XML format for CI/CD test reporting."""
    
    def format(self, endpoints: List[Endpoint], summary: Dict[str, Any],
               violations: Optional[List[Dict]] = None) -> str:
        violations = violations or []
        critical = [e for e in endpoints if e.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        
        total_tests = len(endpoints)
        failures = len(critical) + len(violations)
        
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="API Security Scan" tests="{total_tests}" failures="{failures}" timestamp="{datetime.now().isoformat()}">
  <testsuite name="Endpoint Risk Analysis" tests="{len(endpoints)}" failures="{len(critical)}">
'''
        
        for ep in endpoints:
            test_name = f"{ep.method} {ep.route}".replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
            classname = ep.framework.replace('"', '&quot;')
            
            if ep.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                failure_msg = f"Risk Level: {ep.risk_level.value}"
                failure_detail = ', '.join(ep.risk_reasons).replace('"', '&quot;').replace('<', '&lt;')
                xml += f'''    <testcase name="{test_name}" classname="{classname}">
      <failure message="{failure_msg}">{failure_detail}</failure>
    </testcase>
'''
            else:
                xml += f'''    <testcase name="{test_name}" classname="{classname}" />
'''
        
        xml += '''  </testsuite>
'''
        
        if violations:
            xml += f'''  <testsuite name="Policy Compliance" tests="{len(violations)}" failures="{len(violations)}">
'''
            for v in violations:
                policy_name = v["policy"].replace('"', '&quot;')
                route = v["endpoint"]["route"].replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                xml += f'''    <testcase name="{policy_name}: {route}" classname="SecurityPolicy">
      <failure message="{v['severity']}">{v['description'].replace('"', '&quot;')}</failure>
    </testcase>
'''
            xml += '''  </testsuite>
'''
        
        xml += '''</testsuites>'''
        return xml
    
    def file_extension(self) -> str:
        return ".xml"


# =============================================================================
# INCREMENTAL SCANNING - CI/CD Optimization
# =============================================================================
class IncrementalScanner:
    """
    Scan only changed files since last scan for CI/CD efficiency.
    Maintains a baseline of file hashes.
    """
    
    def __init__(self, target: str, baseline_file: str = ".api-scan-baseline.json"):
        self.target = Path(target)
        self.baseline_file = Path(baseline_file)
        self.baseline = self._load_baseline()
        self._current_hashes: Dict[str, str] = {}
    
    def _load_baseline(self) -> Dict[str, Any]:
        """Load baseline from previous scan."""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load baseline: {e}")
        return {"files": {}, "endpoints": [], "timestamp": None}
    
    def _hash_file(self, path: Path) -> str:
        """Calculate MD5 hash of file content."""
        try:
            return hashlib.md5(path.read_bytes()).hexdigest()
        except IOError:
            return ""
    
    def get_changed_files(self, all_files: List[Path]) -> Tuple[List[Path], List[Path]]:
        """
        Identify new or modified files.
        Returns: (changed_files, unchanged_files)
        """
        changed = []
        unchanged = []
        previous_hashes = self.baseline.get("files", {})
        
        for fp in all_files:
            current_hash = self._hash_file(fp)
            self._current_hashes[str(fp)] = current_hash
            
            if str(fp) not in previous_hashes or previous_hashes[str(fp)] != current_hash:
                changed.append(fp)
            else:
                unchanged.append(fp)
        
        logger.info(f"Incremental scan: {len(changed)} changed, {len(unchanged)} unchanged")
        return changed, unchanged
    
    def get_cached_endpoints(self, unchanged_files: List[Path]) -> List[Endpoint]:
        """Get endpoints from cache for unchanged files."""
        cached = []
        cached_eps = {ep["file_path"]: ep for ep in self.baseline.get("endpoints", [])}
        
        for fp in unchanged_files:
            if str(fp) in cached_eps:
                ep_data = cached_eps[str(fp)]
                # Reconstruct endpoint from cached data
                cached.append(Endpoint(
                    file_path=ep_data["file_path"],
                    line_number=ep_data["line_number"],
                    language=Language(ep_data["language"]),
                    framework=ep_data["framework"],
                    kind=EndpointKind(ep_data["kind"]),
                    method=ep_data["method"],
                    route=ep_data["route"],
                    raw_match=ep_data.get("raw_match", ""),
                    risk_level=RiskLevel(ep_data["risk_level"]),
                    auth_status=AuthStatus(ep_data["auth_status"]),
                    risk_reasons=ep_data.get("risk_reasons", []),
                ))
        
        return cached
    
    def save_baseline(self, endpoints: List[Endpoint]):
        """Save current state as new baseline."""
        baseline = {
            "timestamp": datetime.now().isoformat(),
            "files": self._current_hashes,
            "endpoints": [ep.to_dict() for ep in endpoints],
        }
        
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        logger.info(f"Baseline saved: {len(endpoints)} endpoints")


# =============================================================================
# API CHANGE DETECTION
# =============================================================================
@dataclass
class APIChange:
    """Represents a change between two API scans."""
    change_type: str  # ADDED, REMOVED, MODIFIED
    endpoint: Endpoint
    previous_endpoint: Optional[Endpoint] = None
    breaking: bool = False
    reason: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "change_type": self.change_type,
            "breaking": self.breaking,
            "reason": self.reason,
            "endpoint": self.endpoint.to_dict(),
            "previous": self.previous_endpoint.to_dict() if self.previous_endpoint else None,
        }


class APIChangeDetector:
    """
    Detect API changes between scans for breaking change analysis.
    Useful for PR reviews and release gates.
    """
    
    BREAKING_CHANGE_REASONS = {
        "route_removed": "Endpoint removed - may break clients",
        "method_removed": "HTTP method removed from endpoint",
        "auth_added": "Authentication requirement added (PUBLIC -> PRIVATE)",
        "route_changed": "Route pattern changed",
    }
    
    def compare(self, previous: List[Endpoint], current: List[Endpoint]) -> List[APIChange]:
        """
        Compare two scan results and identify changes.
        
        Args:
            previous: Endpoints from previous scan (baseline)
            current: Endpoints from current scan
        
        Returns:
            List of API changes with breaking change indicators
        """
        changes = []
        
        # Create lookup maps
        prev_map: Dict[Tuple[str, str], Endpoint] = {
            (e.route, e.method): e for e in previous
        }
        curr_map: Dict[Tuple[str, str], Endpoint] = {
            (e.route, e.method): e for e in current
        }
        
        # Detect removed endpoints (BREAKING)
        for key, ep in prev_map.items():
            if key not in curr_map:
                changes.append(APIChange(
                    change_type="REMOVED",
                    endpoint=ep,
                    breaking=True,
                    reason=self.BREAKING_CHANGE_REASONS["route_removed"]
                ))
        
        # Detect added endpoints (non-breaking)
        for key, ep in curr_map.items():
            if key not in prev_map:
                changes.append(APIChange(
                    change_type="ADDED",
                    endpoint=ep,
                    breaking=False,
                    reason="New endpoint added"
                ))
        
        # Detect modified endpoints
        for key in prev_map.keys() & curr_map.keys():
            prev_ep = prev_map[key]
            curr_ep = curr_map[key]
            
            # Auth status change: PUBLIC -> PRIVATE is breaking
            if prev_ep.auth_status == AuthStatus.PUBLIC and curr_ep.auth_status == AuthStatus.PRIVATE:
                changes.append(APIChange(
                    change_type="MODIFIED",
                    endpoint=curr_ep,
                    previous_endpoint=prev_ep,
                    breaking=True,
                    reason=self.BREAKING_CHANGE_REASONS["auth_added"]
                ))
            # Auth status change: PRIVATE -> PUBLIC is not breaking but notable
            elif prev_ep.auth_status == AuthStatus.PRIVATE and curr_ep.auth_status == AuthStatus.PUBLIC:
                changes.append(APIChange(
                    change_type="MODIFIED",
                    endpoint=curr_ep,
                    previous_endpoint=prev_ep,
                    breaking=False,
                    reason="Authentication requirement removed (security concern)"
                ))
        
        return changes
    
    def has_breaking_changes(self, changes: List[APIChange]) -> bool:
        """Check if any changes are breaking."""
        return any(c.breaking for c in changes)
    
    def summary(self, changes: List[APIChange]) -> Dict[str, int]:
        """Generate change summary."""
        return {
            "total": len(changes),
            "added": len([c for c in changes if c.change_type == "ADDED"]),
            "removed": len([c for c in changes if c.change_type == "REMOVED"]),
            "modified": len([c for c in changes if c.change_type == "MODIFIED"]),
            "breaking": len([c for c in changes if c.breaking]),
        }


# =============================================================================
# AUDIT LOGGING & METRICS - Enterprise Compliance
# =============================================================================
class AuditLogger:
    """
    Audit logging for compliance and forensics.
    Produces JSON-formatted logs suitable for SIEM ingestion.
    """
    
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file
        self._audit_logger = logging.getLogger("api_scanner.audit")
        self._audit_logger.setLevel(logging.INFO)
        self._audit_logger.handlers.clear()
        
        if log_file:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter('%(message)s'))
            self._audit_logger.addHandler(handler)
    
    def _log(self, event: Dict[str, Any]):
        """Write audit event."""
        event["timestamp"] = datetime.utcnow().isoformat() + "Z"
        if self.log_file:
            self._audit_logger.info(json.dumps(event))
    
    def log_scan_started(self, target: str, user: str, config: Dict[str, Any], scan_id: str):
        """Log scan initiation."""
        self._log({
            "event_type": "SCAN_STARTED",
            "scan_id": scan_id,
            "target": target,
            "user": user,
            "config": config,
        })
    
    def log_scan_completed(self, scan_id: str, summary: Dict[str, Any], duration_seconds: float):
        """Log scan completion."""
        self._log({
            "event_type": "SCAN_COMPLETED",
            "scan_id": scan_id,
            "summary": summary,
            "duration_seconds": duration_seconds,
        })
    
    def log_critical_finding(self, scan_id: str, endpoint: Endpoint, 
                            policy_violation: Optional[str] = None):
        """Log critical security finding."""
        self._log({
            "event_type": "CRITICAL_FINDING",
            "scan_id": scan_id,
            "endpoint": endpoint.to_dict(),
            "policy_violation": policy_violation,
        })
    
    def log_policy_violation(self, scan_id: str, violation: Dict[str, Any]):
        """Log policy violation."""
        self._log({
            "event_type": "POLICY_VIOLATION",
            "scan_id": scan_id,
            "violation": violation,
        })


@dataclass
class ScanMetrics:
    """
    Metrics for monitoring and observability.
    Exports to Prometheus and Datadog formats.
    """
    scan_id: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    files_scanned: int = 0
    files_errored: int = 0
    endpoints_found: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    shadow_apis: int = 0
    policy_violations: int = 0
    duration_seconds: float = 0.0
    
    def finalize(self, summary: Dict[str, Any], violations: int = 0):
        """Finalize metrics after scan."""
        self.end_time = datetime.now()
        self.duration_seconds = (self.end_time - self.start_time).total_seconds()
        self.files_scanned = summary.get("files_scanned", 0)
        self.endpoints_found = summary.get("total", 0)
        self.critical_findings = summary.get("by_risk", {}).get("CRITICAL", 0)
        self.high_findings = summary.get("by_risk", {}).get("HIGH", 0)
        self.shadow_apis = summary.get("shadow_apis", 0)
        self.policy_violations = violations
    
    def to_prometheus(self) -> str:
        """Export as Prometheus metrics format."""
        labels = f'target="{self.target}",scan_id="{self.scan_id}"'
        return f'''# HELP api_scan_files_total Total files scanned
# TYPE api_scan_files_total counter
api_scan_files_total{{{labels}}} {self.files_scanned}

# HELP api_scan_endpoints_total Total endpoints discovered
# TYPE api_scan_endpoints_total counter
api_scan_endpoints_total{{{labels}}} {self.endpoints_found}

# HELP api_scan_critical_findings Critical security findings
# TYPE api_scan_critical_findings gauge
api_scan_critical_findings{{{labels}}} {self.critical_findings}

# HELP api_scan_high_findings High severity findings
# TYPE api_scan_high_findings gauge
api_scan_high_findings{{{labels}}} {self.high_findings}

# HELP api_scan_shadow_apis Shadow APIs without auth info
# TYPE api_scan_shadow_apis gauge
api_scan_shadow_apis{{{labels}}} {self.shadow_apis}

# HELP api_scan_policy_violations Policy violations count
# TYPE api_scan_policy_violations gauge
api_scan_policy_violations{{{labels}}} {self.policy_violations}

# HELP api_scan_duration_seconds Scan duration in seconds
# TYPE api_scan_duration_seconds gauge
api_scan_duration_seconds{{{labels}}} {self.duration_seconds}
'''
    
    def to_datadog(self) -> List[Dict[str, Any]]:
        """Export as Datadog metrics format."""
        timestamp = int(self.end_time.timestamp() if self.end_time else time.time())
        tags = [f"target:{self.target}", f"scan_id:{self.scan_id}"]
        
        return [
            {"metric": "api_scan.files_scanned", "points": [[timestamp, self.files_scanned]], "tags": tags, "type": "count"},
            {"metric": "api_scan.endpoints_found", "points": [[timestamp, self.endpoints_found]], "tags": tags, "type": "count"},
            {"metric": "api_scan.critical_findings", "points": [[timestamp, self.critical_findings]], "tags": tags, "type": "gauge"},
            {"metric": "api_scan.high_findings", "points": [[timestamp, self.high_findings]], "tags": tags, "type": "gauge"},
            {"metric": "api_scan.shadow_apis", "points": [[timestamp, self.shadow_apis]], "tags": tags, "type": "gauge"},
            {"metric": "api_scan.policy_violations", "points": [[timestamp, self.policy_violations]], "tags": tags, "type": "gauge"},
            {"metric": "api_scan.duration_seconds", "points": [[timestamp, self.duration_seconds]], "tags": tags, "type": "gauge"},
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "files_errored": self.files_errored,
            "endpoints_found": self.endpoints_found,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "shadow_apis": self.shadow_apis,
            "policy_violations": self.policy_violations,
        }

# =============================================================================
# SCANNER ORCHESTRATOR - Production Ready
# =============================================================================
class PolyglotScanner:
    """
    Universal Polyglot Scanner orchestrator.
    Coordinates all language-specific scanners with enterprise features.
    
    Features:
    - Parallel file processing
    - Configurable via ScannerConfig
    - Error isolation per file
    - Progress reporting
    """
    
    def __init__(self, target_path: str, config: Optional[ScannerConfig] = None):
        self.target = Path(target_path)
        self.config = config or ScannerConfig.from_env()
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
            # Spec scanners
            ".json": SpecScanner(),
            ".yaml": SpecScanner(),
            ".yml": SpecScanner(),
            ".graphql": SpecScanner(),
            ".gql": SpecScanner(),
        }
        self.enricher = Enricher()
        self.endpoints: List[Endpoint] = []
        self.stats = {
            "files_scanned": 0, 
            "files_skipped": 0, 
            "files_errored": 0,
            "by_language": {}
        }
        self._lock = Lock()
        self._ignore_dirs = self.config.ignore_dirs or DEFAULT_IGNORE_DIRS
    
    def should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored."""
        for part in path.parts:
            if part in self._ignore_dirs:
                return True
        return False
    
    def _scan_single_file(self, fp: Path) -> List[Endpoint]:
        """
        Scan a single file with error isolation.
        Returns list of endpoints found.
        """
        try:
            # Check file size
            file_size_mb = fp.stat().st_size / (1024 * 1024)
            if file_size_mb > self.config.max_file_size_mb:
                logger.warning(f"Skipping large file {fp}: {file_size_mb:.1f}MB > {self.config.max_file_size_mb}MB")
                return []
            
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            ext = fp.suffix.lower()
            scanner = self.scanners.get(ext)
            
            if not scanner:
                return []
            
            found = scanner.scan_file(fp, content, lines)
            enriched = [self.enricher.enrich(ep) for ep in found]
            
            return enriched
            
        except (IOError, UnicodeDecodeError) as e:
            logger.debug(f"File read error {fp}: {e}")
            with self._lock:
                self.stats["files_errored"] += 1
            return []
        except Exception as e:
            logger.error(f"Unexpected error scanning {fp}: {e}")
            with self._lock:
                self.stats["files_errored"] += 1
            return []
    
    def _collect_files(self) -> List[Path]:
        """Collect all scannable files."""
        all_files = []
        
        for root, dirs, files in os.walk(self.target):
            # Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if d not in self._ignore_dirs]
            
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
        
        return all_files
    
    def scan(self, progress_cb: Optional[Callable[[int, int, Path], None]] = None) -> List[Endpoint]:
        """
        Scan the target directory sequentially.
        Use scan_parallel() for large codebases.
        """
        self.endpoints = []
        all_files = self._collect_files()
        
        for i, fp in enumerate(all_files):
            if progress_cb:
                progress_cb(i + 1, len(all_files), fp)
            
            found = self._scan_single_file(fp)
            self.endpoints.extend(found)
            
            # Update language stats
            for ep in found:
                lang = ep.language.value
                self.stats["by_language"][lang] = self.stats["by_language"].get(lang, 0) + 1
            
            self.stats["files_scanned"] += 1
        
        # Deduplicate
        self.endpoints = self._deduplicate()
        return self.endpoints
    
    def scan_parallel(self, progress_cb: Optional[Callable[[int, int, Path], None]] = None) -> List[Endpoint]:
        """
        Parallel file scanning for large codebases.
        Uses ThreadPoolExecutor with configurable workers.
        """
        self.endpoints = []
        all_files = self._collect_files()
        completed = 0
        
        logger.info(f"Starting parallel scan with {self.config.parallel_workers} workers")
        
        with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
            # Submit all file scan tasks
            future_to_file = {
                executor.submit(self._scan_single_file, fp): fp 
                for fp in all_files
            }
            
            # Process results as they complete
            for future in as_completed(future_to_file):
                fp = future_to_file[future]
                completed += 1
                
                if progress_cb:
                    progress_cb(completed, len(all_files), fp)
                
                try:
                    found = future.result(timeout=30)  # 30s timeout per file
                    
                    with self._lock:
                        self.endpoints.extend(found)
                        self.stats["files_scanned"] += 1
                        
                        for ep in found:
                            lang = ep.language.value
                            self.stats["by_language"][lang] = self.stats["by_language"].get(lang, 0) + 1
                            
                except Exception as e:
                    logger.error(f"Task error for {fp}: {e}")
                    with self._lock:
                        self.stats["files_errored"] += 1
        
        # Deduplicate
        self.endpoints = self._deduplicate()
        
        logger.info(f"Parallel scan complete: {len(self.endpoints)} endpoints from {self.stats['files_scanned']} files")
        return self.endpoints
    
    def scan_incremental(self, incremental: IncrementalScanner,
                        progress_cb: Optional[Callable[[int, int, Path], None]] = None) -> List[Endpoint]:
        """
        Incremental scan - only process changed files.
        Uses cache for unchanged files.
        """
        self.endpoints = []
        all_files = self._collect_files()
        
        # Identify changed files
        changed_files, unchanged_files = incremental.get_changed_files(all_files)
        
        # Get cached endpoints for unchanged files
        cached_endpoints = incremental.get_cached_endpoints(unchanged_files)
        self.endpoints.extend(cached_endpoints)
        
        logger.info(f"Incremental scan: {len(changed_files)} to scan, {len(cached_endpoints)} cached")
        
        # Scan changed files (can use parallel)
        if len(changed_files) > 10 and self.config.parallel_workers > 1:
            # Use parallel for many files
            with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
                futures = {executor.submit(self._scan_single_file, fp): fp for fp in changed_files}
                
                for i, future in enumerate(as_completed(futures)):
                    fp = futures[future]
                    if progress_cb:
                        progress_cb(i + 1, len(changed_files), fp)
                    
                    try:
                        found = future.result(timeout=30)
                        with self._lock:
                            self.endpoints.extend(found)
                            self.stats["files_scanned"] += 1
                    except Exception as e:
                        logger.error(f"Error scanning {fp}: {e}")
        else:
            # Sequential for few files
            for i, fp in enumerate(changed_files):
                if progress_cb:
                    progress_cb(i + 1, len(changed_files), fp)
                
                found = self._scan_single_file(fp)
                self.endpoints.extend(found)
                self.stats["files_scanned"] += 1
        
        # Deduplicate and save new baseline
        self.endpoints = self._deduplicate()
        incremental.save_baseline(self.endpoints)
        
        return self.endpoints
    
    def _deduplicate(self) -> List[Endpoint]:
        """Remove duplicate endpoints."""
        seen = set()
        unique = []
        
        for ep in self.endpoints:
            key = (ep.file_path, ep.line_number, ep.route, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        return unique
    
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
            "files_errored": self.stats.get("files_errored", 0),
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
            
            # Initialize parameters list
            operation["parameters"] = []
            
            # Add path parameters
            if path_params:
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
            
            # Add query parameters from metadata
            if ep.metadata.get("parameters"):
                for param_info in ep.metadata["parameters"]:
                    if param_info.get("is_query") and param_info["name"] not in path_params:
                        param_schema = param_info.get("schema", {"type": "string"})
                        # Don't include $ref in query params - use primitive type
                        if "$ref" in param_schema:
                            param_schema = {"type": "string"}
                        
                        operation["parameters"].append({
                            "name": param_info["name"],
                            "in": "query",
                            "required": param_info.get("required", False),
                            "schema": param_schema,
                            "description": f"Query parameter: {param_info['name']} ({param_info.get('type', 'unknown')})"
                        })
            
            # Remove empty parameters list
            if not operation["parameters"]:
                del operation["parameters"]
            
            # Add request body for mutation methods with discovered payload info
            if method in ["post", "put", "patch"]:
                request_body_info = ep.metadata.get("request_body")
                
                if request_body_info and request_body_info.get("type"):
                    # We have discovered a request body DTO
                    body_type = request_body_info["type"]
                    body_schema = request_body_info.get("schema", {"type": "object"})
                    
                    operation["requestBody"] = {
                        "description": f"Request body: {body_type}",
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": body_schema
                            }
                        }
                    }
                    
                    # Track schema reference for later resolution
                    if "$ref" in body_schema:
                        schema_name = body_schema["$ref"].split("/")[-1]
                        if schema_name not in spec["components"]["schemas"]:
                            spec["components"]["schemas"][schema_name] = {
                                "type": "object",
                                "description": f"Auto-discovered DTO: {schema_name}",
                                "x-discovered-from": ep.file_path
                            }
                else:
                    # Fallback to generic object
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
            
            # Add response schema if discovered
            response_type = ep.metadata.get("response_type")
            if response_type:
                operation["responses"]["200"]["content"] = {
                    "application/json": {
                        "schema": {
                            "$ref": f"#/components/schemas/{response_type}"
                        }
                    }
                }
                # Track schema reference
                if response_type not in spec["components"]["schemas"]:
                    spec["components"]["schemas"][response_type] = {
                        "type": "object",
                        "description": f"Auto-discovered response type: {response_type}",
                        "x-discovered-from": ep.file_path
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


def export_openapi(endpoints: List[Endpoint], target: str, output_file: str, service_name: Optional[str] = None, 
                   extract_schemas: bool = True) -> None:
    """
    Export endpoints to an OpenAPI 3.0 specification file.
    
    Args:
        endpoints: List of discovered endpoints
        target: Source directory or URL that was scanned  
        output_file: Path to write the OpenAPI spec
        service_name: Optional microservice identifier for enterprise deployments
        extract_schemas: Whether to extract DTO schemas from source files
    """
    spec = generate_openapi_spec(endpoints, target, service_name)
    
    # Extract DTO schemas if enabled
    if extract_schemas and os.path.isdir(target):
        console.print("[cyan]Extracting DTO/Model schemas...[/cyan]")
        extractor = DtoSchemaExtractor()
        extractor.index_files(Path(target), DEFAULT_IGNORE_DIRS)
        
        # Find all schema references that need resolution
        schemas_to_resolve = set()
        for path_item in spec["paths"].values():
            for operation in path_item.values():
                # Check request body
                if "requestBody" in operation:
                    content = operation["requestBody"].get("content", {})
                    for media_type in content.values():
                        schema = media_type.get("schema", {})
                        if "$ref" in schema:
                            schema_name = schema["$ref"].split("/")[-1]
                            schemas_to_resolve.add(schema_name)
                
                # Check responses
                for response in operation.get("responses", {}).values():
                    content = response.get("content", {})
                    for media_type in content.values():
                        schema = media_type.get("schema", {})
                        if "$ref" in schema:
                            schema_name = schema["$ref"].split("/")[-1]
                            schemas_to_resolve.add(schema_name)
        
        # Resolve schemas
        resolved_count = 0
        for schema_name in schemas_to_resolve:
            extracted = extractor.extract_schema(schema_name)
            if extracted:
                spec["components"]["schemas"][schema_name] = extracted
                resolved_count += 1
        
        # Add all extracted schemas (including nested ones)
        for name, schema in extractor.schemas.items():
            if name not in spec["components"]["schemas"]:
                spec["components"]["schemas"][name] = schema
        
        console.print(f"  • Resolved {resolved_count} schema references")
        console.print(f"  • Total schemas: {len(spec['components']['schemas'])}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(spec, f, indent=2)
    
    # Print summary
    path_count = len(spec["paths"])
    operation_count = sum(len(methods) for methods in spec["paths"].values())
    schema_count = len(spec.get("components", {}).get("schemas", {}))
    
    console.print(f"\n[green]✓ OpenAPI 3.0 spec exported: {output_file}[/green]")
    console.print(f"  • Paths: {path_count}")
    console.print(f"  • Operations: {operation_count}")
    console.print(f"  • Schemas: {schema_count}")
    console.print(f"  • Ready for import into Invicti/Burp Suite/DAST tools")


def export_openapi_enriched(
    endpoints: List[Endpoint],
    target: str,
    output_file: str,
    service_name: Optional[str] = None,
    use_cache: bool = True
) -> None:
    """
    Export endpoints with AI-powered enrichment to OpenAPI 3.0 specification.

    This function uses Claude AI to generate comprehensive OpenAPI specs with:
    - Complete parameter definitions with types and validation
    - Request/response schemas with examples
    - Authentication/authorization detection
    - Security test payloads
    - API dependency graphs and test sequences

    Args:
        endpoints: List of discovered endpoints
        target: Source directory that was scanned
        output_file: Path to write the enriched OpenAPI spec
        service_name: Optional microservice identifier
        use_cache: Whether to use caching (default: True)

    Environment Variables:
        LLM_PROVIDER: AI provider (anthropic, openai, gemini, bedrock) - default: anthropic
        ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY / AWS_ACCESS_KEY_ID: API keys
        ENRICHMENT_CACHE_DIR: Cache directory (default: ./.cache/enrichment)
        LLM_MODEL: Model to use (provider-specific defaults)
    """
    import asyncio
    from agents import AgentOrchestrator, OrchestrationConfig
    from cache.cache_manager import CacheManager

    # Check for API key based on provider
    provider = os.getenv("LLM_PROVIDER", "anthropic").lower()
    api_key = None
    provider_name = ""

    if provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        provider_name = "Anthropic Claude"
    elif provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        provider_name = "OpenAI GPT-4"
    elif provider == "gemini":
        api_key = os.getenv("GOOGLE_API_KEY")
        provider_name = "Google Gemini"
    elif provider == "bedrock":
        # Bedrock requires both access key and secret key
        api_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        if not api_key or not secret_key:
            api_key = None
        provider_name = "AWS Bedrock"
    else:
        console.print(f"[yellow]⚠️ Unknown LLM provider: {provider}[/yellow]")
        console.print("[yellow]   Supported providers: anthropic, openai, gemini, bedrock[/yellow]")
        export_openapi(endpoints, target, output_file, service_name)
        return

    if not api_key:
        console.print(f"[yellow]⚠️ API key not found for {provider_name}. Falling back to basic OpenAPI export.[/yellow]")
        if provider == "anthropic":
            console.print("[yellow]   Set ANTHROPIC_API_KEY in .env to enable AI enrichment.[/yellow]")
        elif provider == "openai":
            console.print("[yellow]   Set OPENAI_API_KEY in .env to enable AI enrichment.[/yellow]")
        elif provider == "gemini":
            console.print("[yellow]   Set GOOGLE_API_KEY in .env to enable AI enrichment.[/yellow]")
        elif provider == "bedrock":
            console.print("[yellow]   Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env to enable AI enrichment.[/yellow]")
        export_openapi(endpoints, target, output_file, service_name)
        return

    console.print(f"\n[bold cyan]🤖 AI-Powered Enrichment Starting ({provider_name})...[/bold cyan]")

    # Get model name (provider-specific defaults handled by LLMProviderFactory)
    model_name = os.getenv("LLM_MODEL", "")
    if not model_name:
        # Show default model for the provider
        model_defaults = {
            "anthropic": "claude-sonnet-4-5-20250929",
            "openai": "gpt-4-turbo",
            "gemini": "gemini-1.5-pro",
            "bedrock": "anthropic.claude-3-5-sonnet-20241022-v2:0"
        }
        model_name = model_defaults.get(provider, "default")
    console.print(f"[dim]Using {model_name}[/dim]")

    try:
        # Initialize cache manager
        cache_dir = os.getenv("ENRICHMENT_CACHE_DIR", "./.cache/enrichment")
        cache_ttl = int(os.getenv("ENRICHMENT_CACHE_TTL", "604800"))
        cache_manager = CacheManager(cache_dir=cache_dir, ttl_seconds=cache_ttl) if use_cache else None

        # Build orchestration config
        config = OrchestrationConfig(
            enabled_agents=os.getenv("ENRICHMENT_AGENTS", "openapi_enrichment,auth_flow_detector,payload_generator,dependency_graph").split(","),
            max_concurrent_enrichments=int(os.getenv("ENRICHMENT_MAX_WORKERS", "3")),
            use_cache=use_cache,
            llm_provider=provider,
            model=os.getenv("LLM_MODEL") or None,  # None means use provider default
            fallback_enabled=os.getenv("ENRICHMENT_FALLBACK_ENABLED", "true").lower() == "true"
        )

        # Initialize orchestrator
        orchestrator = AgentOrchestrator(
            api_key=api_key,
            cache_manager=cache_manager,
            config=config
        )

        # Build code map (file_path → source code)
        console.print("[cyan]Loading source code for analysis...[/cyan]")
        code_map = {}
        seen_files = set()
        for ep in endpoints:
            if ep.file_path not in seen_files and os.path.isfile(ep.file_path):
                try:
                    with open(ep.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code_map[ep.file_path] = f.read()
                    seen_files.add(ep.file_path)
                except Exception as e:
                    console.print(f"[yellow]  ⚠️ Could not read {ep.file_path}: {e}[/yellow]")

        console.print(f"[cyan]Loaded {len(code_map)} source files[/cyan]")

        # Run enrichment pipeline
        console.print("[cyan]Running AI enrichment pipeline...[/cyan]")
        console.print(f"[dim]  • Global auth detection[/dim]")
        console.print(f"[dim]  • Dependency graph analysis[/dim]")
        console.print(f"[dim]  • Per-endpoint schema generation (parallel)[/dim]")
        console.print(f"[dim]  • Security payload generation[/dim]")

        # Run async enrichment
        enriched_spec = asyncio.run(orchestrator.enrich_all(endpoints, code_map))

        # Get stats
        stats = orchestrator.get_stats()

        # Write output
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(enriched_spec, f, indent=2)

        # Print summary
        path_count = len(enriched_spec.get("paths", {}))
        operation_count = sum(len(methods) for methods in enriched_spec.get("paths", {}).values())
        schema_count = len(enriched_spec.get("components", {}).get("schemas", {}))

        console.print(f"\n[green]✓ AI-Enriched OpenAPI 3.0 spec exported: {output_file}[/green]")
        console.print(f"  • Paths: {path_count}")
        console.print(f"  • Operations: {operation_count}")
        console.print(f"  • Schemas: {schema_count}")
        console.print(f"\n[bold]AI Enrichment Statistics:[/bold]")
        console.print(f"  • Total endpoints processed: {stats['total_endpoints']}")
        console.print(f"  • Successfully enriched: {stats['enriched_endpoints']}")
        console.print(f"  • Failed: {stats['failed_endpoints']}")
        console.print(f"  • Cache hits: {stats['cache_hits']}")
        console.print(f"  • Cache misses: {stats['cache_misses']}")
        console.print(f"  • API calls made: {stats['total_api_calls']}")

        if cache_manager:
            cache_stats = cache_manager.get_stats()
            hit_rate = cache_stats.get('hit_rate', 0) * 100
            console.print(f"  • Cache hit rate: {hit_rate:.1f}%")
            console.print(f"  • Cache entries: {cache_stats.get('entries', 0)}")

        console.print(f"\n[green]✓ Ready for import into Invicti with complete payloads and auth config[/green]")

    except ImportError as e:
        console.print(f"[yellow]⚠️ AI enrichment dependencies not installed: {e}[/yellow]")
        console.print(f"[yellow]   Run: pip install -r requirements.txt[/yellow]")
        console.print(f"[yellow]   Falling back to basic OpenAPI export...[/yellow]")
        export_openapi(endpoints, target, output_file, service_name)

    except Exception as e:
        console.print(f"[red]✗ AI enrichment failed: {e}[/red]")
        if config.fallback_enabled:
            console.print(f"[yellow]   Falling back to basic OpenAPI export...[/yellow]")
            export_openapi(endpoints, target, output_file, service_name)
        else:
            raise


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
# MAIN CLI - Production Ready
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description=f"Universal Polyglot API Scanner v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py ./src                          # Basic scan
  python main.py ./src --parallel               # Parallel scan for large repos
  python main.py ./src --incremental            # Only scan changed files
  python main.py ./src --export-sarif           # Export SARIF for GitHub
  python main.py ./src --policy policy.yaml     # Custom security policies
  python main.py ./src --fail-on-critical       # CI gate mode

  # AI-Powered Enrichment (v5.0+)
  python main.py ./src --export-openapi --ai-enrich              # AI-enriched OpenAPI spec
  python main.py ./src --export-openapi --ai-enrich --no-cache   # Force fresh analysis
  ANTHROPIC_API_KEY=sk-ant-... python main.py ./src --ai-enrich # With API key
        """
    )
    
    # Target
    parser.add_argument("target", help="Directory or Git URL to scan")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output", help="Output JSON file")
    output_group.add_argument("--export-openapi", metavar="FILE", nargs="?", const="AUTO",
                             help="Export OpenAPI 3.0 spec for DAST tools")
    output_group.add_argument("--export-sarif", metavar="FILE", nargs="?", const="AUTO",
                             help="Export SARIF format for GitHub Security")
    output_group.add_argument("--export-junit", metavar="FILE", nargs="?", const="AUTO",
                             help="Export JUnit XML for CI/CD")
    output_group.add_argument("--service-name", "-s", metavar="NAME",
                             help="Microservice identifier for output files")
    output_group.add_argument("--ai-enrich", action="store_true",
                             help="Enable AI-powered enrichment for OpenAPI specs (requires ANTHROPIC_API_KEY)")
    output_group.add_argument("--no-cache", action="store_true",
                             help="Disable caching for AI enrichment (force fresh analysis)")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--parallel", action="store_true",
                           help="Enable parallel file scanning")
    scan_group.add_argument("--workers", type=int, default=4,
                           help="Number of parallel workers (default: 4)")
    scan_group.add_argument("--incremental", action="store_true",
                           help="Incremental scan - only changed files")
    scan_group.add_argument("--baseline", metavar="FILE", default=".api-scan-baseline.json",
                           help="Baseline file for incremental scans")
    scan_group.add_argument("--max-file-size", type=int, default=10,
                           help="Max file size in MB to scan (default: 10)")
    scan_group.add_argument("--config", metavar="FILE",
                           help="Configuration file (JSON/YAML)")
    
    # Policy & Compliance
    policy_group = parser.add_argument_group("Policy & Compliance")
    policy_group.add_argument("--policy", metavar="FILE",
                             help="Security policy file (JSON/YAML)")
    policy_group.add_argument("--fail-on-critical", action="store_true",
                             help="Exit with error if critical findings")
    policy_group.add_argument("--fail-on-policy", action="store_true",
                             help="Exit with error if policy violations")
    
    # Audit & Metrics
    audit_group = parser.add_argument_group("Audit & Metrics")
    audit_group.add_argument("--audit-log", metavar="FILE",
                            help="Write audit log to file")
    audit_group.add_argument("--metrics", metavar="FILE",
                            help="Export Prometheus metrics to file")
    
    # Compare mode
    compare_group = parser.add_argument_group("Change Detection")
    compare_group.add_argument("--compare", metavar="FILE",
                              help="Compare with previous scan result JSON")
    
    # General
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output")
    
    args = parser.parse_args()
    
    # Banner
    if not args.quiet:
        console.print(Panel.fit(
            f"[bold cyan]🛡️ Universal Polyglot API Scanner v{__version__}[/bold cyan]\n"
            "[dim]Python | C#/.NET | Go | Java | JavaScript/TypeScript | OpenAPI | GraphQL[/dim]\n"
            "[dim]Production Ready: Parallel | Incremental | Policy | SARIF | Metrics[/dim]",
            border_style="cyan"
        ))
    
    # Build configuration
    if args.config:
        config = ScannerConfig.from_file(args.config)
    else:
        config = ScannerConfig.from_env()
    
    # Override with CLI args
    config.parallel_workers = args.workers
    config.max_file_size_mb = args.max_file_size
    config.verbose = args.verbose
    config.fail_on_critical = args.fail_on_critical
    config.enable_incremental = args.incremental
    config.baseline_file = args.baseline
    config.policy_file = args.policy
    config.audit_log_file = args.audit_log
    
    # Initialize
    scan_id = str(uuid.uuid4())[:8]
    start_time = datetime.now()
    target = args.target
    tmp = None
    exit_code = 0
    
    # Initialize audit logger
    audit = AuditLogger(args.audit_log) if args.audit_log else None
    
    # Initialize metrics
    metrics = ScanMetrics(
        scan_id=scan_id,
        target=target,
        start_time=start_time
    ) if args.metrics else None
    
    try:
        # Clone if URL
        if target.startswith(("http://", "https://", "git@")):
            tmp = clone_repo(target)
            target = tmp
        elif not os.path.exists(target):
            console.print(f"[red]Error: {target} not found[/red]")
            sys.exit(1)
        
        # Log scan start
        if audit:
            audit.log_scan_started(
                target=args.target,
                user=os.getenv("USER", os.getenv("USERNAME", "unknown")),
                config=config.to_dict(),
                scan_id=scan_id
            )
        
        # Create scanner
        scanner = PolyglotScanner(target, config)
        
        if not args.quiet:
            console.print(f"\n[bold cyan]▶ Scanning...[/bold cyan] [dim](scan_id: {scan_id})[/dim]")
        
        # Progress callback
        def progress_cb(cur, tot, fp):
            if not args.quiet:
                prog.update(task, completed=(cur / tot) * 100, 
                           description=f"[cyan]{Path(fp).name[:25]}")
        
        # Run scan
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), 
                     BarColumn(), TextColumn("{task.percentage:>3.0f}%"), 
                     console=console, disable=args.quiet) as prog:
            task = prog.add_task("[cyan]Scanning", total=100)
            
            if args.incremental:
                # Incremental scan
                inc_scanner = IncrementalScanner(target, args.baseline)
                endpoints = scanner.scan_incremental(inc_scanner, progress_cb=progress_cb)
            elif args.parallel:
                # Parallel scan
                endpoints = scanner.scan_parallel(progress_cb=progress_cb)
            else:
                # Sequential scan
                endpoints = scanner.scan(progress_cb=progress_cb)
        
        summary = scanner.summary()
        
        # Policy evaluation
        violations = []
        if args.policy:
            if not args.quiet:
                console.print("\n[bold cyan]▶ Evaluating policies...[/bold cyan]")
            policy_engine = PolicyEngine.from_file(args.policy)
            violations = policy_engine.evaluate(endpoints)
            
            if audit:
                for v in violations:
                    audit.log_policy_violation(scan_id, v)
        else:
            # Use default policies
            policy_engine = PolicyEngine()
            violations = policy_engine.evaluate(endpoints)
        
        # Log critical findings
        if audit:
            for ep in endpoints:
                if ep.risk_level == RiskLevel.CRITICAL:
                    audit.log_critical_finding(scan_id, ep)
        
        # Print results
        if not args.quiet:
            console.print(f"\n[green]✓ Found {len(endpoints)} endpoints[/green]")
            console.print("\n" + "=" * 70)
            console.print(make_summary(summary))
            console.print()
        
        if endpoints and not args.quiet:
            risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, 
                         RiskLevel.LOW: 3, RiskLevel.INFO: 4}
            endpoints.sort(key=lambda e: risk_order.get(e.risk_level, 5))
            console.print(make_table(endpoints))
            
            # High priority
            critical = [e for e in endpoints if e.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
            if critical:
                console.print("\n[bold red]⚠️ HIGH PRIORITY[/bold red]")
                for e in critical[:10]:
                    console.print(f"  • [{e.risk_level.value}] {e.language.value} {e.method} {e.route}")
                    for r in e.risk_reasons[:2]:
                        console.print(f"    └─ {r}")
            
            # Shadow APIs
            shadow = [e for e in endpoints if e.auth_status == AuthStatus.UNKNOWN]
            if shadow:
                console.print(f"\n[bold yellow]👻 Shadow APIs: {len(shadow)}[/bold yellow]")
            
            # Policy violations
            if violations:
                console.print(f"\n[bold red]🚨 Policy Violations: {len(violations)}[/bold red]")
                for v in violations[:5]:
                    console.print(f"  • [{v['severity']}] {v['policy']}: {v['endpoint']['method']} {v['endpoint']['route']}")
        
        # Compare mode
        if args.compare:
            if not args.quiet:
                console.print("\n[bold cyan]▶ Comparing with baseline...[/bold cyan]")
            
            with open(args.compare, 'r') as f:
                prev_data = json.load(f)
            
            # Reconstruct previous endpoints
            prev_endpoints = []
            for ep_data in prev_data.get("endpoints", []):
                prev_endpoints.append(Endpoint(
                    file_path=ep_data["file_path"],
                    line_number=ep_data["line_number"],
                    language=Language(ep_data["language"]),
                    framework=ep_data["framework"],
                    kind=EndpointKind(ep_data["kind"]),
                    method=ep_data["method"],
                    route=ep_data["route"],
                    raw_match=ep_data.get("raw_match", ""),
                    risk_level=RiskLevel(ep_data["risk_level"]),
                    auth_status=AuthStatus(ep_data["auth_status"]),
                ))
            
            detector = APIChangeDetector()
            changes = detector.compare(prev_endpoints, endpoints)
            change_summary = detector.summary(changes)
            
            if not args.quiet:
                console.print(f"\n[bold]API Changes:[/bold]")
                console.print(f"  • Added: {change_summary['added']}")
                console.print(f"  • Removed: {change_summary['removed']}")
                console.print(f"  • Modified: {change_summary['modified']}")
                console.print(f"  • [bold red]Breaking: {change_summary['breaking']}[/bold red]")
                
                if detector.has_breaking_changes(changes):
                    console.print("\n[bold red]⚠️ BREAKING CHANGES DETECTED[/bold red]")
                    for c in changes:
                        if c.breaking:
                            console.print(f"  • {c.change_type}: {c.endpoint.method} {c.endpoint.route}")
                            console.print(f"    └─ {c.reason}")
        
        # Export outputs
        if args.output:
            data = {
                "timestamp": datetime.now().isoformat(),
                "scan_id": scan_id,
                "target": args.target,
                "version": __version__,
                "summary": summary,
                "endpoints": [e.to_dict() for e in endpoints],
                "policy_violations": violations,
            }
            with open(args.output, 'w') as f:
                json.dump(data, f, indent=2)
            if not args.quiet:
                console.print(f"\n[green]✓ Saved: {args.output}[/green]")
        
        # OpenAPI export
        if args.export_openapi:
            if args.export_openapi == "AUTO":
                openapi_file = f"{args.service_name or 'api'}-openapi.json"
            else:
                openapi_file = args.export_openapi

            # Use AI-enriched export if requested
            if args.ai_enrich:
                export_openapi_enriched(
                    endpoints,
                    target,
                    openapi_file,
                    args.service_name,
                    use_cache=not args.no_cache
                )
            else:
                export_openapi(endpoints, target, openapi_file, args.service_name)
        
        # SARIF export
        if args.export_sarif:
            if args.export_sarif == "AUTO":
                sarif_file = f"{args.service_name or 'api'}-scan.sarif"
            else:
                sarif_file = args.export_sarif
            
            formatter = SARIFFormatter()
            sarif_output = formatter.format(endpoints, summary, violations)
            with open(sarif_file, 'w') as f:
                f.write(sarif_output)
            if not args.quiet:
                console.print(f"[green]✓ SARIF exported: {sarif_file}[/green]")
        
        # JUnit export
        if args.export_junit:
            if args.export_junit == "AUTO":
                junit_file = f"{args.service_name or 'api'}-scan.xml"
            else:
                junit_file = args.export_junit
            
            formatter = JUnitFormatter()
            junit_output = formatter.format(endpoints, summary, violations)
            with open(junit_file, 'w') as f:
                f.write(junit_output)
            if not args.quiet:
                console.print(f"[green]✓ JUnit exported: {junit_file}[/green]")
        
        # Metrics export
        if metrics:
            metrics.finalize(summary, len(violations))
            
            with open(args.metrics, 'w') as f:
                f.write(metrics.to_prometheus())
            if not args.quiet:
                console.print(f"[green]✓ Metrics exported: {args.metrics}[/green]")
        
        # Log completion
        if audit:
            duration = (datetime.now() - start_time).total_seconds()
            audit.log_scan_completed(scan_id, summary, duration)
        
        # Determine exit code
        if args.fail_on_critical and summary.get("critical", 0) > 0:
            if not args.quiet:
                console.print("\n[bold red]✗ Failed: Critical findings detected[/bold red]")
            exit_code = 1
        
        if args.fail_on_policy and len(violations) > 0:
            if not args.quiet:
                console.print("\n[bold red]✗ Failed: Policy violations detected[/bold red]")
            exit_code = 1
        
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
    
    if not args.quiet and exit_code == 0:
        console.print("\n[bold green]✓ Complete![/bold green]")
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()