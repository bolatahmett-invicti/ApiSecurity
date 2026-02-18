"""
Shared data models and BaseScanner for the Universal Polyglot API Scanner.

All language-specific scanners import from this module.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Set


# =============================================================================
# ENUMS
# =============================================================================

class Language(Enum):
    PYTHON = "Python"
    DOTNET = "C#/.NET"
    GO = "Go"
    JAVA = "Java"
    JAVASCRIPT = "JavaScript"
    TYPESCRIPT = "TypeScript"
    RUBY = "Ruby"
    RUST = "Rust"
    PHP = "PHP"
    KOTLIN = "Kotlin"
    CRYSTAL = "Crystal"
    ELIXIR = "Elixir"
    SCALA = "Scala"
    SWIFT = "Swift"
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


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class PatternDef(NamedTuple):
    """Definition of a detection pattern."""
    regex: str
    framework: str
    kind: EndpointKind
    method_group: Optional[int] = None   # Regex group for HTTP method
    route_group: Optional[int] = None    # Regex group for route/name
    label: Optional[str] = None          # Custom label for display


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
