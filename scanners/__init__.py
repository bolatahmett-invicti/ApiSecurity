"""
Scanner package for the Universal Polyglot API Scanner.

Exports all language-specific scanner classes and shared data models.
"""

from .base import (
    Language,
    EndpointKind,
    RiskLevel,
    AuthStatus,
    PatternDef,
    Endpoint,
    BaseScanner,
)

from .python import PythonScanner
from .dotnet import DotNetScanner, DtoSchemaExtractor
from .go import GoScanner
from .java import JavaScanner
from .javascript import JavaScriptScanner
from .spec import SpecScanner
from .ruby import RubyScanner
from .rust import RustScanner
from .php import PHPScanner
from .kotlin import KotlinScanner
from .crystal import CrystalScanner
from .elixir import ElixirScanner
from .scala import ScalaScanner
from .swift import SwiftScanner

__all__ = [
    # Data models
    "Language",
    "EndpointKind",
    "RiskLevel",
    "AuthStatus",
    "PatternDef",
    "Endpoint",
    "BaseScanner",
    # Scanner classes
    "PythonScanner",
    "DotNetScanner",
    "DtoSchemaExtractor",
    "GoScanner",
    "JavaScanner",
    "JavaScriptScanner",
    "SpecScanner",
    "RubyScanner",
    "RustScanner",
    "PHPScanner",
    "KotlinScanner",
    "CrystalScanner",
    "ElixirScanner",
    "ScalaScanner",
    "SwiftScanner",
]
