#!/usr/bin/env python3
"""
Deterministic Enrichers Module
================================
Python-based enrichers that extract API information without LLM calls.

These modules replace LLM usage for well-defined, pattern-based tasks:

**Phase 1 (70% cost savings):**
- Parameter extraction from route patterns
- HTTP method → operation mapping
- Standard status code responses

**Phase 2 (additional 15% savings):**
- Type hint → OpenAPI type conversion (AST-based)
- Decorator → security scheme detection (AST-based)
- Docstring → description extraction (AST-based)

Philosophy: "Python for structure, LLM for semantics"
"""

# Phase 1 modules
from .parameter_extractor import DeterministicParameterExtractor
from .http_method_analyzer import HTTPMethodAnalyzer
from .status_code_analyzer import StatusCodeAnalyzer

# Phase 2 modules (AST-based)
from .type_hint_analyzer import TypeHintAnalyzer
from .decorator_analyzer import DecoratorAnalyzer
from .docstring_parser import DocstringParser

__all__ = [
    # Phase 1
    'DeterministicParameterExtractor',
    'HTTPMethodAnalyzer',
    'StatusCodeAnalyzer',
    # Phase 2
    'TypeHintAnalyzer',
    'DecoratorAnalyzer',
    'DocstringParser',
]
