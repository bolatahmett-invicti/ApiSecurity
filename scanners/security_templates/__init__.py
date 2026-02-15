#!/usr/bin/env python3
"""
Security Payload Templates
===========================
Static security testing payload library.

Based on OWASP Top 10, PayloadsAllTheThings, and industry standards.

Cost savings: 100% (no LLM needed - payloads are standardized)
Coverage: OWASP Top 10 + common attack vectors
"""

from .payloads import SecurityPayloadTemplates

__all__ = ['SecurityPayloadTemplates']
