"""
AI Enrichment Agents for API Scanner
=====================================

This module provides AI-powered agents that enrich API endpoint discovery
with comprehensive OpenAPI specifications suitable for DAST tools like Invicti.

Agents:
    - BaseAgent: Abstract base class for all agents
    - OpenAPIEnrichmentAgent: Generates complete operation objects
    - AuthFlowDetectorAgent: Detects authentication flows
    - PayloadGeneratorAgent: Generates test payloads
    - DependencyGraphAgent: Analyzes endpoint dependencies
    - AgentOrchestrator: Coordinates all agents

Usage:
    from agents import AgentOrchestrator, OpenAPIEnrichmentAgent

    orchestrator = AgentOrchestrator(config)
    result = await orchestrator.enrich_endpoints(endpoints, target_path)
"""

__version__ = "1.0.0"

from .base_agent import (
    BaseAgent,
    EnrichmentContext,
    EnrichmentResult,
    AgentStatus,
)
from .openapi_enrichment_agent import OpenAPIEnrichmentAgent
from .auth_flow_detector_agent import AuthFlowDetectorAgent
from .payload_generator_agent import PayloadGeneratorAgent
from .dependency_graph_agent import DependencyGraphAgent
from .orchestrator import AgentOrchestrator, OrchestrationConfig

__all__ = [
    "BaseAgent",
    "EnrichmentContext",
    "EnrichmentResult",
    "AgentStatus",
    "OpenAPIEnrichmentAgent",
    "AuthFlowDetectorAgent",
    "PayloadGeneratorAgent",
    "DependencyGraphAgent",
    "AgentOrchestrator",
    "OrchestrationConfig",
]
