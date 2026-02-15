#!/usr/bin/env python3
"""
Base Agent Abstract Class
==========================
Foundation for all AI enrichment agents.

This module provides the abstract base class and data structures
that all enrichment agents inherit from.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum
import logging

logger = logging.getLogger("api_scanner.agents")


class AgentStatus(Enum):
    """Agent execution status."""
    SUCCESS = "success"
    PARTIAL = "partial"  # Some enrichment succeeded
    FAILED = "failed"
    SKIPPED = "skipped"  # Not applicable


@dataclass
class EnrichmentContext:
    """
    Context passed to agents for enrichment.
    Contains all information agents need to perform enrichment.
    """
    # Endpoint information
    endpoint: Any  # Endpoint dataclass from main.py

    # Source code context
    file_content: Optional[str] = None  # Full file content
    surrounding_code: Optional[str] = None  # ~50 lines around endpoint
    function_body: Optional[str] = None  # Complete function/method body

    # Framework/Language metadata
    language: str = "unknown"
    framework: str = "unknown"

    # Related endpoints (for dependency analysis)
    related_endpoints: List[Any] = field(default_factory=list)

    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "endpoint": {
                "route": self.endpoint.route,
                "method": self.endpoint.method,
                "file_path": self.endpoint.file_path,
                "line_number": self.endpoint.line_number,
            },
            "language": self.language,
            "framework": self.framework,
            "has_file_content": self.file_content is not None,
            "has_function_body": self.function_body is not None,
        }


@dataclass
class EnrichmentResult:
    """
    Result returned by agents after enrichment.
    Standardized format for all agents.
    """
    status: AgentStatus
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)  # Agent-specific metadata

    def is_success(self) -> bool:
        """Check if enrichment was successful."""
        return self.status in [AgentStatus.SUCCESS, AgentStatus.PARTIAL]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "status": self.status.value,
            "data": self.data,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


class BaseAgent(ABC):
    """
    Abstract base class for all AI enrichment agents.

    Each agent is responsible for enriching a specific aspect of API documentation:
    - OpenAPIEnrichmentAgent: Complete operation objects
    - AuthFlowDetectorAgent: Authentication/authorization detection
    - PayloadGeneratorAgent: Test payload generation
    - DependencyGraphAgent: Endpoint dependencies and test sequences

    Usage:
        class MyAgent(BaseAgent):
            @property
            def agent_name(self) -> str:
                return "my_agent"

            async def enrich(self, context: EnrichmentContext) -> EnrichmentResult:
                # Implementation here
                pass
    """

    def __init__(self, anthropic_api_key: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the agent.

        Args:
            anthropic_api_key: Anthropic API key for Claude
            config: Agent-specific configuration
        """
        self.api_key = anthropic_api_key
        self.config = config or {}
        self.logger = logging.getLogger(f"api_scanner.agents.{self.__class__.__name__}")

        # Claude client (lazily initialized)
        self._client = None

        # Statistics
        self.stats = {
            "total_calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "cache_hits": 0,
            "tokens_used": 0,
        }

    @property
    def client(self):
        """Lazy initialization of Anthropic client."""
        if self._client is None:
            try:
                from anthropic import Anthropic
                self._client = Anthropic(api_key=self.api_key)
            except ImportError:
                self.logger.error("anthropic package not installed. Run: pip install anthropic")
                raise
        return self._client

    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Unique identifier for this agent (for logging/caching)."""
        pass

    @property
    def model(self) -> str:
        """Claude model to use (can be overridden in config)."""
        return self.config.get("model", "claude-sonnet-4-5-20250929")

    @property
    def max_tokens(self) -> int:
        """Maximum tokens for response."""
        return self.config.get("max_tokens", 4096)

    @abstractmethod
    async def enrich(self, context: EnrichmentContext) -> EnrichmentResult:
        """
        Perform enrichment based on the provided context.

        Args:
            context: EnrichmentContext with all necessary information

        Returns:
            EnrichmentResult with enriched data or errors
        """
        pass

    def _build_system_prompt(self) -> str:
        """Build system prompt for this agent (override in subclasses)."""
        return "You are an expert API documentation assistant."

    def _build_user_prompt(self, context: EnrichmentContext) -> str:
        """Build user prompt from context (override in subclasses)."""
        return "Analyze this API endpoint."

    async def _call_claude(self, system_prompt: str, user_prompt: str) -> str:
        """
        Call Claude API with retry logic and error handling.

        Args:
            system_prompt: System instructions
            user_prompt: User query

        Returns:
            Claude's response text

        Raises:
            Exception: If API call fails after retries
        """
        try:
            from tenacity import retry, stop_after_attempt, wait_exponential
        except ImportError:
            self.logger.warning("tenacity not installed, retries disabled. Run: pip install tenacity")
            # Fallback to simple retry
            return await self._call_claude_simple(system_prompt, user_prompt)

        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=2, max=10)
        )
        async def _make_request():
            self.stats["total_calls"] += 1

            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )

            self.stats["successful_calls"] += 1
            self.stats["tokens_used"] += response.usage.input_tokens + response.usage.output_tokens

            return response.content[0].text

        try:
            return await _make_request()
        except Exception as e:
            self.stats["failed_calls"] += 1
            self.logger.error(f"Claude API call failed: {e}")
            raise

    async def _call_claude_simple(self, system_prompt: str, user_prompt: str) -> str:
        """Simple Claude API call without retry library."""
        import asyncio

        for attempt in range(3):
            try:
                self.stats["total_calls"] += 1

                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_prompt}
                    ]
                )

                self.stats["successful_calls"] += 1
                self.stats["tokens_used"] += response.usage.input_tokens + response.usage.output_tokens

                return response.content[0].text

            except Exception as e:
                if attempt < 2:  # Retry
                    await asyncio.sleep(2 ** attempt)
                    continue
                self.stats["failed_calls"] += 1
                raise

    def get_stats(self) -> Dict[str, int]:
        """Get agent statistics."""
        return self.stats.copy()
