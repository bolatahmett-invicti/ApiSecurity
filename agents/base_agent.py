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

    def __init__(self, api_key: str = None, config: Optional[Dict[str, Any]] = None, provider=None):
        """
        Initialize the agent.

        Args:
            api_key: API key (legacy parameter, kept for backward compatibility)
            config: Agent-specific configuration
            provider: LLMProvider instance (if None, will create from config/env)
        """
        self.api_key = api_key
        self.config = config or {}
        self.logger = logging.getLogger(f"api_scanner.agents.{self.__class__.__name__}")

        # LLM Provider (lazily initialized)
        self._provider = provider

        # Statistics
        self.stats = {
            "total_calls": 0,
            "successful_calls": 0,
            "failed_calls": 0,
            "cache_hits": 0,
            "tokens_used": 0,
        }

    @property
    def provider(self):
        """Lazy initialization of LLM provider."""
        if self._provider is None:
            try:
                from agents.llm_provider import LLMProviderFactory

                # Try to get provider from config first
                provider_type = self.config.get("llm_provider", "anthropic")
                model = self.config.get("model", None)
                max_tokens = self.config.get("max_tokens", 4096)

                # Use api_key if provided, otherwise let factory use environment variables
                if self.api_key:
                    self._provider = LLMProviderFactory.create(
                        provider_type=provider_type,
                        api_key=self.api_key,
                        model=model or LLMProviderFactory._get_default_model(provider_type),
                        max_tokens=max_tokens
                    )
                else:
                    # Use environment variables
                    self._provider = LLMProviderFactory.from_env()

                self.logger.info(f"Initialized {self._provider.get_provider_name()} provider with model {self._provider.model}")
            except ImportError as e:
                self.logger.error(f"Failed to import LLM provider: {e}")
                raise
        return self._provider

    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Unique identifier for this agent (for logging/caching)."""
        pass

    @property
    def model(self) -> str:
        """LLM model to use (from provider)."""
        return self.provider.model

    @property
    def max_tokens(self) -> int:
        """Maximum tokens for response (from provider)."""
        return self.provider.max_tokens

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

    async def _call_claude(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> str:
        """
        Call LLM API with retry logic and error handling.

        Args:
            system_prompt: System instructions
            user_prompt: User query
            temperature: Sampling temperature (0.0 = deterministic)

        Returns:
            LLM response text

        Raises:
            Exception: If API call fails after retries
        """
        try:
            from tenacity import retry, stop_after_attempt, wait_exponential
        except ImportError:
            self.logger.warning("tenacity not installed, retries disabled. Run: pip install tenacity")
            # Fallback to simple retry
            return await self._call_llm_simple(system_prompt, user_prompt, temperature)

        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=2, max=10)
        )
        async def _make_request():
            self.stats["total_calls"] += 1

            # Use provider's generate method
            response_text = await self.provider.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature
            )

            self.stats["successful_calls"] += 1

            # Estimate tokens (all providers support count_tokens)
            tokens_used = self.provider.count_tokens(system_prompt + user_prompt + response_text)
            self.stats["tokens_used"] += tokens_used

            return response_text

        try:
            return await _make_request()
        except Exception as e:
            self.stats["failed_calls"] += 1

            # Enhanced error messages for common issues
            error_msg = str(e).lower()
            if "rate limit" in error_msg or "429" in error_msg:
                self.logger.error(f"Rate limit exceeded. Consider reducing ENRICHMENT_MAX_WORKERS or adding delays.")
                raise Exception(f"Rate limit exceeded: {e}")
            elif "quota" in error_msg or "insufficient_quota" in error_msg:
                self.logger.error(f"API quota exceeded or insufficient credits")
                raise Exception(f"Quota exceeded: {e}")
            elif "invalid_api_key" in error_msg or "authentication" in error_msg:
                self.logger.error(f"API authentication failed. Check your API key.")
                raise Exception(f"Authentication failed: {e}")
            elif "invalid" in error_msg and ("model" in error_msg or "engine" in error_msg):
                self.logger.error(f"Invalid model specified: {self.model}")
                raise Exception(f"Invalid model: {e}")
            else:
                self.logger.error(f"LLM API call failed: {e}")
                raise

    async def _call_llm_simple(self, system_prompt: str, user_prompt: str, temperature: float = 0.0) -> str:
        """Simple LLM API call without retry library."""
        import asyncio

        for attempt in range(3):
            try:
                self.stats["total_calls"] += 1

                # Use provider's generate method
                response_text = await self.provider.generate(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature
                )

                self.stats["successful_calls"] += 1

                # Estimate tokens
                tokens_used = self.provider.count_tokens(system_prompt + user_prompt + response_text)
                self.stats["tokens_used"] += tokens_used

                return response_text

            except Exception as e:
                if attempt < 2:  # Retry
                    await asyncio.sleep(2 ** attempt)
                    continue
                self.stats["failed_calls"] += 1
                raise

    def get_stats(self) -> Dict[str, int]:
        """Get agent statistics."""
        return self.stats.copy()
