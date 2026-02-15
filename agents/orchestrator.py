#!/usr/bin/env python3
"""
Agent Orchestrator
==================
Coordinates all AI enrichment agents with caching, error handling, and parallel execution.

This module manages the complete enrichment pipeline:
1. Global analysis (auth detection, dependency graph)
2. Per-endpoint enrichment (OpenAPI schemas, payloads)
3. Cache management to reduce API costs
4. Parallel execution with concurrency limits
5. Error handling with graceful fallback
6. Result aggregation into complete OpenAPI spec

Usage:
    orchestrator = AgentOrchestrator(
        anthropic_api_key="sk-ant-...",
        cache_manager=cache,
        config=config
    )
    enriched_spec = await orchestrator.enrich_all(endpoints, source_code_map)
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import hashlib

from .base_agent import EnrichmentContext, EnrichmentResult, AgentStatus
from .openapi_enrichment_agent import OpenAPIEnrichmentAgent
from .auth_flow_detector_agent import AuthFlowDetectorAgent
from .payload_generator_agent import PayloadGeneratorAgent
from .dependency_graph_agent import DependencyGraphAgent

# Import cache manager - adjust path based on project structure
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from cache.cache_manager import CacheManager

logger = logging.getLogger("api_scanner.orchestrator")


@dataclass
class OrchestrationConfig:
    """Configuration for agent orchestration."""

    # Enabled agents
    enabled_agents: List[str] = field(default_factory=lambda: [
        "openapi_enrichment",
        "auth_flow_detector",
        "payload_generator",
        "dependency_graph"
    ])

    # Concurrency
    max_concurrent_enrichments: int = 3

    # Cache settings
    use_cache: bool = True
    cache_ttl: int = 604800  # 7 days

    # Error handling
    fail_fast: bool = False  # If True, stop on first error
    fallback_enabled: bool = True  # Fallback to basic export on errors

    # Performance
    max_endpoints_for_global_analysis: int = 100
    max_code_context_size: int = 2000  # chars

    # LLM provider configuration
    llm_provider: str = "anthropic"  # anthropic, openai, gemini, bedrock
    model: str = None  # If None, uses provider default
    max_tokens: int = 4096


class AgentOrchestrator:
    """
    Orchestrates all AI enrichment agents with caching and error handling.

    Responsibilities:
    - Coordinate agent execution pipeline
    - Manage concurrency (max 3 parallel per-endpoint enrichments)
    - Integrate caching to reduce API costs
    - Handle errors gracefully with fallback
    - Aggregate results into complete OpenAPI spec

    Usage:
        config = OrchestrationConfig(use_cache=True, max_concurrent_enrichments=3)
        orchestrator = AgentOrchestrator(
            anthropic_api_key="sk-ant-...",
            cache_manager=cache_manager,
            config=config
        )
        result = await orchestrator.enrich_all(endpoints, code_map)
    """

    def __init__(
        self,
        api_key: str = None,
        cache_manager: Optional[CacheManager] = None,
        config: Optional[OrchestrationConfig] = None,
        provider = None
    ):
        """
        Initialize orchestrator.

        Args:
            api_key: API key for LLM provider (legacy parameter, kept for backward compatibility)
            cache_manager: Optional cache manager for results
            config: Optional orchestration configuration
            provider: Pre-configured LLMProvider instance (if None, will create from config/env)
        """
        self.api_key = api_key
        self.cache = cache_manager
        self.config = config or OrchestrationConfig()

        # Create or use provided LLM provider
        if provider is None:
            from agents.llm_provider import LLMProviderFactory

            # Try to create provider from config/env
            if self.api_key:
                provider_type = self.config.llm_provider
                model = self.config.model
                provider = LLMProviderFactory.create(
                    provider_type=provider_type,
                    api_key=self.api_key,
                    model=model or LLMProviderFactory._get_default_model(provider_type),
                    max_tokens=self.config.max_tokens
                )
            else:
                # Use environment variables
                provider = LLMProviderFactory.from_env()

            logger.info(f"Created {provider.get_provider_name()} provider with model {provider.model}")

        # Initialize agents with provider
        agent_config = {
            "llm_provider": self.config.llm_provider,
            "model": self.config.model,
            "max_tokens": self.config.max_tokens
        }

        self.openapi_agent = OpenAPIEnrichmentAgent(api_key=self.api_key, config=agent_config, provider=provider)
        self.auth_agent = AuthFlowDetectorAgent(api_key=self.api_key, config=agent_config, provider=provider)
        self.payload_agent = PayloadGeneratorAgent(api_key=self.api_key, config=agent_config, provider=provider)
        self.dependency_agent = DependencyGraphAgent(api_key=self.api_key, config=agent_config, provider=provider)

        # Statistics
        self.stats = {
            "total_endpoints": 0,
            "enriched_endpoints": 0,
            "failed_endpoints": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "total_api_calls": 0,
            "global_analyses": 0,
        }

        logger.info("AgentOrchestrator initialized with config: %s", self.config)

    async def enrich_all(
        self,
        endpoints: List[Any],
        code_map: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Enrich all endpoints with AI analysis.

        Execution flow:
        1. Build enrichment contexts
        2. Run global analyses (auth, dependencies)
        3. Run per-endpoint enrichments (parallel)
        4. Aggregate results
        5. Return enriched OpenAPI spec

        Args:
            endpoints: List of Endpoint objects from scanner
            code_map: Optional map of file_path → source code

        Returns:
            Enriched OpenAPI specification with all agent results
        """
        self.stats["total_endpoints"] = len(endpoints)
        logger.info(f"Starting enrichment for {len(endpoints)} endpoints")

        try:
            # Step 1: Build contexts
            contexts = self._build_contexts(endpoints, code_map or {})
            logger.info(f"Built {len(contexts)} enrichment contexts")

            # Step 2: Global analyses (auth, dependencies)
            global_results = await self._run_global_analyses(contexts)
            logger.info("Global analyses complete")

            # Step 3: Per-endpoint enrichments (parallel)
            endpoint_results = await self._run_endpoint_enrichments(contexts, global_results)
            logger.info(f"Per-endpoint enrichments complete: {len(endpoint_results)} results")

            # Step 4: Aggregate results
            enriched_spec = self._aggregate_results(
                endpoints,
                endpoint_results,
                global_results
            )

            logger.info("Enrichment complete. Stats: %s", self.stats)
            return enriched_spec

        except Exception as e:
            error_msg = str(e)

            # For user-friendly errors, don't show full traceback
            if any(phrase in error_msg.lower() for phrase in [
                "aws bedrock authentication failed",
                "authentication failed",
                "invalid or expired aws credentials",
                "rate limit exceeded",
                "quota exceeded",
                "invalid model"
            ]):
                # Clean error message without traceback for known user errors
                logger.error(f"Orchestration failed: {error_msg}")
            else:
                # Full traceback for unexpected errors (debugging)
                logger.error(f"Orchestration failed: {e}", exc_info=True)

            if self.config.fallback_enabled:
                logger.warning("Falling back to basic export")
                return {"error": error_msg, "fallback": True}
            raise

    def _build_contexts(
        self,
        endpoints: List[Any],
        code_map: Dict[str, str]
    ) -> List[EnrichmentContext]:
        """
        Build EnrichmentContext objects for all endpoints.

        Args:
            endpoints: List of Endpoint objects
            code_map: Map of file_path → source code

        Returns:
            List of EnrichmentContext objects
        """
        contexts = []

        for endpoint in endpoints:
            # Get source code for this endpoint
            file_content = code_map.get(endpoint.file_path, "")

            # Extract surrounding code (~50 lines around endpoint)
            surrounding_code = self._extract_surrounding_code(
                file_content,
                endpoint.line_number
            )

            # Extract function body (if possible)
            function_body = self._extract_function_body(
                file_content,
                endpoint.line_number
            )

            # Determine framework/language
            framework, language = self._detect_framework_language(endpoint.file_path)

            context = EnrichmentContext(
                endpoint=endpoint,
                file_content=file_content[:self.config.max_code_context_size],
                surrounding_code=surrounding_code,
                function_body=function_body,
                language=language,
                framework=framework,
                config={"model": self.config.model}
            )

            contexts.append(context)

        return contexts

    async def _run_global_analyses(
        self,
        contexts: List[EnrichmentContext]
    ) -> Dict[str, EnrichmentResult]:
        """
        Run global analyses (auth detection, dependency graph).

        Args:
            contexts: List of all endpoint contexts

        Returns:
            Dictionary with global analysis results
        """
        results = {}

        # Limit contexts for global analysis to prevent token overflow
        limited_contexts = contexts[:self.config.max_endpoints_for_global_analysis]

        # Run auth detection (global)
        if "auth_flow_detector" in self.config.enabled_agents:
            try:
                cache_key = self._generate_global_cache_key("auth", contexts)
                cached = self._check_cache(cache_key) if self.config.use_cache else None

                if cached:
                    logger.info("Auth detection: cache hit")
                    self.stats["cache_hits"] += 1
                    results["auth"] = EnrichmentResult(
                        status=AgentStatus.SUCCESS,
                        data=cached,
                        metadata={"cached": True}
                    )
                else:
                    logger.info("Auth detection: analyzing...")
                    self.stats["cache_misses"] += 1
                    self.stats["global_analyses"] += 1
                    auth_result = await self.auth_agent.detect_auth_flows(limited_contexts)
                    results["auth"] = auth_result

                    if auth_result.is_success() and self.config.use_cache:
                        self._set_cache(cache_key, auth_result.data)

            except Exception as e:
                logger.error(f"Auth detection failed: {e}", exc_info=True)
                results["auth"] = EnrichmentResult(
                    status=AgentStatus.FAILED,
                    errors=[str(e)]
                )

        # Run dependency graph analysis (global)
        if "dependency_graph" in self.config.enabled_agents:
            try:
                cache_key = self._generate_global_cache_key("dependencies", contexts)
                cached = self._check_cache(cache_key) if self.config.use_cache else None

                if cached:
                    logger.info("Dependency analysis: cache hit")
                    self.stats["cache_hits"] += 1
                    results["dependencies"] = EnrichmentResult(
                        status=AgentStatus.SUCCESS,
                        data=cached,
                        metadata={"cached": True}
                    )
                else:
                    logger.info("Dependency analysis: analyzing...")
                    self.stats["cache_misses"] += 1
                    self.stats["global_analyses"] += 1
                    dep_result = await self.dependency_agent.analyze_dependencies(limited_contexts)
                    results["dependencies"] = dep_result

                    if dep_result.is_success() and self.config.use_cache:
                        self._set_cache(cache_key, dep_result.data)

            except Exception as e:
                logger.error(f"Dependency analysis failed: {e}", exc_info=True)
                results["dependencies"] = EnrichmentResult(
                    status=AgentStatus.FAILED,
                    errors=[str(e)]
                )

        return results

    async def _run_endpoint_enrichments(
        self,
        contexts: List[EnrichmentContext],
        global_results: Dict[str, EnrichmentResult]
    ) -> Dict[str, Dict[str, EnrichmentResult]]:
        """
        Run per-endpoint enrichments with parallel execution.

        Args:
            contexts: List of endpoint contexts
            global_results: Results from global analyses

        Returns:
            Dictionary mapping endpoint_id → agent results
        """
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent_enrichments)

        # Create tasks for all endpoints
        tasks = []
        for context in contexts:
            task = self._enrich_single_endpoint(context, global_results, semaphore)
            tasks.append(task)

        # Execute all tasks concurrently (with semaphore limiting concurrency)
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Build results dictionary
        endpoint_results = {}
        for context, result in zip(contexts, results):
            endpoint_id = f"{context.endpoint.method} {context.endpoint.route}"

            if isinstance(result, Exception):
                logger.error(f"Endpoint enrichment failed for {endpoint_id}: {result}")
                endpoint_results[endpoint_id] = {
                    "error": str(result)
                }
                self.stats["failed_endpoints"] += 1
            else:
                endpoint_results[endpoint_id] = result
                self.stats["enriched_endpoints"] += 1

        return endpoint_results

    async def _enrich_single_endpoint(
        self,
        context: EnrichmentContext,
        global_results: Dict[str, EnrichmentResult],
        semaphore: asyncio.Semaphore
    ) -> Dict[str, EnrichmentResult]:
        """
        Enrich a single endpoint with all applicable agents.

        Args:
            context: Endpoint context
            global_results: Global analysis results
            semaphore: Concurrency limiter

        Returns:
            Dictionary of agent results for this endpoint
        """
        async with semaphore:
            results = {}
            endpoint_id = f"{context.endpoint.method} {context.endpoint.route}"

            # OpenAPI enrichment
            if "openapi_enrichment" in self.config.enabled_agents:
                cache_key = self._generate_endpoint_cache_key("openapi", context)
                cached = self._check_cache(cache_key) if self.config.use_cache else None

                if cached:
                    self.stats["cache_hits"] += 1
                    results["openapi"] = EnrichmentResult(
                        status=AgentStatus.SUCCESS,
                        data=cached,
                        metadata={"cached": True}
                    )
                else:
                    self.stats["cache_misses"] += 1
                    self.stats["total_api_calls"] += 1
                    openapi_result = await self.openapi_agent.enrich(context)
                    results["openapi"] = openapi_result

                    if openapi_result.is_success() and self.config.use_cache:
                        self._set_cache(cache_key, openapi_result.data)

            # Payload generation
            if "payload_generator" in self.config.enabled_agents:
                cache_key = self._generate_endpoint_cache_key("payloads", context)
                cached = self._check_cache(cache_key) if self.config.use_cache else None

                if cached:
                    self.stats["cache_hits"] += 1
                    results["payloads"] = EnrichmentResult(
                        status=AgentStatus.SUCCESS,
                        data=cached,
                        metadata={"cached": True}
                    )
                else:
                    self.stats["cache_misses"] += 1
                    # Only count API call if not skipped
                    payload_result = await self.payload_agent.enrich(context)
                    if payload_result.status != AgentStatus.SKIPPED:
                        self.stats["total_api_calls"] += 1
                    results["payloads"] = payload_result

                    if payload_result.is_success() and self.config.use_cache:
                        self._set_cache(cache_key, payload_result.data)

            logger.debug(f"Enriched endpoint: {endpoint_id}")
            return results

    def _aggregate_results(
        self,
        endpoints: List[Any],
        endpoint_results: Dict[str, Dict[str, EnrichmentResult]],
        global_results: Dict[str, EnrichmentResult]
    ) -> Dict[str, Any]:
        """
        Aggregate all results into enriched OpenAPI spec.

        Args:
            endpoints: Original endpoints
            endpoint_results: Per-endpoint enrichment results
            global_results: Global analysis results

        Returns:
            Complete enriched OpenAPI specification
        """
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "AI-Enriched API",
                "version": "1.0.0",
                "description": "API specification generated with AI enrichment"
            },
            "paths": {},
            "components": {
                "securitySchemes": {}
            },
            "x-ai-enrichment": {
                "enabled": True,
                "agents": self.config.enabled_agents,
                "model": self.config.model,
                "stats": self.stats
            }
        }

        # Add auth schemes from global auth analysis
        if "auth" in global_results and global_results["auth"].is_success():
            auth_data = global_results["auth"].data.get("auth_config", {})
            for mechanism in auth_data.get("auth_mechanisms", []):
                scheme_name = mechanism.get("scheme_name", "unknown")
                openapi_scheme = mechanism.get("openapi_scheme", {})
                spec["components"]["securitySchemes"][scheme_name] = openapi_scheme

            spec["x-ai-enrichment"]["auth_config"] = auth_data

        # Add dependency graph
        if "dependencies" in global_results and global_results["dependencies"].is_success():
            dep_data = global_results["dependencies"].data.get("dependencies", {})
            spec["x-ai-enrichment"]["dependencies"] = dep_data

        # Add per-endpoint enrichments
        for endpoint in endpoints:
            endpoint_id = f"{endpoint.method} {endpoint.route}"
            endpoint_enrichment = endpoint_results.get(endpoint_id, {})

            # Initialize path if needed
            if endpoint.route not in spec["paths"]:
                spec["paths"][endpoint.route] = {}

            # Build operation object
            operation = {
                "summary": f"{endpoint.method} {endpoint.route}",
                "responses": {
                    "200": {"description": "Success"}
                }
            }

            # Add OpenAPI enrichment
            if "openapi" in endpoint_enrichment:
                openapi_result = endpoint_enrichment["openapi"]
                if openapi_result.is_success():
                    operation_data = openapi_result.data.get("operation", {})
                    operation.update(operation_data)

            # Add test payloads
            if "payloads" in endpoint_enrichment:
                payload_result = endpoint_enrichment["payloads"]
                if payload_result.is_success():
                    operation["x-test-payloads"] = payload_result.data.get("payloads", {})

            # Add to spec
            spec["paths"][endpoint.route][endpoint.method.lower()] = operation

        return spec

    def _generate_global_cache_key(self, analysis_type: str, contexts: List[EnrichmentContext]) -> str:
        """Generate cache key for global analysis."""
        # Hash all endpoint signatures
        signatures = [f"{ctx.endpoint.method}:{ctx.endpoint.route}" for ctx in contexts]
        content = f"{analysis_type}:{'|'.join(sorted(signatures))}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _generate_endpoint_cache_key(self, agent_name: str, context: EnrichmentContext) -> str:
        """Generate cache key for endpoint enrichment."""
        ep = context.endpoint
        code_hash = hashlib.md5((context.function_body or "").encode()).hexdigest()
        content = f"{agent_name}:{ep.method}:{ep.route}:{code_hash}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _check_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """Check cache for key."""
        if not self.cache:
            return None
        return self.cache.get(key)

    def _set_cache(self, key: str, value: Dict[str, Any]):
        """Set cache value."""
        if self.cache:
            self.cache.set(key, value)

    @staticmethod
    def _extract_surrounding_code(file_content: str, line_number: int, context_lines: int = 25) -> str:
        """Extract ~50 lines of code around the target line."""
        if not file_content:
            return ""

        lines = file_content.split('\n')
        start = max(0, line_number - context_lines)
        end = min(len(lines), line_number + context_lines)

        return '\n'.join(lines[start:end])

    @staticmethod
    def _extract_function_body(file_content: str, line_number: int) -> str:
        """
        Extract complete function body starting from line_number.
        Simple heuristic - find next function or class definition.
        """
        if not file_content:
            return ""

        lines = file_content.split('\n')
        if line_number >= len(lines):
            return ""

        # Start from endpoint line
        start = line_number
        function_lines = []

        # Go backwards to find function start
        for i in range(start, max(0, start - 50), -1):
            line = lines[i]
            if any(keyword in line for keyword in ['def ', 'function ', 'async ', 'public ', 'private ']):
                start = i
                break

        # Extract function (up to next function or 100 lines)
        for i in range(start, min(len(lines), start + 100)):
            function_lines.append(lines[i])
            # Stop at next function definition
            if i > start and any(keyword in lines[i] for keyword in ['def ', 'function ', 'class ']):
                break

        return '\n'.join(function_lines)

    @staticmethod
    def _detect_framework_language(file_path: str) -> tuple[str, str]:
        """Detect framework and language from file path."""
        path_lower = file_path.lower()

        # Language detection
        if path_lower.endswith('.py'):
            language = "python"
            if 'flask' in path_lower:
                framework = "flask"
            elif 'fastapi' in path_lower or 'fast_api' in path_lower:
                framework = "fastapi"
            elif 'django' in path_lower:
                framework = "django"
            else:
                framework = "unknown"

        elif path_lower.endswith(('.cs', '.csx')):
            language = "csharp"
            framework = "aspnet"

        elif path_lower.endswith('.go'):
            language = "go"
            if 'gin' in path_lower:
                framework = "gin"
            elif 'echo' in path_lower:
                framework = "echo"
            else:
                framework = "unknown"

        elif path_lower.endswith(('.js', '.ts')):
            language = "javascript" if path_lower.endswith('.js') else "typescript"
            if 'express' in path_lower:
                framework = "express"
            elif 'fastify' in path_lower:
                framework = "fastify"
            else:
                framework = "unknown"

        elif path_lower.endswith('.java'):
            language = "java"
            framework = "spring"

        else:
            language = "unknown"
            framework = "unknown"

        return framework, language

    def get_stats(self) -> Dict[str, int]:
        """Get orchestration statistics."""
        return self.stats.copy()
