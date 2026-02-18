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
from .batch_processor import BatchProcessor

# Import cache manager - adjust path based on project structure
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from cache.cache_manager import CacheManager

# Import deterministic enrichers (HYBRID ARCHITECTURE - Phase 1)
from scanners.deterministic.parameter_extractor import DeterministicParameterExtractor
from scanners.deterministic.http_method_analyzer import HTTPMethodAnalyzer
from scanners.deterministic.status_code_analyzer import StatusCodeAnalyzer

# Import AST-based enrichers (HYBRID ARCHITECTURE - Phase 2)
from scanners.deterministic.type_hint_analyzer import TypeHintAnalyzer
from scanners.deterministic.decorator_analyzer import DecoratorAnalyzer
from scanners.deterministic.docstring_parser import DocstringParser

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

    # Per-agent model configuration (for cost optimization)
    # Use cheaper models (Haiku) for simple tasks, expensive models (Sonnet) for complex tasks
    model_openapi: str = None  # OpenAPI enrichment (default: sonnet) - requires code analysis
    model_auth: str = None  # Auth detection (default: haiku) - simple pattern matching
    model_payloads: str = None  # Payload generation (default: sonnet) - complex generation
    model_dependency: str = None  # Dependency graph (default: haiku) - relationship detection

    # Batch processing (cost optimization - Phase 2)
    # Process multiple endpoints per LLM call instead of one-by-one
    # Savings: ~25% for OpenAPI, ~30% for payloads
    enable_batching: bool = True  # Master switch for batch processing
    openapi_batch_size: int = 20  # Group 20 endpoints per OpenAPI call
    payload_batch_size: int = 15  # Group 15 endpoints per payload call
    batch_fallback_per_endpoint: bool = True  # Fall back to per-endpoint on batch errors

    # Hybrid architecture (cost optimization - Phase 1)
    # Use deterministic Python code for pattern-based tasks, LLM for complex analysis
    # Savings: 70-85% total cost reduction
    use_deterministic_enrichment: bool = True  # Master switch (default: enabled)
    deterministic_parameters: bool = True  # Extract parameters from routes
    deterministic_status_codes: bool = True  # Extract status codes from code
    deterministic_http_methods: bool = True  # Map HTTP methods to operations
    deterministic_confidence_threshold: float = 0.7  # Use LLM if Python confidence < 70%

    # Hybrid architecture (cost optimization - Phase 2: AST-based)
    # Use Python AST module for type hints, decorators, and docstrings
    # Additional savings: 15% (total 85% reduction)
    deterministic_type_hints: bool = True  # Extract type hints from function signatures
    deterministic_decorators: bool = True  # Detect auth patterns from decorators
    deterministic_docstrings: bool = True  # Extract descriptions from docstrings

    # Logic-oriented Fuzzing (LoF) — Phase 3 extension
    # Generates constraint-violating payloads from AST-extracted business rules
    # Cost: $0 (fully deterministic — no LLM call)
    enable_lof: bool = True                   # Master switch (default: enabled)
    lof_confidence_threshold: float = 0.4    # Min evidence confidence to emit a payload
                                              # 0.4 = balanced (medium+ FP risk)
                                              # 0.6 = conservative (low FP risk only)


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

        # Initialize agents with model-specific configurations
        # This allows cost optimization by using cheaper models for simple tasks
        import os

        agent_config = {
            "llm_provider": self.config.llm_provider,
            "model": self.config.model,
            "max_tokens": self.config.max_tokens
        }

        # Get per-agent models from config or environment variables
        # Priority: config > environment > defaults
        model_openapi = (self.config.model_openapi or
                        os.getenv("LLM_MODEL_OPENAPI") or
                        self.config.model or  # Fall back to global model
                        "claude-sonnet-4-5-20250929")  # Default for OpenAPI (needs code analysis)

        model_auth = (self.config.model_auth or
                     os.getenv("LLM_MODEL_AUTH") or
                     "claude-haiku-4-5-20251001")  # Default to Haiku (simple pattern matching)

        model_payloads = (self.config.model_payloads or
                         os.getenv("LLM_MODEL_PAYLOADS") or
                         self.config.model or
                         "claude-sonnet-4-5-20250929")  # Default to Sonnet (complex generation)

        model_dependency = (self.config.model_dependency or
                           os.getenv("LLM_MODEL_DEPENDENCY") or
                           "claude-haiku-4-5-20251001")  # Default to Haiku (simple relationships)

        # Initialize agents with model overrides
        self.openapi_agent = OpenAPIEnrichmentAgent(
            api_key=self.api_key,
            config=agent_config,
            provider=provider,
            model_override=model_openapi
        )

        self.auth_agent = AuthFlowDetectorAgent(
            api_key=self.api_key,
            config=agent_config,
            provider=provider,
            model_override=model_auth
        )

        self.payload_agent = PayloadGeneratorAgent(
            api_key=self.api_key,
            config=agent_config,
            provider=provider,
            model_override=model_payloads
        )

        self.dependency_agent = DependencyGraphAgent(
            api_key=self.api_key,
            config=agent_config,
            provider=provider,
            model_override=model_dependency
        )

        # Log model assignments for cost tracking
        logger.info(f"Agent models configured:")
        logger.info(f"  - OpenAPI: {model_openapi}")
        logger.info(f"  - Auth: {model_auth}")
        logger.info(f"  - Payloads: {model_payloads}")
        logger.info(f"  - Dependency: {model_dependency}")

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

            # Step 2: Deterministic enrichment (HYBRID ARCHITECTURE - Phase 1)
            # Extract structured data using Python patterns (70-85% cost savings!)
            contexts = self._run_deterministic_enrichment(contexts)
            logger.info("Deterministic enrichment complete")

            # Step 3: Global analyses (auth, dependencies)
            global_results = await self._run_global_analyses(contexts)
            logger.info("Global analyses complete")

            # Step 4: Per-endpoint enrichments (parallel, using Python-extracted data)
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

    def _run_deterministic_enrichment(
        self,
        contexts: List[EnrichmentContext]
    ) -> List[EnrichmentContext]:
        """
        Run deterministic (Python-based) enrichment on all contexts BEFORE LLM enrichment.

        This extracts structured data using pattern matching and code analysis:
        - Parameters from route patterns ({id}, <int:id>, :id)
        - HTTP method expectations (GET=no body, POST=body required)
        - Status codes from source code (return ..., 200)

        Cost savings: 70-85% (these tasks don't need AI intelligence)
        Speed: 100-1000x faster than LLM calls
        Accuracy: 90-95% for well-defined patterns

        Args:
            contexts: List of EnrichmentContext objects

        Returns:
            Modified contexts with deterministic_data in config
        """
        if not self.config.use_deterministic_enrichment:
            logger.info("Deterministic enrichment disabled, skipping")
            return contexts

        logger.info(f"Running deterministic enrichment on {len(contexts)} endpoints")

        for context in contexts:
            deterministic_data = {}

            # Extract parameters from route pattern
            if self.config.deterministic_parameters:
                try:
                    params = DeterministicParameterExtractor.extract(
                        context.endpoint.route,
                        context.endpoint.method
                    )
                    if params:
                        deterministic_data["parameters"] = params
                        logger.debug(
                            f"Extracted {len(params)} parameters from {context.endpoint.route}: "
                            f"{[p['name'] for p in params]}"
                        )
                except Exception as e:
                    logger.warning(f"Parameter extraction failed for {context.endpoint.route}: {e}")

            # Get HTTP method expectations
            if self.config.deterministic_http_methods:
                try:
                    resource = HTTPMethodAnalyzer.extract_resource_from_route(context.endpoint.route)
                    expectations = HTTPMethodAnalyzer.get_expectations(
                        context.endpoint.method,
                        resource
                    )
                    deterministic_data["method_expectations"] = expectations
                    logger.debug(
                        f"{context.endpoint.method} {context.endpoint.route}: "
                        f"has_body={expectations['has_request_body']}"
                    )
                except Exception as e:
                    logger.warning(f"HTTP method analysis failed for {context.endpoint.route}: {e}")

            # Extract status codes from source code
            if self.config.deterministic_status_codes and context.function_body:
                try:
                    detected_codes = StatusCodeAnalyzer.extract_from_code(context.function_body)
                    if detected_codes:
                        responses = StatusCodeAnalyzer.merge_with_detected(
                            detected_codes,
                            context.endpoint.method
                        )
                        deterministic_data["responses"] = responses
                        logger.debug(
                            f"Detected {len(detected_codes)} status codes in {context.endpoint.route}: "
                            f"{sorted(detected_codes)}"
                        )
                except Exception as e:
                    logger.warning(f"Status code extraction failed for {context.endpoint.route}: {e}")

            # PHASE 2: AST-based enrichment (type hints, decorators, docstrings)
            # Only run on Python code (skip JavaScript, C#, etc.)
            if context.function_body and self._is_python_code(context.function_body):
                # Extract type hints from function signature
                if self.config.deterministic_type_hints:
                    try:
                        type_hints = TypeHintAnalyzer.extract_from_function(context.function_body)
                        if type_hints:
                            deterministic_data["type_hints"] = type_hints
                            logger.debug(
                                f"Extracted {len(type_hints)} type hints from {context.endpoint.route}: "
                                f"{list(type_hints.keys())}"
                            )
                    except Exception as e:
                        logger.debug(f"Type hint extraction skipped for {context.endpoint.route} (non-Python code)")

                # Detect auth decorators
                if self.config.deterministic_decorators:
                    try:
                        auth_info = DecoratorAnalyzer.extract_from_function(context.function_body)
                        if auth_info:
                            deterministic_data["auth_decorators"] = auth_info
                            if "security" in auth_info:
                                logger.debug(
                                    f"Detected auth decorators on {context.endpoint.route}: "
                                    f"{[list(s.keys())[0] for s in auth_info['security']]}"
                                )
                    except Exception as e:
                        logger.debug(f"Decorator analysis skipped for {context.endpoint.route} (non-Python code)")

                # Extract docstring
                if self.config.deterministic_docstrings:
                    try:
                        docstring_info = DocstringParser.extract_from_function(context.function_body)
                        if docstring_info:
                            deterministic_data["docstring"] = docstring_info
                            if "summary" in docstring_info:
                                logger.debug(
                                    f"Extracted docstring summary from {context.endpoint.route}: "
                                    f"{docstring_info['summary'][:50]}..."
                                )
                    except Exception as e:
                        logger.debug(f"Docstring extraction skipped for {context.endpoint.route} (non-Python code)")

            # Add deterministic data to context config
            if deterministic_data:
                if context.config is None:
                    context.config = {}
                context.config["deterministic_data"] = deterministic_data

            # Pass LoF configuration so PayloadGeneratorAgent can use it
            if context.config is None:
                context.config = {}
            context.config["lof_confidence_threshold"] = self.config.lof_confidence_threshold
            context.config["enable_lof"] = self.config.enable_lof

            logger.debug(
                f"Deterministic enrichment complete for {context.endpoint.route}: "
                f"{len(deterministic_data)} data items"
            )

        enriched_count = sum(1 for ctx in contexts if ctx.config and "deterministic_data" in ctx.config)
        logger.info(
            f"Deterministic enrichment complete: {enriched_count}/{len(contexts)} endpoints enriched"
        )

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
        Run per-endpoint enrichments with batch processing and parallel execution.

        Batching strategy (if enabled):
        - OpenAPI: Group by HTTP method (20 per batch)
        - Payloads: Group by resource type (15 per batch)

        Args:
            contexts: List of endpoint contexts
            global_results: Results from global analyses

        Returns:
            Dictionary mapping endpoint_id → agent results
        """
        if self.config.enable_batching and "openapi_enrichment" in self.config.enabled_agents:
            # Use batch processing for OpenAPI enrichment
            logger.info("Using batch processing for OpenAPI enrichment")
            return await self._run_endpoint_enrichments_batched(contexts, global_results)
        else:
            # Use traditional per-endpoint processing
            logger.info("Using per-endpoint processing (batching disabled)")
            return await self._run_endpoint_enrichments_per_endpoint(contexts, global_results)

    async def _run_endpoint_enrichments_batched(
        self,
        contexts: List[EnrichmentContext],
        global_results: Dict[str, EnrichmentResult]
    ) -> Dict[str, Dict[str, EnrichmentResult]]:
        """
        Run enrichments using batch processing.

        This groups endpoints and processes them in batches to reduce LLM API calls.

        Args:
            contexts: List of endpoint contexts
            global_results: Results from global analyses

        Returns:
            Dictionary mapping endpoint_id → agent results
        """
        endpoint_results = {}

        # Step 1: OpenAPI enrichment (batched by HTTP method)
        if "openapi_enrichment" in self.config.enabled_agents:
            batch_size = BatchProcessor.validate_batch_size(
                self.config.openapi_batch_size,
                max_batch_size=50
            )

            # Group contexts by HTTP method
            batches = BatchProcessor.group_by_method(contexts, batch_size=batch_size)
            logger.info(
                f"OpenAPI enrichment: {len(contexts)} endpoints → {len(batches)} batches "
                f"({batch_size} per batch)"
            )

            # Process each batch
            for batch_idx, batch_contexts in enumerate(batches, 1):
                batch_summary = BatchProcessor.create_batch_summary(batch_contexts)
                logger.info(f"Processing OpenAPI batch {batch_idx}/{len(batches)}: {batch_summary}")

                try:
                    # Check cache first
                    cached_results = await self._check_batch_cache("openapi", batch_contexts)

                    if cached_results:
                        # Use cached results
                        for ctx, cached_data in zip(batch_contexts, cached_results):
                            endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"
                            if endpoint_id not in endpoint_results:
                                endpoint_results[endpoint_id] = {}

                            endpoint_results[endpoint_id]["openapi"] = EnrichmentResult(
                                status=AgentStatus.SUCCESS,
                                data=cached_data,
                                metadata={"cached": True}
                            )
                        self.stats["cache_hits"] += len(batch_contexts)
                        logger.info(f"Batch {batch_idx}: All from cache")
                    else:
                        # Call agent with batch
                        self.stats["cache_misses"] += len(batch_contexts)
                        self.stats["total_api_calls"] += 1  # Only 1 call for entire batch!

                        batch_results = await self.openapi_agent.enrich_batch(batch_contexts)

                        # Store results
                        for ctx, result in zip(batch_contexts, batch_results):
                            endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"

                            if endpoint_id not in endpoint_results:
                                endpoint_results[endpoint_id] = {}

                            endpoint_results[endpoint_id]["openapi"] = result

                            # Cache successful results
                            if result.is_success() and self.config.use_cache:
                                cache_key = self._generate_endpoint_cache_key("openapi", ctx)
                                self._set_cache(cache_key, result.data)

                        success_count = sum(1 for r in batch_results if r.is_success())
                        logger.info(
                            f"Batch {batch_idx}: {success_count}/{len(batch_results)} successful"
                        )

                except Exception as e:
                    logger.error(f"Batch {batch_idx} failed: {e}", exc_info=True)
                    # Mark all endpoints in batch as failed
                    for ctx in batch_contexts:
                        endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"
                        if endpoint_id not in endpoint_results:
                            endpoint_results[endpoint_id] = {}
                        endpoint_results[endpoint_id]["openapi"] = EnrichmentResult(
                            status=AgentStatus.FAILED,
                            errors=[f"Batch processing failed: {str(e)}"]
                        )

        # Step 2: Payload generation (batched by resource - Phase 3)
        if "payload_generator" in self.config.enabled_agents:
            batch_size = BatchProcessor.validate_batch_size(
                self.config.payload_batch_size,
                max_batch_size=30  # Payloads are simpler, can handle larger batches
            )

            # Group contexts by resource
            batches = BatchProcessor.group_by_resource(contexts, batch_size=batch_size)
            logger.info(
                f"Payload generation: {len(contexts)} endpoints → {len(batches)} batches "
                f"({batch_size} per batch)"
            )

            # Process each batch
            for batch_idx, batch_contexts in enumerate(batches, 1):
                batch_summary = BatchProcessor.create_batch_summary(batch_contexts)
                logger.info(f"Processing payload batch {batch_idx}/{len(batches)}: {batch_summary}")

                try:
                    # Check cache first
                    cached_results = await self._check_batch_cache("payloads", batch_contexts)

                    if cached_results:
                        # Use cached results
                        for ctx, cached_data in zip(batch_contexts, cached_results):
                            endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"
                            if endpoint_id not in endpoint_results:
                                endpoint_results[endpoint_id] = {}

                            endpoint_results[endpoint_id]["payloads"] = EnrichmentResult(
                                status=AgentStatus.SUCCESS,
                                data=cached_data,
                                metadata={"cached": True}
                            )
                        self.stats["cache_hits"] += len(batch_contexts)
                        logger.info(f"Batch {batch_idx}: All from cache")
                    else:
                        # Call agent with batch
                        self.stats["cache_misses"] += len(batch_contexts)

                        # Filter out GET/DELETE (payload agent skips them)
                        payload_contexts = [c for c in batch_contexts if c.endpoint.method in ["POST", "PUT", "PATCH"]]
                        if payload_contexts:
                            self.stats["total_api_calls"] += 1  # Only 1 call for entire batch!

                        batch_results = await self.payload_agent.enrich_batch(batch_contexts)

                        # Store results
                        for ctx, result in zip(batch_contexts, batch_results):
                            endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"

                            if endpoint_id not in endpoint_results:
                                endpoint_results[endpoint_id] = {}

                            endpoint_results[endpoint_id]["payloads"] = result

                            # Cache successful results
                            if result.is_success() and self.config.use_cache:
                                cache_key = self._generate_endpoint_cache_key("payloads", ctx)
                                self._set_cache(cache_key, result.data)

                        success_count = sum(1 for r in batch_results if r.is_success())
                        logger.info(
                            f"Batch {batch_idx}: {success_count}/{len(batch_results)} successful"
                        )

                except Exception as e:
                    logger.error(f"Batch {batch_idx} failed: {e}", exc_info=True)
                    # Mark all endpoints in batch as failed
                    for ctx in batch_contexts:
                        endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"
                        if endpoint_id not in endpoint_results:
                            endpoint_results[endpoint_id] = {}
                        endpoint_results[endpoint_id]["payloads"] = EnrichmentResult(
                            status=AgentStatus.FAILED,
                            errors=[f"Batch processing failed: {str(e)}"]
                        )

        return endpoint_results

    async def _run_endpoint_enrichments_per_endpoint(
        self,
        contexts: List[EnrichmentContext],
        global_results: Dict[str, EnrichmentResult]
    ) -> Dict[str, Dict[str, EnrichmentResult]]:
        """
        Run per-endpoint enrichments with parallel execution (original method).

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

    async def _check_batch_cache(
        self,
        agent_name: str,
        batch_contexts: List[EnrichmentContext]
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Check if all endpoints in a batch are cached.

        Args:
            agent_name: Name of the agent (e.g., "openapi", "payloads")
            batch_contexts: Batch of contexts to check

        Returns:
            List of cached data if ALL are cached, None otherwise
        """
        if not self.config.use_cache:
            return None

        cached_data = []
        for ctx in batch_contexts:
            cache_key = self._generate_endpoint_cache_key(agent_name, ctx)
            cached = self._check_cache(cache_key)

            if cached is None:
                # One endpoint not cached - must process entire batch
                return None

            cached_data.append(cached)

        # All cached!
        return cached_data

    async def _run_payload_enrichments_per_endpoint(
        self,
        contexts: List[EnrichmentContext],
        endpoint_results: Dict[str, Dict[str, EnrichmentResult]]
    ) -> None:
        """
        Run payload generation per-endpoint (fallback until Phase 3).

        Args:
            contexts: List of endpoint contexts
            endpoint_results: Dictionary to update with payload results (modified in place)
        """
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent_enrichments)

        async def enrich_payload(ctx: EnrichmentContext):
            """Enrich payload for one endpoint."""
            async with semaphore:
                endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"

                cache_key = self._generate_endpoint_cache_key("payloads", ctx)
                cached = self._check_cache(cache_key) if self.config.use_cache else None

                if cached:
                    self.stats["cache_hits"] += 1
                    if endpoint_id not in endpoint_results:
                        endpoint_results[endpoint_id] = {}
                    endpoint_results[endpoint_id]["payloads"] = EnrichmentResult(
                        status=AgentStatus.SUCCESS,
                        data=cached,
                        metadata={"cached": True}
                    )
                else:
                    self.stats["cache_misses"] += 1
                    payload_result = await self.payload_agent.enrich(ctx)
                    if payload_result.status != AgentStatus.SKIPPED:
                        self.stats["total_api_calls"] += 1

                    if endpoint_id not in endpoint_results:
                        endpoint_results[endpoint_id] = {}
                    endpoint_results[endpoint_id]["payloads"] = payload_result

                    if payload_result.is_success() and self.config.use_cache:
                        self._set_cache(cache_key, payload_result.data)

        # Process all endpoints in parallel
        tasks = [enrich_payload(ctx) for ctx in contexts]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Payload generation complete (per-endpoint mode)")

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
    def _is_python_code(code: str) -> bool:
        """
        Detect if code is Python (vs JavaScript, C#, etc.) before attempting AST parsing.

        Uses simple heuristics to avoid AST syntax errors on non-Python code.
        Returns False for JavaScript/TypeScript (with curly braces, semicolons)
        and C# code (with curly braces, C# keywords).
        """
        if not code or not code.strip():
            return False

        # JavaScript/TypeScript indicators (common in Node.js/Express)
        js_indicators = [
            'function(',  # JavaScript function
            'const ',     # ES6 const
            'let ',       # ES6 let
            'var ',       # JavaScript var
            ') {',        # Function body with brace
            '};',         # Statement ending
            'async function',  # Async function
            'module.exports',  # Node.js export
            'router.',    # Express router
            'app.use(',   # Express middleware
        ]

        # C# indicators
        csharp_indicators = [
            'public ',
            'private ',
            'protected ',
            ' Task<',
            'IActionResult',
            '[Route',
            '[Http',
            'namespace ',
            'using System',
        ]

        # Count indicators
        js_count = sum(1 for indicator in js_indicators if indicator in code)
        csharp_count = sum(1 for indicator in csharp_indicators if indicator in code)

        # Strong indicators of non-Python code
        if js_count >= 2 or csharp_count >= 2:
            return False

        # Check for unmatched curly braces (common in JS/C#, rare in Python)
        if code.count('{') > 0 and code.count('}') > 0:
            # Python dicts use {}, but function bodies don't
            # If we see function-like structures with {}, it's likely not Python
            if any(pattern in code for pattern in ['function ', ') {', 'if (', 'for (']):
                return False

        # Python indicators
        python_indicators = [
            'def ',
            'class ',
            'import ',
            'from ',
            '__init__',
            'self.',
            '@',  # Decorators
            ':',  # Colons for blocks
        ]

        python_count = sum(1 for indicator in python_indicators if indicator in code)

        # If we see Python indicators and no strong non-Python indicators, assume Python
        if python_count >= 1:
            return True

        # Default: assume not Python (conservative approach to avoid AST errors)
        return False

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
