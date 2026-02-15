#!/usr/bin/env python3
"""
Batch Processing Utilities
===========================
Groups endpoints for batch LLM processing to reduce API calls and costs.

Cost savings example (100 endpoints):
- Before: 100 LLM calls × 4.5K tokens = 450K tokens → $4.05
- After: 5 batches × 60K tokens = 300K tokens → $2.70 (33% savings)
"""

import logging
from typing import List, Dict, Any
from collections import defaultdict
from .base_agent import EnrichmentContext

logger = logging.getLogger("api_scanner.agents.batch_processor")


class BatchProcessor:
    """
    Groups endpoints into batches for efficient LLM processing.

    Grouping strategies:
    1. By HTTP method (GET, POST, PUT, PATCH, DELETE)
    2. By resource type (extracted from route patterns)
    3. By framework/language

    Usage:
        contexts = [EnrichmentContext(...), ...]
        batches = BatchProcessor.group_by_method(contexts, batch_size=20)
        for batch in batches:
            result = await agent.enrich_batch(batch)
    """

    @staticmethod
    def group_by_method(
        contexts: List[EnrichmentContext],
        batch_size: int = 20
    ) -> List[List[EnrichmentContext]]:
        """
        Group endpoints by HTTP method, then split into batches.

        This ensures similar endpoints are processed together, improving
        LLM context efficiency.

        Args:
            contexts: List of EnrichmentContext objects
            batch_size: Maximum number of endpoints per batch (default: 20)

        Returns:
            List of batches (each batch is a list of contexts)

        Example:
            100 endpoints (60 GET, 30 POST, 10 DELETE):
            - GET: 3 batches of 20
            - POST: 2 batches (20, 10)
            - DELETE: 1 batch of 10
            Total: 6 batches instead of 100 LLM calls
        """
        # Group by method
        method_groups = defaultdict(list)
        for ctx in contexts:
            method = ctx.endpoint.method.upper()
            method_groups[method].append(ctx)

        # Split each method group into batches
        batches = []
        for method, group_contexts in method_groups.items():
            for i in range(0, len(group_contexts), batch_size):
                batch = group_contexts[i:i + batch_size]
                batches.append(batch)
                logger.debug(f"Created batch: {method} × {len(batch)} endpoints")

        logger.info(
            f"Grouped {len(contexts)} endpoints into {len(batches)} batches "
            f"(avg {len(contexts) / len(batches):.1f} per batch)"
        )

        return batches

    @staticmethod
    def group_by_resource(
        contexts: List[EnrichmentContext],
        batch_size: int = 15
    ) -> List[List[EnrichmentContext]]:
        """
        Group endpoints by resource type extracted from route patterns.

        This is useful for payload generation where similar resources
        need similar test data.

        Args:
            contexts: List of EnrichmentContext objects
            batch_size: Maximum number of endpoints per batch (default: 15)

        Returns:
            List of batches grouped by resource

        Example:
            Routes:
            - POST /api/users
            - GET /api/users/:id
            - PUT /api/users/:id
            - POST /api/products
            - GET /api/products/:id

            Result:
            - Batch 1: All /api/users endpoints (3)
            - Batch 2: All /api/products endpoints (2)
        """
        # Extract resource from route
        def get_resource(route: str) -> str:
            """Extract base resource from route (e.g., /api/users/123 -> users)."""
            parts = route.split('/')
            # Find first non-empty, non-parameter segment after /api
            for part in parts:
                if part and not part.startswith(':') and not part.startswith('{'):
                    if part != 'api' and part != 'v1' and part != 'v2':
                        return part
            return 'default'

        # Group by resource
        resource_groups = defaultdict(list)
        for ctx in contexts:
            resource = get_resource(ctx.endpoint.route)
            resource_groups[resource].append(ctx)

        # Split each resource group into batches
        batches = []
        for resource, group_contexts in resource_groups.items():
            for i in range(0, len(group_contexts), batch_size):
                batch = group_contexts[i:i + batch_size]
                batches.append(batch)
                logger.debug(f"Created batch: {resource} × {len(batch)} endpoints")

        logger.info(
            f"Grouped {len(contexts)} endpoints by resource into {len(batches)} batches "
            f"(avg {len(contexts) / len(batches):.1f} per batch)"
        )

        return batches

    @staticmethod
    def group_mixed(
        contexts: List[EnrichmentContext],
        batch_size: int = 20
    ) -> List[List[EnrichmentContext]]:
        """
        Simple grouping - split into equal-sized batches regardless of method/resource.

        Fastest but least efficient for LLM context.
        Use when you need maximum parallelization over context efficiency.

        Args:
            contexts: List of EnrichmentContext objects
            batch_size: Maximum number of endpoints per batch (default: 20)

        Returns:
            List of batches
        """
        batches = []
        for i in range(0, len(contexts), batch_size):
            batch = contexts[i:i + batch_size]
            batches.append(batch)

        logger.info(f"Created {len(batches)} mixed batches from {len(contexts)} endpoints")
        return batches

    @staticmethod
    def create_batch_summary(batch: List[EnrichmentContext]) -> str:
        """
        Create a summary of a batch for logging and debugging.

        Args:
            batch: List of EnrichmentContext objects

        Returns:
            Human-readable batch summary

        Example:
            "20 endpoints: 15 GET, 5 POST | Resources: users (10), products (8), orders (2)"
        """
        if not batch:
            return "Empty batch"

        # Count by method
        method_counts = defaultdict(int)
        for ctx in batch:
            method_counts[ctx.endpoint.method.upper()] += 1

        method_str = ", ".join(f"{count} {method}" for method, count in method_counts.items())

        return f"{len(batch)} endpoints: {method_str}"

    @staticmethod
    def validate_batch_size(batch_size: int, max_batch_size: int = 50) -> int:
        """
        Validate and clamp batch size to safe limits.

        Very large batches can:
        - Exceed LLM context limits
        - Reduce response quality
        - Make error recovery harder

        Args:
            batch_size: Requested batch size
            max_batch_size: Maximum allowed batch size (default: 50)

        Returns:
            Validated batch size (clamped to 1-max_batch_size)
        """
        if batch_size < 1:
            logger.warning(f"Batch size {batch_size} too small, using 1")
            return 1

        if batch_size > max_batch_size:
            logger.warning(
                f"Batch size {batch_size} exceeds recommended maximum {max_batch_size}, "
                f"clamping to {max_batch_size} for quality"
            )
            return max_batch_size

        return batch_size
