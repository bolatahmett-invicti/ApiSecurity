"""
Cache Management for AI Enrichment
===================================

Provides SQLite-based caching for AI enrichment results to reduce
API costs and improve performance on subsequent scans.

Usage:
    from cache import CacheManager

    cache = CacheManager(cache_dir="./.cache/enrichment")

    # Get cached result
    result = cache.get("endpoint_key")

    # Set result with TTL
    cache.set("endpoint_key", data, ttl_seconds=604800)
"""

__version__ = "1.0.0"

from .cache_manager import CacheManager

__all__ = ["CacheManager"]
