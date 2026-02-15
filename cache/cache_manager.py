#!/usr/bin/env python3
"""
Cache Manager
=============
SQLite-based caching for AI enrichment results.

This module provides persistent caching to reduce API costs and improve
performance on subsequent scans.
"""

import sqlite3
import json
import time
import hashlib
from pathlib import Path
from typing import Any, Optional, Dict
import logging

logger = logging.getLogger("api_scanner.cache")


class CacheManager:
    """
    Persistent cache for AI enrichment results.

    Cache Strategy:
    - Cache key: SHA256(agent_name + endpoint_signature + code_hash)
    - Storage: SQLite database
    - TTL: Configurable (default: 7 days)
    - Invalidation: Code change detection via hash

    Usage:
        cache = CacheManager(cache_dir="./.cache/enrichment")

        # Get cached result
        result = cache.get("endpoint_key")

        # Set result with TTL
        cache.set("endpoint_key", data, ttl_seconds=604800)

        # Clear expired entries
        cache.clear_expired()
    """

    def __init__(self, cache_dir: str = "./.cache/enrichment", ttl_seconds: int = 604800):
        """
        Initialize cache manager.

        Args:
            cache_dir: Directory for cache database
            ttl_seconds: Time-to-live in seconds (default: 7 days = 604800)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.db_path = self.cache_dir / "enrichment_cache.db"
        self.ttl_seconds = ttl_seconds

        self._init_db()

        # Statistics
        self.stats = {"hits": 0, "misses": 0, "sets": 0, "evictions": 0}

    def _init_db(self):
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                accessed_at INTEGER NOT NULL,
                access_count INTEGER DEFAULT 0,
                metadata TEXT
            )
        """)

        # Index for TTL-based cleanup
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_accessed_at ON cache(accessed_at)
        """)

        conn.commit()
        conn.close()

        logger.info(f"Cache database initialized at {self.db_path}")

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value as dictionary, or None if not found or expired
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT value, created_at, accessed_at, access_count
            FROM cache
            WHERE key = ?
        """, (key,))

        row = cursor.fetchone()

        if row is None:
            self.stats["misses"] += 1
            conn.close()
            return None

        value_json, created_at, accessed_at, access_count = row

        # Check TTL
        current_time = int(time.time())
        if current_time - created_at > self.ttl_seconds:
            # Expired - delete and return None
            cursor.execute("DELETE FROM cache WHERE key = ?", (key,))
            conn.commit()
            conn.close()
            self.stats["misses"] += 1
            self.stats["evictions"] += 1
            logger.debug(f"Cache entry expired: {key}")
            return None

        # Update access stats
        cursor.execute("""
            UPDATE cache
            SET accessed_at = ?, access_count = ?
            WHERE key = ?
        """, (current_time, access_count + 1, key))

        conn.commit()
        conn.close()

        self.stats["hits"] += 1
        logger.debug(f"Cache hit: {key}")
        return json.loads(value_json)

    def set(self, key: str, value: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None):
        """
        Store value in cache.

        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
            metadata: Optional metadata about the cached entry
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        current_time = int(time.time())
        value_json = json.dumps(value)
        metadata_json = json.dumps(metadata) if metadata else None

        cursor.execute("""
            INSERT OR REPLACE INTO cache (key, value, created_at, accessed_at, access_count, metadata)
            VALUES (?, ?, ?, ?, 0, ?)
        """, (key, value_json, current_time, current_time, metadata_json))

        conn.commit()
        conn.close()

        self.stats["sets"] += 1
        logger.debug(f"Cache set: {key}")

    def clear_expired(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        current_time = int(time.time())
        cutoff = current_time - self.ttl_seconds

        cursor.execute("SELECT COUNT(*) FROM cache WHERE created_at < ?", (cutoff,))
        count = cursor.fetchone()[0]

        cursor.execute("DELETE FROM cache WHERE created_at < ?", (cutoff,))

        conn.commit()
        conn.close()

        self.stats["evictions"] += count
        logger.info(f"Cleared {count} expired cache entries")
        return count

    def clear_all(self):
        """Clear entire cache."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("DELETE FROM cache")

        conn.commit()
        conn.close()

        logger.info("Cleared all cache entries")

    def get_stats(self) -> Dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics including hit rate
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*), SUM(LENGTH(value)) FROM cache")
        count, total_size = cursor.fetchone()

        conn.close()

        return {
            **self.stats,
            "entries": count or 0,
            "total_size_bytes": total_size or 0,
            "hit_rate": self.stats["hits"] / (self.stats["hits"] + self.stats["misses"])
            if (self.stats["hits"] + self.stats["misses"]) > 0
            else 0.0,
        }

    @staticmethod
    def generate_key(agent_name: str, *inputs) -> str:
        """
        Generate cache key from agent name and inputs.

        Args:
            agent_name: Name of the agent
            *inputs: Variable number of inputs to hash

        Returns:
            SHA256 hash as hex string
        """
        content = f"{agent_name}:{'|'.join(str(i) for i in inputs)}"
        return hashlib.sha256(content.encode()).hexdigest()
