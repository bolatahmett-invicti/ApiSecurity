#!/usr/bin/env python3
"""
Mock LLM Provider for Testing
==============================
Simulates LLM responses without making actual API calls.
Use this for testing AI enrichment logic without spending money.
"""

import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("api_scanner.agents.mock_llm_provider")


class MockLLMProvider:
    """
    Mock LLM provider that returns pre-defined responses for testing.

    Usage:
        export LLM_PROVIDER=mock
        export MOCK_LLM_QUALITY=high  # high, medium, low (simulates different JSON quality)
        python main.py ./project --ai-enrich
    """

    def __init__(self, quality: str = "high"):
        """
        Initialize mock provider.

        Args:
            quality: Response quality - "high" (perfect JSON), "medium" (minor issues),
                    "low" (requires aggressive cleaning)
        """
        self.quality = quality.lower()
        self.call_count = 0

    def generate_openapi_operation(self, endpoint_info: Dict[str, Any]) -> str:
        """Generate mock OpenAPI operation object."""
        self.call_count += 1

        route = endpoint_info.get("route", "/api/endpoint")
        method = endpoint_info.get("method", "GET")

        # Perfect JSON response
        response = {
            "summary": f"{method} {route}",
            "description": f"Mock endpoint for testing - {route}",
            "operationId": f"{method.lower()}{route.replace('/', '_')}",
            "tags": ["mock", "testing"],
            "parameters": [
                {
                    "name": "id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "Resource identifier"
                }
            ] if ":" in route or "{" in route else [],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "example": "Test User"},
                                "email": {"type": "string", "format": "email", "example": "test@example.com"}
                            },
                            "required": ["name", "email"]
                        }
                    }
                }
            } if method in ["POST", "PUT", "PATCH"] else None,
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "string"},
                                    "name": {"type": "string"},
                                    "email": {"type": "string"}
                                }
                            },
                            "example": {
                                "id": "123",
                                "name": "Test User",
                                "email": "test@example.com"
                            }
                        }
                    }
                },
                "400": {"description": "Bad request"},
                "401": {"description": "Unauthorized"},
                "500": {"description": "Internal server error"}
            },
            "security": [{"bearerAuth": []}]
        }

        return self._apply_quality(response)

    def generate_auth_config(self, endpoints: list) -> str:
        """Generate mock authentication configuration."""
        self.call_count += 1

        response = {
            "authentication_mechanisms": [
                {
                    "type": "bearer",
                    "scheme": "JWT",
                    "location": "header",
                    "header_name": "Authorization",
                    "format": "Bearer {token}",
                    "token_endpoint": "/api/auth/login",
                    "refresh_endpoint": "/api/auth/refresh",
                    "test_credentials": {
                        "username": "test@example.com",
                        "password": "TestPassword123!"
                    }
                }
            ],
            "protected_endpoints": [ep.get("route", "/api/endpoint") for ep in endpoints[:5]],
            "public_endpoints": ["/api/health", "/api/auth/login"],
            "security_recommendations": [
                "Implement rate limiting on authentication endpoints",
                "Use secure password hashing (bcrypt, argon2)",
                "Enable HTTPS in production"
            ]
        }

        return self._apply_quality(response)

    def generate_payloads(self, endpoint_info: Dict[str, Any]) -> str:
        """Generate mock test payloads."""
        self.call_count += 1

        response = {
            "valid": [
                {
                    "name": "valid_request",
                    "description": "Standard valid request",
                    "payload": {
                        "name": "John Doe",
                        "email": "john@example.com",
                        "age": 30
                    },
                    "expected_status": 200
                }
            ],
            "edge_cases": [
                {
                    "name": "empty_optional_fields",
                    "description": "Empty optional fields",
                    "payload": {
                        "name": "",
                        "email": "test@example.com"
                    },
                    "expected_status": [200, 400]
                }
            ],
            "security": [
                {
                    "name": "sql_injection",
                    "category": "sql_injection",
                    "description": "SQL injection attempt",
                    "payload": {
                        "username": "admin' OR '1'='1",
                        "password": "anything"
                    },
                    "expected_status": [400, 401],
                    "detection": "Should reject SQL syntax"
                },
                {
                    "name": "xss_attack",
                    "category": "xss",
                    "description": "XSS injection attempt",
                    "payload": {
                        "name": "<script>alert('XSS')</script>"
                    },
                    "expected_status": [400, 422],
                    "detection": "Should escape HTML/JS"
                }
            ],
            "fuzz": [
                {
                    "name": "invalid_type",
                    "description": "Invalid data type",
                    "payload": {
                        "age": "not_a_number"
                    },
                    "expected_status": [400, 422]
                }
            ],
            "summary": "Generated 4 test payloads for mock testing"
        }

        return self._apply_quality(response)

    def generate_dependencies(self, endpoints: list) -> str:
        """Generate mock dependency graph."""
        self.call_count += 1

        response = {
            "dependencies": [
                {
                    "from": "/api/auth/login",
                    "to": "/api/users/profile",
                    "type": "authentication",
                    "description": "Login required before accessing profile"
                }
            ],
            "test_sequences": [
                {
                    "name": "user_registration_flow",
                    "description": "Complete user registration and profile setup",
                    "steps": [
                        {"endpoint": "/api/auth/register", "method": "POST"},
                        {"endpoint": "/api/auth/login", "method": "POST"},
                        {"endpoint": "/api/users/profile", "method": "GET"}
                    ]
                }
            ],
            "critical_paths": [
                "/api/auth/login -> /api/users/profile"
            ]
        }

        return self._apply_quality(response)

    def _apply_quality(self, data: Dict[str, Any]) -> str:
        """
        Apply quality degradation to simulate real LLM responses.

        - high: Perfect JSON
        - medium: Minor formatting issues (extra whitespace, occasional missing comma)
        - low: Multiple issues (missing commas, trailing commas, etc.)
        """
        json_str = json.dumps(data, indent=2)

        if self.quality == "high":
            # Perfect JSON
            return json_str

        elif self.quality == "medium":
            # Add some whitespace issues and maybe one missing comma
            if self.call_count % 3 == 0:
                # Simulate missing comma (1 in 3 calls)
                json_str = json_str.replace('",\n    "description"', '"\n    "description"', 1)
            return json_str

        elif self.quality == "low":
            # Multiple issues
            # Missing comma
            json_str = json_str.replace('",\n    "description"', '"\n    "description"', 1)
            # Trailing comma
            json_str = json_str.replace('}\n  }', '},\n  }', 1)
            # Extra whitespace
            json_str = json_str.replace('\n', '\n\n', 2)
            return json_str

        return json_str

    def get_stats(self) -> Dict[str, int]:
        """Get usage statistics."""
        return {
            "total_calls": self.call_count,
            "total_tokens": 0,  # Mock doesn't use real tokens
            "total_cost": 0.0
        }


def create_mock_provider(quality: str = "high") -> MockLLMProvider:
    """
    Factory function to create mock provider.

    Args:
        quality: "high", "medium", or "low"

    Returns:
        MockLLMProvider instance
    """
    logger.info(f"🧪 Using Mock LLM Provider (quality: {quality})")
    return MockLLMProvider(quality=quality)
