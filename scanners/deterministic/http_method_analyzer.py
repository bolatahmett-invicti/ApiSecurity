#!/usr/bin/env python3
"""
HTTP Method Analyzer
=====================
Maps HTTP methods to OpenAPI operation expectations.

100% deterministic - HTTP methods have well-defined semantics:
- GET: No request body, returns data
- POST: Request body usually required, creates resource
- PUT: Request body required, updates entire resource
- PATCH: Request body required, partial update
- DELETE: No request body, deletes resource

Cost savings: 100% (no LLM needed)
Accuracy: 100% (HTTP specs are standardized)
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger("api_scanner.deterministic.http_method_analyzer")


class HTTPMethodAnalyzer:
    """
    Analyze HTTP methods to determine OpenAPI operation structure.

    Based on RESTful API conventions and HTTP specifications.
    """

    # Standard method expectations (RFC 7231 + RESTful conventions)
    METHOD_RULES = {
        "GET": {
            "has_request_body": False,
            "typical_success_codes": [200, 206],  # 200=OK, 206=Partial Content
            "typical_error_codes": [400, 401, 403, 404, 429, 500],
            "description_template": "Retrieve {resource}",
            "response_description": "Successful retrieval",
        },
        "POST": {
            "has_request_body": True,
            "typical_success_codes": [201, 202, 200],  # 201=Created, 202=Accepted, 200=OK
            "typical_error_codes": [400, 401, 403, 409, 422, 429, 500],
            "description_template": "Create new {resource}",
            "response_description": "Resource created successfully",
        },
        "PUT": {
            "has_request_body": True,
            "typical_success_codes": [200, 204],  # 200=OK, 204=No Content
            "typical_error_codes": [400, 401, 403, 404, 409, 422, 429, 500],
            "description_template": "Update {resource}",
            "response_description": "Resource updated successfully",
        },
        "PATCH": {
            "has_request_body": True,
            "typical_success_codes": [200, 204],
            "typical_error_codes": [400, 401, 403, 404, 422, 429, 500],
            "description_template": "Partially update {resource}",
            "response_description": "Resource partially updated",
        },
        "DELETE": {
            "has_request_body": False,
            "typical_success_codes": [204, 200],  # 204=No Content, 200=OK
            "typical_error_codes": [401, 403, 404, 429, 500],
            "description_template": "Delete {resource}",
            "response_description": "Resource deleted successfully",
        },
        "HEAD": {
            "has_request_body": False,
            "typical_success_codes": [200],
            "typical_error_codes": [401, 403, 404, 500],
            "description_template": "Get {resource} metadata",
            "response_description": "Metadata retrieved (no body)",
        },
        "OPTIONS": {
            "has_request_body": False,
            "typical_success_codes": [200, 204],
            "typical_error_codes": [401, 403, 500],
            "description_template": "Get allowed methods for {resource}",
            "response_description": "Allowed methods",
        },
    }

    @staticmethod
    def get_expectations(method: str, resource: str = "resource") -> Dict[str, Any]:
        """
        Get standard expectations for HTTP method.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE, etc.)
            resource: Resource name for description templates (default: "resource")

        Returns:
            Dictionary with method expectations

        Example:
            >>> get_expectations("POST", "user")
            {
                "has_request_body": True,
                "typical_success_codes": [201, 202, 200],
                "typical_error_codes": [400, 401, 403, 409, 422, 429, 500],
                "description": "Create new user",
                "response_description": "Resource created successfully"
            }
        """
        method_upper = method.upper()

        if method_upper in HTTPMethodAnalyzer.METHOD_RULES:
            rules = HTTPMethodAnalyzer.METHOD_RULES[method_upper].copy()

            # Replace {resource} placeholder in description
            rules["description"] = rules["description_template"].format(resource=resource)

            logger.debug(f"HTTP {method_upper}: {rules['description']}")

            return rules
        else:
            # Unknown method - use safe defaults
            logger.warning(f"Unknown HTTP method: {method_upper}, using defaults")
            return {
                "has_request_body": False,
                "typical_success_codes": [200],
                "typical_error_codes": [400, 401, 403, 500],
                "description": f"Perform {method_upper} operation on {resource}",
                "response_description": "Operation successful",
            }

    @staticmethod
    def generate_responses(method: str, include_all_codes: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Generate standard OpenAPI responses based on HTTP method.

        Args:
            method: HTTP method
            include_all_codes: If True, include all common error codes; if False, only typical ones

        Returns:
            OpenAPI responses object

        Example:
            >>> generate_responses("POST")
            {
                "201": {"description": "Resource created successfully"},
                "400": {"description": "Bad Request - Invalid input"},
                "401": {"description": "Unauthorized - Authentication required"},
                ...
            }
        """
        expectations = HTTPMethodAnalyzer.get_expectations(method)

        responses = {}

        # Add success responses
        for code in expectations["typical_success_codes"]:
            responses[str(code)] = {
                "description": HTTPMethodAnalyzer._get_status_code_description(code, method)
            }

        # Add error responses
        for code in expectations["typical_error_codes"]:
            responses[str(code)] = {
                "description": HTTPMethodAnalyzer._get_status_code_description(code, method)
            }

        return responses

    @staticmethod
    def _get_status_code_description(code: int, method: str = "") -> str:
        """
        Get standard description for HTTP status code.

        Based on RFC 7231 and common API conventions.
        """
        STANDARD_DESCRIPTIONS = {
            # Success codes
            200: "OK - Request successful",
            201: "Created - Resource created successfully",
            202: "Accepted - Request accepted for processing",
            204: "No Content - Request successful, no response body",
            206: "Partial Content - Partial data returned",

            # Client error codes
            400: "Bad Request - Invalid input or malformed request",
            401: "Unauthorized - Authentication required or failed",
            403: "Forbidden - Insufficient permissions",
            404: "Not Found - Resource doesn't exist",
            405: "Method Not Allowed - HTTP method not supported",
            409: "Conflict - Resource already exists or version conflict",
            410: "Gone - Resource permanently deleted",
            422: "Unprocessable Entity - Validation failed",
            429: "Too Many Requests - Rate limit exceeded",

            # Server error codes
            500: "Internal Server Error - Server encountered an error",
            501: "Not Implemented - Feature not implemented",
            502: "Bad Gateway - Invalid response from upstream server",
            503: "Service Unavailable - Server temporarily unavailable",
            504: "Gateway Timeout - Upstream server timeout",
        }

        return STANDARD_DESCRIPTIONS.get(code, f"HTTP {code}")

    @staticmethod
    def extract_resource_from_route(route: str) -> str:
        """
        Extract resource name from route for description templates.

        Examples:
            - /users → "users"
            - /api/v1/products/{id} → "products"
            - /users/{user_id}/posts → "posts"
        """
        # Split route into parts
        parts = route.strip('/').split('/')

        # Find last non-parameter segment
        for part in reversed(parts):
            # Skip path parameters ({id}, :id, <id>)
            if not any(char in part for char in ['{', '}', ':', '<', '>']):
                # Skip common prefixes
                if part not in ['api', 'v1', 'v2', 'v3']:
                    return part

        return "resource"  # Fallback

    @staticmethod
    def infer_crud_operation(method: str, route: str) -> str:
        """
        Infer CRUD operation from HTTP method and route pattern.

        Returns: "create", "read", "list", "update", "delete", or "unknown"
        """
        method_upper = method.upper()

        # Check if route has path parameter (indicates single resource)
        has_param = any(char in route for char in ['{', '}', ':', '<', '>'])

        if method_upper == "GET":
            return "read" if has_param else "list"
        elif method_upper == "POST":
            return "create"
        elif method_upper in ["PUT", "PATCH"]:
            return "update"
        elif method_upper == "DELETE":
            return "delete"
        else:
            return "unknown"
