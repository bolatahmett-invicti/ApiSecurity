#!/usr/bin/env python3
"""
Payload Generator Agent
=======================
Generates comprehensive test payloads for API security testing.

This agent analyzes endpoint schemas to generate:
- Valid payloads (happy path)
- Edge case payloads (boundaries, special chars)
- Security test payloads (injection attacks, XSS, etc.)
- Fuzz payloads (malformed data)

Input: Endpoint + request schema
Output: Categorized test payloads for Invicti
"""

import json
import re
from typing import Dict, Any, List
from .base_agent import BaseAgent, EnrichmentContext, EnrichmentResult, AgentStatus
from .json_parser import RobustJSONParser


class PayloadGeneratorAgent(BaseAgent):
    """
    Agent that generates comprehensive test payloads for security testing.

    Generates 4 categories of payloads:
    1. **Valid**: Normal happy path data that should succeed
    2. **Edge Cases**: Boundary values, special characters, empty strings
    3. **Security**: SQL injection, XSS, command injection, path traversal, XXE
    4. **Fuzz**: Random/malformed data to test error handling

    Only runs for POST/PUT/PATCH methods with request bodies.

    Usage:
        agent = PayloadGeneratorAgent(anthropic_api_key="sk-ant-...")
        context = EnrichmentContext(endpoint=ep, function_body=code, ...)
        result = await agent.enrich(context)
    """

    @property
    def agent_name(self) -> str:
        return "payload_generator"

    def _build_system_prompt(self) -> str:
        return """You are an expert security researcher and penetration tester specializing in API security testing.

Your task is to generate comprehensive test payloads for API endpoints to be used in DAST security scanning.

CRITICAL REQUIREMENTS:
1. Return ONLY valid JSON (no markdown code fences, no explanations)
2. Generate payloads in 4 categories: valid, edge_cases, security, fuzz
3. Ensure valid payloads match the expected schema exactly
4. Include diverse security payloads covering OWASP Top 10
5. Make edge cases realistic (boundary values, special characters)
6. Fuzz payloads should test error handling robustly

PAYLOAD CATEGORIES:

**1. VALID PAYLOADS** (happy path - should succeed):
- Normal data that matches schema exactly
- Realistic values (proper emails, valid dates, reasonable strings)
- At least 3 different valid examples
- Include both minimal and complete data

**2. EDGE CASES** (boundary testing - may succeed or fail gracefully):
- Empty strings, null values, missing optional fields
- Minimum/maximum length strings
- Boundary numbers (0, -1, MAX_INT, MIN_INT)
- Special characters in strings (unicode, emojis, quotes)
- Very long strings (1000+ chars)
- Arrays with 0 elements, 1 element, many elements

**3. SECURITY PAYLOADS** (attack vectors - should be blocked):
- **SQL Injection**: ' OR '1'='1, '; DROP TABLE users--
- **XSS**: <script>alert('XSS')</script>, javascript:alert(1)
- **Command Injection**: ; ls -la, && cat /etc/passwd
- **Path Traversal**: ../../etc/passwd, ..\\..\\windows\\system32
- **XXE**: XML entities for file access
- **LDAP Injection**: *)(uid=*))(|(uid=*
- **NoSQL Injection**: {"$gt": ""}, {"$ne": null}
- **Header Injection**: \r\nSet-Cookie: admin=true
- **SSRF**: http://169.254.169.254/latest/meta-data/

**4. FUZZ PAYLOADS** (malformed data - should fail gracefully):
- Invalid types (string instead of number, object instead of array)
- Extra unexpected fields
- Deeply nested objects (50+ levels)
- Very large payloads (10MB+ strings)
- Invalid JSON structure
- Binary data in string fields

OUTPUT FORMAT (strict JSON):
{
  "valid": [
    {
      "name": "valid_user_registration",
      "description": "Standard user registration with all required fields",
      "payload": {
        "email": "user@example.com",
        "username": "john_doe",
        "password": "SecurePass123!",
        "age": 25
      },
      "expected_status": 200
    },
    {
      "name": "valid_minimal",
      "description": "Minimal valid payload with only required fields",
      "payload": {
        "email": "min@example.com",
        "password": "pass123"
      },
      "expected_status": 200
    }
  ],
  "edge_cases": [
    {
      "name": "empty_optional_fields",
      "description": "Empty strings in optional fields",
      "payload": {
        "email": "test@example.com",
        "username": "",
        "bio": ""
      },
      "expected_status": [200, 400]
    },
    {
      "name": "boundary_string_length",
      "description": "Username at maximum allowed length",
      "payload": {
        "username": "a" * 255,
        "email": "long@example.com"
      },
      "expected_status": [200, 400]
    },
    {
      "name": "special_characters",
      "description": "Unicode and special characters",
      "payload": {
        "name": "用户名 🎉",
        "email": "user+tag@sub.example.com"
      },
      "expected_status": [200, 400]
    }
  ],
  "security": [
    {
      "name": "sql_injection_authentication_bypass",
      "category": "sql_injection",
      "description": "SQL injection in login",
      "payload": {
        "username": "admin' OR '1'='1",
        "password": "anything"
      },
      "expected_status": [400, 401],
      "detection": "Should reject or sanitize SQL syntax"
    },
    {
      "name": "xss_script_injection",
      "category": "xss",
      "description": "XSS attack in user input",
      "payload": {
        "name": "<script>alert('XSS')</script>",
        "bio": "<img src=x onerror=alert(1)>"
      },
      "expected_status": [400, 422],
      "detection": "Should escape or reject HTML/JS"
    },
    {
      "name": "command_injection",
      "category": "command_injection",
      "description": "Command injection attempt",
      "payload": {
        "filename": "test.txt; rm -rf /"
      },
      "expected_status": [400, 422],
      "detection": "Should reject shell metacharacters"
    },
    {
      "name": "path_traversal",
      "category": "path_traversal",
      "description": "Path traversal in file parameter",
      "payload": {
        "file": "../../etc/passwd"
      },
      "expected_status": [400, 403],
      "detection": "Should block directory traversal"
    },
    {
      "name": "nosql_injection",
      "category": "nosql_injection",
      "description": "NoSQL injection operators",
      "payload": {
        "username": {"$gt": ""},
        "password": {"$ne": null}
      },
      "expected_status": [400, 401],
      "detection": "Should reject MongoDB operators"
    }
  ],
  "fuzz": [
    {
      "name": "invalid_type_string_as_number",
      "description": "String value for numeric field",
      "payload": {
        "age": "not_a_number",
        "price": "expensive"
      },
      "expected_status": [400, 422]
    },
    {
      "name": "extra_unexpected_fields",
      "description": "Additional fields not in schema",
      "payload": {
        "email": "test@example.com",
        "unexpected_field": "should_be_ignored",
        "admin": true,
        "role": "administrator"
      },
      "expected_status": [200, 400]
    },
    {
      "name": "deeply_nested_object",
      "description": "Deeply nested JSON (30 levels)",
      "payload": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": "deep"}}}}}}}},
      "expected_status": [400, 413]
    },
    {
      "name": "very_large_string",
      "description": "10MB string payload",
      "payload": {
        "data": "A" * 10000000
      },
      "expected_status": [400, 413]
    }
  ],
  "summary": "Generated 15 test payloads across 4 categories for comprehensive API security testing"
}

Generate realistic and diverse payloads. Focus on security testing quality."""

    def _build_user_prompt(self, context: EnrichmentContext) -> str:
        ep = context.endpoint

        # Check if this endpoint accepts request body
        if ep.method not in ["POST", "PUT", "PATCH"]:
            return ""  # Skip GET/DELETE

        prompt = f"""Generate comprehensive test payloads for this API endpoint.

ENDPOINT INFORMATION:
- Route: {ep.route}
- HTTP Method: {ep.method}
- Framework: {context.framework}
- Language: {context.language}
- File: {ep.file_path}:{ep.line_number}

SOURCE CODE CONTEXT:
```
{context.surrounding_code or context.function_body or ep.raw_match}
```
"""

        # Add schema hint if available from enrichment
        if context.config and "request_schema" in context.config:
            prompt += f"""

REQUEST SCHEMA:
```json
{json.dumps(context.config['request_schema'], indent=2)}
```
"""

        prompt += """

PAYLOAD GENERATION REQUIREMENTS:
1. Generate at least 3 valid payloads (happy path)
2. Generate at least 5 edge case payloads (boundary testing)
3. Generate at least 8 security payloads covering:
   - SQL Injection (at least 2)
   - XSS (at least 2)
   - Command Injection
   - Path Traversal
   - NoSQL Injection
   - Any other relevant attack vectors
4. Generate at least 4 fuzz payloads (error handling)

IMPORTANT NOTES:
- Analyze the code to understand expected field names and types
- Make valid payloads realistic (proper emails, valid formats)
- Security payloads should target common vulnerabilities
- Edge cases should test boundary conditions
- Fuzz payloads should test error handling robustly

IMPORTANT: Return ONLY the JSON object, no markdown formatting, no explanations."""

        return prompt

    async def enrich(self, context: EnrichmentContext) -> EnrichmentResult:
        """
        Generate test payloads for endpoint.

        Args:
            context: EnrichmentContext with endpoint and code information

        Returns:
            EnrichmentResult with categorized payloads or SKIPPED for GET/DELETE
        """
        # Skip for methods without request body
        if context.endpoint.method not in ["POST", "PUT", "PATCH"]:
            self.logger.debug(f"Skipping payload generation for {context.endpoint.method} {context.endpoint.route}")
            return EnrichmentResult(
                status=AgentStatus.SKIPPED,
                data={"reason": "Method does not accept request body"},
                metadata={
                    "endpoint": f"{context.endpoint.method} {context.endpoint.route}",
                }
            )

        try:
            # Build prompts
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_user_prompt(context)

            if not user_prompt:
                return EnrichmentResult(
                    status=AgentStatus.SKIPPED,
                    data={"reason": "No request body expected"}
                )

            # Call Claude
            self.logger.info(f"Generating payloads for {context.endpoint.method} {context.endpoint.route}")
            response = await self._call_claude(system_prompt, user_prompt)

            # Parse JSON response
            payloads = self._parse_json_response(response)

            # Validate payload structure
            self._validate_payloads(payloads)

            return EnrichmentResult(
                status=AgentStatus.SUCCESS,
                data={"payloads": payloads},
                metadata={
                    "model": self.model,
                    "endpoint": f"{context.endpoint.method} {context.endpoint.route}",
                    "valid_count": len(payloads.get("valid", [])),
                    "edge_case_count": len(payloads.get("edge_cases", [])),
                    "security_count": len(payloads.get("security", [])),
                    "fuzz_count": len(payloads.get("fuzz", [])),
                }
            )

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Claude response as JSON: {e}")
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[f"Invalid JSON response: {str(e)}"],
                data={"raw_response": response[:500] if 'response' in locals() else None}
            )

        except Exception as e:
            self._log_error("Payload generation failed", e)
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[str(e)]
            )

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """
        Parse JSON from LLM response using robust parser.

        This handles common LLM response issues across all providers:
        - Markdown code blocks
        - Comments (// and /* */)
        - Trailing commas
        - Missing commas (heuristic fixes)
        - Smart quotes
        - Leading/trailing non-JSON text

        Args:
            response: Raw response from LLM (Claude, GPT-4, Gemini, etc.)

        Returns:
            Parsed JSON object

        Raises:
            json.JSONDecodeError: If response is not valid JSON after all strategies
        """
        return RobustJSONParser.parse(response, context="payload object")

    def _validate_payloads(self, payloads: Dict[str, Any]) -> None:
        """
        Validate payload structure.

        Args:
            payloads: Payloads to validate

        Raises:
            ValueError: If payload structure is invalid
        """
        if not isinstance(payloads, dict):
            raise ValueError("Payloads must be a dictionary")

        # Should have at least one category
        categories = ["valid", "edge_cases", "security", "fuzz"]
        if not any(cat in payloads for cat in categories):
            self.logger.warning("No payload categories found, adding empty defaults")
            for cat in categories:
                payloads[cat] = []

        # Validate each category is a list
        for category in categories:
            if category in payloads:
                if not isinstance(payloads[category], list):
                    raise ValueError(f"'{category}' must be a list")

                # Validate each payload has required fields
                for i, payload_obj in enumerate(payloads[category]):
                    if not isinstance(payload_obj, dict):
                        raise ValueError(f"{category}[{i}] must be a dictionary")
                    if "payload" not in payload_obj:
                        raise ValueError(f"{category}[{i}] missing 'payload' field")
                    if "name" not in payload_obj:
                        self.logger.warning(f"{category}[{i}] missing 'name' field")
                        payload_obj["name"] = f"{category}_{i}"

        # Add summary if missing
        if "summary" not in payloads:
            total = sum(len(payloads.get(cat, [])) for cat in categories)
            payloads["summary"] = f"Generated {total} test payloads across {len(categories)} categories"

        self.logger.debug("Payload structure validated successfully")
