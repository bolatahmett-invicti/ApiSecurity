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

# Import static security payload templates (COST SAVINGS: 100% for security payloads)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from scanners.security_templates.payloads import SecurityPayloadTemplates


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
        return """You are an expert API testing specialist.

Your task is to generate test payloads for API endpoints (VALID, EDGE CASES, and FUZZ payloads only).

NOTE: Security payloads (SQL injection, XSS, etc.) are handled by static templates - you don't need to generate them.

CRITICAL REQUIREMENTS:
1. Return ONLY valid JSON (no markdown code fences, no explanations)
2. EVERY object property MUST be followed by a comma except the last one in the object
3. EVERY array element MUST be followed by a comma except the last one in the array
4. All strings MUST use double quotes ("), not single quotes (')
5. Generate payloads in 3 categories: valid, edge_cases, fuzz
6. Ensure valid payloads match the expected schema exactly
7. Make edge cases realistic (boundary values, special characters)
8. Fuzz payloads should test error handling robustly

JSON SYNTAX RULES (CRITICAL):
- Use commas between all object properties: {"a": 1, "b": 2, "c": 3}
- Use commas between all array elements: [1, 2, 3]
- NO comma after the last property in an object
- NO comma after the last element in an array
- All property names and string values use double quotes

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

**3. FUZZ PAYLOADS** (malformed data - should fail gracefully):
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
        "username": "aaaaaaaaa...(255 chars)",
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
    }
  ],
  "summary": "Generated payloads for valid/edge/fuzz testing (security payloads added from templates)"
}

BEFORE RESPONDING:
1. Verify all commas are present between object properties
2. Verify all commas are present between array elements
3. Verify NO trailing commas before closing } or ]
4. Verify all strings use double quotes
5. Test your JSON syntax mentally before responding

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
3. Generate at least 4 fuzz payloads (error handling)

NOTE: Security payloads (SQL injection, XSS, etc.) are generated from static templates automatically.

IMPORTANT NOTES:
- Analyze the code to understand expected field names and types
- Make valid payloads realistic (proper emails, valid formats)
- Edge cases should test boundary conditions
- Fuzz payloads should test error handling robustly

IMPORTANT: Return ONLY the JSON object with 'valid', 'edge_cases', and 'fuzz' arrays. No markdown formatting, no explanations."""

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

            # Call Claude for valid/edge_cases/fuzz payloads only (NOT security!)
            self.logger.info(f"Generating payloads for {context.endpoint.method} {context.endpoint.route}")
            response = await self._call_claude(system_prompt, user_prompt)

            # Parse JSON response (valid, edge_cases, fuzz)
            payloads = self._parse_json_response(response)

            # Generate security payloads from static templates (COST SAVINGS: $0!)
            security_payloads = self._generate_security_payloads_from_templates(context)
            payloads["security"] = security_payloads

            self.logger.info(
                f"Hybrid payload generation: "
                f"{len(payloads.get('valid', []))} valid, "
                f"{len(payloads.get('edge_cases', []))} edge cases, "
                f"{len(security_payloads)} security (templates), "
                f"{len(payloads.get('fuzz', []))} fuzz"
            )

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
                    "security_source": "static_templates",  # NEW: indicate templates used
                    "fuzz_count": len(payloads.get("fuzz", [])),
                    "cost_savings": "100% for security payloads",
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

    def _generate_security_payloads_from_templates(
        self,
        context: EnrichmentContext,
        limit_per_category: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Generate security payloads from static templates (NO LLM NEEDED).

        This replaces LLM generation for security payloads with deterministic templates.

        Args:
            context: EnrichmentContext with endpoint info
            limit_per_category: Max payloads per vulnerability category (default: 2)

        Returns:
            List of security payload objects matching LLM format

        Cost savings: 100% (was ~$0.015-0.02 per endpoint)
        """
        endpoint_info = {
            "route": context.endpoint.route,
            "method": context.endpoint.method,
            "parameters": [],  # Will be populated if we have schema
        }

        # Extract parameters from config if available
        if context.config and "parameters" in context.config:
            endpoint_info["parameters"] = context.config["parameters"]

        # Get all vulnerability categories
        categories = SecurityPayloadTemplates.get_all_categories()

        security_payloads = []

        # Generate payloads for each category
        for category in categories:
            category_payloads = SecurityPayloadTemplates.get_payloads_by_category(category)

            # Limit payloads per category to avoid overwhelming the test suite
            for payload_data in category_payloads[:limit_per_category]:
                # Convert template format to LLM-compatible format
                security_payload = {
                    "name": f"{category}_{len(security_payloads)}",
                    "category": category,
                    "description": payload_data["description"],
                    "payload": payload_data["payload"],
                    "expected_status": [400, 401, 403, 422],  # Should be rejected
                    "detection": f"Should reject {category.replace('_', ' ')} attack",
                    "source": "static_template"  # Mark as template-generated
                }

                # For string payloads, inject into likely field names
                if isinstance(payload_data["payload"], str):
                    # Infer field names from context
                    field_name = self._infer_vulnerable_field(context, category)
                    security_payload["payload"] = {field_name: payload_data["payload"]}

                security_payloads.append(security_payload)

        self.logger.debug(
            f"Generated {len(security_payloads)} security payloads from templates "
            f"({len(categories)} categories × {limit_per_category} payloads each)"
        )

        return security_payloads

    def _infer_vulnerable_field(self, context: EnrichmentContext, category: str) -> str:
        """
        Infer which field name is most vulnerable for a given attack category.

        Args:
            context: EnrichmentContext
            category: Vulnerability category (e.g., "sql_injection", "xss")

        Returns:
            Field name to inject payload into
        """
        # Category-specific field mappings
        field_mappings = {
            "sql_injection": ["username", "email", "id", "search", "query"],
            "xss": ["name", "bio", "comment", "message", "description"],
            "command_injection": ["filename", "file", "path", "command"],
            "path_traversal": ["file", "path", "filename", "directory"],
            "nosql_injection": ["username", "email", "id"],
            "ldap_injection": ["username", "email", "cn", "uid"],
            "header_injection": ["redirect_url", "callback", "next"],
            "ssrf": ["url", "callback", "webhook", "image_url"],
            "template_injection": ["template", "content", "message"],
            "xxe": ["xml", "data", "content"],
        }

        # Get likely fields for this category
        likely_fields = field_mappings.get(category, ["input", "data", "value"])

        # TODO: Could analyze context.function_body to detect actual field names
        # For now, use first field from mapping
        return likely_fields[0]

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

    async def enrich_batch(self, contexts: List[EnrichmentContext]) -> List[EnrichmentResult]:
        """
        Generate payloads for multiple endpoints in a single LLM call (batch processing).

        This is more cost-efficient than generating one-by-one:
        - Before: 15 endpoints × 7K tokens = 105K tokens
        - After: 1 batch × 50K tokens = 50K tokens (52% savings)

        Args:
            contexts: List of EnrichmentContext objects to process together

        Returns:
            List of EnrichmentResult objects (one per context)

        Note:
            If batch processing fails, falls back to per-endpoint enrichment
            Skips GET/DELETE methods automatically
        """
        if not contexts:
            return []

        # Filter out GET/DELETE endpoints (they don't have request bodies)
        payload_contexts = [
            ctx for ctx in contexts
            if ctx.endpoint.method in ["POST", "PUT", "PATCH"]
        ]

        # Create skipped results for GET/DELETE
        skipped_results = []
        for ctx in contexts:
            if ctx.endpoint.method not in ["POST", "PUT", "PATCH"]:
                skipped_results.append((ctx, EnrichmentResult(
                    status=AgentStatus.SKIPPED,
                    data={"reason": "Method does not accept request body"},
                    metadata={
                        "endpoint": f"{ctx.endpoint.method} {ctx.endpoint.route}",
                    }
                )))

        # If no endpoints need payloads, return skipped results
        if not payload_contexts:
            return [result for _, result in skipped_results]

        # Single endpoint - use regular enrich
        if len(payload_contexts) == 1:
            result = await self.enrich(payload_contexts[0])
            return [result]

        try:
            # Build batch prompts
            system_prompt = self._build_batch_system_prompt()
            user_prompt = self._build_batch_user_prompt(payload_contexts)

            # Call LLM
            batch_summary = f"{len(payload_contexts)} endpoints (POST/PUT/PATCH only)"
            self.logger.info(f"Batch generating payloads for {batch_summary}")
            response = await self._call_claude(system_prompt, user_prompt)

            # Parse batch JSON response
            batch_data = self._parse_batch_json_response(response, payload_contexts)

            # Create results for each endpoint
            results = []
            for ctx in payload_contexts:
                endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"

                # Find this endpoint's payloads in batch response
                payloads = batch_data.get(endpoint_id)

                if payloads:
                    # Add security payloads from templates (COST SAVINGS!)
                    security_payloads = self._generate_security_payloads_from_templates(ctx)
                    payloads["security"] = security_payloads

                    # Validate payloads
                    try:
                        self._validate_payloads(payloads)
                        results.append(EnrichmentResult(
                            status=AgentStatus.SUCCESS,
                            data={"payloads": payloads},
                            metadata={
                                "model": self.model,
                                "endpoint": endpoint_id,
                                "batch_processed": True,
                                "batch_size": len(payload_contexts),
                                "valid_count": len(payloads.get("valid", [])),
                                "edge_case_count": len(payloads.get("edge_cases", [])),
                                "security_count": len(payloads.get("security", [])),
                                "security_source": "static_templates",  # NEW
                                "fuzz_count": len(payloads.get("fuzz", [])),
                                "cost_savings": "100% for security payloads",
                            }
                        ))
                    except ValueError as e:
                        self.logger.warning(f"Batch validation failed for {endpoint_id}: {e}")
                        results.append(EnrichmentResult(
                            status=AgentStatus.FAILED,
                            errors=[f"Validation error: {str(e)}"],
                            data={"payloads": payloads}
                        ))
                else:
                    # Endpoint missing from batch response
                    self.logger.warning(f"Endpoint {endpoint_id} missing from batch response")
                    results.append(EnrichmentResult(
                        status=AgentStatus.FAILED,
                        errors=[f"Endpoint not found in batch response"],
                        data={}
                    ))

            # Merge with skipped results
            all_results = []
            result_map = {f"{ctx.endpoint.method} {ctx.endpoint.route}": result
                         for ctx, result in zip(payload_contexts, results)}

            for ctx in contexts:
                endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"
                if endpoint_id in result_map:
                    all_results.append(result_map[endpoint_id])
                else:
                    # Must be a skipped endpoint
                    for skip_ctx, skip_result in skipped_results:
                        if f"{skip_ctx.endpoint.method} {skip_ctx.endpoint.route}" == endpoint_id:
                            all_results.append(skip_result)
                            break

            # Check success rate
            success_count = sum(1 for r in results if r.is_success())
            self.logger.info(
                f"Batch payload generation complete: {success_count}/{len(payload_contexts)} successful "
                f"({success_count / len(payload_contexts) * 100:.0f}%)"
            )

            return all_results

        except Exception as e:
            # Batch processing failed - fall back to per-endpoint
            self._log_error("Batch payload generation failed, falling back to per-endpoint", e)
            self.logger.info(f"Processing {len(contexts)} endpoints individually...")

            # Fallback: enrich one-by-one
            results = []
            for ctx in contexts:
                result = await self.enrich(ctx)
                results.append(result)

            return results

    def _build_batch_system_prompt(self) -> str:
        """Build system prompt for batch payload generation."""
        return """You are an expert API testing specialist.

Your task is to generate test payloads for MULTIPLE API endpoints in a single response.

NOTE: Security payloads (SQL injection, XSS, etc.) are handled by static templates - you don't need to generate them.

CRITICAL REQUIREMENTS:
1. Return ONLY valid JSON (no markdown code fences, no explanations)
2. Process ALL endpoints provided (do not skip any)
3. Return a JSON object where keys are endpoint IDs (METHOD /route)
4. For each endpoint, generate payloads in 3 categories: valid, edge_cases, fuzz
5. Ensure valid payloads match the expected schema exactly
6. Make edge cases realistic (boundary values, special characters)
7. Fuzz payloads should test error handling robustly

OUTPUT FORMAT (strict JSON):
{
  "POST /api/users": {
    "valid": [...],
    "edge_cases": [...],
    "fuzz": [...],
    "summary": "Generated payloads for user creation"
  },
  "PUT /api/users/:id": {
    "valid": [...],
    "edge_cases": [...],
    "fuzz": [...],
    "summary": "Generated payloads for user update"
  },
  "POST /api/products": {
    "valid": [...],
    "edge_cases": [...],
    "fuzz": [...],
    "summary": "Generated payloads for product creation"
  }
}

PAYLOAD CATEGORIES (for each endpoint):
1. **valid**: At least 3 happy path payloads that should succeed
2. **edge_cases**: At least 5 boundary/special character tests
3. **fuzz**: At least 4 malformed data tests

IMPORTANT: Process ALL endpoints. Return payload sets for every endpoint provided."""

    def _build_batch_user_prompt(self, contexts: List[EnrichmentContext]) -> str:
        """Build user prompt for batch payload generation."""
        prompt = f"""Generate comprehensive test payloads for these {len(contexts)} API endpoints.

ENDPOINTS TO PROCESS (all POST/PUT/PATCH):
"""

        # Add each endpoint
        for i, ctx in enumerate(contexts, 1):
            ep = ctx.endpoint
            prompt += f"""
{'=' * 60}
ENDPOINT #{i}: {ep.method} {ep.route}
{'=' * 60}
Framework: {ctx.framework} | Language: {ctx.language}
File: {ep.file_path}:{ep.line_number}

SOURCE CODE:
```
{(ctx.surrounding_code or ctx.function_body or ep.raw_match)[:600]}
```
"""

        prompt += f"""
{'=' * 60}

PAYLOAD GENERATION REQUIREMENTS FOR EACH ENDPOINT:
1. At least 3 valid payloads (happy path)
2. At least 5 edge case payloads (boundaries, special chars)
3. At least 4 fuzz payloads (malformed data)

NOTE: Security payloads (SQL injection, XSS, etc.) are generated from static templates automatically.

IMPORTANT:
- Process ALL {len(contexts)} endpoints
- Return JSON object with keys: {', '.join(f'"{c.endpoint.method} {c.endpoint.route}"' for c in contexts[:3])}{"..." if len(contexts) > 3 else ""}
- Analyze code to understand field names and types
- NO markdown formatting, NO explanations, ONLY JSON with 'valid', 'edge_cases', 'fuzz' arrays"""

        return prompt

    def _parse_batch_json_response(
        self,
        response: str,
        contexts: List[EnrichmentContext]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Parse batch JSON response for payloads.

        Expected format:
        {
          "POST /api/users": {
            "valid": [...],
            "edge_cases": [...],
            "security": [...],
            "fuzz": [...]
          }
        }

        Args:
            response: Raw LLM response
            contexts: Original contexts (for validation)

        Returns:
            Dictionary mapping endpoint_id to payload object

        Raises:
            json.JSONDecodeError: If response is not valid JSON
        """
        # Parse JSON using robust parser
        batch_data = RobustJSONParser.parse(response, context="batch payload objects")

        if not isinstance(batch_data, dict):
            raise ValueError(f"Batch response must be a dictionary, got {type(batch_data).__name__}")

        # Validate we got responses for expected endpoints
        expected_ids = {f"{ctx.endpoint.method} {ctx.endpoint.route}" for ctx in contexts}
        received_ids = set(batch_data.keys())

        missing = expected_ids - received_ids
        if missing:
            self.logger.warning(f"Missing {len(missing)} endpoints from batch response: {list(missing)[:3]}")

        extra = received_ids - expected_ids
        if extra:
            self.logger.warning(f"Unexpected {len(extra)} endpoints in batch response: {list(extra)[:3]}")

        return batch_data
