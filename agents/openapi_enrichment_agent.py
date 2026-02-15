#!/usr/bin/env python3
"""
OpenAPI Enrichment Agent
=========================
Enriches API endpoints with complete OpenAPI operation objects.

This agent analyzes source code to generate comprehensive parameter definitions,
request/response schemas, and examples for each discovered API endpoint.

Input: Endpoint + code context
Output: Full OpenAPI operation with parameters, requestBody, responses, examples
"""

import json
import re
from typing import Dict, Any, List
from .base_agent import BaseAgent, EnrichmentContext, EnrichmentResult, AgentStatus
from .json_parser import RobustJSONParser


class OpenAPIEnrichmentAgent(BaseAgent):
    """
    Agent that generates comprehensive OpenAPI operation objects.

    Uses Claude to analyze source code and generate:
    - Complete parameter definitions (path, query, header, cookie)
    - Request body schemas with examples
    - Response schemas for different status codes
    - Security requirements
    - Detailed descriptions and examples

    Usage:
        agent = OpenAPIEnrichmentAgent(anthropic_api_key="sk-ant-...")
        context = EnrichmentContext(endpoint=ep, function_body=code, ...)
        result = await agent.enrich(context)
    """

    @property
    def agent_name(self) -> str:
        return "openapi_enrichment"

    def _build_system_prompt(self) -> str:
        return """You are an expert OpenAPI 3.0 specification generator with deep knowledge of API design patterns.

Your task is to analyze API endpoint source code and generate a complete OpenAPI operation object.

CRITICAL REQUIREMENTS:
1. Return ONLY valid JSON (no markdown code fences, no explanations)
2. Follow OpenAPI 3.0 specification exactly
3. Be thorough - extract ALL parameters from the code
4. Infer realistic data types from variable names, type hints, and context
5. Generate practical examples for request/response bodies
6. Identify security requirements from decorators/attributes/middleware
7. If information is not explicitly available, use reasonable defaults

OUTPUT FORMAT (strict JSON):
{
  "parameters": [
    {
      "name": "user_id",
      "in": "path",
      "required": true,
      "schema": {"type": "integer", "format": "int64", "minimum": 1},
      "description": "User identifier from the database",
      "example": 12345
    }
  ],
  "requestBody": {
    "required": true,
    "content": {
      "application/json": {
        "schema": {
          "type": "object",
          "properties": {
            "email": {"type": "string", "format": "email"},
            "name": {"type": "string", "minLength": 1, "maxLength": 100}
          },
          "required": ["email", "name"]
        },
        "examples": {
          "valid": {
            "value": {"email": "user@example.com", "name": "John Doe"}
          },
          "edge_case": {
            "value": {"email": "user+test@subdomain.example.com", "name": "A"}
          }
        }
      }
    }
  },
  "responses": {
    "200": {
      "description": "Success",
      "content": {
        "application/json": {
          "schema": {"type": "object", "properties": {"id": {"type": "integer"}}},
          "example": {"id": 12345, "status": "created"}
        }
      }
    },
    "400": {"description": "Bad Request - Invalid input"},
    "401": {"description": "Unauthorized - Authentication required"},
    "404": {"description": "Not Found - Resource doesn't exist"},
    "500": {"description": "Internal Server Error"}
  },
  "security": [{"bearerAuth": []}],
  "description": "Detailed endpoint description explaining what it does",
  "summary": "Brief summary of endpoint"
}

If you cannot determine something from the code, use reasonable defaults based on REST API best practices."""

    def _build_user_prompt(self, context: EnrichmentContext) -> str:
        ep = context.endpoint

        prompt = f"""Analyze this API endpoint and generate a complete OpenAPI operation object.

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

        if context.function_body and context.function_body != context.surrounding_code:
            prompt += f"""

COMPLETE FUNCTION BODY:
```
{context.function_body[:1500]}  # Limit to prevent token overflow
```
"""

        prompt += """

ANALYSIS CHECKLIST:
1. Extract ALL parameters (path, query, header, cookie) with types and constraints
2. Determine request body schema if POST/PUT/PATCH - identify all fields
3. Infer response schemas for success (200/201/204) and error cases (400/401/404/500)
4. Identify authentication/authorization decorators or middleware
5. Extract validation rules (required, min/max length, patterns, enums)
6. Generate at least 2 realistic examples per request/response
7. Write clear, concise descriptions

IMPORTANT: Return ONLY the JSON object, no markdown formatting, no explanations."""

        return prompt

    async def enrich(self, context: EnrichmentContext) -> EnrichmentResult:
        """
        Enrich endpoint with complete OpenAPI operation object.

        Args:
            context: EnrichmentContext with endpoint and code information

        Returns:
            EnrichmentResult with operation object or error
        """
        try:
            # Build prompts
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_user_prompt(context)

            # Call Claude
            self.logger.info(f"Enriching {context.endpoint.method} {context.endpoint.route}")
            response = await self._call_claude(system_prompt, user_prompt)

            # Parse JSON response
            # Claude sometimes wraps JSON in markdown code blocks - handle that
            operation_object = self._parse_json_response(response)

            # Validate operation object has required keys
            self._validate_operation_object(operation_object)

            return EnrichmentResult(
                status=AgentStatus.SUCCESS,
                data={"operation": operation_object},
                metadata={
                    "model": self.model,
                    "endpoint": f"{context.endpoint.method} {context.endpoint.route}",
                    "has_parameters": "parameters" in operation_object,
                    "has_request_body": "requestBody" in operation_object,
                    "has_responses": "responses" in operation_object,
                }
            )

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse LLM response as JSON: {e}")
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[f"Invalid JSON response: {str(e)}"],
                data={"raw_response": response[:500] if 'response' in locals() else None}
            )

        except ValueError as e:
            # Validation error - include the operation object for debugging
            self.logger.error(f"Operation validation failed: {e}")
            if 'operation_object' in locals():
                self.logger.debug(f"Failed operation object: {json.dumps(operation_object, indent=2)[:1000]}")
            if 'response' in locals():
                self.logger.debug(f"Raw LLM response: {response[:1000]}")
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[f"Validation error: {str(e)}"],
                data={
                    "operation": operation_object if 'operation_object' in locals() else None,
                    "raw_response": response[:500] if 'response' in locals() else None
                }
            )

        except Exception as e:
            self._log_error("Enrichment failed", e)
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[str(e)],
                data={"raw_response": response[:500] if 'response' in locals() else None}
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
        return RobustJSONParser.parse(response, context="operation object")

    def _validate_operation_object(self, operation: Dict[str, Any]) -> None:
        """
        Validate that operation object has reasonable structure.

        Args:
            operation: Operation object to validate

        Raises:
            ValueError: If operation object is invalid
        """
        if not isinstance(operation, dict):
            raise ValueError("Operation must be a dictionary")

        # Must have at least responses
        if "responses" not in operation:
            self.logger.warning("Operation missing 'responses' key, adding defaults")
            operation["responses"] = {
                "200": {"description": "Success"},
                "500": {"description": "Internal Server Error"}
            }

        # Validate parameters if present
        if "parameters" in operation:
            params = operation["parameters"]

            # Handle common issues
            if params is None or params == "":
                self.logger.warning("parameters is null/empty, removing it")
                del operation["parameters"]
            elif not isinstance(params, list):
                self.logger.error(f"'parameters' must be a list, got {type(params).__name__}: {str(params)[:200]}")
                raise ValueError(f"'parameters' must be a list, got {type(params).__name__}")
            else:
                for i, param in enumerate(params):
                    if not isinstance(param, dict):
                        self.logger.error(f"Parameter {i} must be a dictionary, got {type(param).__name__}")
                        raise ValueError(f"Parameter {i} must be a dictionary, got {type(param).__name__}")
                    if "name" not in param:
                        raise ValueError(f"Parameter {i} missing 'name'")
                    if "in" not in param:
                        raise ValueError(f"Parameter {i} missing 'in' (path/query/header/cookie)")
                    if param["in"] not in ["path", "query", "header", "cookie"]:
                        raise ValueError(f"Parameter 'in' must be path/query/header/cookie, got: {param['in']}")

        # Validate requestBody if present
        if "requestBody" in operation:
            req_body = operation["requestBody"]

            # Handle common issues
            if req_body is None or req_body == "":
                self.logger.warning("requestBody is null/empty, removing it")
                del operation["requestBody"]
            elif not isinstance(req_body, dict):
                self.logger.error(f"'requestBody' must be a dictionary, got {type(req_body).__name__}: {str(req_body)[:200]}")
                raise ValueError(f"'requestBody' must be a dictionary, got {type(req_body).__name__}")
            elif "content" not in req_body:
                self.logger.warning("'requestBody' missing 'content', adding default")
                operation["requestBody"]["content"] = {
                    "application/json": {
                        "schema": {"type": "object"}
                    }
                }

        # Validate responses
        if not isinstance(operation["responses"], dict):
            raise ValueError("'responses' must be a dictionary")

        # Add summary if missing
        if "summary" not in operation:
            operation["summary"] = f"API endpoint operation"

        self.logger.debug(f"Operation object validated successfully")

    async def enrich_batch(self, contexts: List[EnrichmentContext]) -> List[EnrichmentResult]:
        """
        Enrich multiple endpoints in a single LLM call (batch processing).

        This is more cost-efficient than enriching one-by-one:
        - Before: 20 endpoints × 4.5K tokens = 90K tokens
        - After: 1 batch × 60K tokens = 60K tokens (33% savings)

        Args:
            contexts: List of EnrichmentContext objects to process together

        Returns:
            List of EnrichmentResult objects (one per context)

        Note:
            If batch processing fails, falls back to per-endpoint enrichment
        """
        if not contexts:
            return []

        if len(contexts) == 1:
            # Single endpoint - use regular enrich
            return [await self.enrich(contexts[0])]

        try:
            # Build batch prompts
            system_prompt = self._build_batch_system_prompt()
            user_prompt = self._build_batch_user_prompt(contexts)

            # Call LLM
            batch_summary = f"{len(contexts)} endpoints ({', '.join(set(c.endpoint.method for c in contexts))})"
            self.logger.info(f"Batch enriching {batch_summary}")
            response = await self._call_claude(system_prompt, user_prompt)

            # Parse batch JSON response
            batch_data = self._parse_batch_json_response(response, contexts)

            # Create results for each endpoint
            results = []
            for i, ctx in enumerate(contexts):
                endpoint_id = f"{ctx.endpoint.method} {ctx.endpoint.route}"

                # Find this endpoint's operation in batch response
                operation = batch_data.get(endpoint_id)

                if operation:
                    # Validate operation
                    try:
                        self._validate_operation_object(operation)
                        results.append(EnrichmentResult(
                            status=AgentStatus.SUCCESS,
                            data={"operation": operation},
                            metadata={
                                "model": self.model,
                                "endpoint": endpoint_id,
                                "batch_processed": True,
                                "batch_size": len(contexts),
                                "has_parameters": "parameters" in operation,
                                "has_request_body": "requestBody" in operation,
                                "has_responses": "responses" in operation,
                            }
                        ))
                    except ValueError as e:
                        self.logger.warning(f"Batch validation failed for {endpoint_id}: {e}")
                        results.append(EnrichmentResult(
                            status=AgentStatus.FAILED,
                            errors=[f"Validation error: {str(e)}"],
                            data={"operation": operation}
                        ))
                else:
                    # Endpoint missing from batch response
                    self.logger.warning(f"Endpoint {endpoint_id} missing from batch response")
                    results.append(EnrichmentResult(
                        status=AgentStatus.FAILED,
                        errors=[f"Endpoint not found in batch response"],
                        data={}
                    ))

            # Check success rate
            success_count = sum(1 for r in results if r.is_success())
            self.logger.info(
                f"Batch enrichment complete: {success_count}/{len(contexts)} successful "
                f"({success_count / len(contexts) * 100:.0f}%)"
            )

            return results

        except Exception as e:
            # Batch processing failed - fall back to per-endpoint
            self._log_error("Batch enrichment failed, falling back to per-endpoint", e)
            self.logger.info(f"Processing {len(contexts)} endpoints individually...")

            # Fallback: enrich one-by-one
            results = []
            for ctx in contexts:
                result = await self.enrich(ctx)
                results.append(result)

            return results

    def _build_batch_system_prompt(self) -> str:
        """Build system prompt for batch enrichment."""
        return """You are an expert OpenAPI 3.0 specification generator with deep knowledge of API design patterns.

Your task is to analyze MULTIPLE API endpoints and generate OpenAPI operation objects for ALL of them.

CRITICAL REQUIREMENTS:
1. Return ONLY valid JSON (no markdown code fences, no explanations)
2. Follow OpenAPI 3.0 specification exactly
3. Process ALL endpoints provided (do not skip any)
4. Return a JSON object where keys are endpoint IDs (METHOD /route)
5. Be thorough - extract ALL parameters from the code for each endpoint
6. Infer realistic data types from variable names, type hints, and context
7. Generate practical examples for request/response bodies
8. Identify security requirements from decorators/attributes/middleware

OUTPUT FORMAT (strict JSON):
{
  "GET /api/users": {
    "parameters": [...],
    "responses": {...},
    "security": [...],
    "description": "...",
    "summary": "..."
  },
  "POST /api/users": {
    "requestBody": {...},
    "responses": {...},
    "security": [...],
    "description": "...",
    "summary": "..."
  },
  "GET /api/users/:id": {
    "parameters": [...],
    "responses": {...},
    "description": "...",
    "summary": "..."
  }
}

IMPORTANT: Process ALL endpoints. Return operations for every endpoint provided."""

    def _build_batch_user_prompt(self, contexts: List[EnrichmentContext]) -> str:
        """Build user prompt for batch enrichment."""
        prompt = f"""Analyze these {len(contexts)} API endpoints and generate OpenAPI operation objects for ALL of them.

ENDPOINTS TO PROCESS:
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
{(ctx.surrounding_code or ctx.function_body or ep.raw_match)[:800]}
```
"""

        prompt += f"""
{'=' * 60}

ANALYSIS CHECKLIST FOR EACH ENDPOINT:
1. Extract ALL parameters (path, query, header, cookie) with types and constraints
2. Determine request body schema if POST/PUT/PATCH - identify all fields
3. Infer response schemas for success (200/201/204) and error cases (400/401/404/500)
4. Identify authentication/authorization decorators or middleware
5. Extract validation rules (required, min/max length, patterns, enums)
6. Generate realistic examples per request/response
7. Write clear, concise descriptions

IMPORTANT:
- Process ALL {len(contexts)} endpoints
- Return JSON object with keys: {', '.join(f'"{c.endpoint.method} {c.endpoint.route}"' for c in contexts[:3])}{"..." if len(contexts) > 3 else ""}
- NO markdown formatting, NO explanations, ONLY JSON"""

        return prompt

    def _parse_batch_json_response(
        self,
        response: str,
        contexts: List[EnrichmentContext]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Parse batch JSON response.

        Expected format:
        {
          "GET /api/users": { operation object },
          "POST /api/users": { operation object }
        }

        Args:
            response: Raw LLM response
            contexts: Original contexts (for validation)

        Returns:
            Dictionary mapping endpoint_id to operation object

        Raises:
            json.JSONDecodeError: If response is not valid JSON
        """
        # Parse JSON using robust parser
        batch_data = RobustJSONParser.parse(response, context="batch operation objects")

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
