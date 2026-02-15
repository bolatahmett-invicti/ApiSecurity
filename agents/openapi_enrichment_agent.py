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
from typing import Dict, Any
from .base_agent import BaseAgent, EnrichmentContext, EnrichmentResult, AgentStatus


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
            self.logger.error(f"Failed to parse Claude response as JSON: {e}")
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[f"Invalid JSON response: {str(e)}"],
                data={"raw_response": response[:500] if 'response' in locals() else None}
            )

        except Exception as e:
            self._log_error("Enrichment failed", e)
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[str(e)]
            )

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """
        Parse JSON from Claude response, handling markdown code blocks.

        Args:
            response: Raw response from Claude

        Returns:
            Parsed JSON object

        Raises:
            json.JSONDecodeError: If response is not valid JSON
        """
        # Try to extract JSON from markdown code block
        json_match = re.search(r'```(?:json)?\n?(.*?)\n?```', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_str = response.strip()

        # Parse JSON
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # Try cleaning up common issues
            json_str = json_str.strip()
            # Remove leading/trailing text
            if '{' in json_str:
                json_str = json_str[json_str.find('{'):]
            if '}' in json_str:
                json_str = json_str[:json_str.rfind('}') + 1]
            return json.loads(json_str)

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
            if not isinstance(operation["parameters"], list):
                raise ValueError("'parameters' must be a list")

            for i, param in enumerate(operation["parameters"]):
                if "name" not in param:
                    raise ValueError(f"Parameter {i} missing 'name'")
                if "in" not in param:
                    raise ValueError(f"Parameter {i} missing 'in' (path/query/header/cookie)")
                if param["in"] not in ["path", "query", "header", "cookie"]:
                    raise ValueError(f"Parameter 'in' must be path/query/header/cookie, got: {param['in']}")

        # Validate requestBody if present
        if "requestBody" in operation:
            if not isinstance(operation["requestBody"], dict):
                raise ValueError("'requestBody' must be a dictionary")
            if "content" not in operation["requestBody"]:
                raise ValueError("'requestBody' must have 'content'")

        # Validate responses
        if not isinstance(operation["responses"], dict):
            raise ValueError("'responses' must be a dictionary")

        # Add summary if missing
        if "summary" not in operation:
            operation["summary"] = f"API endpoint operation"

        self.logger.debug(f"Operation object validated successfully")
