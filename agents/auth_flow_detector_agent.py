#!/usr/bin/env python3
"""
Auth Flow Detector Agent
========================
Detects authentication and authorization mechanisms across API surfaces.

This agent analyzes all endpoints to identify:
- Authentication schemes (JWT, OAuth2, API Key, Basic Auth, Session)
- Auth endpoints (/login, /token, /oauth)
- Authorization patterns (roles, permissions, scopes)
- Security requirements per endpoint

Input: All endpoints + code context
Output: Invicti-compatible auth configuration + per-endpoint security info
"""

import json
import re
from typing import Dict, Any, List, Optional
from .base_agent import BaseAgent, EnrichmentContext, EnrichmentResult, AgentStatus


class AuthFlowDetectorAgent(BaseAgent):
    """
    Agent that detects authentication flows and generates auth configurations.

    Analyzes endpoints to identify:
    - Auth mechanism types (JWT, OAuth2, API Key, Session, Basic)
    - Auth endpoints (login, token refresh, logout)
    - Authorization requirements (roles, permissions)
    - Security schemes for OpenAPI spec
    - Invicti test configuration

    Usage:
        agent = AuthFlowDetectorAgent(anthropic_api_key="sk-ant-...")
        # Analyze all endpoints together for global auth detection
        contexts = [EnrichmentContext(endpoint=ep, ...) for ep in endpoints]
        result = await agent.detect_auth_flows(contexts)
    """

    @property
    def agent_name(self) -> str:
        return "auth_flow_detector"

    def _build_system_prompt(self) -> str:
        return """You are an expert security analyst specializing in API authentication and authorization patterns.

Your task is to analyze API endpoints and their source code to detect authentication mechanisms.

CRITICAL REQUIREMENTS:
1. Return ONLY valid JSON (no markdown code fences, no explanations)
2. Identify ALL authentication mechanisms used in the API
3. Detect auth endpoints (login, token, oauth, etc.)
4. Identify authorization patterns (roles, permissions, decorators)
5. Generate OpenAPI security schemes
6. Provide Invicti-compatible test configuration

AUTHENTICATION MECHANISMS TO DETECT:
- **JWT (JSON Web Token)**: Look for "jwt", "bearer", token generation/validation
- **OAuth2**: Look for oauth endpoints, authorization code flow, client credentials
- **API Key**: Look for "api_key", "x-api-key", key validation in headers/query
- **Session**: Look for session cookies, session middleware, flask.session
- **Basic Auth**: Look for "basic auth", HTTP basic authentication
- **Custom**: Any custom authentication schemes

AUTHORIZATION PATTERNS:
- Role-based (RBAC): @roles, @require_role, check_role
- Permission-based: @permission, has_permission, check_permission
- Scope-based (OAuth): scopes in decorators/middleware
- Policy-based: @policy, authorize decorators

OUTPUT FORMAT (strict JSON):
{
  "auth_mechanisms": [
    {
      "type": "jwt",
      "confidence": 0.95,
      "evidence": ["@jwt_required decorator", "JWT token in Authorization header"],
      "scheme_name": "bearerAuth",
      "openapi_scheme": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      },
      "invicti_config": {
        "type": "bearer_token",
        "header_name": "Authorization",
        "token_prefix": "Bearer",
        "token_endpoint": "/api/auth/login",
        "token_field": "access_token"
      }
    }
  ],
  "auth_endpoints": [
    {
      "endpoint": "/api/auth/login",
      "method": "POST",
      "purpose": "authentication",
      "request_fields": ["username", "password"],
      "response_fields": ["access_token", "refresh_token", "expires_in"]
    },
    {
      "endpoint": "/api/auth/token/refresh",
      "method": "POST",
      "purpose": "token_refresh",
      "request_fields": ["refresh_token"],
      "response_fields": ["access_token"]
    }
  ],
  "endpoint_security": {
    "/api/users": {
      "required": true,
      "mechanisms": ["bearerAuth"],
      "authorization": {
        "type": "role",
        "required_roles": ["admin", "user"]
      }
    },
    "/api/admin/*": {
      "required": true,
      "mechanisms": ["bearerAuth"],
      "authorization": {
        "type": "role",
        "required_roles": ["admin"]
      }
    },
    "/api/public/*": {
      "required": false
    }
  },
  "test_sequence": [
    {
      "step": 1,
      "description": "Obtain access token",
      "endpoint": "/api/auth/login",
      "method": "POST",
      "body": {"username": "test_user", "password": "test_password"},
      "extract": {"access_token": "$.access_token"}
    },
    {
      "step": 2,
      "description": "Use token for protected endpoints",
      "header": "Authorization: Bearer {access_token}"
    }
  ],
  "summary": "API uses JWT bearer token authentication with role-based authorization"
}

Be thorough in your analysis. If you cannot determine something, indicate low confidence."""

    def _build_user_prompt_global(self, contexts: List[EnrichmentContext]) -> str:
        """
        Build prompt for global auth detection across all endpoints.

        Args:
            contexts: List of EnrichmentContext for all endpoints

        Returns:
            User prompt with endpoint summary
        """
        # Summarize endpoints
        endpoint_summary = []
        auth_related_code = []

        for ctx in contexts[:50]:  # Limit to 50 endpoints to prevent token overflow
            ep = ctx.endpoint
            endpoint_summary.append(f"- {ep.method} {ep.route} ({ep.file_path}:{ep.line_number})")

            # Extract auth-related code snippets
            if ctx.function_body and self._looks_like_auth_code(ctx.function_body):
                auth_related_code.append({
                    "endpoint": f"{ep.method} {ep.route}",
                    "code": ctx.function_body[:800]  # Limit code size
                })

        prompt = f"""Analyze these API endpoints to detect authentication and authorization mechanisms.

TOTAL ENDPOINTS: {len(contexts)}

ENDPOINT SUMMARY (first 50):
{"".join(endpoint_summary[:50])}

"""

        if auth_related_code:
            prompt += f"""
AUTH-RELATED CODE SAMPLES:
"""
            for i, sample in enumerate(auth_related_code[:10], 1):  # Limit to 10 samples
                prompt += f"""
Sample {i} - {sample['endpoint']}:
```
{sample['code']}
```
"""

        prompt += """

ANALYSIS CHECKLIST:
1. Identify all authentication mechanisms (JWT, OAuth2, API Key, Session, Basic)
2. Find auth endpoints (/login, /token, /oauth, /refresh)
3. Detect authorization patterns (roles, permissions, scopes)
4. Determine which endpoints require authentication
5. Generate OpenAPI security schemes
6. Create Invicti test configuration with sample credentials
7. Provide test sequence for authentication flow

IMPORTANT: Return ONLY the JSON object, no markdown formatting, no explanations."""

        return prompt

    def _build_user_prompt_single(self, context: EnrichmentContext) -> str:
        """
        Build prompt for single endpoint security analysis.

        Args:
            context: EnrichmentContext for one endpoint

        Returns:
            User prompt for endpoint-specific security
        """
        ep = context.endpoint

        prompt = f"""Analyze this specific endpoint's authentication and authorization requirements.

ENDPOINT INFORMATION:
- Route: {ep.route}
- HTTP Method: {ep.method}
- Framework: {context.framework}
- Language: {context.language}
- File: {ep.file_path}:{ep.line_number}

SOURCE CODE:
```
{context.surrounding_code or context.function_body or ep.raw_match}
```

ANALYSIS:
1. Does this endpoint require authentication? (yes/no/unknown)
2. What authentication mechanisms are required?
3. What authorization checks are performed? (roles, permissions, scopes)
4. Are there any security decorators or middleware?

OUTPUT (JSON only):
{{
  "requires_auth": true/false,
  "auth_mechanisms": ["bearerAuth"],
  "authorization": {{
    "type": "role",
    "required_roles": ["admin"]
  }},
  "confidence": 0.9
}}"""

        return prompt

    async def detect_auth_flows(self, contexts: List[EnrichmentContext]) -> EnrichmentResult:
        """
        Detect authentication flows across all endpoints (global analysis).

        Args:
            contexts: List of EnrichmentContext for all endpoints

        Returns:
            EnrichmentResult with auth configuration
        """
        try:
            # Build prompts
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_user_prompt_global(contexts)

            # Call Claude
            self.logger.info(f"Analyzing authentication flows across {len(contexts)} endpoints")
            response = await self._call_claude(system_prompt, user_prompt)

            # Parse JSON response
            auth_config = self._parse_json_response(response)

            # Validate auth config structure
            self._validate_auth_config(auth_config)

            return EnrichmentResult(
                status=AgentStatus.SUCCESS,
                data={"auth_config": auth_config},
                metadata={
                    "model": self.model,
                    "total_endpoints": len(contexts),
                    "auth_mechanisms_found": len(auth_config.get("auth_mechanisms", [])),
                    "auth_endpoints_found": len(auth_config.get("auth_endpoints", [])),
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
            self._log_error("Auth detection failed", e)
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[str(e)]
            )

    async def enrich(self, context: EnrichmentContext) -> EnrichmentResult:
        """
        Analyze single endpoint's security requirements.

        Args:
            context: EnrichmentContext with endpoint and code

        Returns:
            EnrichmentResult with endpoint security info
        """
        try:
            # Build prompts
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_user_prompt_single(context)

            # Call Claude
            self.logger.info(f"Analyzing security for {context.endpoint.method} {context.endpoint.route}")
            response = await self._call_claude(system_prompt, user_prompt)

            # Parse JSON response
            security_info = self._parse_json_response(response)

            return EnrichmentResult(
                status=AgentStatus.SUCCESS,
                data={"security": security_info},
                metadata={
                    "model": self.model,
                    "endpoint": f"{context.endpoint.method} {context.endpoint.route}",
                }
            )

        except Exception as e:
            self._log_error("Security analysis failed", e)
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

    def _validate_auth_config(self, config: Dict[str, Any]) -> None:
        """
        Validate auth configuration structure.

        Args:
            config: Auth configuration to validate

        Raises:
            ValueError: If config is invalid
        """
        if not isinstance(config, dict):
            raise ValueError("Auth config must be a dictionary")

        # Should have at least auth_mechanisms or endpoint_security
        if "auth_mechanisms" not in config and "endpoint_security" not in config:
            self.logger.warning("No auth mechanisms or endpoint security detected")
            config["auth_mechanisms"] = []
            config["endpoint_security"] = {}

        # Validate auth_mechanisms if present
        if "auth_mechanisms" in config:
            if not isinstance(config["auth_mechanisms"], list):
                raise ValueError("'auth_mechanisms' must be a list")

            for i, mechanism in enumerate(config["auth_mechanisms"]):
                if "type" not in mechanism:
                    raise ValueError(f"Auth mechanism {i} missing 'type'")
                if "openapi_scheme" not in mechanism:
                    self.logger.warning(f"Auth mechanism {i} missing OpenAPI scheme")

        # Add summary if missing
        if "summary" not in config:
            config["summary"] = f"Detected {len(config.get('auth_mechanisms', []))} authentication mechanism(s)"

        self.logger.debug("Auth config validated successfully")

    @staticmethod
    def _looks_like_auth_code(code: str) -> bool:
        """
        Quick heuristic to check if code contains auth-related patterns.

        Args:
            code: Source code snippet

        Returns:
            True if code looks auth-related
        """
        auth_keywords = [
            "auth", "login", "token", "jwt", "oauth", "bearer",
            "permission", "role", "authorize", "authenticate",
            "session", "api_key", "credential", "password"
        ]

        code_lower = code.lower()
        return any(keyword in code_lower for keyword in auth_keywords)
