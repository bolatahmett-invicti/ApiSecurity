#!/usr/bin/env python3
"""
Dependency Graph Agent
======================
Analyzes API endpoint dependencies and data flow.

This agent examines all endpoints to understand:
- Which endpoints depend on others (e.g., POST /users before GET /users/{id})
- Data flow between endpoints (e.g., user_id from POST used in GET)
- Optimal test execution sequences
- CRUD operation relationships

Input: All endpoints + code context
Output: Dependency graph + test sequences
"""

import json
import re
from typing import Dict, Any, List, Set, Tuple
from .base_agent import BaseAgent, EnrichmentContext, EnrichmentResult, AgentStatus


class DependencyGraphAgent(BaseAgent):
    """
    Agent that analyzes endpoint dependencies and generates test sequences.

    Analyzes:
    - **Data dependencies**: Endpoints that produce data used by other endpoints
    - **CRUD relationships**: Create → Read → Update → Delete sequences
    - **Authentication flow**: Login/token endpoints before protected endpoints
    - **Hierarchical resources**: Parent resources before child resources

    Outputs:
    - Dependency graph (adjacency list)
    - Optimal test execution sequences
    - Resource groupings (CRUD sets)

    Usage:
        agent = DependencyGraphAgent(anthropic_api_key="sk-ant-...")
        contexts = [EnrichmentContext(endpoint=ep, ...) for ep in endpoints]
        result = await agent.analyze_dependencies(contexts)
    """

    @property
    def agent_name(self) -> str:
        return "dependency_graph"

    def _build_system_prompt(self) -> str:
        return """You are an expert API architect and security tester specializing in API dependency analysis.

Your task is to analyze a complete API surface to understand endpoint dependencies and data flow.

CRITICAL REQUIREMENTS:
1. Return ONLY valid JSON (no markdown code fences, no explanations)
2. Identify all dependency relationships between endpoints
3. Generate optimal test execution sequences
4. Group related endpoints (CRUD operations on same resource)
5. Identify prerequisite endpoints (auth, resource creation)
6. Build a dependency graph for Invicti test orchestration

DEPENDENCY TYPES:

**1. DATA DEPENDENCIES**:
- Endpoint A produces data that endpoint B consumes
- Example: POST /users → returns user_id → GET /users/{user_id}
- Example: POST /auth/login → returns token → GET /profile (needs token)

**2. CRUD RELATIONSHIPS**:
- Create → Read → Update → Delete sequences on same resource
- Example: POST /articles → GET /articles/{id} → PUT /articles/{id} → DELETE /articles/{id}
- Group by resource type (users, articles, orders, etc.)

**3. AUTHENTICATION FLOW**:
- Auth endpoints must execute before protected endpoints
- Example: POST /login → (get token) → GET /protected/*

**4. HIERARCHICAL RESOURCES**:
- Parent resources before child resources
- Example: POST /users → POST /users/{user_id}/posts → GET /users/{user_id}/posts/{post_id}

**5. STATE DEPENDENCIES**:
- Endpoints that modify state needed by other endpoints
- Example: POST /cart/items → PUT /cart/checkout
- Example: POST /orders → GET /orders/{id}/status

OUTPUT FORMAT (strict JSON):
{
  "resources": [
    {
      "name": "users",
      "base_path": "/api/users",
      "endpoints": [
        {"method": "POST", "path": "/api/users", "operation": "create"},
        {"method": "GET", "path": "/api/users", "operation": "list"},
        {"method": "GET", "path": "/api/users/{id}", "operation": "read"},
        {"method": "PUT", "path": "/api/users/{id}", "operation": "update"},
        {"method": "DELETE", "path": "/api/users/{id}", "operation": "delete"}
      ],
      "crud_complete": true
    }
  ],
  "dependencies": [
    {
      "from": {"method": "POST", "path": "/api/users"},
      "to": {"method": "GET", "path": "/api/users/{id}"},
      "type": "data_dependency",
      "description": "POST creates user and returns ID for GET",
      "data_flow": {
        "produces": ["user_id"],
        "consumes": ["user_id"]
      }
    },
    {
      "from": {"method": "POST", "path": "/api/auth/login"},
      "to": {"method": "GET", "path": "/api/profile"},
      "type": "authentication",
      "description": "Login provides token for protected endpoint",
      "data_flow": {
        "produces": ["access_token"],
        "consumes": ["access_token"]
      }
    }
  ],
  "test_sequences": [
    {
      "sequence_id": 1,
      "name": "User CRUD workflow",
      "description": "Complete user lifecycle testing",
      "steps": [
        {
          "step": 1,
          "method": "POST",
          "path": "/api/auth/login",
          "description": "Authenticate to get token",
          "extract": {
            "access_token": "$.access_token"
          }
        },
        {
          "step": 2,
          "method": "POST",
          "path": "/api/users",
          "description": "Create new user",
          "requires": ["access_token"],
          "extract": {
            "user_id": "$.id"
          }
        },
        {
          "step": 3,
          "method": "GET",
          "path": "/api/users/{user_id}",
          "description": "Retrieve created user",
          "requires": ["access_token", "user_id"],
          "path_params": {
            "user_id": "{user_id}"
          }
        },
        {
          "step": 4,
          "method": "PUT",
          "path": "/api/users/{user_id}",
          "description": "Update user data",
          "requires": ["access_token", "user_id"]
        },
        {
          "step": 5,
          "method": "DELETE",
          "path": "/api/users/{user_id}",
          "description": "Delete user",
          "requires": ["access_token", "user_id"]
        }
      ]
    }
  ],
  "prerequisite_endpoints": [
    {
      "method": "POST",
      "path": "/api/auth/login",
      "reason": "Required for authentication before testing protected endpoints",
      "priority": 1
    }
  ],
  "dependency_graph": {
    "nodes": [
      {"id": "POST /api/auth/login", "type": "auth"},
      {"id": "POST /api/users", "type": "create"},
      {"id": "GET /api/users/{id}", "type": "read"}
    ],
    "edges": [
      {"from": "POST /api/auth/login", "to": "POST /api/users", "type": "auth"},
      {"from": "POST /api/users", "to": "GET /api/users/{id}", "type": "data"}
    ]
  },
  "summary": "Analyzed 15 endpoints, found 5 resources, 8 dependencies, generated 3 test sequences"
}

Be thorough in your analysis. Identify all meaningful dependencies."""

    def _build_user_prompt(self, contexts: List[EnrichmentContext]) -> str:
        """
        Build prompt for dependency analysis across all endpoints.

        Args:
            contexts: List of EnrichmentContext for all endpoints

        Returns:
            User prompt with endpoint summary
        """
        # Summarize endpoints by resource
        endpoint_summary = []
        resource_groups = self._group_endpoints_by_resource(contexts)

        prompt = f"""Analyze these API endpoints to identify dependencies and data flow.

TOTAL ENDPOINTS: {len(contexts)}

ENDPOINT LIST:
"""

        # List all endpoints
        for ctx in contexts:
            ep = ctx.endpoint
            endpoint_summary.append(f"- {ep.method} {ep.route}")

        prompt += "\n".join(endpoint_summary[:100])  # Limit to 100 endpoints

        # Add resource grouping hint
        if resource_groups:
            prompt += f"""

DETECTED RESOURCE PATTERNS:
"""
            for resource, endpoints in list(resource_groups.items())[:20]:
                prompt += f"\n- Resource: {resource} ({len(endpoints)} endpoints)"
                for ep in endpoints[:5]:
                    prompt += f"\n  - {ep}"

        # Add code samples for key endpoints
        auth_endpoints = [ctx for ctx in contexts if self._looks_like_auth_endpoint(ctx.endpoint.route)]
        if auth_endpoints:
            prompt += f"""

AUTHENTICATION ENDPOINTS DETECTED:
"""
            for ctx in auth_endpoints[:3]:
                ep = ctx.endpoint
                prompt += f"""
- {ep.method} {ep.route}
```
{(ctx.function_body or ctx.surrounding_code or ep.raw_match)[:600]}
```
"""

        prompt += """

ANALYSIS TASKS:
1. Identify all resources (users, articles, orders, etc.) and their CRUD endpoints
2. Find data dependencies (endpoint A produces data for endpoint B)
3. Detect authentication flow (which endpoints need auth)
4. Identify hierarchical relationships (parent/child resources)
5. Build dependency graph showing relationships
6. Generate test sequences in optimal execution order
7. List prerequisite endpoints that must execute first

IMPORTANT: Return ONLY the JSON object, no markdown formatting, no explanations."""

        return prompt

    async def analyze_dependencies(self, contexts: List[EnrichmentContext]) -> EnrichmentResult:
        """
        Analyze dependencies across all endpoints (global analysis).

        Args:
            contexts: List of EnrichmentContext for all endpoints

        Returns:
            EnrichmentResult with dependency graph and test sequences
        """
        try:
            # Build prompts
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_user_prompt(contexts)

            # Call Claude
            self.logger.info(f"Analyzing dependencies across {len(contexts)} endpoints")
            response = await self._call_claude(system_prompt, user_prompt)

            # Parse JSON response
            dependency_data = self._parse_json_response(response)

            # Validate structure
            self._validate_dependency_data(dependency_data)

            return EnrichmentResult(
                status=AgentStatus.SUCCESS,
                data={"dependencies": dependency_data},
                metadata={
                    "model": self.model,
                    "total_endpoints": len(contexts),
                    "resources_found": len(dependency_data.get("resources", [])),
                    "dependencies_found": len(dependency_data.get("dependencies", [])),
                    "test_sequences": len(dependency_data.get("test_sequences", [])),
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
            self.logger.error(f"Dependency analysis failed: {e}", exc_info=True)
            return EnrichmentResult(
                status=AgentStatus.FAILED,
                errors=[str(e)]
            )

    async def enrich(self, context: EnrichmentContext) -> EnrichmentResult:
        """
        Single endpoint enrichment (not used for this agent).

        This agent operates globally on all endpoints.
        Use analyze_dependencies() instead.

        Args:
            context: EnrichmentContext (ignored)

        Returns:
            SKIPPED result
        """
        return EnrichmentResult(
            status=AgentStatus.SKIPPED,
            data={"reason": "DependencyGraphAgent operates globally, use analyze_dependencies()"}
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

    def _validate_dependency_data(self, data: Dict[str, Any]) -> None:
        """
        Validate dependency data structure.

        Args:
            data: Dependency data to validate

        Raises:
            ValueError: If data structure is invalid
        """
        if not isinstance(data, dict):
            raise ValueError("Dependency data must be a dictionary")

        # Should have at least one of these keys
        required_keys = ["resources", "dependencies", "test_sequences"]
        if not any(key in data for key in required_keys):
            self.logger.warning("Missing expected keys, adding defaults")
            data["resources"] = []
            data["dependencies"] = []
            data["test_sequences"] = []

        # Validate lists
        for key in required_keys:
            if key in data and not isinstance(data[key], list):
                raise ValueError(f"'{key}' must be a list")

        # Add summary if missing
        if "summary" not in data:
            data["summary"] = (
                f"Analyzed endpoints: {len(data.get('resources', []))} resources, "
                f"{len(data.get('dependencies', []))} dependencies"
            )

        self.logger.debug("Dependency data validated successfully")

    def _group_endpoints_by_resource(self, contexts: List[EnrichmentContext]) -> Dict[str, List[str]]:
        """
        Group endpoints by resource name (heuristic).

        Args:
            contexts: List of endpoint contexts

        Returns:
            Dictionary mapping resource names to endpoint paths
        """
        resources: Dict[str, List[str]] = {}

        for ctx in contexts:
            route = ctx.endpoint.route
            method = ctx.endpoint.method

            # Extract resource from route (e.g., /api/users/{id} → users)
            parts = route.strip('/').split('/')
            if len(parts) >= 2:
                # Try to find the resource (usually first non-api part)
                for part in parts:
                    if part.lower() not in ['api', 'v1', 'v2', 'v3'] and '{' not in part:
                        resource = part.lower()
                        if resource not in resources:
                            resources[resource] = []
                        resources[resource].append(f"{method} {route}")
                        break

        return resources

    @staticmethod
    def _looks_like_auth_endpoint(route: str) -> bool:
        """
        Check if route looks like an authentication endpoint.

        Args:
            route: Route path

        Returns:
            True if route appears to be auth-related
        """
        auth_patterns = [
            'auth', 'login', 'logout', 'token', 'oauth',
            'signin', 'signout', 'register', 'signup'
        ]
        route_lower = route.lower()
        return any(pattern in route_lower for pattern in auth_patterns)
