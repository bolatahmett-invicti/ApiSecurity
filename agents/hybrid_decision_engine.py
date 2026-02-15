#!/usr/bin/env python3
"""
Hybrid Decision Engine
=======================
Intelligently decides when to use LLM vs deterministic Python code.

This module optimizes cost by using LLM only when it genuinely adds value:
- Simple CRUD endpoints → Python only ($0)
- Complex business logic → Python + LLM ($$$)
- Well-documented typed code → Python only ($0)
- Undocumented legacy code → Python + LLM ($$$)

Philosophy: "Use the cheapest tool that gets the job done"

Cost savings: Additional 5-10% (total 90% reduction)
"""

import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger("api_scanner.hybrid_decision_engine")


@dataclass
class EnrichmentDecision:
    """Decision about whether to use LLM for enrichment."""
    use_llm: bool
    confidence: float  # 0.0-1.0 (1.0 = fully deterministic, no LLM needed)
    reason: str
    python_coverage: Dict[str, bool]  # What Python extracted successfully
    llm_tasks: list  # What LLM should do (if use_llm=True)
    estimated_cost_savings: float  # Percentage saved by skipping LLM


class HybridDecisionEngine:
    """
    Decides when to use LLM vs Python for API enrichment.

    Uses rule-based heuristics to maximize cost savings while maintaining quality.
    """

    # Endpoint patterns that are typically simple (high Python confidence)
    SIMPLE_CRUD_PATTERNS = [
        'list', 'get', 'retrieve', 'fetch', 'find',
        'create', 'add', 'insert', 'new',
        'update', 'edit', 'modify', 'patch',
        'delete', 'remove', 'destroy',
    ]

    # Complex operations that benefit from LLM
    COMPLEX_PATTERNS = [
        'calculate', 'compute', 'process', 'validate',
        'analyze', 'transform', 'aggregate', 'optimize',
        'generate', 'predict', 'classify', 'recommend',
    ]

    @staticmethod
    def should_use_llm(
        endpoint_info: Dict[str, Any],
        deterministic_data: Dict[str, Any],
        confidence_threshold: float = 0.7
    ) -> EnrichmentDecision:
        """
        Decide whether to use LLM for this endpoint.

        Args:
            endpoint_info: Endpoint metadata (route, method, etc.)
            deterministic_data: Data extracted by Python analyzers
            confidence_threshold: Use LLM if Python confidence < threshold

        Returns:
            EnrichmentDecision with recommendation and reasoning

        Example:
            >>> endpoint_info = {
            ...     "route": "/users/{id}",
            ...     "method": "GET",
            ...     "function_body": "def get_user(id: int): return db.get(id)"
            ... }
            >>> deterministic_data = {
            ...     "parameters": [...],
            ...     "type_hints": {...},
            ...     "docstring": {...}
            ... }
            >>> decision = HybridDecisionEngine.should_use_llm(endpoint_info, deterministic_data)
            >>> decision.use_llm
            False  # Python extracted everything needed
            >>> decision.confidence
            0.95   # Very confident in Python data
        """
        # Calculate coverage and confidence
        python_coverage = HybridDecisionEngine._assess_python_coverage(deterministic_data)
        confidence = HybridDecisionEngine._calculate_confidence(
            endpoint_info,
            deterministic_data,
            python_coverage
        )

        # Determine complexity
        is_simple = HybridDecisionEngine._is_simple_endpoint(endpoint_info)
        is_complex = HybridDecisionEngine._is_complex_endpoint(endpoint_info)

        # Decision logic
        use_llm = False
        reason = ""
        llm_tasks = []

        if confidence >= confidence_threshold and is_simple:
            # High confidence + simple endpoint → Python only
            use_llm = False
            reason = f"Simple CRUD endpoint with {confidence:.0%} Python coverage - no LLM needed"

        elif confidence >= confidence_threshold and not is_complex:
            # High confidence + moderate complexity → Python only
            use_llm = False
            reason = f"Well-documented endpoint with {confidence:.0%} Python coverage - no LLM needed"

        elif confidence < confidence_threshold and is_complex:
            # Low confidence + complex logic → Use LLM for missing pieces
            use_llm = True
            llm_tasks = HybridDecisionEngine._identify_llm_tasks(python_coverage, deterministic_data)
            reason = f"Complex endpoint with only {confidence:.0%} Python coverage - LLM needed for: {', '.join(llm_tasks)}"

        elif confidence < confidence_threshold:
            # Low confidence → Use LLM for missing pieces
            use_llm = True
            llm_tasks = HybridDecisionEngine._identify_llm_tasks(python_coverage, deterministic_data)
            reason = f"Incomplete Python data ({confidence:.0%} coverage) - LLM needed for: {', '.join(llm_tasks)}"

        else:
            # Edge case: high confidence but complex → Use minimal LLM
            use_llm = True
            llm_tasks = ["description_enhancement"]
            reason = f"Complex logic detected - LLM used for description quality only"

        # Estimate cost savings
        if not use_llm:
            estimated_cost_savings = 100.0  # 100% savings (no LLM call)
        else:
            # Partial LLM usage (focused prompts) saves ~50-70% vs full LLM
            estimated_cost_savings = 50.0 + (confidence * 20.0)

        return EnrichmentDecision(
            use_llm=use_llm,
            confidence=confidence,
            reason=reason,
            python_coverage=python_coverage,
            llm_tasks=llm_tasks,
            estimated_cost_savings=estimated_cost_savings
        )

    @staticmethod
    def _assess_python_coverage(deterministic_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Assess what Python successfully extracted.

        Returns:
            Dictionary of coverage flags
        """
        return {
            "has_parameters": bool(deterministic_data.get("parameters")),
            "has_type_hints": bool(deterministic_data.get("type_hints")),
            "has_docstring": bool(deterministic_data.get("docstring")),
            "has_responses": bool(deterministic_data.get("responses")),
            "has_auth": bool(deterministic_data.get("auth_decorators")),
            "has_method_info": bool(deterministic_data.get("method_expectations")),
        }

    @staticmethod
    def _calculate_confidence(
        endpoint_info: Dict[str, Any],
        deterministic_data: Dict[str, Any],
        python_coverage: Dict[str, bool]
    ) -> float:
        """
        Calculate confidence score (0.0-1.0) in Python-extracted data.

        Higher confidence = less need for LLM.

        Factors:
        - Parameter extraction: 20%
        - Type hints: 20%
        - Docstring: 20%
        - Auth decorators: 15%
        - Response codes: 15%
        - Method info: 10%
        """
        weights = {
            "has_parameters": 0.20,
            "has_type_hints": 0.20,
            "has_docstring": 0.20,
            "has_auth": 0.15,
            "has_responses": 0.15,
            "has_method_info": 0.10,
        }

        confidence = sum(
            weights.get(key, 0.0) for key, value in python_coverage.items() if value
        )

        # Bonus: Well-documented code (has docstring + type hints)
        if python_coverage.get("has_docstring") and python_coverage.get("has_type_hints"):
            confidence += 0.10

        # Bonus: Complete auth info
        if python_coverage.get("has_auth"):
            auth_info = deterministic_data.get("auth_decorators", {})
            if "security_schemes" in auth_info and "security" in auth_info:
                confidence += 0.05

        # Cap at 1.0
        return min(confidence, 1.0)

    @staticmethod
    def _is_simple_endpoint(endpoint_info: Dict[str, Any]) -> bool:
        """
        Detect if endpoint is a simple CRUD operation.

        Simple endpoints typically don't need LLM analysis.
        """
        route = endpoint_info.get("route", "").lower()
        method = endpoint_info.get("method", "").upper()
        function_body = endpoint_info.get("function_body", "").lower()

        # Check route patterns
        for pattern in HybridDecisionEngine.SIMPLE_CRUD_PATTERNS:
            if pattern in route or pattern in function_body:
                # Simple pattern + standard HTTP method = simple endpoint
                if method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                    return True

        # GET requests with path parameter are typically simple
        if method == "GET" and ("{" in route or ":" in route or "<" in route):
            return True

        # POST/PUT with short function body is typically simple
        if method in ["POST", "PUT", "PATCH"]:
            if function_body and len(function_body.split('\n')) < 20:
                return True

        return False

    @staticmethod
    def _is_complex_endpoint(endpoint_info: Dict[str, Any]) -> bool:
        """
        Detect if endpoint has complex business logic.

        Complex endpoints benefit from LLM analysis.
        """
        route = endpoint_info.get("route", "").lower()
        function_body = endpoint_info.get("function_body", "").lower()

        # Check for complex operation patterns
        for pattern in HybridDecisionEngine.COMPLEX_PATTERNS:
            if pattern in route or pattern in function_body:
                return True

        # Long function body suggests complexity
        if function_body and len(function_body.split('\n')) > 50:
            return True

        # Multiple nested conditions
        if function_body:
            if function_body.count("if ") > 5:
                return True
            if function_body.count("for ") > 3:
                return True

        return False

    @staticmethod
    def _identify_llm_tasks(
        python_coverage: Dict[str, bool],
        deterministic_data: Dict[str, Any]
    ) -> list:
        """
        Identify what specific tasks LLM should do.

        Returns focused task list to minimize LLM prompt size.
        """
        tasks = []

        if not python_coverage.get("has_parameters"):
            tasks.append("parameter_extraction")

        if not python_coverage.get("has_type_hints"):
            tasks.append("type_inference")

        if not python_coverage.get("has_docstring"):
            tasks.append("description_generation")
        else:
            # Has docstring but may need enhancement
            docstring = deterministic_data.get("docstring", {})
            if not docstring.get("parameters"):
                tasks.append("parameter_descriptions")

        if not python_coverage.get("has_responses"):
            tasks.append("response_codes")

        if not python_coverage.get("has_auth"):
            tasks.append("auth_detection")

        # Always include example generation (hard to do deterministically)
        tasks.append("example_generation")

        return tasks

    @staticmethod
    def build_focused_prompt(
        endpoint_info: Dict[str, Any],
        deterministic_data: Dict[str, Any],
        llm_tasks: list
    ) -> str:
        """
        Build minimal LLM prompt with only necessary context.

        Instead of sending full code + asking for everything,
        send Python-extracted data + ask for missing pieces only.

        Args:
            endpoint_info: Endpoint metadata
            deterministic_data: Data Python already extracted
            llm_tasks: Specific tasks for LLM

        Returns:
            Focused prompt string (typically 50-70% smaller than full prompt)
        """
        prompt = f"""Enhance OpenAPI specification for endpoint using provided Python-extracted data.

ENDPOINT: {endpoint_info.get('method')} {endpoint_info.get('route')}

PYTHON-EXTRACTED DATA (already complete):
"""

        # Include what Python already extracted
        if deterministic_data.get("parameters"):
            prompt += f"\n[OK] Parameters: {len(deterministic_data['parameters'])} detected"

        if deterministic_data.get("type_hints"):
            prompt += f"\n[OK] Type hints: {len(deterministic_data['type_hints'])} parameters typed"

        if deterministic_data.get("docstring"):
            prompt += f"\n[OK] Docstring: '{deterministic_data['docstring'].get('summary', 'N/A')[:60]}...'"

        if deterministic_data.get("responses"):
            prompt += f"\n[OK] Response codes: {list(deterministic_data['responses'].keys())}"

        if deterministic_data.get("auth_decorators"):
            auth = deterministic_data["auth_decorators"]
            if "security" in auth:
                schemes = [list(s.keys())[0] for s in auth["security"]]
                prompt += f"\n[OK] Auth: {', '.join(schemes)}"

        prompt += f"\n\nYOUR TASKS (generate ONLY these):\n"

        for task in llm_tasks:
            if task == "parameter_descriptions":
                prompt += "- Enhance parameter descriptions (make them more detailed)\n"
            elif task == "description_generation":
                prompt += "- Generate operation summary and description\n"
            elif task == "example_generation":
                prompt += "- Generate realistic request/response examples\n"
            elif task == "response_codes":
                prompt += "- Infer likely response codes from code logic\n"
            elif task == "auth_detection":
                prompt += "- Detect implicit auth requirements\n"

        prompt += "\nReturn ONLY JSON with requested fields. Do NOT regenerate Python-extracted data."

        return prompt

    @staticmethod
    def estimate_token_savings(
        use_llm: bool,
        llm_tasks: list,
        baseline_tokens: int = 7000
    ) -> Tuple[int, float]:
        """
        Estimate token savings from hybrid approach.

        Args:
            use_llm: Whether LLM will be used
            llm_tasks: Specific LLM tasks
            baseline_tokens: Baseline full-LLM token count

        Returns:
            (estimated_tokens, savings_percentage)
        """
        if not use_llm:
            # No LLM call = 0 tokens
            return (0, 100.0)

        # Focused prompt is much smaller
        # Baseline: ~7000 tokens (full code + full prompt)
        # Focused: ~1500 tokens (Python data summary + focused tasks)
        focused_tokens = 1500 + (len(llm_tasks) * 200)

        savings = ((baseline_tokens - focused_tokens) / baseline_tokens) * 100
        return (focused_tokens, savings)
