#!/usr/bin/env python3
"""
Logic-oriented Fuzz Generator
==============================
Generates constraint-violating test payloads from extracted field constraints.

Each payload targets a specific business rule violation:
- Range violations: price=-1 when gt=0 is required
- Enum violations: role="superuser" when only ["admin","user"] allowed
- IDOR candidates: user_id=<OTHER_USER_ID> for ownership bypass
- Missing required: omit a required field from the request body
- Type boundary: float for int-only field, string for numeric field

False positive reduction:
- Every payload carries a `confidence` score (0.0–1.0)
- `fp_risk`: "low" (≥0.7), "medium" (0.4–0.7)
- Payloads below `confidence_threshold` are not emitted
- Context filters auto-skip irrelevant tests

Cost: $0 (fully deterministic, no LLM)
"""

import logging
import string
from typing import Dict, Any, List, Optional

logger = logging.getLogger("api_scanner.logic_fuzz.generator")

# Field names likely to be in a typical POST/PUT request body
# Used to select which fields to combine when generating multi-field payloads
NUMERIC_FIELD_HINTS = {"price", "amount", "cost", "fee", "total", "quantity", "qty", "count",
                       "age", "score", "rating", "weight", "size", "duration", "timeout"}


class LogicFuzzGenerator:
    """
    Generates logic-violating fuzz payloads from constraint data.

    Usage:
        constraints = ConstraintExtractor.extract_from_code(source)
        payloads = LogicFuzzGenerator.generate(
            constraints=constraints,
            endpoint_method="POST",
            confidence_threshold=0.4
        )
    """

    @staticmethod
    def generate(
        constraints: Dict[str, Dict[str, Any]],
        endpoint_method: str = "POST",
        confidence_threshold: float = 0.4,
    ) -> List[Dict[str, Any]]:
        """
        Generate logic-fuzz payloads from constraint data.

        Args:
            constraints: Output of ConstraintExtractor.extract_from_code()
            endpoint_method: HTTP method (GET/POST/PUT/PATCH/DELETE)
            confidence_threshold: Min confidence to emit a payload (default 0.4)

        Returns:
            List of logic_fuzz payload objects, each with:
            {
                name, category, description, payload,
                confidence, confidence_signals, fp_risk,
                expected_status, violation_type, source
            }
        """
        payloads: List[Dict[str, Any]] = []

        if not constraints:
            return payloads

        for field_name, field_data in constraints.items():
            field_confidence = field_data.get("confidence", 0.0)
            if field_confidence < confidence_threshold:
                logger.debug(
                    f"Skipping '{field_name}': confidence {field_confidence:.2f} < threshold {confidence_threshold}"
                )
                continue

            field_constraints = field_data.get("constraints", {})
            field_type = field_data.get("type", "string")
            signals = field_data.get("signals", [])
            is_required = field_data.get("required", False)

            # --- Range violations ---
            payloads.extend(LogicFuzzGenerator._generate_range_violations(
                field_name, field_constraints, field_type, field_confidence, signals
            ))

            # --- Enum violations ---
            payloads.extend(LogicFuzzGenerator._generate_enum_violations(
                field_name, field_constraints, field_confidence, signals, endpoint_method
            ))

            # --- IDOR / ownership bypass ---
            payloads.extend(LogicFuzzGenerator._generate_idor_payloads(
                field_name, field_constraints, field_confidence, signals, endpoint_method
            ))

            # --- Missing required field ---
            if is_required:
                payloads.extend(LogicFuzzGenerator._generate_missing_required(
                    field_name, constraints, field_confidence, signals
                ))

            # --- Type coercion violations ---
            payloads.extend(LogicFuzzGenerator._generate_type_violations(
                field_name, field_type, field_constraints, field_confidence, signals
            ))

            # --- String length violations ---
            payloads.extend(LogicFuzzGenerator._generate_length_violations(
                field_name, field_constraints, field_confidence, signals
            ))

        logger.debug(f"Generated {len(payloads)} logic_fuzz payloads from {len(constraints)} fields")
        return payloads

    # ------------------------------------------------------------------
    # Violation generators
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_range_violations(
        field: str,
        constraints: Dict[str, Any],
        field_type: str,
        confidence: float,
        signals: List[str],
    ) -> List[Dict[str, Any]]:
        """Generate payloads that violate numeric range constraints."""
        payloads = []
        fp_risk = LogicFuzzGenerator._fp_risk(confidence)

        # gt/ge → test values at and below the boundary
        if "gt" in constraints:
            boundary = constraints["gt"]
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_at_exclusive_minimum",
                description=f"'{field}' equals exclusive minimum ({boundary}), should be rejected (gt={boundary})",
                payload={field: boundary},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="range_violation",
            ))
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_below_minimum",
                description=f"'{field}' below minimum allowed value (gt={boundary})",
                payload={field: boundary - 1 if isinstance(boundary, int) else round(boundary - 0.01, 4)},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="range_violation",
            ))

        if "ge" in constraints:
            boundary = constraints["ge"]
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_below_minimum",
                description=f"'{field}' below minimum allowed value (ge={boundary})",
                payload={field: boundary - 1 if isinstance(boundary, int) else round(boundary - 0.01, 4)},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="range_violation",
            ))

        # lt/le → test values at and above the boundary
        if "lt" in constraints:
            boundary = constraints["lt"]
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_at_exclusive_maximum",
                description=f"'{field}' equals exclusive maximum ({boundary}), should be rejected (lt={boundary})",
                payload={field: boundary},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="range_violation",
            ))
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_above_maximum",
                description=f"'{field}' above maximum allowed value (lt={boundary})",
                payload={field: boundary + 1 if isinstance(boundary, int) else round(boundary + 0.01, 4)},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="range_violation",
            ))

        if "le" in constraints:
            boundary = constraints["le"]
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_above_maximum",
                description=f"'{field}' above maximum allowed value (le={boundary})",
                payload={field: boundary + 1 if isinstance(boundary, int) else round(boundary + 0.01, 4)},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="range_violation",
            ))

        # Inferred positive (field_name_inference) — lower confidence
        if constraints.get("inferred_positive") and "gt" not in constraints and "ge" not in constraints:
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_negative_value",
                description=f"'{field}' with negative value (inferred: should be positive)",
                payload={field: -1},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="range_violation",
            ))

        return payloads

    @staticmethod
    def _generate_enum_violations(
        field: str,
        constraints: Dict[str, Any],
        confidence: float,
        signals: List[str],
        endpoint_method: str,
    ) -> List[Dict[str, Any]]:
        """Generate payloads with invalid/privileged enum values."""
        payloads = []

        if "enum" not in constraints:
            return payloads

        allowed = constraints["enum"]
        fp_risk = LogicFuzzGenerator._fp_risk(confidence)

        # Generic invalid value
        payloads.append(LogicFuzzGenerator._make_payload(
            name=f"{field}_invalid_enum_value",
            description=f"'{field}' with value not in allowed set {allowed[:3]}",
            payload={field: "INVALID_VALUE_XYZ"},
            confidence=confidence,
            signals=signals,
            fp_risk=fp_risk,
            expected_status=[400, 422],
            violation_type="enum_violation",
        ))

        # Privilege escalation attempt:
        # Only generate if there is a privileged role NOT already in the allowed enum.
        # Example: enum=["user","guest"] → try "admin"
        # Example: enum=["admin","user"] → try "superuser" (admin already allowed)
        from scanners.deterministic.constraint_extractor import PRIVILEGE_VALUES
        allowed_lower = {v.lower() for v in allowed}
        escalation_targets = [v for v in sorted(PRIVILEGE_VALUES) if v not in allowed_lower]
        if escalation_targets:
            target = escalation_targets[0]
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_privilege_escalation",
                description=(
                    f"'{field}' set to privileged value '{target}' "
                    f"which is not in the allowed set {allowed[:3]}"
                ),
                payload={field: target},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 403, 422],
                violation_type="privilege_escalation",
            ))

        # Empty string for enum field
        payloads.append(LogicFuzzGenerator._make_payload(
            name=f"{field}_empty_enum",
            description=f"'{field}' as empty string (enum field)",
            payload={field: ""},
            confidence=confidence,
            signals=signals,
            fp_risk=fp_risk,
            expected_status=[400, 422],
            violation_type="enum_violation",
        ))

        return payloads

    @staticmethod
    def _generate_idor_payloads(
        field: str,
        constraints: Dict[str, Any],
        confidence: float,
        signals: List[str],
        endpoint_method: str,
    ) -> List[Dict[str, Any]]:
        """Generate IDOR (Insecure Direct Object Reference) test payloads."""
        if not constraints.get("idor_risk"):
            return []

        # Only generate IDOR payloads when there's an ownership signal
        if "ownership_pattern" not in signals and "path_param_id" not in signals:
            return []

        fp_risk = LogicFuzzGenerator._fp_risk(confidence)

        return [
            LogicFuzzGenerator._make_payload(
                name=f"{field}_idor_other_user",
                description=(
                    f"IDOR: Access resource owned by a different user by substituting '{field}'. "
                    f"Replace <OTHER_USER_ID> with a valid ID belonging to another user."
                ),
                payload={field: "<OTHER_USER_ID>"},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[403, 404],
                violation_type="idor",
            ),
            LogicFuzzGenerator._make_payload(
                name=f"{field}_idor_zero_id",
                description=f"IDOR: Access resource with id=0 (often invalid or sentinel value)",
                payload={field: 0},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 403, 404],
                violation_type="idor",
            ),
        ]

    @staticmethod
    def _generate_missing_required(
        field: str,
        all_constraints: Dict[str, Dict[str, Any]],
        confidence: float,
        signals: List[str],
    ) -> List[Dict[str, Any]]:
        """Generate payload with required field omitted."""
        # Build a minimal valid payload from other fields
        other_fields = {
            f: LogicFuzzGenerator._placeholder_value(
                data.get("type", "string"),
                data.get("constraints", {})
            )
            for f, data in all_constraints.items()
            if f != field and data.get("confidence", 0) >= 0.1
        }

        return [
            LogicFuzzGenerator._make_payload(
                name=f"missing_required_{field}",
                description=f"Required field '{field}' is omitted from the request",
                payload=other_fields,
                confidence=min(confidence + 0.1, 1.0),  # missing-required is reliable
                signals=signals,
                fp_risk=LogicFuzzGenerator._fp_risk(confidence),
                expected_status=[400, 422],
                violation_type="missing_required",
            )
        ]

    @staticmethod
    def _generate_type_violations(
        field: str,
        field_type: str,
        constraints: Dict[str, Any],
        confidence: float,
        signals: List[str],
    ) -> List[Dict[str, Any]]:
        """Generate type coercion violations for strongly-typed fields."""
        payloads = []
        fp_risk = LogicFuzzGenerator._fp_risk(confidence)

        # Only for fields with explicit type signal (not just inference)
        strong_signals = {"pydantic_field_constraint", "annotated_constraint", "literal_type", "type_hint_only"}
        if not any(s in strong_signals for s in signals):
            return payloads

        if field_type == "integer":
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_float_for_integer",
                description=f"Float value for integer field '{field}'",
                payload={field: 1.5},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="type_coercion",
            ))
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_string_for_integer",
                description=f"String value for integer field '{field}'",
                payload={field: "not_a_number"},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="type_coercion",
            ))

        elif field_type == "number":
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_string_for_number",
                description=f"String value for numeric field '{field}'",
                payload={field: "NaN"},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="type_coercion",
            ))

        elif field_type == "boolean":
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_string_for_boolean",
                description=f"Non-boolean string for boolean field '{field}'",
                payload={field: "yes"},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="type_coercion",
            ))

        return payloads

    @staticmethod
    def _generate_length_violations(
        field: str,
        constraints: Dict[str, Any],
        confidence: float,
        signals: List[str],
    ) -> List[Dict[str, Any]]:
        """Generate string length constraint violations."""
        payloads = []
        fp_risk = LogicFuzzGenerator._fp_risk(confidence)

        if "min_length" in constraints:
            min_len = int(constraints["min_length"])
            if min_len > 0:
                payloads.append(LogicFuzzGenerator._make_payload(
                    name=f"{field}_below_min_length",
                    description=f"'{field}' shorter than min_length={min_len}",
                    payload={field: "x" * max(0, min_len - 1)},
                    confidence=confidence,
                    signals=signals,
                    fp_risk=fp_risk,
                    expected_status=[400, 422],
                    violation_type="length_violation",
                ))
                if min_len > 1:
                    payloads.append(LogicFuzzGenerator._make_payload(
                        name=f"{field}_empty_for_min_length",
                        description=f"'{field}' empty string when min_length={min_len}",
                        payload={field: ""},
                        confidence=confidence,
                        signals=signals,
                        fp_risk=fp_risk,
                        expected_status=[400, 422],
                        violation_type="length_violation",
                    ))

        if "max_length" in constraints:
            max_len = int(constraints["max_length"])
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_above_max_length",
                description=f"'{field}' longer than max_length={max_len}",
                payload={field: "a" * (max_len + 1)},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 422],
                violation_type="length_violation",
            ))
            payloads.append(LogicFuzzGenerator._make_payload(
                name=f"{field}_far_above_max_length",
                description=f"'{field}' far above max_length={max_len} (10x)",
                payload={field: "a" * (max_len * 10)},
                confidence=confidence,
                signals=signals,
                fp_risk=fp_risk,
                expected_status=[400, 413, 422],
                violation_type="length_violation",
            ))

        return payloads

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_payload(
        name: str,
        description: str,
        payload: Dict[str, Any],
        confidence: float,
        signals: List[str],
        fp_risk: str,
        expected_status: List[int],
        violation_type: str,
    ) -> Dict[str, Any]:
        """Build a standardized logic_fuzz payload object."""
        return {
            "name": name,
            "category": "logic_fuzz",
            "description": description,
            "payload": payload,
            "confidence": round(confidence, 2),
            "confidence_signals": list(set(signals)),
            "fp_risk": fp_risk,
            "expected_status": expected_status,
            "violation_type": violation_type,
            "source": "logic_fuzz_deterministic",
        }

    @staticmethod
    def _fp_risk(confidence: float) -> str:
        """Map confidence score to false-positive risk label."""
        if confidence >= 0.7:
            return "low"
        return "medium"

    @staticmethod
    def _placeholder_value(field_type: str, constraints: Optional[Dict[str, Any]] = None) -> Any:
        """Return a valid placeholder value for a given type and constraints."""
        constraints = constraints or {}

        # For enum fields, use the first allowed value (avoids triggering enum validation error)
        if "enum" in constraints and constraints["enum"]:
            return constraints["enum"][0]

        # For gt/ge constraints, use a clearly valid value
        if "gt" in constraints:
            return constraints["gt"] + 1
        if "ge" in constraints:
            return constraints["ge"]

        # For string length constraints, use a valid-length string
        if "min_length" in constraints:
            return "x" * int(constraints["min_length"])

        return {
            "integer": 1,
            "number": 1.0,
            "boolean": True,
            "array": [],
            "object": {},
        }.get(field_type, "example")
