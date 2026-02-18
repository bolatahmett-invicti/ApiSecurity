#!/usr/bin/env python3
"""
Constraint Extractor
====================
Extracts business logic constraints from Python source code via AST + regex.

Used by Logic-oriented Fuzzing (LoF) to generate semantically-valid but
logically-violating test payloads.

Extracts:
- Pydantic Field constraints (gt, lt, ge, le, min_length, max_length, pattern)
- Literal["a", "b"] → enum constraints
- Annotated[int, Field(ge=0)] → annotated constraints
- Inline validation: `if age < 0: raise` → range inference
- Ownership patterns: current_user + user_id → IDOR signal
- Required vs optional fields

Cost: $0 (fully deterministic, no LLM)
Accuracy: High for typed/validated code, lower for legacy code
"""

import ast
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("api_scanner.deterministic.constraint_extractor")

# Signal weight table — determines confidence per evidence type
SIGNAL_WEIGHTS = {
    "pydantic_field_constraint": 0.50,  # Field(gt=0) — machine-readable, explicit
    "literal_type": 0.45,               # Literal["a","b"] — unambiguous enum
    "pydantic_validator": 0.40,         # @validator or @field_validator
    "annotated_constraint": 0.40,       # Annotated[int, Field(...)]
    "inline_validation": 0.30,          # if x < 0: raise ValueError
    "ownership_pattern": 0.30,          # current_user + user_id in code
    "docstring_constraint": 0.20,       # documented range/enum in docstring
    "path_param_id": 0.20,              # {user_id} in route → IDOR candidate
    "type_hint_only": 0.10,             # just `price: float`, no explicit constraint
    "field_name_inference": 0.10,       # "price" → infer positive
}

# Field names that semantically imply positive-only constraints
POSITIVE_ONLY_FIELDS = {
    "price", "amount", "cost", "fee", "total", "subtotal",
    "quantity", "qty", "count", "stock", "inventory",
    "age", "duration", "timeout", "limit", "offset",
    "width", "height", "size", "weight", "score", "rating",
}

# Field names that imply ownership / IDOR risk when in path
OWNERSHIP_FIELD_NAMES = {
    "user_id", "account_id", "owner_id", "customer_id",
    "profile_id", "member_id", "subscriber_id",
}

# Privilege-sensitive enum values
PRIVILEGE_VALUES = {"admin", "root", "superuser", "administrator", "staff", "moderator", "manager"}


class ConstraintExtractor:
    """
    Extracts parameter constraints from Python source code.

    Usage:
        constraints = ConstraintExtractor.extract_from_code(
            source_code=function_body,
            route="/api/users/{user_id}",
            auth_info={"security": [{"bearerAuth": []}]}
        )
    """

    @staticmethod
    def extract_from_code(
        source_code: str,
        route: str = "",
        auth_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Extract constraints for each parameter found in the source code.

        Args:
            source_code: Python function body or surrounding code
            route: API route (e.g. "/users/{user_id}") for path param detection
            auth_info: Auth decorator data from DecoratorAnalyzer

        Returns:
            Dict mapping field name → constraint info with confidence:
            {
                "price": {
                    "type": "number",
                    "constraints": {"gt": 0},
                    "confidence": 0.9,
                    "signals": ["pydantic_field_constraint", "field_name_inference"]
                }
            }
        """
        if not source_code or not source_code.strip():
            return {}

        results: Dict[str, Dict[str, Any]] = {}
        auth_info = auth_info or {}

        # Detect ownership context (is current_user referenced?)
        has_ownership_context = ConstraintExtractor._detect_ownership_context(source_code)

        # Extract path parameters from route
        path_params = ConstraintExtractor._extract_path_params(route)

        # Try AST-based extraction first
        try:
            ast_constraints = ConstraintExtractor._extract_via_ast(source_code)
            for field, data in ast_constraints.items():
                results[field] = data
        except SyntaxError:
            logger.debug("AST parsing failed, falling back to regex")

        # Regex-based extraction for patterns AST misses
        regex_constraints = ConstraintExtractor._extract_via_regex(source_code)
        for field, data in regex_constraints.items():
            if field not in results:
                results[field] = data
            else:
                # Merge signals and constraints
                results[field]["signals"].extend(data.get("signals", []))
                results[field]["constraints"].update(data.get("constraints", {}))

        # Add IDOR signals for path params
        for param_name, param_type in path_params.items():
            if param_name not in results:
                results[param_name] = {
                    "type": param_type,
                    "constraints": {},
                    "signals": [],
                    "required": True,
                }

            if param_name in OWNERSHIP_FIELD_NAMES and has_ownership_context:
                results[param_name]["constraints"]["idor_risk"] = True
                results[param_name]["signals"].append("ownership_pattern")
                results[param_name]["signals"].append("path_param_id")
            elif param_name in OWNERSHIP_FIELD_NAMES:
                results[param_name]["signals"].append("path_param_id")

        # Add field name inference for fields without explicit constraints
        for field, data in results.items():
            base_name = field.lower().rstrip("_").replace("-", "_")
            if base_name in POSITIVE_ONLY_FIELDS and "gt" not in data["constraints"] and "ge" not in data["constraints"]:
                if "field_name_inference" not in data["signals"]:
                    data["signals"].append("field_name_inference")
                    data["constraints"]["inferred_positive"] = True

        # Recalculate confidence for each field
        for field, data in results.items():
            data["confidence"] = ConstraintExtractor._calculate_confidence(data["signals"])
            data.setdefault("required", False)

        logger.debug(f"Extracted constraints for {len(results)} fields")
        return results

    @staticmethod
    def _extract_via_ast(source_code: str) -> Dict[str, Dict[str, Any]]:
        """Extract constraints using Python AST."""
        results: Dict[str, Dict[str, Any]] = {}

        # Wrap in function if needed for parsing
        code_to_parse = source_code
        try:
            tree = ast.parse(code_to_parse)
        except SyntaxError:
            code_to_parse = f"def _wrapper():\n" + "\n".join("    " + l for l in source_code.splitlines())
            tree = ast.parse(code_to_parse)

        for node in ast.walk(tree):
            # Extract from function definitions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ConstraintExtractor._extract_from_function_args(node, results)

            # Extract from Pydantic BaseModel class body
            elif isinstance(node, ast.ClassDef):
                ConstraintExtractor._extract_from_class_body(node, results)

            # Extract inline validation patterns
            elif isinstance(node, (ast.If, ast.Assert)):
                ConstraintExtractor._extract_from_condition(node, results)

        return results

    @staticmethod
    def _extract_from_class_body(
        class_node: ast.ClassDef,
        results: Dict[str, Dict[str, Any]]
    ) -> None:
        """
        Extract Pydantic model field constraints from class body annotations.

        Handles:
        - `price: Annotated[float, Field(gt=0)]`
        - `role: Literal["admin", "user"]`
        - `name: str = Field(min_length=1, max_length=100)`
        """
        for stmt in class_node.body:
            # Annotated attribute: `field: SomeType` or `field: Annotated[...]`
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                field_name = stmt.target.id
                if field_name.startswith("_"):
                    continue

                annotation = stmt.annotation
                constraint_data = ConstraintExtractor._parse_annotation(annotation)

                if constraint_data:
                    is_required = stmt.value is None  # No default → required
                    # If default is Field(...), extract its constraints too
                    if isinstance(stmt.value, ast.Call):
                        func_name = ""
                        if isinstance(stmt.value.func, ast.Name):
                            func_name = stmt.value.func.id
                        elif isinstance(stmt.value.func, ast.Attribute):
                            func_name = stmt.value.func.attr
                        if func_name == "Field":
                            field_constraints = ConstraintExtractor._extract_field_kwargs(stmt.value)
                            if field_constraints:
                                constraint_data["constraints"].update(field_constraints)
                                constraint_data["signals"].append("pydantic_field_constraint")
                        is_required = False  # has default (Field(...))

                    if field_name not in results:
                        results[field_name] = {
                            "type": constraint_data.get("type", "string"),
                            "constraints": constraint_data.get("constraints", {}),
                            "signals": constraint_data.get("signals", []),
                            "required": is_required,
                        }
                    else:
                        results[field_name]["constraints"].update(constraint_data.get("constraints", {}))
                        results[field_name]["signals"].extend(constraint_data.get("signals", []))

    @staticmethod
    def _extract_from_function_args(
        func_node: ast.FunctionDef,
        results: Dict[str, Dict[str, Any]]
    ) -> None:
        """Extract constraints from function argument annotations."""
        for arg in func_node.args.args + func_node.args.posonlyargs + func_node.args.kwonlyargs:
            if arg.annotation is None:
                continue

            field_name = arg.arg
            if field_name in ("self", "cls", "request", "db", "session", "current_user"):
                continue

            annotation = arg.annotation
            constraint_data = ConstraintExtractor._parse_annotation(annotation)

            if constraint_data:
                is_required = not ConstraintExtractor._has_default(func_node, field_name)
                results[field_name] = {
                    "type": constraint_data.get("type", "string"),
                    "constraints": constraint_data.get("constraints", {}),
                    "signals": constraint_data.get("signals", []),
                    "required": is_required,
                }

    @staticmethod
    def _parse_annotation(annotation: ast.expr) -> Optional[Dict[str, Any]]:
        """Parse a type annotation node into constraint data."""
        # Simple type: int, float, str, bool
        if isinstance(annotation, ast.Name):
            type_map = {
                "int": "integer", "float": "number", "str": "string",
                "bool": "boolean", "bytes": "string",
            }
            py_type = annotation.id
            if py_type in type_map:
                return {
                    "type": type_map[py_type],
                    "constraints": {},
                    "signals": ["type_hint_only"],
                }

        # Generic: List[X], Optional[X], Dict[K,V], Literal["a","b"]
        elif isinstance(annotation, ast.Subscript):
            return ConstraintExtractor._parse_subscript(annotation)

        # Attribute: datetime.date, EmailStr, etc.
        elif isinstance(annotation, ast.Attribute):
            attr_name = annotation.attr
            type_map = {
                "date": "string", "datetime": "string", "time": "string",
                "Decimal": "number", "UUID": "string",
            }
            if attr_name in type_map:
                return {
                    "type": type_map[attr_name],
                    "constraints": {},
                    "signals": ["type_hint_only"],
                }

        return None

    @staticmethod
    def _parse_subscript(node: ast.Subscript) -> Optional[Dict[str, Any]]:
        """Parse subscript annotations like Optional[X], Literal["a"], Annotated[X, Field(...)]."""
        if not isinstance(node.value, ast.Name):
            return None

        outer_name = node.value.id

        # Optional[X] → nullable, recurse on X
        if outer_name == "Optional":
            slice_node = node.slice
            inner = ConstraintExtractor._parse_annotation(slice_node)
            if inner:
                inner["constraints"]["nullable"] = True
                return inner
            return {"type": "string", "constraints": {"nullable": True}, "signals": ["type_hint_only"]}

        # List[X]
        if outer_name in ("List", "list"):
            return {"type": "array", "constraints": {}, "signals": ["type_hint_only"]}

        # Literal["a", "b", "c"]
        if outer_name == "Literal":
            enum_values = ConstraintExtractor._extract_literal_values(node.slice)
            if enum_values:
                has_privilege = any(str(v).lower() in PRIVILEGE_VALUES for v in enum_values)
                return {
                    "type": "string",
                    "constraints": {
                        "enum": [str(v) for v in enum_values],
                        "has_privilege_values": has_privilege,
                    },
                    "signals": ["literal_type"],
                }

        # Annotated[int, Field(gt=0, ...)]
        if outer_name == "Annotated":
            return ConstraintExtractor._parse_annotated(node.slice)

        return None

    @staticmethod
    def _extract_literal_values(slice_node: ast.expr) -> List[Any]:
        """Extract values from Literal["a", "b"] or Literal[1, 2]."""
        values = []
        if isinstance(slice_node, ast.Tuple):
            for elt in slice_node.elts:
                if isinstance(elt, ast.Constant):
                    values.append(elt.value)
        elif isinstance(slice_node, ast.Constant):
            values.append(slice_node.value)
        return values

    @staticmethod
    def _parse_annotated(slice_node: ast.expr) -> Optional[Dict[str, Any]]:
        """Parse Annotated[BaseType, Field(...)] to extract Field constraints."""
        if not isinstance(slice_node, ast.Tuple) or len(slice_node.elts) < 2:
            return None

        base_annotation = slice_node.elts[0]
        base_data = ConstraintExtractor._parse_annotation(base_annotation) or {
            "type": "string", "constraints": {}, "signals": []
        }

        # Look for Field(...) call in remaining elements
        for field_node in slice_node.elts[1:]:
            if isinstance(field_node, ast.Call):
                func_name = ""
                if isinstance(field_node.func, ast.Name):
                    func_name = field_node.func.id
                elif isinstance(field_node.func, ast.Attribute):
                    func_name = field_node.func.attr

                if func_name == "Field":
                    field_constraints = ConstraintExtractor._extract_field_kwargs(field_node)
                    base_data["constraints"].update(field_constraints)
                    if field_constraints:
                        base_data["signals"].append("annotated_constraint")

        return base_data

    @staticmethod
    def _extract_field_kwargs(field_call: ast.Call) -> Dict[str, Any]:
        """Extract keyword arguments from Field(gt=0, lt=100, min_length=1, ...)."""
        constraints: Dict[str, Any] = {}
        numeric_kwargs = {"gt", "lt", "ge", "le", "min_length", "max_length", "multiple_of"}
        string_kwargs = {"pattern", "regex"}

        for kw in field_call.keywords:
            if kw.arg in numeric_kwargs and isinstance(kw.value, ast.Constant):
                constraints[kw.arg] = kw.value.value
                if kw.arg in {"gt", "lt", "ge", "le", "min_length", "max_length"}:
                    # Upgrade signal weight for explicit numeric constraint
                    constraints["_signal"] = "pydantic_field_constraint"
            elif kw.arg in string_kwargs and isinstance(kw.value, ast.Constant):
                constraints["pattern"] = kw.value.value

        return {k: v for k, v in constraints.items() if k != "_signal"}, constraints.get("_signal")

    @staticmethod
    def _extract_field_kwargs(field_call: ast.Call) -> Dict[str, Any]:
        """Extract keyword arguments from Field(gt=0, lt=100, ...)."""
        constraints: Dict[str, Any] = {}
        known_kwargs = {"gt", "lt", "ge", "le", "min_length", "max_length", "multiple_of", "pattern", "regex"}

        for kw in field_call.keywords:
            if kw.arg in known_kwargs and isinstance(kw.value, ast.Constant):
                constraints[kw.arg] = kw.value.value

        return constraints

    @staticmethod
    def _extract_from_condition(node: ast.stmt, results: Dict[str, Dict[str, Any]]) -> None:
        """Extract range constraints from inline if/assert validation."""
        # Handle: if x < 0: raise / assert x > 0
        test = None
        if isinstance(node, ast.If):
            test = node.test
        elif isinstance(node, ast.Assert):
            test = node.test

        if test is None:
            return

        # Pattern: `field < 0` or `field > 100` or `field <= 0` etc.
        if isinstance(test, ast.Compare):
            ConstraintExtractor._parse_comparison(test, results)
        # Pattern: `not (0 <= x <= 100)`
        elif isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            if isinstance(test.operand, ast.Compare):
                ConstraintExtractor._parse_comparison(test.operand, results, inverted=True)
        # Pattern: `x < 0 or x > 100`
        elif isinstance(test, ast.BoolOp):
            for value in test.values:
                if isinstance(value, ast.Compare):
                    ConstraintExtractor._parse_comparison(value, results)

    @staticmethod
    def _parse_comparison(compare: ast.Compare, results: Dict[str, Dict[str, Any]], inverted: bool = False) -> None:
        """Parse ast.Compare to extract field range constraints."""
        if not (isinstance(compare.left, ast.Name) and len(compare.ops) == 1 and len(compare.comparators) == 1):
            return

        field_name = compare.left.id
        op = compare.ops[0]
        comparator = compare.comparators[0]

        if not isinstance(comparator, ast.Constant):
            return

        value = comparator.value
        if not isinstance(value, (int, float)):
            return

        op_map = {
            ast.Lt: "lt", ast.LtE: "le", ast.Gt: "gt", ast.GtE: "ge",
        }
        op_key = op_map.get(type(op))
        if not op_key:
            return

        if field_name not in results:
            results[field_name] = {
                "type": "number",
                "constraints": {},
                "signals": [],
                "required": False,
            }

        results[field_name]["constraints"][op_key] = value
        if "inline_validation" not in results[field_name]["signals"]:
            results[field_name]["signals"].append("inline_validation")

    @staticmethod
    def _extract_via_regex(source_code: str) -> Dict[str, Dict[str, Any]]:
        """Regex-based extraction for patterns difficult to get via AST."""
        results: Dict[str, Dict[str, Any]] = {}

        # Pydantic v1 @validator patterns: @validator("field_name")
        validator_pattern = re.compile(
            r'@(?:validator|field_validator)\s*\(\s*["\'](\w+)["\']', re.MULTILINE
        )
        for match in validator_pattern.finditer(source_code):
            field = match.group(1)
            if field not in results:
                results[field] = {"type": "string", "constraints": {}, "signals": [], "required": False}
            if "pydantic_validator" not in results[field]["signals"]:
                results[field]["signals"].append("pydantic_validator")

        # Inline raise patterns: raise ValueError("age must be positive")
        raise_pattern = re.compile(
            r'raise\s+\w+\(["\']([^"\']*(?:must|should|cannot|invalid)[^"\']*)["\']',
            re.IGNORECASE
        )
        for match in raise_pattern.finditer(source_code):
            message = match.group(1).lower()
            # Try to extract field name from message
            field = ConstraintExtractor._infer_field_from_message(message)
            if field:
                if field not in results:
                    results[field] = {"type": "string", "constraints": {}, "signals": [], "required": False}
                if "inline_validation" not in results[field]["signals"]:
                    results[field]["signals"].append("inline_validation")

        # Docstring constraints: ":param age: Must be between 0 and 150"
        docstring_pattern = re.compile(
            r':param\s+(\w+):\s*([^\n]+)', re.MULTILINE
        )
        for match in docstring_pattern.finditer(source_code):
            field = match.group(1)
            desc = match.group(2)
            constraint = ConstraintExtractor._parse_docstring_constraint(desc)
            if constraint:
                if field not in results:
                    results[field] = {"type": "string", "constraints": {}, "signals": [], "required": False}
                results[field]["constraints"].update(constraint)
                if "docstring_constraint" not in results[field]["signals"]:
                    results[field]["signals"].append("docstring_constraint")

        return results

    @staticmethod
    def _infer_field_from_message(message: str) -> Optional[str]:
        """Infer field name from a validation error message."""
        common_fields = list(POSITIVE_ONLY_FIELDS) + list(OWNERSHIP_FIELD_NAMES) + [
            "email", "username", "password", "name", "title", "status", "role"
        ]
        for field in common_fields:
            if field in message:
                return field
        return None

    @staticmethod
    def _parse_docstring_constraint(description: str) -> Dict[str, Any]:
        """Parse simple constraints from docstring param descriptions."""
        constraints: Dict[str, Any] = {}
        desc_lower = description.lower()

        # "Must be between X and Y" / "Range: X to Y"
        between = re.search(r'between\s+(\d+(?:\.\d+)?)\s+and\s+(\d+(?:\.\d+)?)', desc_lower)
        if between:
            constraints["ge"] = float(between.group(1))
            constraints["le"] = float(between.group(2))

        # "Minimum X" / "At least X"
        min_match = re.search(r'(?:minimum|at least|min)\s+(\d+(?:\.\d+)?)', desc_lower)
        if min_match:
            constraints["ge"] = float(min_match.group(1))

        # "Maximum X" / "At most X"
        max_match = re.search(r'(?:maximum|at most|max)\s+(\d+(?:\.\d+)?)', desc_lower)
        if max_match:
            constraints["le"] = float(max_match.group(1))

        # "positive" implies gt=0
        if "positive" in desc_lower or "greater than 0" in desc_lower:
            constraints["gt"] = 0

        return constraints

    @staticmethod
    def _detect_ownership_context(source_code: str) -> bool:
        """Detect if the function uses current_user for ownership checks."""
        ownership_patterns = [
            r'\bcurrent_user\b', r'\bget_current_user\b', r'\brequest\.user\b',
            r'\bauth\.user\b', r'\.user_id\b', r'current_user\.id\b',
        ]
        for pattern in ownership_patterns:
            if re.search(pattern, source_code):
                return True
        return False

    @staticmethod
    def _extract_path_params(route: str) -> Dict[str, str]:
        """Extract path parameters and their types from route string."""
        params: Dict[str, str] = {}

        # FastAPI/Flask: {user_id:int}, {post_id:uuid}, {item_id}
        for match in re.finditer(r'\{(\w+)(?::(\w+))?\}', route):
            name = match.group(1)
            type_hint = match.group(2) or ""
            params[name] = ConstraintExtractor._map_route_type(name, type_hint)

        # Express: :user_id
        for match in re.finditer(r':(\w+)', route):
            name = match.group(1)
            if name not in params:
                params[name] = ConstraintExtractor._map_route_type(name, "")

        return params

    @staticmethod
    def _map_route_type(name: str, type_hint: str) -> str:
        """Map route type hint or field name to OpenAPI type."""
        type_map = {
            "int": "integer", "integer": "integer",
            "float": "number", "decimal": "number",
            "str": "string", "string": "string",
            "uuid": "string", "path": "string",
        }
        if type_hint in type_map:
            return type_map[type_hint]
        # Name-based inference
        if name.endswith("_id") or name.endswith("Id") or name == "id":
            return "integer"
        if "uuid" in name.lower():
            return "string"
        return "string"

    @staticmethod
    def _has_default(func_node: ast.FunctionDef, arg_name: str) -> bool:
        """Check if an argument has a default value (making it optional)."""
        all_args = func_node.args.args + func_node.args.posonlyargs
        defaults = func_node.args.defaults

        # defaults are right-aligned: last len(defaults) args have defaults
        n_no_default = len(all_args) - len(defaults)
        for i, arg in enumerate(all_args):
            if arg.arg == arg_name:
                return i >= n_no_default

        # kwonly args with kw_defaults
        for arg, default in zip(func_node.args.kwonlyargs, func_node.args.kw_defaults):
            if arg.arg == arg_name:
                return default is not None

        return False

    @staticmethod
    def _calculate_confidence(signals: List[str]) -> float:
        """Calculate overall confidence from list of signals (capped at 1.0)."""
        total = sum(SIGNAL_WEIGHTS.get(s, 0.0) for s in set(signals))
        return min(round(total, 2), 1.0)
