"""C#/.NET scanner: ASP.NET Core, Minimal API, SignalR, gRPC. Also exports DtoSchemaExtractor."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import (
    BaseScanner, Language, EndpointKind, AuthStatus, PatternDef, Endpoint
)


class DotNetScanner(BaseScanner):
    """
    .NET/C# scanner with STATEFUL DEEP CONTROLLER PARSING.
    """

    @property
    def language(self) -> Language:
        return Language.DOTNET

    @property
    def extensions(self) -> Set[str]:
        return {".cs"}

    @property
    def patterns(self) -> List[PatternDef]:
        # Minimal API patterns only - Controllers handled by _deep_scan_controllers
        return [
            PatternDef(
                regex=r'app\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="MinimalAPI",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'endpoints\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']+)["\']',
                framework="MinimalAPI",
                kind=EndpointKind.ENDPOINT,
                method_group=1,
                route_group=2,
            ),
            PatternDef(
                regex=r'\.MapHealthChecks\s*\(\s*["\']([^"\']+)["\']',
                framework="ASP.NET",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'\.MapHub<\w+>\s*\(\s*["\']([^"\']+)["\']',
                framework="SignalR",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
            PatternDef(
                regex=r'\.MapGrpcService<(\w+)>',
                framework="gRPC",
                kind=EndpointKind.ENDPOINT,
                route_group=1,
            ),
        ]

    def scan_file(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """Override to use deep controller scanning as PRIMARY method."""
        results = []

        # PRIMARY: Deep scan for Controllers with proper route combination
        results.extend(self._deep_scan_controllers(file_path, content, lines))

        # SECONDARY: Minimal API patterns for .NET 6+
        results.extend(self.scan_with_patterns(file_path, content, lines))

        return results

    def _deep_scan_controllers(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """
        STATEFUL REGEX PARSING for .NET Controllers.
        Supports:
        - ASP.NET Core: public class XController : ControllerBase
        - ASP.NET Web API 2: public class XController : ApiController (System.Web.Http)
        - Generated: public abstract class XControllerBase : Microsoft.AspNetCore.Mvc.Controller
        """
        results = []

        # Detect if this is ASP.NET Web API 2 (System.Web.Http) or ASP.NET Core
        is_webapi2 = "System.Web.Http" in content or "using System.Web.Http;" in content

        # Extended pattern to match both standard and fully-qualified controller base classes
        controller_pattern = r'public\s+(?:abstract\s+)?class\s+(\w+)\s*:\s*(?:Microsoft\.AspNetCore\.Mvc\.)?(Controller|ControllerBase|ApiController|ODataController|InvictiApiController|\w+ApiController|\w+Controller)'

        for class_match in re.finditer(controller_pattern, content, re.MULTILINE):
            controller_name = class_match.group(1)
            base_class = class_match.group(2)
            class_start_pos = class_match.start()
            class_end_pos = class_match.end()

            # Skip if it's just a class ending with Controller but not inheriting from a controller base
            if base_class not in ('Controller', 'ControllerBase', 'ApiController', 'ODataController') and not base_class.endswith('ApiController') and not base_class.endswith('Controller'):
                continue

            lookback_start = max(0, class_start_pos - 500)
            preceding_text = content[lookback_start:class_start_pos]

            base_route = ""

            # Support both [Route("...")] and [Microsoft.AspNetCore.Mvc.Route("...")]
            route_match = re.search(r'\[(?:Microsoft\.AspNetCore\.Mvc\.)?Route\s*\(\s*["\']([^"\']+)["\']\s*\)\]', preceding_text)
            if route_match:
                base_route = route_match.group(1)

            # ASP.NET Web API 2: Support [RoutePrefix("api/1.0/discovery")]
            route_prefix_match = re.search(r'\[RoutePrefix\s*\(\s*["\']([^"\']+)["\']\s*\)\]', preceding_text)
            if route_prefix_match:
                base_route = route_prefix_match.group(1)

            if "[controller]" in base_route.lower():
                ctrl_short_name = controller_name
                if ctrl_short_name.endswith("Controller"):
                    ctrl_short_name = ctrl_short_name[:-10]
                ctrl_short_name = ctrl_short_name.lower()

                base_route = re.sub(r'\[controller\]', ctrl_short_name, base_route, flags=re.IGNORECASE)

            brace_start = content.find('{', class_end_pos)
            if brace_start == -1:
                continue

            brace_depth = 1
            brace_end = brace_start + 1
            while brace_depth > 0 and brace_end < len(content):
                if content[brace_end] == '{':
                    brace_depth += 1
                elif content[brace_end] == '}':
                    brace_depth -= 1
                brace_end += 1

            class_body = content[brace_start:brace_end]
            class_body_start_line = content[:brace_start].count('\n')

            http_verbs = [
                ('HttpGet', 'GET'),
                ('HttpPost', 'POST'),
                ('HttpPut', 'PUT'),
                ('HttpDelete', 'DELETE'),
                ('HttpPatch', 'PATCH'),
                ('HttpHead', 'HEAD'),
                ('HttpOptions', 'OPTIONS'),
            ]

            for verb_attr, http_method in http_verbs:
                patterns = [
                    # Standard: [HttpGet("route")] or [HttpGet]
                    rf'\[{verb_attr}(?:\s*\(\s*["\']([^"\']*)["\']\s*\)|\s*\(\s*\))?\s*\]',
                    # Fully qualified with optional route in same attribute
                    rf'\[Microsoft\.AspNetCore\.Mvc\.{verb_attr}(?:\s*\(\s*["\']([^"\']*)["\']\s*\))?\s*(?:,\s*Microsoft\.AspNetCore\.Mvc\.Route\s*\(\s*["\']([^"\']+)["\']\s*\))?\s*\]',
                ]

                for pattern in patterns:
                    for verb_match in re.finditer(pattern, class_body, re.IGNORECASE):
                        # Extract route from match groups
                        groups = verb_match.groups()
                        method_route = ""
                        for g in groups:
                            if g:
                                method_route = g
                                break

                        verb_pos = verb_match.start()
                        line_num = class_body_start_line + class_body[:verb_pos].count('\n') + 1

                        method_context_start = max(0, verb_pos - 300)
                        method_preceding = class_body[method_context_start:verb_pos]

                        # ASP.NET Web API 2 & Core: Support [Route("...")] attribute for method-level routes
                        method_route_attr = re.search(r'\[(?:Microsoft\.AspNetCore\.Mvc\.)?Route\s*\(\s*["\']([^"\']+)["\']\s*\)\]', method_preceding)
                        if method_route_attr and not method_route:
                            method_route = method_route_attr.group(1)

                        # Also check for [Route] after the verb attribute (common in Web API 2)
                        method_following_block = class_body[verb_pos:verb_pos + 500]
                        # Look for [Route("...")] between verb and method signature
                        route_after_verb = re.search(r'\]\s*\[Route\s*\(\s*["\']([^"\']+)["\']\s*\)\]', method_following_block)
                        if route_after_verb and not method_route:
                            method_route = route_after_verb.group(1)

                        method_following = class_body[verb_pos:verb_pos + 1000]  # Extended for parameter extraction
                        action_name = "Unknown"

                        sig_pattern = r'(?:public|private|protected)\s+(?:async\s+)?(?:virtual\s+)?(?:override\s+)?(?:Task<)?(?:IActionResult|ActionResult(?:<[^>]+>)?|IHttpActionResult|HttpResponseMessage|[\w<>\[\]]+)>?\s+(\w+)\s*\('
                        sig_match = re.search(sig_pattern, method_following)
                        if sig_match:
                            action_name = sig_match.group(1)

                        # Extract method parameters for payload discovery
                        method_params = self._extract_method_parameters(method_following)

                        if "[action]" in method_route.lower():
                            method_route = re.sub(r'\[action\]', action_name.lower(), method_route, flags=re.IGNORECASE)

                        full_route = self._combine_routes(base_route, method_route)

                        if not full_route or full_route == "/":
                            if base_route:
                                full_route = "/" + base_route.strip('/')
                            else:
                                ctrl_short = controller_name.replace("Controller", "").lower()
                                full_route = f"/api/{ctrl_short}"

                        auth_status = AuthStatus.UNKNOWN

                        auth_context_start = max(0, verb_pos - 200)
                        auth_context_end = min(len(class_body), verb_pos + 200)
                        auth_context = class_body[auth_context_start:auth_context_end]

                        if re.search(r'\[Authorize', auth_context, re.IGNORECASE):
                            auth_status = AuthStatus.PRIVATE
                        if re.search(r'\[Authorize', preceding_text, re.IGNORECASE):
                            auth_status = AuthStatus.PRIVATE
                        if re.search(r'\[ApiAuthorize', auth_context, re.IGNORECASE):
                            auth_status = AuthStatus.PRIVATE

                        if re.search(r'\[AllowAnonymous\]', auth_context, re.IGNORECASE):
                            auth_status = AuthStatus.PUBLIC

                        results.append(Endpoint(
                            file_path=str(file_path),
                            line_number=line_num,
                            language=self.language,
                            framework="ASP.NET",
                            kind=EndpointKind.ENDPOINT,
                            method=http_method,
                            route=full_route,
                            raw_match=verb_match.group(0),
                            context=self.get_context(lines, line_num - 1),
                            auth_status=auth_status,
                            metadata={
                                "controller": controller_name,
                                "action": action_name,
                                "base_route": base_route,
                                "method_route": method_route,
                                "parameters": method_params.get("parameters", []),
                                "request_body": method_params.get("request_body"),
                                "response_type": method_params.get("response_type"),
                            },
                        ))

        return results

    def _combine_routes(self, base_route: str, method_route: str) -> str:
        """Combine class-level base route with method-level route."""
        base = base_route.strip('/') if base_route else ""
        method = method_route.strip('/') if method_route else ""

        if method_route:
            if method_route.startswith("~/"):
                return "/" + method_route[2:].lstrip('/')
            if method_route.startswith("/"):
                return method_route

        if base and method:
            return f"/{base}/{method}"
        elif base:
            return f"/{base}"
        elif method:
            return f"/{method}"
        else:
            return "/"

    def scan_with_heuristics(self, file_path: Path, content: str, lines: List[str]) -> List[Endpoint]:
        """No additional heuristics - deep scanning handles all controller patterns."""
        return []

    def _extract_method_parameters(self, method_body: str) -> Dict[str, Any]:
        """
        Extract method parameters including request body DTOs, query params, and route params.
        Returns a dict with 'parameters' and 'request_body' info.
        """
        result: Dict[str, Any] = {
            "parameters": [],
            "request_body": None,
            "response_type": None
        }

        sig_pattern = r'(?:public|private|protected)\s+(?:async\s+)?(?:virtual\s+)?(?:override\s+)?(?:Task<)?(?:IActionResult|ActionResult(?:<([^>]+)>)?|IHttpActionResult|HttpResponseMessage|([A-Z]\w+))>?\s+\w+\s*\(([^)]*)\)'

        sig_match = re.search(sig_pattern, method_body, re.DOTALL)
        if not sig_match:
            return result

        response_type = sig_match.group(1) or sig_match.group(2)
        if response_type and response_type not in ('IActionResult', 'IHttpActionResult', 'HttpResponseMessage', 'Task'):
            result["response_type"] = response_type

        params_str = sig_match.group(3)
        if not params_str or not params_str.strip():
            return result

        params = self._split_parameters(params_str)

        for param in params:
            param = param.strip()
            if not param:
                continue

            param_info = self._parse_parameter(param)
            if param_info:
                if param_info.get("is_body"):
                    result["request_body"] = param_info
                else:
                    result["parameters"].append(param_info)

        return result

    def _split_parameters(self, params_str: str) -> List[str]:
        """Split parameter string handling nested generics."""
        params = []
        current = ""
        depth = 0

        for char in params_str:
            if char == '<':
                depth += 1
                current += char
            elif char == '>':
                depth -= 1
                current += char
            elif char == ',' and depth == 0:
                params.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            params.append(current.strip())

        return params

    def _parse_parameter(self, param: str) -> Optional[Dict[str, Any]]:
        """Parse a single parameter and determine its source and type."""
        from_body = bool(re.search(r'\[FromBody\]', param, re.IGNORECASE))
        from_query = bool(re.search(r'\[FromQuery\]', param, re.IGNORECASE))
        from_route = bool(re.search(r'\[FromRoute\]', param, re.IGNORECASE))
        from_uri = bool(re.search(r'\[FromUri\]', param, re.IGNORECASE))  # Web API 2

        # Remove attributes for type parsing
        clean_param = re.sub(r'\[[^\]]+\]\s*', '', param).strip()

        type_pattern = r'^([\w<>,\[\]\?\.]+)\s+(\w+)(?:\s*=\s*(.+))?$'
        match = re.match(type_pattern, clean_param)

        if not match:
            return None

        param_type = match.group(1)
        param_name = match.group(2)
        default_value = match.group(3)

        is_complex_type = self._is_complex_type(param_type)

        is_body = from_body or (is_complex_type and not from_query and not from_route and not from_uri)

        param_info = {
            "name": param_name,
            "type": param_type,
            "is_body": is_body,
            "is_query": from_query or from_uri or (not is_complex_type and not from_body and not from_route),
            "is_route": from_route,
            "required": default_value is None,
            "default": default_value,
            "schema": self._type_to_schema(param_type)
        }

        return param_info

    def _is_complex_type(self, type_name: str) -> bool:
        """Check if a type is a complex type (DTO/Model) vs primitive."""
        simple_types = {
            'int', 'long', 'short', 'byte', 'float', 'double', 'decimal',
            'bool', 'boolean', 'string', 'char', 'guid', 'datetime',
            'int32', 'int64', 'int16', 'uint', 'uint32', 'uint64',
            'timespan', 'datetimeoffset', 'object', 'dynamic'
        }

        clean_type = type_name.lower().replace('?', '').replace('[]', '')

        if re.match(r'^(list|ienumerable|icollection|array)<', clean_type):
            inner = re.search(r'<(.+)>', clean_type)
            if inner:
                return self._is_complex_type(inner.group(1))

        return clean_type not in simple_types

    def _type_to_schema(self, type_name: str) -> Dict[str, Any]:
        """Convert C# type to OpenAPI schema."""
        type_lower = type_name.lower().replace('?', '')
        nullable = '?' in type_name

        if type_lower in ('int', 'int32', 'short', 'int16', 'byte'):
            schema: Dict[str, Any] = {"type": "integer", "format": "int32"}
        elif type_lower in ('long', 'int64'):
            schema = {"type": "integer", "format": "int64"}
        elif type_lower in ('float', 'single'):
            schema = {"type": "number", "format": "float"}
        elif type_lower in ('double', 'decimal'):
            schema = {"type": "number", "format": "double"}
        elif type_lower in ('bool', 'boolean'):
            schema = {"type": "boolean"}
        elif type_lower == 'string':
            schema = {"type": "string"}
        elif type_lower == 'guid':
            schema = {"type": "string", "format": "uuid"}
        elif type_lower in ('datetime', 'datetimeoffset'):
            schema = {"type": "string", "format": "date-time"}
        elif type_lower == 'timespan':
            schema = {"type": "string", "format": "duration"}
        elif type_lower.endswith('[]'):
            inner_type = type_name[:-2]
            schema = {"type": "array", "items": self._type_to_schema(inner_type)}
        elif re.match(r'^(list|ienumerable|icollection|array)<', type_lower):
            inner = re.search(r'<(.+)>', type_name)
            if inner:
                schema = {"type": "array", "items": self._type_to_schema(inner.group(1))}
            else:
                schema = {"type": "array", "items": {"type": "object"}}
        else:
            schema = {"$ref": f"#/components/schemas/{type_name}"}

        if nullable:
            schema["nullable"] = True

        return schema


# =============================================================================
# DTO/MODEL SCHEMA EXTRACTOR
# =============================================================================

class DtoSchemaExtractor:
    """
    Extract DTO/Model class definitions and convert to OpenAPI schemas.
    Parses C# class files to build component schemas.
    """

    def __init__(self):
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self._files_content: Dict[str, str] = {}
        self._processed_types: Set[str] = set()

    def index_files(self, target_path: Path, ignore_dirs: Set[str]):
        """Index all C# files for DTO lookup."""
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]

            for f in files:
                if f.endswith('.cs'):
                    fp = Path(root) / f
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as file:
                            self._files_content[str(fp)] = file.read()
                    except IOError:
                        continue

    def extract_schema(self, type_name: str) -> Optional[Dict[str, Any]]:
        """Extract schema for a DTO type by searching through indexed files."""
        clean_name = type_name.split('.')[-1].replace('?', '').replace('[]', '')

        if clean_name in self._processed_types:
            return self.schemas.get(clean_name)

        self._processed_types.add(clean_name)

        for file_path, content in self._files_content.items():
            schema = self._extract_class_schema(clean_name, content)
            if schema:
                self.schemas[clean_name] = schema
                return schema

        return None

    def _extract_class_schema(self, class_name: str, content: str) -> Optional[Dict[str, Any]]:
        """Extract schema from a class definition."""
        class_pattern = rf'(?:public|internal)\s+(?:partial\s+)?(?:class|record|struct)\s+{re.escape(class_name)}(?:\s*<[^>]+>)?(?:\s*:\s*[^{{]+)?\s*\{{'

        match = re.search(class_pattern, content, re.IGNORECASE)
        if not match:
            return None

        class_start = match.end() - 1
        brace_depth = 1
        class_end = class_start + 1

        while brace_depth > 0 and class_end < len(content):
            if content[class_end] == '{':
                brace_depth += 1
            elif content[class_end] == '}':
                brace_depth -= 1
            class_end += 1

        class_body = content[class_start:class_end]

        properties: Dict[str, Any] = {}
        required: List[str] = []

        prop_pattern = r'(?:\[([^\]]+)\]\s*)*(?:public|internal)\s+([\w<>,\[\]\?\.]+)\s+(\w+)\s*\{\s*get;'

        for prop_match in re.finditer(prop_pattern, class_body):
            attributes = prop_match.group(1) or ""
            prop_type = prop_match.group(2)
            prop_name = prop_match.group(3)

            if prop_name.startswith('_'):
                continue

            json_name = prop_name
            json_prop_match = re.search(r'JsonProperty\s*\(\s*["\']([^"\']+)["\']', attributes)
            if json_prop_match:
                json_name = json_prop_match.group(1)

            json_key = json_name[0].lower() + json_name[1:] if json_name else json_name

            prop_schema = self._type_to_openapi_schema(prop_type)
            properties[json_key] = prop_schema

            if 'Required' in attributes:
                required.append(json_key)

            if '$ref' in prop_schema or (prop_schema.get('type') == 'array' and '$ref' in prop_schema.get('items', {})):
                nested_type = prop_type.replace('?', '').replace('[]', '')
                generic_match = re.search(r'<(.+)>', nested_type)
                if generic_match:
                    nested_type = generic_match.group(1)

                if nested_type not in self._processed_types:
                    self.extract_schema(nested_type)

        schema: Dict[str, Any] = {
            "type": "object",
            "properties": properties
        }

        if required:
            schema["required"] = required

        return schema if properties else None

    def _type_to_openapi_schema(self, type_name: str) -> Dict[str, Any]:
        """Convert C# type to OpenAPI schema."""
        type_lower = type_name.lower().replace('?', '')
        nullable = '?' in type_name

        if type_lower in ('int', 'int32', 'short', 'int16', 'byte'):
            schema: Dict[str, Any] = {"type": "integer", "format": "int32"}
        elif type_lower in ('long', 'int64'):
            schema = {"type": "integer", "format": "int64"}
        elif type_lower in ('float', 'single'):
            schema = {"type": "number", "format": "float"}
        elif type_lower in ('double', 'decimal'):
            schema = {"type": "number", "format": "double"}
        elif type_lower in ('bool', 'boolean'):
            schema = {"type": "boolean"}
        elif type_lower == 'string':
            schema = {"type": "string"}
        elif type_lower == 'guid':
            schema = {"type": "string", "format": "uuid"}
        elif type_lower in ('datetime', 'datetimeoffset'):
            schema = {"type": "string", "format": "date-time"}
        elif type_lower == 'timespan':
            schema = {"type": "string", "format": "duration"}
        elif type_lower == 'object':
            schema = {"type": "object"}
        elif type_lower.endswith('[]'):
            inner_type = type_name[:-2]
            schema = {"type": "array", "items": self._type_to_openapi_schema(inner_type)}
        elif re.match(r'^(list|ienumerable|icollection|ilist|array|hashset)<', type_lower):
            inner = re.search(r'<(.+)>', type_name)
            if inner:
                schema = {"type": "array", "items": self._type_to_openapi_schema(inner.group(1))}
            else:
                schema = {"type": "array", "items": {"type": "object"}}
        elif re.match(r'^(dictionary|idictionary|concurrentdictionary)<', type_lower):
            schema = {"type": "object", "additionalProperties": True}
        else:
            clean_type = type_name.split('.')[-1].replace('?', '').replace('[]', '')
            clean_type = re.sub(r'<.+>', '', clean_type)
            schema = {"$ref": f"#/components/schemas/{clean_type}"}

        if nullable and '$ref' not in schema:
            schema["nullable"] = True

        return schema

    def _is_nullable_reference(self, type_name: str) -> bool:
        """Check if type is a nullable reference type."""
        simple_types = {'int', 'long', 'short', 'byte', 'float', 'double', 'decimal',
                        'bool', 'boolean', 'char', 'guid', 'datetime', 'timespan'}
        return type_name.lower() not in simple_types
