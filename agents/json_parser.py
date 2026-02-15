#!/usr/bin/env python3
"""
Robust JSON Parser for LLM Responses
=====================================
Handles common JSON syntax errors that LLMs make across different providers
(Claude, GPT-4, Gemini, etc.)

This parser tries multiple strategies to extract valid JSON from LLM responses:
1. Standard JSON parsing
2. Markdown code block extraction
3. Comment removal (// and /* */)
4. Trailing comma fixes
5. Quote fixing and escaping
6. Multiple fallback strategies
"""

import json
import re
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("api_scanner.agents.json_parser")


class RobustJSONParser:
    """
    Robust JSON parser that handles common LLM response issues.

    Designed to work with responses from:
    - Anthropic Claude
    - OpenAI GPT-4
    - Google Gemini
    - AWS Bedrock models
    """

    @staticmethod
    def parse(response: str, context: str = "LLM response") -> Dict[str, Any]:
        """
        Parse JSON from LLM response with multiple fallback strategies.

        Args:
            response: Raw response text from LLM
            context: Context string for error messages (e.g., "operation object")

        Returns:
            Parsed JSON dictionary

        Raises:
            json.JSONDecodeError: If all parsing strategies fail
        """
        if not response or not response.strip():
            raise ValueError(f"Empty {context}")

        # Strategy 1: Direct JSON parsing
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass

        # Strategy 2: Extract from markdown code block
        try:
            json_str = RobustJSONParser._extract_from_markdown(response)
            if json_str:
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Strategy 3: Clean and parse
        try:
            json_str = RobustJSONParser._clean_json_string(response)
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            # Log the cleaned JSON for debugging
            logger.debug(f"Failed to parse cleaned JSON: {json_str[:500]}")

            # Strategy 4: Aggressive cleaning
            try:
                json_str = RobustJSONParser._aggressive_clean(response)
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

            # All strategies failed - provide helpful error
            logger.error(f"Failed to parse {context} after all strategies")
            logger.debug(f"Original response: {response[:1000]}")
            logger.debug(f"Last JSON parse error: {e}")
            raise json.JSONDecodeError(
                f"Could not parse {context} as JSON after trying multiple strategies. "
                f"Last error: {str(e)}",
                response[:200],
                0
            )

    @staticmethod
    def _extract_from_markdown(text: str) -> Optional[str]:
        """
        Extract JSON from markdown code blocks.

        Handles:
        ```json
        {...}
        ```
        or
        ```
        {...}
        ```
        """
        # Try to find JSON code block
        patterns = [
            r'```json\s*\n(.*?)\n```',
            r'```\s*\n(.*?)\n```',
            r'```json(.*?)```',
            r'```(.*?)```',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(1).strip()

        return None

    @staticmethod
    def _clean_json_string(text: str) -> str:
        """
        Clean JSON string by removing common LLM mistakes.

        Handles:
        - Comments (// and /* */)
        - Trailing commas
        - Leading/trailing non-JSON text
        - Multiple JSON objects (takes first)
        """
        # Remove comments (// style)
        text = re.sub(r'//.*?$', '', text, flags=re.MULTILINE)

        # Remove comments (/* */ style)
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)

        # Extract first JSON object or array
        text = text.strip()

        # Find the start of JSON
        start_chars = ['{', '[']
        start_idx = -1
        start_char = None
        for char in start_chars:
            idx = text.find(char)
            if idx != -1 and (start_idx == -1 or idx < start_idx):
                start_idx = idx
                start_char = char

        if start_idx == -1:
            return text

        text = text[start_idx:]

        # Find the matching end
        if start_char == '{':
            end_char = '}'
        else:
            end_char = ']'

        # Count braces/brackets to find matching end
        count = 0
        in_string = False
        escape_next = False
        end_idx = -1

        for i, char in enumerate(text):
            if escape_next:
                escape_next = False
                continue

            if char == '\\':
                escape_next = True
                continue

            if char == '"' and not escape_next:
                in_string = not in_string
                continue

            if not in_string:
                if char == start_char:
                    count += 1
                elif char == end_char:
                    count -= 1
                    if count == 0:
                        end_idx = i
                        break

        if end_idx != -1:
            text = text[:end_idx + 1]

        # Remove trailing commas before closing braces/brackets
        text = re.sub(r',(\s*[}\]])', r'\1', text)

        return text.strip()

    @staticmethod
    def _aggressive_clean(text: str) -> str:
        """
        Aggressive cleaning for badly malformed JSON.

        This is a last resort that tries to fix common syntax errors.
        """
        # First do basic cleaning
        text = RobustJSONParser._clean_json_string(text)

        # Fix common quote issues
        # Replace smart quotes with regular quotes
        text = text.replace('"', '"').replace('"', '"')
        text = text.replace(''', "'").replace(''', "'")

        # Fix missing commas between properties (heuristic)
        # Pattern 1: "value"\n"key" -> "value",\n"key"
        text = re.sub(r'"\s*\n\s*"', '",\n"', text)

        # Pattern 2: }\n"key" -> },\n"key" (object followed by property)
        text = re.sub(r'}\s*\n\s*"', '},\n"', text)

        # Pattern 3: ]\n"key" -> ],\n"key" (array followed by property)
        text = re.sub(r']\s*\n\s*"', '],\n"', text)

        # Pattern 4: true/false/null/number\n"key" -> value,\n"key"
        text = re.sub(r'(true|false|null|\d+)\s*\n\s*"', r'\1,\n"', text)

        # Fix missing commas between objects in arrays
        # Look for patterns like: }\n{ and add comma
        text = re.sub(r'}\s*\n\s*{', '},\n{', text)

        # Remove trailing commas (again, more aggressively)
        text = re.sub(r',\s*}', '}', text)
        text = re.sub(r',\s*]', ']', text)

        # Fix unescaped quotes in strings (heuristic - risky)
        # This is very tricky and might break valid JSON
        # Only do minimal fixes

        return text.strip()

    @staticmethod
    def safe_parse(response: str, context: str = "LLM response",
                   default: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Safe JSON parsing that returns None or default on error instead of raising.

        Args:
            response: Raw response text
            context: Context for error messages
            default: Default value to return on error (default: None)

        Returns:
            Parsed JSON or default value
        """
        try:
            return RobustJSONParser.parse(response, context)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse {context}: {e}")
            return default


# Convenience function for direct import
def parse_llm_json(response: str, context: str = "LLM response") -> Dict[str, Any]:
    """
    Parse JSON from LLM response with robust error handling.

    This is the main function to use for parsing LLM JSON responses.
    """
    return RobustJSONParser.parse(response, context)
