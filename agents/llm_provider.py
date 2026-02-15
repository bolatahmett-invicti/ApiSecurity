#!/usr/bin/env python3
"""
LLM Provider Abstraction Layer
===============================
Unified interface for multiple LLM providers (Claude, GPT, Gemini, Bedrock).

This allows agents to work with any LLM provider without code changes.
Simply configure the provider via environment variables.

Supported Providers:
- Anthropic Claude (default)
- OpenAI GPT-4
- Google Gemini
- AWS Bedrock (Claude, Llama, etc.)

Usage:
    provider = LLMProviderFactory.create(
        provider_type="anthropic",
        api_key="sk-ant-...",
        model="claude-sonnet-4-5-20250929"
    )
    response = await provider.generate(system_prompt, user_prompt)
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging
import os

logger = logging.getLogger("api_scanner.llm_provider")


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    All providers must implement the generate() method to return text responses.
    """

    def __init__(self, api_key: str, model: str, max_tokens: int = 4096):
        """
        Initialize provider.

        Args:
            api_key: API key for the provider
            model: Model identifier
            max_tokens: Maximum tokens for response
        """
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self._client = None

    @property
    @abstractmethod
    def client(self):
        """Lazy initialization of provider client."""
        pass

    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0
    ) -> str:
        """
        Generate text completion.

        Args:
            system_prompt: System instructions
            user_prompt: User query
            temperature: Sampling temperature (0.0 = deterministic)

        Returns:
            Generated text response

        Raises:
            Exception: If generation fails
        """
        pass

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """
        Count tokens in text (approximate).

        Args:
            text: Text to count tokens for

        Returns:
            Approximate token count
        """
        pass

    def get_provider_name(self) -> str:
        """Get human-readable provider name."""
        return self.__class__.__name__.replace("Provider", "")


# =============================================================================
# Anthropic Claude Provider
# =============================================================================
class AnthropicProvider(LLMProvider):
    """
    Anthropic Claude provider.

    Models:
    - claude-sonnet-4-5-20250929 (recommended)
    - claude-opus-4-6 (most capable)
    - claude-haiku-4-5-20251001 (fastest, cheapest)
    """

    @property
    def client(self):
        """Lazy initialization of Anthropic client."""
        if self._client is None:
            try:
                from anthropic import Anthropic
                self._client = Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("anthropic package not installed. Run: pip install anthropic")
        return self._client

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0
    ) -> str:
        """Generate with Claude."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        )
        return response.content[0].text

    def count_tokens(self, text: str) -> int:
        """Approximate token count (Claude uses ~4 chars/token)."""
        return len(text) // 4


# =============================================================================
# OpenAI GPT Provider
# =============================================================================
class OpenAIProvider(LLMProvider):
    """
    OpenAI GPT provider.

    Models:
    - gpt-4-turbo (recommended for quality)
    - gpt-4o (faster, cheaper)
    - gpt-4o-mini (fastest, cheapest)
    """

    @property
    def client(self):
        """Lazy initialization of OpenAI client."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                self._client = AsyncOpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("openai package not installed. Run: pip install openai")
        return self._client

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0
    ) -> str:
        """Generate with GPT."""
        response = await self.client.chat.completions.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        return response.choices[0].message.content

    def count_tokens(self, text: str) -> int:
        """Token count using tiktoken."""
        try:
            import tiktoken
            encoding = tiktoken.encoding_for_model(self.model)
            return len(encoding.encode(text))
        except:
            # Fallback: approximate
            return len(text) // 4


# =============================================================================
# Google Gemini Provider
# =============================================================================
class GeminiProvider(LLMProvider):
    """
    Google Gemini provider.

    Models:
    - gemini-1.5-pro (recommended)
    - gemini-1.5-flash (faster, cheaper)
    """

    @property
    def client(self):
        """Lazy initialization of Gemini client."""
        if self._client is None:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(self.model)
            except ImportError:
                raise ImportError("google-generativeai package not installed. Run: pip install google-generativeai")
        return self._client

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0
    ) -> str:
        """Generate with Gemini."""
        # Gemini combines system and user prompts
        combined_prompt = f"{system_prompt}\n\n{user_prompt}"

        generation_config = {
            "max_output_tokens": self.max_tokens,
            "temperature": temperature,
        }

        response = self.client.generate_content(
            combined_prompt,
            generation_config=generation_config
        )
        return response.text

    def count_tokens(self, text: str) -> int:
        """Approximate token count."""
        return len(text) // 4


# =============================================================================
# AWS Bedrock Provider
# =============================================================================
class BedrockProvider(LLMProvider):
    """
    AWS Bedrock provider (supports multiple models).

    Models:
    - anthropic.claude-3-5-sonnet-20241022-v2:0 (Claude via Bedrock)
    - meta.llama3-70b-instruct-v1:0 (Llama 3)
    - mistral.mistral-large-2402-v1:0 (Mistral)
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        max_tokens: int = 4096,
        region: str = "us-east-1"
    ):
        """
        Initialize Bedrock provider.

        Args:
            api_key: AWS access key (or use IAM role)
            model: Bedrock model ID
            max_tokens: Maximum tokens
            region: AWS region
        """
        super().__init__(api_key, model, max_tokens)
        self.region = region

    @property
    def client(self):
        """Lazy initialization of Bedrock client."""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client(
                    "bedrock-runtime",
                    region_name=self.region,
                    aws_access_key_id=self.api_key,
                    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
                )
            except ImportError:
                raise ImportError("boto3 package not installed. Run: pip install boto3")
        return self._client

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0
    ) -> str:
        """Generate with Bedrock."""
        import json

        # Format depends on model (Claude vs Llama vs Mistral)
        if "claude" in self.model.lower():
            # Claude format via Bedrock
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "temperature": temperature,
                "system": system_prompt,
                "messages": [
                    {"role": "user", "content": user_prompt}
                ]
            })
        elif "llama" in self.model.lower():
            # Llama format
            body = json.dumps({
                "prompt": f"{system_prompt}\n\nUser: {user_prompt}\n\nAssistant:",
                "max_gen_len": self.max_tokens,
                "temperature": temperature,
            })
        else:
            # Generic format (Mistral, etc.)
            body = json.dumps({
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "max_tokens": self.max_tokens,
                "temperature": temperature,
            })

        response = self.client.invoke_model(
            modelId=self.model,
            body=body
        )

        response_body = json.loads(response["body"].read())

        # Extract text based on model
        if "claude" in self.model.lower():
            return response_body["content"][0]["text"]
        elif "llama" in self.model.lower():
            return response_body["generation"]
        else:
            return response_body.get("outputs", [{}])[0].get("text", "")

    def count_tokens(self, text: str) -> int:
        """Approximate token count."""
        return len(text) // 4


# =============================================================================
# Provider Factory
# =============================================================================
class LLMProviderFactory:
    """
    Factory for creating LLM providers.

    Usage:
        provider = LLMProviderFactory.create(
            provider_type="anthropic",
            api_key="sk-ant-...",
            model="claude-sonnet-4-5-20250929"
        )
    """

    _providers = {
        "anthropic": AnthropicProvider,
        "openai": OpenAIProvider,
        "gemini": GeminiProvider,
        "bedrock": BedrockProvider,
    }

    @classmethod
    def create(
        cls,
        provider_type: str,
        api_key: str,
        model: str,
        max_tokens: int = 4096,
        **kwargs
    ) -> LLMProvider:
        """
        Create LLM provider instance.

        Args:
            provider_type: Provider type (anthropic, openai, gemini, bedrock)
            api_key: API key for the provider
            model: Model identifier
            max_tokens: Maximum tokens for response
            **kwargs: Additional provider-specific arguments

        Returns:
            LLMProvider instance

        Raises:
            ValueError: If provider type is not supported
        """
        provider_type = provider_type.lower()

        if provider_type not in cls._providers:
            raise ValueError(
                f"Unsupported provider: {provider_type}. "
                f"Supported: {', '.join(cls._providers.keys())}"
            )

        provider_class = cls._providers[provider_type]
        return provider_class(api_key, model, max_tokens, **kwargs)

    @classmethod
    def from_env(cls) -> LLMProvider:
        """
        Create provider from environment variables.

        Environment Variables:
            LLM_PROVIDER: Provider type (default: anthropic)
            LLM_API_KEY: API key (falls back to provider-specific keys)
            LLM_MODEL: Model identifier
            LLM_MAX_TOKENS: Maximum tokens (default: 4096)
            AWS_REGION: AWS region for Bedrock (default: us-east-1)

        Returns:
            LLM Provider instance
        """
        provider_type = os.getenv("LLM_PROVIDER", "anthropic")
        model = os.getenv("LLM_MODEL", cls._get_default_model(provider_type))
        max_tokens = int(os.getenv("LLM_MAX_TOKENS", "4096"))

        # Try LLM_API_KEY first, then provider-specific keys
        api_key = os.getenv("LLM_API_KEY")
        if not api_key:
            api_key = cls._get_provider_specific_key(provider_type)

        if not api_key:
            raise ValueError(
                f"No API key found for {provider_type}. "
                f"Set LLM_API_KEY or {cls._get_provider_key_name(provider_type)}"
            )

        kwargs = {}
        if provider_type == "bedrock":
            kwargs["region"] = os.getenv("AWS_REGION", "us-east-1")

        return cls.create(provider_type, api_key, model, max_tokens, **kwargs)

    @staticmethod
    def _get_default_model(provider_type: str) -> str:
        """Get default model for provider."""
        defaults = {
            "anthropic": "claude-sonnet-4-5-20250929",
            "openai": "gpt-4-turbo",
            "gemini": "gemini-1.5-pro",
            "bedrock": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        }
        return defaults.get(provider_type, "")

    @staticmethod
    def _get_provider_specific_key(provider_type: str) -> Optional[str]:
        """Get provider-specific API key from environment."""
        key_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "gemini": "GOOGLE_API_KEY",
            "bedrock": "AWS_ACCESS_KEY_ID",
        }
        key_name = key_map.get(provider_type)
        return os.getenv(key_name) if key_name else None

    @staticmethod
    def _get_provider_key_name(provider_type: str) -> str:
        """Get environment variable name for provider API key."""
        key_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "gemini": "GOOGLE_API_KEY",
            "bedrock": "AWS_ACCESS_KEY_ID",
        }
        return key_map.get(provider_type, "LLM_API_KEY")

    @classmethod
    def list_providers(cls) -> list:
        """List all supported providers."""
        return list(cls._providers.keys())
