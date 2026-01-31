# Sample MCP Server - Python Implementation
# Demonstrates MCP tool, resource, and prompt patterns

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import Tool, Resource, Prompt, TextContent
import mcp.server.stdio as stdio_server
import json

# Create MCP server instance
server = Server("sample-mcp-server")

# =============================================================================
# MCP TOOLS - Functions that the LLM can call
# =============================================================================

@server.list_tools()
async def handle_list_tools():
    """List available tools for the MCP client."""
    return [
        Tool(
            name="get_weather",
            description="Get the current weather for a location",
            inputSchema={
                "type": "object",
                "properties": {
                    "location": {"type": "string", "description": "City name"}
                },
                "required": ["location"]
            }
        ),
        Tool(
            name="search_database",
            description="Search the internal database for records",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "default": 10}
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="execute_sql",
            description="Execute a SQL query (DANGEROUS - admin only)",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "database": {"type": "string"}
                },
                "required": ["query"]
            }
        ),
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict):
    """Handle tool execution requests."""
    if name == "get_weather":
        location = arguments.get("location", "Unknown")
        return [TextContent(type="text", text=f"Weather in {location}: Sunny, 72F")]
    
    elif name == "search_database":
        query = arguments.get("query", "")
        return [TextContent(type="text", text=f"Found 5 results for: {query}")]
    
    elif name == "execute_sql":
        query = arguments.get("query", "")
        return [TextContent(type="text", text=f"Executed: {query}")]
    
    else:
        raise ValueError(f"Unknown tool: {name}")

# Alternative tool definition style using decorator
@server.tool()
async def calculate_sum(a: int, b: int) -> str:
    """Add two numbers together."""
    return str(a + b)

@server.tool()
async def fetch_user_data(user_id: str) -> str:
    """Fetch user data including PII (email, phone, ssn)."""
    return json.dumps({
        "user_id": user_id,
        "email": "user@example.com",
        "phone": "555-1234",
        "ssn": "123-45-6789"
    })

@server.tool()
async def process_payment(amount: float, credit_card: str) -> str:
    """Process a payment transaction."""
    return json.dumps({"status": "success", "transaction_id": "txn_123"})

# =============================================================================
# MCP RESOURCES - Data sources that can be read
# =============================================================================

@server.list_resources()
async def handle_list_resources():
    """List available resources."""
    return [
        Resource(
            uri="file:///config/settings.json",
            name="Application Settings",
            description="Configuration settings for the application",
            mimeType="application/json"
        ),
        Resource(
            uri="db://users/schema",
            name="Users Database Schema",
            description="Schema definition for the users table",
            mimeType="application/json"
        ),
        Resource(
            uri="secret://api-keys",
            name="API Keys",
            description="Stored API keys (SENSITIVE)",
            mimeType="application/json"
        ),
    ]

@server.read_resource()
async def handle_read_resource(uri: str):
    """Read a specific resource by URI."""
    if uri == "file:///config/settings.json":
        return json.dumps({"debug": True, "log_level": "info"})
    elif uri == "db://users/schema":
        return json.dumps({"columns": ["id", "email", "password_hash"]})
    elif uri == "secret://api-keys":
        return json.dumps({"openai": "sk-xxx", "stripe": "sk_test_xxx"})
    else:
        raise ValueError(f"Unknown resource: {uri}")

# Alternative resource definition
@server.resource("memory://cache/{key}")
async def get_cache_item(key: str) -> str:
    """Get an item from the memory cache."""
    return json.dumps({"key": key, "value": "cached_value"})

# =============================================================================
# MCP PROMPTS - Predefined prompt templates
# =============================================================================

@server.list_prompts()
async def handle_list_prompts():
    """List available prompt templates."""
    return [
        Prompt(
            name="code_review",
            description="Review code for security issues",
            arguments=[
                {"name": "code", "description": "Code to review", "required": True},
                {"name": "language", "description": "Programming language", "required": False}
            ]
        ),
        Prompt(
            name="data_analysis",
            description="Analyze dataset for insights",
            arguments=[
                {"name": "dataset", "description": "Dataset name", "required": True}
            ]
        ),
    ]

@server.prompt("summarize_document")
async def summarize_document(document: str, max_length: int = 500) -> str:
    """Summarize a document to the specified length."""
    return f"Please summarize the following document in {max_length} words or less:\n\n{document}"

# =============================================================================
# Server startup
# =============================================================================

async def main():
    """Main entry point for the MCP server."""
    async with stdio_server.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="sample-mcp-server",
                server_version="1.0.0",
            )
        )

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
