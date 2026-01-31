// Sample MCP Server - TypeScript Implementation
// Demonstrates MCP tool, resource, and prompt patterns for Node.js

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    ListResourcesRequestSchema,
    ReadResourceRequestSchema,
    ListPromptsRequestSchema,
    GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// Create the MCP server
const server = new Server(
    {
        name: "sample-mcp-server-ts",
        version: "1.0.0",
    },
    {
        capabilities: {
            tools: {},
            resources: {},
            prompts: {},
        },
    }
);

// =============================================================================
// MCP TOOLS - Functions that the LLM can call
// =============================================================================

// Handler for listing available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "get_stock_price",
                description: "Get the current stock price for a ticker symbol",
                inputSchema: {
                    type: "object",
                    properties: {
                        ticker: {
                            type: "string",
                            description: "Stock ticker symbol (e.g., AAPL, GOOGL)"
                        }
                    },
                    required: ["ticker"]
                }
            },
            {
                name: "send_email",
                description: "Send an email to a recipient",
                inputSchema: {
                    type: "object",
                    properties: {
                        to: { type: "string", description: "Recipient email" },
                        subject: { type: "string", description: "Email subject" },
                        body: { type: "string", description: "Email body" }
                    },
                    required: ["to", "subject", "body"]
                }
            },
            {
                name: "query_database",
                description: "Execute a database query (requires authentication)",
                inputSchema: {
                    type: "object",
                    properties: {
                        sql: { type: "string", description: "SQL query to execute" },
                        database: { type: "string", description: "Target database" }
                    },
                    required: ["sql"]
                }
            },
            {
                name: "get_user_profile",
                description: "Retrieve user profile including PII data",
                inputSchema: {
                    type: "object",
                    properties: {
                        userId: { type: "string", description: "User ID" }
                    },
                    required: ["userId"]
                }
            },
            {
                name: "process_payment",
                description: "Process a credit card payment",
                inputSchema: {
                    type: "object",
                    properties: {
                        amount: { type: "number", description: "Payment amount" },
                        currency: { type: "string", description: "Currency code" },
                        cardToken: { type: "string", description: "Tokenized card" }
                    },
                    required: ["amount", "cardToken"]
                }
            },
            {
                name: "delete_user",
                description: "Permanently delete a user account (ADMIN ONLY)",
                inputSchema: {
                    type: "object",
                    properties: {
                        userId: { type: "string", description: "User ID to delete" },
                        confirm: { type: "boolean", description: "Confirmation flag" }
                    },
                    required: ["userId", "confirm"]
                }
            }
        ]
    };
});

// Handler for calling tools
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
        case "get_stock_price":
            return {
                content: [
                    {
                        type: "text",
                        text: `Stock price for ${args?.ticker}: $150.25`
                    }
                ]
            };

        case "send_email":
            return {
                content: [
                    {
                        type: "text",
                        text: `Email sent to ${args?.to}`
                    }
                ]
            };

        case "query_database":
            // DANGEROUS: Direct SQL execution
            return {
                content: [
                    {
                        type: "text",
                        text: `Query executed: ${args?.sql}`
                    }
                ]
            };

        case "get_user_profile":
            // Returns PII data
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify({
                            userId: args?.userId,
                            email: "user@example.com",
                            phone: "555-123-4567",
                            ssn: "123-45-6789",
                            address: "123 Main St"
                        })
                    }
                ]
            };

        case "process_payment":
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify({
                            status: "success",
                            transactionId: "txn_abc123",
                            amount: args?.amount
                        })
                    }
                ]
            };

        case "delete_user":
            // CRITICAL: User deletion
            return {
                content: [
                    {
                        type: "text",
                        text: `User ${args?.userId} deleted`
                    }
                ]
            };

        default:
            throw new Error(`Unknown tool: ${name}`);
    }
});

// =============================================================================
// MCP RESOURCES - Data sources that can be read
// =============================================================================

server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
        resources: [
            {
                uri: "config://app/settings",
                name: "Application Settings",
                description: "Main application configuration",
                mimeType: "application/json"
            },
            {
                uri: "db://schema/users",
                name: "Users Table Schema",
                description: "Database schema for users table",
                mimeType: "application/json"
            },
            {
                uri: "secrets://credentials",
                name: "API Credentials",
                description: "Stored API credentials (SENSITIVE)",
                mimeType: "application/json"
            },
            {
                uri: "logs://system/recent",
                name: "Recent System Logs",
                description: "Last 100 system log entries",
                mimeType: "text/plain"
            }
        ]
    };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;

    switch (uri) {
        case "config://app/settings":
            return {
                contents: [
                    {
                        uri,
                        mimeType: "application/json",
                        text: JSON.stringify({
                            debug: true,
                            logLevel: "verbose",
                            features: ["payments", "notifications"]
                        })
                    }
                ]
            };

        case "db://schema/users":
            return {
                contents: [
                    {
                        uri,
                        mimeType: "application/json",
                        text: JSON.stringify({
                            tableName: "users",
                            columns: ["id", "email", "password_hash", "ssn", "created_at"]
                        })
                    }
                ]
            };

        case "secrets://credentials":
            // DANGER: Exposing secrets
            return {
                contents: [
                    {
                        uri,
                        mimeType: "application/json",
                        text: JSON.stringify({
                            stripeKey: "sk_test_xxx",
                            openaiKey: "sk-xxx",
                            databasePassword: "super_secret_123"
                        })
                    }
                ]
            };

        default:
            throw new Error(`Unknown resource: ${uri}`);
    }
});

// =============================================================================
// MCP PROMPTS - Predefined prompt templates
// =============================================================================

server.setRequestHandler(ListPromptsRequestSchema, async () => {
    return {
        prompts: [
            {
                name: "analyze_code",
                description: "Analyze code for security vulnerabilities",
                arguments: [
                    {
                        name: "code",
                        description: "Code to analyze",
                        required: true
                    },
                    {
                        name: "language",
                        description: "Programming language",
                        required: false
                    }
                ]
            },
            {
                name: "generate_report",
                description: "Generate a security assessment report",
                arguments: [
                    {
                        name: "target",
                        description: "Target system or application",
                        required: true
                    }
                ]
            },
            {
                name: "customer_lookup",
                description: "Look up customer information (includes PII)",
                arguments: [
                    {
                        name: "customerId",
                        description: "Customer ID to look up",
                        required: true
                    }
                ]
            }
        ]
    };
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
        case "analyze_code":
            return {
                messages: [
                    {
                        role: "user",
                        content: {
                            type: "text",
                            text: `Please analyze this ${args?.language || "code"} for security issues:\n\n${args?.code}`
                        }
                    }
                ]
            };

        case "generate_report":
            return {
                messages: [
                    {
                        role: "user",
                        content: {
                            type: "text",
                            text: `Generate a security assessment report for: ${args?.target}`
                        }
                    }
                ]
            };

        case "customer_lookup":
            return {
                messages: [
                    {
                        role: "user",
                        content: {
                            type: "text",
                            text: `Look up all information for customer: ${args?.customerId}`
                        }
                    }
                ]
            };

        default:
            throw new Error(`Unknown prompt: ${name}`);
    }
});

// =============================================================================
// Server startup
// =============================================================================

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("MCP Server running on stdio");
}

main().catch(console.error);
