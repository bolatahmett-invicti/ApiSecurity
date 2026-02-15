#!/bin/bash
# =============================================================================
# Test Mock LLM Provider
# =============================================================================
# This script tests the API scanner with the mock LLM provider
# instead of making real API calls (saves money during development/testing)
#
# Usage:
#   bash test_mock_provider.sh [quality]
#
# Quality levels:
#   - high:   Perfect JSON (default)
#   - medium: Occasional missing commas (tests parser resilience)
#   - low:    Multiple JSON issues (stress test)
# =============================================================================

# Configuration
QUALITY="${1:-high}"
TEST_DIR="./test-microservices/auth-service"

# Check if test directory exists (use ApiSecurity_TestApp if available)
if [ ! -d "$TEST_DIR" ]; then
    if [ -d "../ApiSecurity_TestApp/test-microservices/auth-service" ]; then
        TEST_DIR="../ApiSecurity_TestApp/test-microservices/auth-service"
    else
        echo "❌ Test directory not found: $TEST_DIR"
        echo "Please run from ApiSecurity directory or provide path to auth-service"
        exit 1
    fi
fi

echo "🧪 Testing API Scanner with Mock LLM Provider"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📁 Target:  $TEST_DIR"
echo "🎚️  Quality: $QUALITY"
echo "💰 Cost:    $0.00 (mock - no real API calls)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Set environment variables
export LLM_PROVIDER=mock
export MOCK_LLM_QUALITY=$QUALITY
export SCANNER_AI_ENRICH=true

# Run scanner with AI enrichment
python main.py "$TEST_DIR" \
    --ai-enrich \
    --export-openapi ./output/mock-test-openapi.json \
    --quiet

# Check results
if [ $? -eq 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ Mock test completed successfully!"
    echo ""

    if [ -f "./output/mock-test-openapi.json" ]; then
        ENDPOINTS=$(python3 -c "import json; print(len(json.load(open('./output/mock-test-openapi.json')).get('paths', {})))" 2>/dev/null || echo "N/A")
        echo "📊 Results:"
        echo "   - Endpoints found: $ENDPOINTS"
        echo "   - OpenAPI spec:    ./output/mock-test-openapi.json"
        echo "   - API calls made:  0 (mock)"
        echo "   - Total cost:      $0.00"
    fi

    echo ""
    echo "💡 Next steps:"
    echo "   - Review generated OpenAPI spec: cat ./output/mock-test-openapi.json | jq"
    echo "   - Test with different quality: bash test_mock_provider.sh medium"
    echo "   - Test with real provider: export LLM_PROVIDER=anthropic && python main.py ..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ Mock test failed!"
    echo "Check the error messages above for details."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi
