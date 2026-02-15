# Testing Guide

## Testing Without API Costs (Mock Provider)

### Quick Start

```bash
# Test with perfect JSON responses (default)
export LLM_PROVIDER=mock
python main.py ./test-microservices/auth-service --ai-enrich

# Test with JSON parsing challenges
export LLM_PROVIDER=mock
export MOCK_LLM_QUALITY=medium  # or 'low'
python main.py ./test-microservices/auth-service --ai-enrich
```

### Using Test Script

```bash
# Perfect JSON (high quality)
bash test_mock_provider.sh high

# Test JSON parser resilience (medium quality - occasional errors)
bash test_mock_provider.sh medium

# Stress test parser (low quality - multiple errors)
bash test_mock_provider.sh low
```

## Mock Provider Quality Levels

### High Quality (Default)
- **JSON:** Perfect, valid JSON every time
- **Use case:** Verify scanner logic without API costs
- **Cost:** $0.00
- **Example:**
  ```bash
  export LLM_PROVIDER=mock
  export MOCK_LLM_QUALITY=high
  ```

### Medium Quality
- **JSON:** Occasional missing commas (1 in 3 responses)
- **Use case:** Test JSON parser resilience
- **Cost:** $0.00
- **Example:**
  ```bash
  export LLM_PROVIDER=mock
  export MOCK_LLM_QUALITY=medium
  ```

### Low Quality
- **JSON:** Multiple syntax errors (missing commas, trailing commas)
- **Use case:** Stress test parser and error handling
- **Cost:** $0.00
- **Example:**
  ```bash
  export LLM_PROVIDER=mock
  export MOCK_LLM_QUALITY=low
  ```

## Comparison: Mock vs Real Providers

| Feature | Mock | Anthropic | OpenAI | Gemini |
|---------|------|-----------|--------|--------|
| Cost per 100 endpoints | $0.00 | $3-5 | $3-5 | $2-4 |
| Response time | Instant | 2-5s | 2-5s | 2-5s |
| JSON quality | Configurable | High | Medium | Medium |
| Realistic schemas | No | Yes | Yes | Yes |
| Security payloads | Basic | Advanced | Advanced | Advanced |
| Best for | Testing, CI/CD | Production | Production | Production |

## Use Cases

### 1. Local Development
```bash
# Develop and test scanner features without API costs
export LLM_PROVIDER=mock
python main.py ./my-project --ai-enrich
```

### 2. CI/CD Testing
```yaml
# .github/workflows/test.yml
env:
  LLM_PROVIDER: mock
  MOCK_LLM_QUALITY: medium
```

### 3. JSON Parser Testing
```bash
# Test parser with malformed JSON
export LLM_PROVIDER=mock
export MOCK_LLM_QUALITY=low
python main.py ./project --ai-enrich
```

### 4. Integration Testing
```python
# tests/test_integration.py
import os
os.environ["LLM_PROVIDER"] = "mock"
os.environ["MOCK_LLM_QUALITY"] = "high"

# Run tests...
```

## Expected Output

### Mock Provider - High Quality
```
🧪 Mock LLM Provider initialized (quality: high)
✓ Found 30 endpoints

AI Enrichment Results:
  • OpenAPI operations: 30/30 (100%)
  • Authentication detected: ✓
  • Test payloads generated: 120
  • Dependency graph: ✓

Total cost: $0.00 (mock - no real API calls)
```

### Mock Provider - Medium Quality
```
🧪 Mock LLM Provider initialized (quality: medium)
⚠️  Warning: JSON parse error (recovered)
✓ Found 30 endpoints

AI Enrichment Results:
  • OpenAPI operations: 28/30 (93%)
  • Authentication detected: ✓
  • Test payloads generated: 112
  • Parse errors recovered: 2

Total cost: $0.00 (mock - no real API calls)
```

## Environment Variables

```bash
# Mock provider configuration
export LLM_PROVIDER=mock              # Use mock instead of real API
export MOCK_LLM_QUALITY=high          # high, medium, or low
export SCANNER_AI_ENRICH=true         # Enable AI enrichment

# Optional
export ENRICHMENT_MAX_WORKERS=3       # Parallel workers (default: 3)
```

## Troubleshooting

### Issue: "Unsupported provider: mock"
**Solution:** Ensure you're using the latest version with mock provider support.

### Issue: Mock responses don't match real LLM quality
**Expected:** Mock responses are simpler and more generic than real LLM responses. Use mock for testing logic, not for validating enrichment quality.

### Issue: Want to test specific error scenarios
**Solution:** Use `MOCK_LLM_QUALITY=low` or modify `agents/mock_llm_provider.py` to inject specific errors.

## Best Practices

### 1. Use Mock for Development
```bash
# During feature development
export LLM_PROVIDER=mock
```

### 2. Test Parser Resilience
```bash
# Regularly test with medium/low quality
export MOCK_LLM_QUALITY=medium
```

### 3. Switch to Real Provider Before Release
```bash
# Final validation with real LLM
export LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

### 4. Use in CI/CD Pipelines
```yaml
# Fast, free CI tests
- name: Test with Mock Provider
  env:
    LLM_PROVIDER: mock
  run: python main.py ./test-samples --ai-enrich

# Occasional real validation (weekly)
- name: Validate with Real Provider
  if: github.event.schedule == 'weekly'
  env:
    LLM_PROVIDER: anthropic
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: python main.py ./test-samples --ai-enrich
```

## Cost Savings Example

### Without Mock Provider
```
Development iterations: 50
Endpoints per test: 30
Cost per endpoint: $0.05
Total: 50 × 30 × $0.05 = $75
```

### With Mock Provider
```
Development iterations: 50 (mock) + 5 (real validation)
Mock cost: $0
Real validation cost: 5 × 30 × $0.05 = $7.50
Total: $7.50
Savings: $67.50 (90%)
```

## Next Steps

- [Main Documentation](../README.md)
- [Security Features](SECURITY.md)
- [AI Enrichment Guide](AI_ENRICHMENT.md)
