#!/usr/bin/env python3
"""Test Express.js pattern matching on auth-service"""
import re

# Express.js pattern from JavaScriptScanner
pattern = r'(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*["\'\`]([^"\'\`]+)["\'\`]'

# Read auth-service file
with open(r'C:\Users\AhmetBolat\Projects\PoC\Claude\ApiSecurity_TestApp\test-microservices\auth-service\app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find all matches
matches = re.findall(pattern, content)
print(f'Found {len(matches)} endpoint matches:\n')

for method, route in matches:
    print(f'  {method.upper():6} {route}')

print(f'\nTotal: {len(matches)} endpoints detected')
