# 🏢 Enterprise Microservices Test Suite

This folder contains a realistic enterprise microservices architecture for testing the Universal Polyglot API Scanner.

## 📦 Services

| Service | Language | Framework | Port | Description |
|---------|----------|-----------|------|-------------|
| **payment-service** | Python | FastAPI | 8001 | Payment processing, billing, subscriptions |
| **auth-service** | JavaScript | Express.js | 8002 | Authentication, OAuth, MFA, sessions |
| **order-service** | Go | Gin | 8003 | Order management, cart, shipping |
| **notification-service** | Java | Spring Boot | 8004 | Email, SMS, push notifications |
| **user-service** | C# | ASP.NET Core | 8005 | User profiles, preferences, security |
| **product-service** | TypeScript | NestJS | 8006 | Product catalog, inventory, search |

## 🔍 Testing the Scanner

### Scan All Services
```bash
# From the ApiSecurity root directory
python main.py ./test-microservices --export-openapi microservices-openapi.json
```

### Scan Individual Services
```bash
# Payment Service
python main.py ./test-microservices/payment-service --service-name payment-service --export-openapi

# Auth Service  
python main.py ./test-microservices/auth-service --service-name auth-service --export-openapi

# Order Service
python main.py ./test-microservices/order-service --service-name order-service --export-openapi

# Notification Service
python main.py ./test-microservices/notification-service --service-name notification-service --export-openapi

# User Service
python main.py ./test-microservices/user-service --service-name user-service --export-openapi

# Product Service
python main.py ./test-microservices/product-service --service-name product-service --export-openapi
```

## 📊 Expected Results

Each service contains:
- Health endpoints (`/health`, `/health/live`, `/health/ready`)
- Public API endpoints (`/api/v1/...`)
- Admin/Internal endpoints (`/internal/admin/...`)
- Webhook handlers (`/webhooks/...`)

### Risk Distribution
- **CRITICAL**: Admin database reset, bulk delete operations
- **HIGH**: Payment processing, authentication, user deletion
- **MEDIUM**: CRUD operations, search
- **LOW**: Health checks, list operations

## 🏗️ Architecture Patterns

These services demonstrate common enterprise patterns:

1. **Consistent Health Checks** - Kubernetes-ready liveness/readiness probes
2. **API Versioning** - `/api/v1/` prefix
3. **Internal APIs** - `/internal/admin/` for service-to-service
4. **Webhook Handlers** - For event-driven architecture
5. **Authentication** - JWT Bearer tokens, API keys
6. **Authorization** - Role-based (admin, user)

## 🧪 Endpoint Count by Service

| Service | Public | Internal | Webhooks | Total |
|---------|--------|----------|----------|-------|
| payment-service | ~25 | ~5 | 2 | ~32 |
| auth-service | ~30 | ~8 | 0 | ~38 |
| order-service | ~20 | ~10 | 3 | ~33 |
| notification-service | ~35 | ~8 | 3 | ~46 |
| user-service | ~20 | ~12 | 0 | ~32 |
| product-service | ~30 | ~10 | 2 | ~42 |
| **TOTAL** | **~160** | **~53** | **~10** | **~223** |
