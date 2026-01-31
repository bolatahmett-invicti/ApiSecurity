# Sample Complex Python Architecture
# This demonstrates WSGI/Gevent, custom routers, and JWT auth patterns

import argparse
from gevent.pywsgi import WSGIServer
from pydantic import BaseModel
import jwt
import yaml

# =============================================================================
# Custom Router Implementation
# =============================================================================
class OpenAPIRouter:
    """Custom OpenAPI-based router."""
    
    def __init__(self, prefix=""):
        self.prefix = prefix
        self.routes = {}
    
    def add_route(self, method: str, path: str, handler):
        """Register a route."""
        full_path = f"{self.prefix}{path}"
        self.routes[(method, full_path)] = handler
    
    def register(self, path: str):
        """Decorator for registering routes."""
        def decorator(func):
            self.routes[("ANY", path)] = func
            return func
        return decorator

# Router instance
api_router = OpenAPIRouter(prefix="/api/v1")

# =============================================================================
# Pydantic Models
# =============================================================================
class UserRequest(BaseModel):
    email: str
    password: str
    ssn: str  # PII!

class PaymentRequest(BaseModel):
    credit_card: str
    amount: float
    
class TokenResponse(BaseModel):
    access_token: str
    token_type: str

# =============================================================================
# JWT Authentication
# =============================================================================
class JWTAuthenticator:
    """Custom JWT authentication handler."""
    
    SECRET_KEY = "super-secret-key"
    
    def create_token(self, user_id: str) -> str:
        """Generate JWT token."""
        return jwt.encode({"user_id": user_id}, self.SECRET_KEY)
    
    def verify_token(self, token: str) -> dict:
        """Verify and decode JWT token."""
        return jwt.decode(token, self.SECRET_KEY, algorithms=["HS256"])
    
    def get_current_user(self, request):
        """Extract current user from request."""
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            return self.verify_token(token)
        return None

jwt_auth = JWTAuthenticator()

# =============================================================================
# Route Handlers
# =============================================================================
# Using add_route pattern
api_router.add_route("GET", "/users", lambda: {"users": []})
api_router.add_route("POST", "/users", lambda: {"id": 1})
api_router.add_route("GET", "/users/{id}", lambda id: {"id": id})
api_router.add_route("DELETE", "/users/{id}", lambda id: {"deleted": True})

# Payment routes - HIGH RISK
api_router.add_route("POST", "/payments/charge", lambda: {"transaction_id": "txn_123"})
api_router.add_route("GET", "/billing/invoices", lambda: {"invoices": []})

# Admin routes - CRITICAL
api_router.add_route("DELETE", "/admin/users/{id}", lambda id: {"deleted": True})
api_router.add_route("POST", "/internal/reset", lambda: {"reset": True})

# =============================================================================
# OpenAPI Spec Loading (Swagger 2.0 / Legacy)
# =============================================================================
def load_swagger_spec(spec_path: str):
    """Load Swagger 2.0 specification."""
    with open(spec_path) as f:
        spec = yaml.safe_load(f)
    return spec

# Handler directory for legacy routing
handlers_dir = "frontend/handlers"
routes_folder = "api/routes"

# URL patterns dictionary
url_map = {
    "/api/v1/products": "products_handler",
    "/api/v1/orders": "orders_handler",
    "/api/v1/search": "search_handler",
}

# Route registration list
routes = [
    ("GET", "/api/v1/health", "health_handler"),
    ("GET", "/api/v1/status", "status_handler"),
    ("POST", "/api/v2/webhooks", "webhook_handler"),
]

# =============================================================================
# Health & Static Endpoints
# =============================================================================
def health_check():
    """Health endpoint."""
    return {"status": "healthy"}

def serve_static(path):
    """Static file server."""
    from flask import send_from_directory
    return send_from_directory("static", path)

# Prometheus metrics
from prometheus_client import Counter
request_counter = Counter('http_requests_total', 'Total HTTP requests')

# =============================================================================
# Worker Pattern (CLI-based)
# =============================================================================
class DataProcessor:
    """Background worker for processing tasks."""
    
    def handle_task(self, task_data):
        """Process a single task."""
        pass
    
    def process_message(self, message):
        """Process incoming message."""
        pass

def setup_worker_cli():
    """Setup CLI for worker."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=["processor", "scheduler"], required=True)
    parser.add_argument("--conf", type=str, help="Config file path")
    parser.add_argument("--worker", type=str, help="Worker type")
    return parser.parse_args()

# =============================================================================
# WSGI Application Entry Point
# =============================================================================
def create_app():
    """Create WSGI application."""
    # Application factory pattern
    pass

def main():
    """Main entry point with Gevent WSGI server."""
    app = create_app()
    
    # Start Gevent WSGI Server
    server = WSGIServer(("0.0.0.0", 8080), app)
    print("Starting server on http://0.0.0.0:8080")
    server.serve_forever()

if __name__ == "__main__":
    main()
