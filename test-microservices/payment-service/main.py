"""
Payment Service - FastAPI Microservice
Handles all payment processing, billing, and transaction management.
"""
from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid

app = FastAPI(
    title="Payment Service",
    description="Core payment processing microservice",
    version="2.1.0"
)

security = HTTPBearer()

# =============================================================================
# MODELS
# =============================================================================
class PaymentStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"

class PaymentMethod(str, Enum):
    CREDIT_CARD = "credit_card"
    DEBIT_CARD = "debit_card"
    BANK_TRANSFER = "bank_transfer"
    CRYPTO = "crypto"

class CreatePaymentRequest(BaseModel):
    amount: float = Field(..., gt=0, description="Payment amount in cents")
    currency: str = Field(default="USD", max_length=3)
    customer_id: str
    order_id: str
    payment_method: PaymentMethod
    card_number: Optional[str] = Field(None, description="Masked card number")
    card_expiry: Optional[str] = None
    card_cvv: Optional[str] = None

class RefundRequest(BaseModel):
    transaction_id: str
    amount: Optional[float] = None  # Partial refund
    reason: str

class PaymentResponse(BaseModel):
    transaction_id: str
    status: PaymentStatus
    amount: float
    currency: str
    created_at: datetime

# =============================================================================
# HEALTH ENDPOINTS
# =============================================================================
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for Kubernetes probes."""
    return {"status": "healthy", "service": "payment-service"}

@app.get("/health/live", tags=["Health"])
async def liveness_probe():
    """Kubernetes liveness probe."""
    return {"alive": True}

@app.get("/health/ready", tags=["Health"])
async def readiness_probe():
    """Kubernetes readiness probe."""
    return {"ready": True, "database": "connected", "redis": "connected"}

# =============================================================================
# PUBLIC ENDPOINTS
# =============================================================================
@app.get("/api/v1/payment-methods", tags=["Public"])
async def list_payment_methods():
    """List available payment methods (public endpoint)."""
    return {
        "methods": [
            {"id": "credit_card", "name": "Credit Card", "enabled": True},
            {"id": "debit_card", "name": "Debit Card", "enabled": True},
            {"id": "bank_transfer", "name": "Bank Transfer", "enabled": True},
            {"id": "crypto", "name": "Cryptocurrency", "enabled": False},
        ]
    }

@app.get("/api/v1/currencies", tags=["Public"])
async def list_currencies():
    """List supported currencies."""
    return {"currencies": ["USD", "EUR", "GBP", "JPY", "CAD"]}

# =============================================================================
# AUTHENTICATED PAYMENT ENDPOINTS
# =============================================================================
@app.post("/api/v1/payments", tags=["Payments"], response_model=PaymentResponse)
async def create_payment(
    request: CreatePaymentRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Process a new payment transaction.
    
    Requires valid JWT token in Authorization header.
    """
    transaction_id = str(uuid.uuid4())
    return PaymentResponse(
        transaction_id=transaction_id,
        status=PaymentStatus.COMPLETED,
        amount=request.amount,
        currency=request.currency,
        created_at=datetime.utcnow()
    )

@app.get("/api/v1/payments/{transaction_id}", tags=["Payments"])
async def get_payment(
    transaction_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get payment details by transaction ID."""
    return {
        "transaction_id": transaction_id,
        "status": "completed",
        "amount": 9999,
        "currency": "USD"
    }

@app.get("/api/v1/payments", tags=["Payments"])
async def list_payments(
    customer_id: Optional[str] = None,
    status: Optional[PaymentStatus] = None,
    limit: int = 50,
    offset: int = 0,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """List payments with optional filters."""
    return {"payments": [], "total": 0, "limit": limit, "offset": offset}

@app.post("/api/v1/payments/{transaction_id}/capture", tags=["Payments"])
async def capture_payment(
    transaction_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Capture an authorized payment."""
    return {"transaction_id": transaction_id, "status": "captured"}

@app.post("/api/v1/payments/{transaction_id}/void", tags=["Payments"])
async def void_payment(
    transaction_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Void a pending payment."""
    return {"transaction_id": transaction_id, "status": "voided"}

# =============================================================================
# REFUND ENDPOINTS
# =============================================================================
@app.post("/api/v1/refunds", tags=["Refunds"])
async def create_refund(
    request: RefundRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Process a refund for a completed transaction."""
    refund_id = str(uuid.uuid4())
    return {
        "refund_id": refund_id,
        "transaction_id": request.transaction_id,
        "amount": request.amount,
        "status": "processed"
    }

@app.get("/api/v1/refunds/{refund_id}", tags=["Refunds"])
async def get_refund(
    refund_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get refund details."""
    return {"refund_id": refund_id, "status": "completed"}

# =============================================================================
# BILLING ENDPOINTS
# =============================================================================
@app.get("/api/v1/billing/invoices", tags=["Billing"])
async def list_invoices(
    customer_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """List customer invoices."""
    return {"invoices": [], "customer_id": customer_id}

@app.get("/api/v1/billing/invoices/{invoice_id}", tags=["Billing"])
async def get_invoice(
    invoice_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get invoice details."""
    return {"invoice_id": invoice_id, "status": "paid"}

@app.post("/api/v1/billing/invoices/{invoice_id}/pay", tags=["Billing"])
async def pay_invoice(
    invoice_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Pay an outstanding invoice."""
    return {"invoice_id": invoice_id, "status": "paid"}

# =============================================================================
# SUBSCRIPTION ENDPOINTS
# =============================================================================
@app.get("/api/v1/subscriptions", tags=["Subscriptions"])
async def list_subscriptions(
    customer_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """List customer subscriptions."""
    return {"subscriptions": []}

@app.post("/api/v1/subscriptions", tags=["Subscriptions"])
async def create_subscription(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Create a new subscription."""
    return {"subscription_id": str(uuid.uuid4()), "status": "active"}

@app.delete("/api/v1/subscriptions/{subscription_id}", tags=["Subscriptions"])
async def cancel_subscription(
    subscription_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Cancel a subscription."""
    return {"subscription_id": subscription_id, "status": "cancelled"}

# =============================================================================
# ADMIN ENDPOINTS (Internal)
# =============================================================================
@app.get("/internal/admin/transactions", tags=["Admin"])
async def admin_list_transactions(
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """[ADMIN] List all transactions across all customers."""
    return {"transactions": [], "total": 0}

@app.post("/internal/admin/refund-batch", tags=["Admin"])
async def admin_batch_refund(
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """[ADMIN] Process batch refunds."""
    return {"processed": 0, "failed": 0}

@app.delete("/internal/admin/transactions/{transaction_id}", tags=["Admin"])
async def admin_delete_transaction(
    transaction_id: str,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """[ADMIN] Delete a transaction (audit log preserved)."""
    return {"deleted": True}

@app.post("/internal/admin/database/reset", tags=["Admin"])
async def admin_reset_database(
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """[ADMIN] Reset database to initial state (DANGEROUS)."""
    return {"reset": True, "warning": "All data has been cleared"}

# =============================================================================
# WEBHOOKS
# =============================================================================
@app.post("/webhooks/stripe", tags=["Webhooks"])
async def stripe_webhook():
    """Handle Stripe payment webhooks."""
    return {"received": True}

@app.post("/webhooks/paypal", tags=["Webhooks"])
async def paypal_webhook():
    """Handle PayPal payment webhooks."""
    return {"received": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
