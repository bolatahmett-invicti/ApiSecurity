# Sample FastAPI Application for Testing the Scanner
# This file contains various API patterns for the scanner to detect

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Models ---
class User(BaseModel):
    email: str
    password: str
    ssn: str  # PII Alert!

class Payment(BaseModel):
    credit_card: str
    amount: float

# --- Public Endpoints (No Auth) ---
@app.get("/health")
def health_check():
    """Public health endpoint"""
    return {"status": "healthy"}

@app.get("/api/public/products")
def list_products():
    """Public product listing"""
    return []

# --- Authentication Endpoints ---
@app.post("/api/auth/login")
def login(user: User):
    """Login endpoint - handles passwords!"""
    return {"token": "jwt_token"}

@app.post("/api/auth/register")
def register(user: User):
    """Registration with SSN collection - HIGH RISK"""
    return {"id": 1}

# --- Protected Endpoints ---
@app.get("/api/users/me")
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Protected user profile"""
    return {"user_id": 1}

@app.get("/api/users/{user_id}")
async def get_user(user_id: int, token: str = Depends(oauth2_scheme)):
    """Get user by ID - PII exposure risk"""
    return {"user_id": user_id, "email": "user@example.com"}

# --- Financial Endpoints (HIGH RISK) ---
@app.post("/api/payments/charge")
async def charge_payment(payment: Payment, token: str = Depends(oauth2_scheme)):
    """Process payment - CRITICAL"""
    return {"transaction_id": "txn_123"}

@app.get("/api/billing/invoices")
async def list_invoices(token: str = Depends(oauth2_scheme)):
    """List user invoices"""
    return []

# --- Admin Endpoints (CRITICAL RISK) ---
@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: int):
    """DANGEROUS: Delete user - NO AUTH CHECK!"""
    return {"deleted": True}

@app.post("/internal/debug/reset")
def reset_database():
    """CRITICAL: Debug endpoint with no auth!"""
    return {"reset": True}

# --- Cart/Checkout Team ---
@app.post("/api/cart/add")
async def add_to_cart(item_id: int):
    return {"cart_id": 1}

@app.post("/api/checkout/complete")
async def complete_checkout(payment: Payment):
    """Checkout with credit card - HIGH RISK"""
    return {"order_id": "ord_123"}
