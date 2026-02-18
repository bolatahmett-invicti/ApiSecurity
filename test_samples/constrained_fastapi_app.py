"""
Constrained FastAPI App — comprehensive LoF test fixture.

Exercises every constraint source the ConstraintExtractor recognises:
  - Pydantic Field(gt, ge, lt, le, min_length, max_length, pattern)
  - Annotated[T, Field(...)]
  - Literal[...] enum types
  - @field_validator / @model_validator decorators
  - Inline if/raise validation guards
  - current_user + {resource_id} IDOR ownership patterns
  - Required field omission tests
  - Cross-field conditional constraints (sale_price < price)

Run the LoF quick-test against this file:

    python -c "
    from scanners.deterministic.constraint_extractor import ConstraintExtractor
    from scanners.logic_fuzz.logic_fuzz_generator import LogicFuzzGenerator
    code = open('test_samples/constrained_fastapi_app.py').read()
    c = ConstraintExtractor.extract_from_code(code, '/orders', {})
    p = LogicFuzzGenerator.generate(c, 'POST', 0.4)
    import json; print(json.dumps(p[:5], indent=2))
    "
"""

from __future__ import annotations

from typing import Annotated, List, Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator, model_validator

app = FastAPI(title="LoF Test Fixture")

# ---------------------------------------------------------------------------
# Literal enum aliases — generate enum_violation and privilege_escalation
# ---------------------------------------------------------------------------

UserRole = Literal["user", "vendor", "support"]        # no admin → escalation target
OrderStatus = Literal["pending", "processing", "shipped", "delivered", "cancelled"]
PaymentMethod = Literal["credit_card", "debit_card", "paypal", "bank_transfer", "crypto"]
ShippingSpeed = Literal["standard", "express", "overnight"]
ReportFormat = Literal["csv", "json", "xlsx"]


# ---------------------------------------------------------------------------
# Auth stub — ownership IDOR pattern
# ---------------------------------------------------------------------------

class CurrentUser(BaseModel):
    id: str
    role: UserRole


def get_current_user() -> CurrentUser:
    return CurrentUser(id="user-abc", role="user")


# ---------------------------------------------------------------------------
# Comprehensive order model — hits most LoF constraint types in one model
# ---------------------------------------------------------------------------

class CreateOrderRequest(BaseModel):
    # range constraints
    quantity: Annotated[int, Field(ge=1, le=500)]
    unit_price: Annotated[float, Field(gt=0, lt=100_000)]
    discount_percent: Annotated[float, Field(ge=0, le=100)]
    shipping_days: Annotated[int, Field(ge=1, le=60)]

    # length constraints
    customer_name: Annotated[str, Field(min_length=2, max_length=100)]
    delivery_address: Annotated[str, Field(min_length=10, max_length=300)]
    coupon_code: Annotated[Optional[str], Field(default=None, min_length=4, max_length=16)]

    # pattern constraint
    postal_code: Annotated[str, Field(pattern=r"^\d{5}(-\d{4})?$")]

    # enum constraints
    status: OrderStatus = "pending"
    payment_method: PaymentMethod
    shipping_speed: ShippingSpeed = "standard"

    # list size
    item_ids: Annotated[List[str], Field(min_length=1, max_length=50)]

    @field_validator("quantity")
    @classmethod
    def quantity_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("quantity must be positive")
        return v

    @model_validator(mode="after")
    def overnight_requires_express_minimum(self) -> CreateOrderRequest:
        if self.shipping_speed == "overnight" and self.shipping_days > 1:
            raise ValueError("Overnight shipping must have shipping_days=1")
        return self


class UpdateOrderRequest(BaseModel):
    status: Optional[OrderStatus] = None
    shipping_speed: Optional[ShippingSpeed] = None
    delivery_address: Annotated[Optional[str], Field(default=None, min_length=10, max_length=300)]
    notes: Annotated[Optional[str], Field(default=None, max_length=1000)]


# ---------------------------------------------------------------------------
# Product model — float ratings, sale_price cross-field, tags list
# ---------------------------------------------------------------------------

class CreateProductRequest(BaseModel):
    title: Annotated[str, Field(min_length=3, max_length=150)]
    price: Annotated[float, Field(gt=0, lt=1_000_000)]
    sale_price: Annotated[Optional[float], Field(default=None, gt=0, lt=1_000_000)]
    rating: Annotated[float, Field(ge=1.0, le=5.0)]
    stock: Annotated[int, Field(ge=0, le=999_999)]
    category: Literal["electronics", "clothing", "food", "books", "sports"]
    tags: Annotated[List[str], Field(default_factory=list, max_length=10)]

    @model_validator(mode="after")
    def sale_price_lt_price(self) -> CreateProductRequest:
        if self.sale_price is not None and self.sale_price >= self.price:
            raise ValueError("sale_price must be less than price")
        return self


# ---------------------------------------------------------------------------
# Subscription model — trial days, billing interval
# ---------------------------------------------------------------------------

BillingInterval = Literal["weekly", "monthly", "quarterly", "yearly"]


class CreateSubscriptionRequest(BaseModel):
    plan_id: Annotated[str, Field(min_length=4, max_length=32)]
    billing_interval: BillingInterval
    trial_days: Annotated[int, Field(ge=0, le=90)]
    seats: Annotated[int, Field(ge=1, le=1000)]
    discount_percent: Annotated[float, Field(ge=0, le=100)]


# ---------------------------------------------------------------------------
# Report model — date range, max records
# ---------------------------------------------------------------------------

class GenerateReportRequest(BaseModel):
    format: ReportFormat
    start_date: Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
    end_date: Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
    max_rows: Annotated[int, Field(ge=1, le=100_000)] = 10_000
    include_deleted: bool = False


# ---------------------------------------------------------------------------
# Batch operations — list size limits
# ---------------------------------------------------------------------------

class BatchDeleteRequest(BaseModel):
    order_ids: Annotated[List[str], Field(min_length=1, max_length=100)]
    reason: Annotated[str, Field(min_length=5, max_length=200)]


class BulkStatusUpdateRequest(BaseModel):
    order_ids: Annotated[List[str], Field(min_length=1, max_length=200)]
    new_status: OrderStatus
    notify_customers: bool = True


# ---------------------------------------------------------------------------
# Orders endpoints
# ---------------------------------------------------------------------------

_orders: dict = {}
_products: dict = {}
_subscriptions: dict = {}


@app.post("/api/orders", status_code=201)
def create_order(
    body: CreateOrderRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    import uuid
    order_id = str(uuid.uuid4())
    order = {"id": order_id, "user_id": current_user.id, **body.model_dump()}
    _orders[order_id] = order

    # Inline validation guard (signals: inline_validation)
    total = body.quantity * body.unit_price * (1 - body.discount_percent / 100)
    if total > 500_000:
        raise HTTPException(400, "Single order total cannot exceed $500,000")

    return order


@app.get("/api/orders/{order_id}")
def get_order(
    order_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    order = _orders.get(order_id)
    if not order:
        raise HTTPException(404, "Order not found")

    # IDOR ownership check
    if order["user_id"] != current_user.id:
        raise HTTPException(403, "Cannot access another user's order")

    return order


@app.put("/api/orders/{order_id}")
def update_order(
    order_id: str,
    body: UpdateOrderRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    order = _orders.get(order_id)
    if not order:
        raise HTTPException(404, "Order not found")

    # IDOR ownership check
    if order["user_id"] != current_user.id:
        raise HTTPException(403, "Cannot update another user's order")

    order.update({k: v for k, v in body.model_dump().items() if v is not None})
    return order


@app.delete("/api/orders/{order_id}", status_code=204)
def cancel_order(
    order_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> None:
    order = _orders.get(order_id)
    if not order:
        raise HTTPException(404, "Order not found")

    if order["user_id"] != current_user.id:
        raise HTTPException(403, "Cannot cancel another user's order")

    if order.get("status") not in ("pending", "processing"):
        raise HTTPException(400, f"Cannot cancel order in status '{order.get('status')}'")

    del _orders[order_id]


@app.post("/api/orders/batch-delete")
def batch_delete_orders(
    body: BatchDeleteRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    deleted = []
    for oid in body.order_ids:
        order = _orders.pop(oid, None)
        if order:
            deleted.append(oid)
    return {"deleted": deleted, "reason": body.reason}


@app.post("/api/orders/bulk-status")
def bulk_status_update(
    body: BulkStatusUpdateRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    updated = []
    for oid in body.order_ids:
        order = _orders.get(oid)
        if order and order["user_id"] == current_user.id:
            order["status"] = body.new_status
            updated.append(oid)
    return {"updated": updated}


@app.get("/api/orders")
def list_orders(
    status: Optional[OrderStatus] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    items = [o for o in _orders.values() if o["user_id"] == current_user.id]
    if status:
        items = [o for o in items if o.get("status") == status]
    start = (page - 1) * page_size
    return {"items": items[start: start + page_size], "total": len(items)}


# ---------------------------------------------------------------------------
# Products endpoints
# ---------------------------------------------------------------------------


@app.post("/api/products", status_code=201)
def create_product(
    body: CreateProductRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    import uuid
    pid = str(uuid.uuid4())
    product = {"id": pid, "vendor_id": current_user.id, **body.model_dump()}
    _products[pid] = product
    return product


@app.get("/api/products")
def list_products(
    category: Optional[Literal["electronics", "clothing", "food", "books", "sports"]] = None,
    min_price: Annotated[Optional[float], Query(ge=0)] = None,
    max_price: Annotated[Optional[float], Query(ge=0)] = None,
    min_rating: Annotated[Optional[float], Query(ge=1.0, le=5.0)] = None,
    page_size: Annotated[int, Query(ge=1, le=200)] = 30,
) -> dict:
    items = list(_products.values())
    if category:
        items = [p for p in items if p["category"] == category]
    if min_price is not None:
        items = [p for p in items if p["price"] >= min_price]
    if max_price is not None:
        items = [p for p in items if p["price"] <= max_price]
    if min_rating is not None:
        items = [p for p in items if p.get("rating", 0) >= min_rating]
    return {"items": items[:page_size], "total": len(items)}


@app.put("/api/products/{product_id}")
def update_product(
    product_id: str,
    body: CreateProductRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    product = _products.get(product_id)
    if not product:
        raise HTTPException(404, "Product not found")

    # IDOR: only the vendor who listed the product may update it
    if product["vendor_id"] != current_user.id:
        raise HTTPException(403, "Cannot update another vendor's product")

    product.update(body.model_dump())
    return product


# ---------------------------------------------------------------------------
# Subscriptions endpoints
# ---------------------------------------------------------------------------


@app.post("/api/subscriptions", status_code=201)
def create_subscription(
    body: CreateSubscriptionRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    import uuid
    sub_id = str(uuid.uuid4())
    sub = {"id": sub_id, "user_id": current_user.id, **body.model_dump()}
    _subscriptions[sub_id] = sub

    # Inline validation guard
    if body.seats > 500 and body.discount_percent < 20:
        raise HTTPException(400, "Enterprise plans (>500 seats) require at least 20% discount")

    return sub


@app.get("/api/subscriptions/{subscription_id}")
def get_subscription(
    subscription_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    sub = _subscriptions.get(subscription_id)
    if not sub:
        raise HTTPException(404, "Subscription not found")

    # IDOR ownership check
    if sub["user_id"] != current_user.id:
        raise HTTPException(403, "Cannot access another user's subscription")

    return sub


# ---------------------------------------------------------------------------
# Reports endpoint
# ---------------------------------------------------------------------------


@app.post("/api/reports")
def generate_report(
    body: GenerateReportRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    # Inline date validation
    if body.start_date > body.end_date:
        raise HTTPException(400, "start_date must not be after end_date")

    return {
        "format": body.format,
        "max_rows": body.max_rows,
        "download_url": f"/api/reports/download/{body.format}",
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "constrained-fastapi-app"}
