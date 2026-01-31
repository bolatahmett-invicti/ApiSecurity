# Sample Flask Application for Testing the Scanner
# This file contains various API patterns for the scanner to detect

from flask import Flask, request, jsonify
from flask_login import login_required, current_user
from functools import wraps

app = Flask(__name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({"error": "Admin required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Public Routes ---
@app.route('/health')
def health():
    return jsonify({"status": "ok"})

@app.route('/api/public/docs')
def public_docs():
    return jsonify({"swagger": "/swagger.json"})

# --- Auth Routes ---
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login with email and password"""
    email = request.json.get('email')
    password = request.json.get('password')
    return jsonify({"token": "abc123"})

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register with sensitive data including SSN"""
    ssn = request.json.get('ssn')
    return jsonify({"user_id": 1})

# --- Protected User Routes ---
@app.get('/api/users/me')
@login_required
def get_me():
    return jsonify({"user": current_user.to_dict()})

@app.put('/api/users/<int:user_id>')
@login_required
def update_user(user_id):
    return jsonify({"updated": True})

@app.delete('/api/users/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    return jsonify({"deleted": True})

# --- Payment Routes ---
@app.post('/api/payments/charge')
@login_required
def charge():
    """Process credit card payment"""
    credit_card = request.json.get('credit_card')
    amount = request.json.get('amount')
    return jsonify({"transaction_id": "txn_123"})

# --- DANGER: Shadow APIs without auth! ---
@app.route('/internal/users/export')
def export_users():
    """CRITICAL: Exports all user data without authentication!"""
    return jsonify({"users": []})

@app.route('/admin/database/backup', methods=['POST'])
def backup_db():
    """CRITICAL: No auth on sensitive admin endpoint!"""
    return jsonify({"backup": "complete"})

# --- Notification Team Routes ---
@app.route('/api/notifications/send', methods=['POST'])
@login_required
def send_notification():
    return jsonify({"sent": True})

@app.route('/api/email/send', methods=['POST'])
@login_required
def send_email():
    return jsonify({"sent": True})
