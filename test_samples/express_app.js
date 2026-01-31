// Sample Express.js Application for Testing the Scanner
// This file contains various API patterns for the scanner to detect

const express = require('express');
const passport = require('passport');
const router = express.Router();
const app = express();

// Middleware
const authenticate = passport.authenticate('jwt', { session: false });
const isAdmin = (req, res, next) => { /* admin check */ next(); };

// --- Public Routes ---
app.get('/health', (req, res) => {
    res.json({ status: 'healthy' });
});

app.get('/api/public/info', (req, res) => {
    res.json({ version: '1.0.0' });
});

// --- Authentication Routes ---
router.post('/api/auth/login', (req, res) => {
    // Handles password and creates JWT token
    const { email, password } = req.body;
    res.json({ token: 'jwt_token' });
});

router.post('/api/auth/register', (req, res) => {
    // Registration collects sensitive data
    const { email, password, ssn, date_of_birth } = req.body;
    res.json({ id: 1 });
});

// --- User Management ---
router.get('/api/users/profile', authenticate, (req, res) => {
    res.json({ user: req.user });
});

router.put('/api/users/:id', authenticate, (req, res) => {
    // Update user - mutation operation
    res.json({ updated: true });
});

router.delete('/api/users/:id', authenticate, isAdmin, (req, res) => {
    // Delete user - requires admin
    res.json({ deleted: true });
});

// --- Payment Routes (HIGH RISK) ---
app.post('/api/payments/process', authenticate, (req, res) => {
    // Processes credit_card information
    const { credit_card, amount } = req.body;
    res.json({ transaction_id: 'txn_123' });
});

app.get('/api/billing/history', authenticate, (req, res) => {
    res.json({ invoices: [] });
});

// --- SHADOW API - No Auth! ---
app.get('/api/internal/users', (req, res) => {
    // DANGEROUS: Exposes all users without auth!
    res.json({ users: [] });
});

app.post('/admin/reset-db', (req, res) => {
    // CRITICAL: Database reset with no protection
    res.json({ reset: true });
});

// --- Search Team Routes ---
router.get('/api/search/products', (req, res) => {
    const { query } = req.query;
    res.json({ results: [] });
});

router.post('/api/search/advanced', authenticate, (req, res) => {
    res.json({ results: [] });
});

module.exports = { app, router };
