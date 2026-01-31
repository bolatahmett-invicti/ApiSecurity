// Sample NestJS Application for Testing the Scanner
// This file contains various API patterns for the scanner to detect

import { Controller, Get, Post, Put, Delete, Body, Param, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';

// --- DTOs ---
interface CreateUserDto {
    email: string;
    password: string;
    ssn: string;  // PII Alert!
}

interface PaymentDto {
    credit_card: string;
    amount: number;
}

// --- Public Controller ---
@Controller('public')
export class PublicController {
    @Get('health')
    healthCheck() {
        return { status: 'healthy' };
    }

    @Get('version')
    getVersion() {
        return { version: '1.0.0' };
    }
}

// --- Auth Controller ---
@Controller('api/auth')
export class AuthController {
    @Post('login')
    login(@Body() body: { email: string; password: string }) {
        // Handles password authentication
        return { token: 'jwt_token' };
    }

    @Post('register')
    register(@Body() body: CreateUserDto) {
        // Collects SSN during registration - HIGH RISK
        return { id: 1 };
    }

    @Post('forgot-password')
    forgotPassword(@Body() body: { email: string }) {
        return { sent: true };
    }
}

// --- User Controller (Protected) ---
@Controller('api/users')
@UseGuards(AuthGuard('jwt'))
export class UserController {
    @Get('me')
    getProfile() {
        return { user: {} };
    }

    @Get(':id')
    getUser(@Param('id') id: string) {
        // Returns user PII
        return { id, email: 'user@example.com', phone: '555-1234' };
    }

    @Put(':id')
    updateUser(@Param('id') id: string, @Body() body: any) {
        return { updated: true };
    }

    @Delete(':id')
    @UseGuards(RolesGuard)
    @Roles('admin')
    deleteUser(@Param('id') id: string) {
        return { deleted: true };
    }
}

// --- Payment Controller (CRITICAL) ---
@Controller('api/payments')
@UseGuards(AuthGuard('jwt'))
export class PaymentController {
    @Post('charge')
    charge(@Body() payment: PaymentDto) {
        // Processes credit_card - CRITICAL
        return { transaction_id: 'txn_123' };
    }

    @Get('history')
    getPaymentHistory() {
        return { payments: [] };
    }

    @Post('refund/:id')
    refund(@Param('id') id: string) {
        return { refunded: true };
    }
}

// --- Admin Controller (DANGER: Check Auth!) ---
@Controller('admin')
export class AdminController {
    @Delete('users/:id')
    // WARNING: No AuthGuard here! Shadow API!
    deleteUserAdmin(@Param('id') id: string) {
        return { deleted: true };
    }

    @Post('database/reset')
    // CRITICAL: No protection on database reset!
    resetDatabase() {
        return { reset: true };
    }

    @Get('internal/metrics')
    // No auth - exposes internal metrics
    getMetrics() {
        return { users: 1000, revenue: 50000 };
    }
}

// --- Cart Controller (Checkout Team) ---
@Controller('api/cart')
export class CartController {
    @Post('add')
    @UseGuards(AuthGuard('jwt'))
    addToCart(@Body() body: { productId: string }) {
        return { cartId: 'cart_123' };
    }

    @Post('checkout')
    @UseGuards(AuthGuard('jwt'))
    checkout(@Body() payment: PaymentDto) {
        // Checkout with credit card
        return { orderId: 'ord_123' };
    }
}
