// Sample Spring Boot Application - Demonstrates Java/Spring patterns

package com.example.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

@SpringBootApplication
public class SampleApplication {
    public static void main(String[] args) {
        SpringApplication.run(SampleApplication.class, args);
    }
}

// =============================================================================
// USER CONTROLLER
// =============================================================================

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    // GET /api/v1/users
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(List.of());
    }

    // GET /api/v1/users/{id}
    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        // Returns PII: email, phone, ssn
        User user = new User();
        user.setEmail("user@example.com");
        user.setPhone("555-1234");
        user.setSsn("123-45-6789");
        return ResponseEntity.ok(user);
    }

    // GET /api/v1/users/search
    @GetMapping("/search")
    public ResponseEntity<List<User>> searchUsers(@RequestParam String query) {
        return ResponseEntity.ok(List.of());
    }

    // POST /api/v1/users
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody UserDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(new User());
    }

    // PUT /api/v1/users/{id}
    @PutMapping("/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Long id, @RequestBody UserDto dto) {
        return ResponseEntity.ok(new User());
    }

    // DELETE /api/v1/users/{id}
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        return ResponseEntity.noContent().build();
    }

    // PATCH /api/v1/users/{id}
    @PatchMapping("/{id}")
    public ResponseEntity<User> patchUser(@PathVariable Long id, @RequestBody Map<String, Object> updates) {
        return ResponseEntity.ok(new User());
    }
}

// =============================================================================
// AUTH CONTROLLER
// =============================================================================

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    // POST /api/v1/auth/login
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        // Handles password authentication
        return ResponseEntity.ok(new TokenResponse("jwt_token"));
    }

    // POST /api/v1/auth/register
    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody RegisterRequest request) {
        // Collects SSN during registration - HIGH RISK
        return ResponseEntity.status(HttpStatus.CREATED).body(new User());
    }

    // POST /api/v1/auth/refresh
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestHeader("Authorization") String token) {
        return ResponseEntity.ok(new TokenResponse("new_jwt_token"));
    }

    // POST /api/v1/auth/logout
    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        return ResponseEntity.ok().build();
    }
}

// =============================================================================
// PAYMENT CONTROLLER - HIGH RISK
// =============================================================================

@RestController
@RequestMapping("/api/v1/payments")
public class PaymentController {

    // POST /api/v1/payments/charge
    @PostMapping("/charge")
    public ResponseEntity<TransactionResponse> charge(@RequestBody PaymentRequest request) {
        // Processes credit_card - CRITICAL RISK
        return ResponseEntity.ok(new TransactionResponse("txn_123"));
    }

    // GET /api/v1/payments/history
    @GetMapping("/history")
    public ResponseEntity<List<Transaction>> getHistory() {
        return ResponseEntity.ok(List.of());
    }

    // POST /api/v1/payments/refund/{transactionId}
    @PostMapping("/refund/{transactionId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<TransactionResponse> refund(@PathVariable String transactionId) {
        return ResponseEntity.ok(new TransactionResponse("refund_123"));
    }

    // GET /api/v1/payments/balance
    @GetMapping("/balance")
    public ResponseEntity<BalanceResponse> getBalance() {
        return ResponseEntity.ok(new BalanceResponse(1000.00));
    }
}

// =============================================================================
// ADMIN CONTROLLER - CRITICAL: Some endpoints missing security!
// =============================================================================

@RestController
@RequestMapping("/admin")
public class AdminController {

    // DELETE /admin/users/{id} - NO @PreAuthorize! Shadow API!
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUserAdmin(@PathVariable Long id) {
        return ResponseEntity.noContent().build();
    }

    // POST /admin/database/reset - CRITICAL: No security!
    @PostMapping("/database/reset")
    public ResponseEntity<Map<String, Boolean>> resetDatabase() {
        Map<String, Boolean> response = new HashMap<>();
        response.put("reset", true);
        return ResponseEntity.ok(response);
    }

    // GET /admin/metrics - Exposes internal metrics
    @GetMapping("/metrics")
    public ResponseEntity<Map<String, Object>> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("users", 1000);
        metrics.put("revenue", 50000);
        return ResponseEntity.ok(metrics);
    }

    // GET /admin/logs
    @GetMapping("/logs")
    public ResponseEntity<List<String>> getLogs() {
        return ResponseEntity.ok(List.of());
    }
}

// =============================================================================
// PRODUCT CONTROLLER (MVC Style)
// =============================================================================

@Controller
@RequestMapping("/products")
public class ProductController {

    @GetMapping
    public String listProducts() {
        return "products/list";
    }

    @GetMapping("/{id}")
    public String showProduct(@PathVariable Long id) {
        return "products/show";
    }

    @GetMapping("/new")
    public String newProductForm() {
        return "products/new";
    }

    @PostMapping
    public String createProduct(@RequestBody ProductDto dto) {
        return "redirect:/products";
    }
}

// =============================================================================
// JAX-RS RESOURCE (Alternative to Spring MVC)
// =============================================================================

@Path("/api/v2/orders")
public class OrderResource {

    @GET
    public List<Order> getAllOrders() {
        return List.of();
    }

    @GET
    @Path("/{id}")
    public Order getOrderById(@PathParam("id") Long id) {
        return new Order();
    }

    @POST
    public Order createOrder(OrderDto dto) {
        return new Order();
    }

    @PUT
    @Path("/{id}")
    public Order updateOrder(@PathParam("id") Long id, OrderDto dto) {
        return new Order();
    }

    @DELETE
    @Path("/{id}")
    public void deleteOrder(@PathParam("id") Long id) {
    }
}

// =============================================================================
// DTOs
// =============================================================================

class User {
    private String email;
    private String phone;
    private String ssn;
    
    // Getters and setters
    public void setEmail(String email) { this.email = email; }
    public void setPhone(String phone) { this.phone = phone; }
    public void setSsn(String ssn) { this.ssn = ssn; }
}

class UserDto {
    private String email;
    private String password;
    private String ssn;
}

class LoginRequest {
    private String email;
    private String password;
}

class RegisterRequest {
    private String email;
    private String password;
    private String ssn;
    private String dateOfBirth;
}

class TokenResponse {
    private String token;
    public TokenResponse(String token) { this.token = token; }
}

class PaymentRequest {
    private String creditCard;
    private double amount;
}

class TransactionResponse {
    private String transactionId;
    public TransactionResponse(String id) { this.transactionId = id; }
}

class Transaction {}

class BalanceResponse {
    private double balance;
    public BalanceResponse(double balance) { this.balance = balance; }
}

class ProductDto {
    private String name;
    private double price;
}

class Order {}

class OrderDto {
    private String productId;
    private int quantity;
}
