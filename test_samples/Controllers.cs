// Sample ASP.NET Core Controllers with Proper Route Combinations
// This file demonstrates the route patterns the scanner should detect

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace SampleApi.Controllers
{
    // ==========================================================================
    // Users Controller - Full CRUD with combined routes
    // Class Route: api/[controller] -> api/users
    // ==========================================================================
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        // Combined Route: GET api/users
        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            return Ok(new { users = new string[] { } });
        }

        // Combined Route: GET api/users/{id}
        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            return Ok(new { id = id, email = "user@example.com" });
        }

        // Combined Route: GET api/users/search?query=xxx
        [HttpGet("search")]
        public async Task<IActionResult> Search([FromQuery] string query)
        {
            return Ok(new { results = new string[] { } });
        }

        // Combined Route: POST api/users
        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Create([FromBody] UserDto user)
        {
            return Created($"/api/users/1", new { id = 1 });
        }

        // Combined Route: PUT api/users/{id}
        [HttpPut("{id}")]
        [Authorize]
        public async Task<IActionResult> Update(int id, [FromBody] UserDto user)
        {
            return Ok(new { updated = true });
        }

        // Combined Route: DELETE api/users/{id}
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete(int id)
        {
            return Ok(new { deleted = true });
        }
    }

    // ==========================================================================
    // Auth Controller - Authentication endpoints
    // Class Route: api/v1/auth
    // ==========================================================================
    [Route("api/v1/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        // Combined Route: POST api/v1/auth/login
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginDto login)
        {
            return Ok(new { token = "jwt_token" });
        }

        // Combined Route: POST api/v1/auth/register
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            return Created("/api/users/1", new { id = 1 });
        }

        // Combined Route: POST api/v1/auth/refresh
        [HttpPost("refresh")]
        [Authorize]
        public async Task<IActionResult> RefreshToken()
        {
            return Ok(new { token = "new_jwt_token" });
        }

        // Combined Route: POST api/v1/auth/logout
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            return Ok(new { success = true });
        }
    }

    // ==========================================================================
    // Payment Controller - Financial operations (CRITICAL RISK)
    // Class Route: api/v1/payments
    // ==========================================================================
    [ApiController]
    [Route("api/v1/payments")]
    [Authorize]
    public class PaymentsController : ControllerBase
    {
        // Combined Route: POST api/v1/payments/charge
        [HttpPost("charge")]
        public async Task<IActionResult> Charge([FromBody] PaymentDto payment)
        {
            return Ok(new { transactionId = "txn_123" });
        }

        // Combined Route: GET api/v1/payments/history
        [HttpGet("history")]
        public async Task<IActionResult> GetHistory()
        {
            return Ok(new { transactions = new string[] { } });
        }

        // Combined Route: POST api/v1/payments/refund/{transactionId}
        [HttpPost("refund/{transactionId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Refund(string transactionId)
        {
            return Ok(new { refunded = true });
        }

        // Combined Route: GET api/v1/payments/balance
        [HttpGet("balance")]
        public async Task<IActionResult> GetBalance()
        {
            return Ok(new { balance = 1000.00 });
        }
    }

    // ==========================================================================
    // Admin Controller - DANGER: Missing auth on some endpoints!
    // Class Route: admin
    // ==========================================================================
    [Route("admin")]
    public class AdminController : Controller
    {
        // Combined Route: DELETE admin/users/{id} - NO [Authorize]! Shadow API!
        [HttpDelete("users/{id}")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            return Ok(new { deleted = true });
        }

        // Combined Route: POST admin/database/reset - CRITICAL: No auth!
        [HttpPost("database/reset")]
        public async Task<IActionResult> ResetDatabase()
        {
            return Ok(new { reset = true });
        }

        // Combined Route: GET admin/metrics - Exposes internal metrics
        [HttpGet("metrics")]
        public async Task<IActionResult> GetMetrics()
        {
            return Ok(new { users = 1000, revenue = 50000 });
        }

        // Combined Route: GET admin/logs
        [HttpGet("logs")]
        public async Task<IActionResult> GetLogs()
        {
            return Ok(new { logs = new string[] { } });
        }
    }

    // ==========================================================================
    // Products Controller - Catalog API with versioned routes
    // Class Route: api/v2/products
    // ==========================================================================
    [ApiController]
    [Route("api/v2/products")]
    public class ProductsController : ControllerBase
    {
        // Combined Route: GET api/v2/products
        [HttpGet]
        public async Task<IActionResult> GetAll([FromQuery] string category)
        {
            return Ok(new { products = new string[] { } });
        }

        // Combined Route: GET api/v2/products/{id}
        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            return Ok(new { id = id, name = "Product" });
        }

        // Combined Route: GET api/v2/products/{id}/reviews
        [HttpGet("{id}/reviews")]
        public async Task<IActionResult> GetReviews(int id)
        {
            return Ok(new { reviews = new string[] { } });
        }

        // Combined Route: POST api/v2/products
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Create([FromBody] ProductDto product)
        {
            return Created($"/api/v2/products/1", new { id = 1 });
        }

        // Combined Route: PATCH api/v2/products/{id}
        [HttpPatch("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> PartialUpdate(int id, [FromBody] object patch)
        {
            return Ok(new { updated = true });
        }
    }

    // ==========================================================================
    // Orders Controller - E-commerce orders
    // Class Route: api/v1/orders
    // ==========================================================================
    [ApiController]
    [Route("api/v1/orders")]
    [Authorize]
    public class OrdersController : ControllerBase
    {
        // Combined Route: GET api/v1/orders
        [HttpGet]
        public async Task<IActionResult> GetMyOrders()
        {
            return Ok(new { orders = new string[] { } });
        }

        // Combined Route: GET api/v1/orders/{id}
        [HttpGet("{id}")]
        public async Task<IActionResult> GetOrder(string id)
        {
            return Ok(new { orderId = id });
        }

        // Combined Route: POST api/v1/orders
        [HttpPost]
        public async Task<IActionResult> CreateOrder([FromBody] OrderDto order)
        {
            return Created("/api/v1/orders/ord_123", new { orderId = "ord_123" });
        }

        // Combined Route: POST api/v1/orders/{id}/cancel
        [HttpPost("{id}/cancel")]
        public async Task<IActionResult> CancelOrder(string id)
        {
            return Ok(new { cancelled = true });
        }
    }

    // ==========================================================================
    // Customers Controller - Using explicit route template
    // Class Route: api/v1/customers
    // ==========================================================================
    [ApiController]
    [Route("api/v1/customers")]
    public class CustomersController : ControllerBase
    {
        // Combined Route: GET api/v1/customers
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> GetAll()
        {
            return Ok(new { customers = new string[] { } });
        }

        // Combined Route: GET api/v1/customers/{customerId}
        [HttpGet("{customerId}")]
        [Authorize]
        public async Task<IActionResult> GetById(string customerId)
        {
            // Returns PII - email, phone, address
            return Ok(new { 
                customerId = customerId, 
                email = "customer@example.com",
                phone = "555-1234",
                address = "123 Main St"
            });
        }

        // Combined Route: GET api/v1/customers/{customerId}/orders
        [HttpGet("{customerId}/orders")]
        [Authorize]
        public async Task<IActionResult> GetCustomerOrders(string customerId)
        {
            return Ok(new { orders = new string[] { } });
        }

        // Combined Route: PUT api/v1/customers/{customerId}
        [HttpPut("{customerId}")]
        [Authorize]
        public async Task<IActionResult> UpdateCustomer(string customerId, [FromBody] CustomerDto dto)
        {
            return Ok(new { updated = true });
        }
    }

    // ==========================================================================
    // DTOs
    // ==========================================================================
    public class UserDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string Ssn { get; set; }
    }

    public class LoginDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class RegisterDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string Ssn { get; set; }
        public string DateOfBirth { get; set; }
    }

    public class PaymentDto
    {
        public string CreditCard { get; set; }
        public decimal Amount { get; set; }
    }

    public class ProductDto
    {
        public string Name { get; set; }
        public decimal Price { get; set; }
    }

    public class OrderDto
    {
        public string ProductId { get; set; }
        public int Quantity { get; set; }
    }

    public class CustomerDto
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
    }
}
