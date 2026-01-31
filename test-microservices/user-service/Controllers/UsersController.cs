using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;

namespace UserService.Controllers;

/// <summary>
/// User Service - ASP.NET Core Microservice
/// Handles user profile management, preferences, and account settings.
/// </summary>

// =============================================================================
// MODELS
// =============================================================================

public record CreateUserRequest(
    [Required] [EmailAddress] string Email,
    [Required] [MinLength(2)] string FirstName,
    [Required] [MinLength(2)] string LastName,
    string? Phone,
    string? Avatar,
    Dictionary<string, object>? Metadata
);

public record UpdateUserRequest(
    string? FirstName,
    string? LastName,
    string? Phone,
    string? Avatar,
    string? Timezone,
    string? Locale
);

public record UserResponse(
    string Id,
    string Email,
    string FirstName,
    string LastName,
    string? Phone,
    string? Avatar,
    DateTime CreatedAt,
    DateTime UpdatedAt
);

public record AddressRequest(
    [Required] string Street,
    [Required] string City,
    [Required] string State,
    [Required] string PostalCode,
    [Required] string Country,
    bool IsDefault
);

public record PreferencesRequest(
    bool EmailNotifications,
    bool SmsNotifications,
    bool PushNotifications,
    string Theme,
    string Language
);

// =============================================================================
// HEALTH CONTROLLER
// =============================================================================

[ApiController]
[Route("[controller]")]
public class HealthController : ControllerBase
{
    [HttpGet("/health")]
    public IActionResult HealthCheck()
    {
        return Ok(new { status = "healthy", service = "user-service" });
    }

    [HttpGet("/health/live")]
    public IActionResult LivenessProbe()
    {
        return Ok(new { alive = true });
    }

    [HttpGet("/health/ready")]
    public IActionResult ReadinessProbe()
    {
        return Ok(new { ready = true, database = "connected", redis = "connected" });
    }
}

// =============================================================================
// USERS CONTROLLER
// =============================================================================

[ApiController]
[Route("api/v1/users")]
[Authorize]
public class UsersController : ControllerBase
{
    /// <summary>
    /// Get current user profile
    /// </summary>
    [HttpGet("me")]
    public ActionResult<UserResponse> GetCurrentUser()
    {
        var userId = User.FindFirst("sub")?.Value ?? "user_123";
        return Ok(new UserResponse(
            userId,
            "user@example.com",
            "John",
            "Doe",
            "+1234567890",
            null,
            DateTime.UtcNow,
            DateTime.UtcNow
        ));
    }

    /// <summary>
    /// Update current user profile
    /// </summary>
    [HttpPut("me")]
    public IActionResult UpdateCurrentUser([FromBody] UpdateUserRequest request)
    {
        return Ok(new { message = "Profile updated successfully" });
    }

    /// <summary>
    /// Delete current user account
    /// </summary>
    [HttpDelete("me")]
    public IActionResult DeleteCurrentUser([FromBody] DeleteAccountRequest request)
    {
        return Ok(new { message = "Account scheduled for deletion" });
    }

    /// <summary>
    /// Get user by ID
    /// </summary>
    [HttpGet("{userId}")]
    public ActionResult<UserResponse> GetUser(string userId)
    {
        return Ok(new UserResponse(
            userId,
            "user@example.com",
            "John",
            "Doe",
            null,
            null,
            DateTime.UtcNow,
            DateTime.UtcNow
        ));
    }

    /// <summary>
    /// Search users
    /// </summary>
    [HttpGet("search")]
    public IActionResult SearchUsers(
        [FromQuery] string? query,
        [FromQuery] int limit = 50,
        [FromQuery] int offset = 0)
    {
        return Ok(new { users = new List<UserResponse>(), total = 0 });
    }
}

public record DeleteAccountRequest(
    [Required] string Password,
    string? Reason
);

// =============================================================================
// ADDRESSES CONTROLLER
// =============================================================================

[ApiController]
[Route("api/v1/users/me/addresses")]
[Authorize]
public class AddressesController : ControllerBase
{
    /// <summary>
    /// List user addresses
    /// </summary>
    [HttpGet]
    public IActionResult GetAddresses()
    {
        return Ok(new { addresses = new List<object>() });
    }

    /// <summary>
    /// Add new address
    /// </summary>
    [HttpPost]
    public IActionResult AddAddress([FromBody] AddressRequest request)
    {
        var addressId = Guid.NewGuid().ToString();
        return Created($"/api/v1/users/me/addresses/{addressId}", new { addressId });
    }

    /// <summary>
    /// Get address by ID
    /// </summary>
    [HttpGet("{addressId}")]
    public IActionResult GetAddress(string addressId)
    {
        return Ok(new { addressId, street = "123 Main St" });
    }

    /// <summary>
    /// Update address
    /// </summary>
    [HttpPut("{addressId}")]
    public IActionResult UpdateAddress(string addressId, [FromBody] AddressRequest request)
    {
        return Ok(new { message = "Address updated" });
    }

    /// <summary>
    /// Delete address
    /// </summary>
    [HttpDelete("{addressId}")]
    public IActionResult DeleteAddress(string addressId)
    {
        return Ok(new { deleted = true });
    }

    /// <summary>
    /// Set default address
    /// </summary>
    [HttpPost("{addressId}/default")]
    public IActionResult SetDefaultAddress(string addressId)
    {
        return Ok(new { message = "Default address updated" });
    }
}

// =============================================================================
// PREFERENCES CONTROLLER
// =============================================================================

[ApiController]
[Route("api/v1/users/me/preferences")]
[Authorize]
public class PreferencesController : ControllerBase
{
    /// <summary>
    /// Get user preferences
    /// </summary>
    [HttpGet]
    public IActionResult GetPreferences()
    {
        return Ok(new
        {
            emailNotifications = true,
            smsNotifications = false,
            pushNotifications = true,
            theme = "light",
            language = "en"
        });
    }

    /// <summary>
    /// Update user preferences
    /// </summary>
    [HttpPut]
    public IActionResult UpdatePreferences([FromBody] PreferencesRequest request)
    {
        return Ok(new { message = "Preferences updated" });
    }

    /// <summary>
    /// Reset preferences to defaults
    /// </summary>
    [HttpPost("reset")]
    public IActionResult ResetPreferences()
    {
        return Ok(new { message = "Preferences reset to defaults" });
    }
}

// =============================================================================
// SECURITY CONTROLLER
// =============================================================================

[ApiController]
[Route("api/v1/users/me/security")]
[Authorize]
public class SecurityController : ControllerBase
{
    /// <summary>
    /// Change password
    /// </summary>
    [HttpPost("change-password")]
    public IActionResult ChangePassword([FromBody] ChangePasswordRequest request)
    {
        return Ok(new { message = "Password changed successfully" });
    }

    /// <summary>
    /// Get active sessions
    /// </summary>
    [HttpGet("sessions")]
    public IActionResult GetSessions()
    {
        return Ok(new { sessions = new List<object>() });
    }

    /// <summary>
    /// Revoke session
    /// </summary>
    [HttpDelete("sessions/{sessionId}")]
    public IActionResult RevokeSession(string sessionId)
    {
        return Ok(new { revoked = true });
    }

    /// <summary>
    /// Get security audit log
    /// </summary>
    [HttpGet("audit-log")]
    public IActionResult GetAuditLog([FromQuery] int limit = 50)
    {
        return Ok(new { events = new List<object>() });
    }

    /// <summary>
    /// Export user data (GDPR)
    /// </summary>
    [HttpPost("export-data")]
    public IActionResult ExportData()
    {
        return Accepted(new { message = "Data export initiated", jobId = Guid.NewGuid() });
    }
}

public record ChangePasswordRequest(
    [Required] string CurrentPassword,
    [Required] [MinLength(8)] string NewPassword
);

// =============================================================================
// ADMIN CONTROLLER
// =============================================================================

[ApiController]
[Route("internal/admin")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    /// <summary>
    /// List all users (admin)
    /// </summary>
    [HttpGet("users")]
    public IActionResult ListUsers(
        [FromQuery] int limit = 100,
        [FromQuery] int offset = 0,
        [FromQuery] string? status = null)
    {
        return Ok(new { users = new List<UserResponse>(), total = 0 });
    }

    /// <summary>
    /// Get user by ID (admin)
    /// </summary>
    [HttpGet("users/{userId}")]
    public IActionResult GetUserAdmin(string userId)
    {
        return Ok(new { userId, adminView = true });
    }

    /// <summary>
    /// Create user (admin)
    /// </summary>
    [HttpPost("users")]
    public IActionResult CreateUser([FromBody] CreateUserRequest request)
    {
        return Created("/internal/admin/users/new_user", new { userId = Guid.NewGuid() });
    }

    /// <summary>
    /// Update user (admin)
    /// </summary>
    [HttpPut("users/{userId}")]
    public IActionResult UpdateUser(string userId, [FromBody] UpdateUserRequest request)
    {
        return Ok(new { message = "User updated" });
    }

    /// <summary>
    /// Delete user permanently (admin)
    /// </summary>
    [HttpDelete("users/{userId}")]
    public IActionResult DeleteUser(string userId)
    {
        return Ok(new { deleted = true });
    }

    /// <summary>
    /// Suspend user account
    /// </summary>
    [HttpPost("users/{userId}/suspend")]
    public IActionResult SuspendUser(string userId, [FromBody] SuspendRequest request)
    {
        return Ok(new { message = "User suspended" });
    }

    /// <summary>
    /// Reactivate user account
    /// </summary>
    [HttpPost("users/{userId}/reactivate")]
    public IActionResult ReactivateUser(string userId)
    {
        return Ok(new { message = "User reactivated" });
    }

    /// <summary>
    /// Force password reset
    /// </summary>
    [HttpPost("users/{userId}/force-password-reset")]
    public IActionResult ForcePasswordReset(string userId)
    {
        return Ok(new { message = "Password reset email sent" });
    }

    /// <summary>
    /// Get user statistics
    /// </summary>
    [HttpGet("stats")]
    public IActionResult GetStats()
    {
        return Ok(new
        {
            totalUsers = 50000,
            activeUsers = 45000,
            newUsersToday = 150,
            suspendedUsers = 500
        });
    }

    /// <summary>
    /// Bulk import users
    /// </summary>
    [HttpPost("users/bulk-import")]
    public IActionResult BulkImport([FromBody] List<CreateUserRequest> users)
    {
        return Accepted(new { jobId = Guid.NewGuid(), total = users.Count });
    }

    /// <summary>
    /// Bulk export users
    /// </summary>
    [HttpPost("users/bulk-export")]
    public IActionResult BulkExport([FromBody] ExportRequest request)
    {
        return Accepted(new { jobId = Guid.NewGuid() });
    }

    /// <summary>
    /// Reset database (DANGEROUS)
    /// </summary>
    [HttpPost("database/reset")]
    public IActionResult ResetDatabase()
    {
        return Ok(new { reset = true, warning = "All user data cleared" });
    }
}

public record SuspendRequest(string Reason, DateTime? Until);
public record ExportRequest(string Format, List<string>? UserIds);
