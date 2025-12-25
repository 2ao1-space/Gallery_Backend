using System.ComponentModel.DataAnnotations;

namespace Gallery.Models;

public class AuditLog
{
    public Guid Id { get; set; }
    
    public Guid UserId { get; set; }
    public virtual User User { get; set; } = null!;
    
    [Required]
    [MaxLength(100)]
    public string Action { get; set; } = string.Empty;
    
    [MaxLength(500)]
    public string? Details { get; set; }
    
    [MaxLength(50)]
    public string IpAddress { get; set; } = string.Empty;
    
    [MaxLength(255)]
    public string? UserAgent { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public static class AuditActions
{
    public const string UserLoggedIn = "User Logged In";
    public const string UserLoggedOut = "User Logged Out";
    public const string PasswordChanged = "Password Changed";
    public const string EmailChanged = "Email Changed";
    public const string AccountCreated = "Account Created";
    public const string EmailVerified = "Email Verified";
    public const string PasswordReset = "Password Reset";
    public const string NewDeviceLogin = "New Device Login";
    public const string SessionRevoked = "Session Revoked";
    public const string GoogleLinked = "Google Account Linked";
    public const string GoogleUnlinked = "Google Account Unlinked";
    public const string AccountDeactivated = "Account Deactivated";
    public const string AccountDeleted = "Account Deleted";
}