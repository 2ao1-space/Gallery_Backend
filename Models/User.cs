using System.ComponentModel.DataAnnotations;

namespace Gallery.Models;

public class User
{
    public Guid Id { get; set; }
    
    [Required]
    [EmailAddress]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    [MaxLength(50)]
    public string Username { get; set; } = string.Empty;
    
    [MaxLength(255)]
    public string? PasswordHash { get; set; }
    
    public bool IsVerified { get; set; } = false;
    
    public AccountStatus Status { get; set; } = AccountStatus.Unverified;
    
    public AuthProvider AuthProvider { get; set; } = AuthProvider.Local;
    
    [MaxLength(255)]
    public string? GoogleId { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? LastLoginAt { get; set; }
    
    public DateTime? EmailVerifiedAt { get; set; }
    
    public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    public virtual ICollection<UserSession> Sessions { get; set; } = new List<UserSession>();
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public virtual ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
}

public enum AccountStatus
{
    Unverified = 0,
    Active = 1,
    Suspended = 2,
    Deleted = 3
}

public enum AuthProvider
{
    Local = 0,
    Google = 1
}