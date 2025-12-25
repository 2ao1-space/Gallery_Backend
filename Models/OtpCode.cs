using System.ComponentModel.DataAnnotations;

namespace Gallery.Models;

public class OtpCode
{
    public Guid Id { get; set; }
    
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    public string CodeHash { get; set; } = string.Empty;
    
    public OtpPurpose Purpose { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime ExpiresAt { get; set; }
    
    public bool IsUsed { get; set; } = false;
    
    public DateTime? UsedAt { get; set; }
    
    public int AttemptCount { get; set; } = 0;
    
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    
    public bool IsValid => !IsUsed && !IsExpired;
}

public enum OtpPurpose
{
    EmailVerification = 0,
    PasswordReset = 1,
    EmailChange = 2
}