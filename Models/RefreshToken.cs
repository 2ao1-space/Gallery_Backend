using System.ComponentModel.DataAnnotations;

namespace Gallery.Models;

public class RefreshToken
{
    public Guid Id { get; set; }
    
    [Required]
    public string Token { get; set; } = string.Empty;
    
    public Guid UserId { get; set; }
    public virtual User User { get; set; } = null!;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime ExpiresAt { get; set; }
    
    public bool IsRevoked { get; set; } = false;
    
    public DateTime? RevokedAt { get; set; }
    
    [MaxLength(50)]
    public string? RevokedByIp { get; set; }
    
    public string? ReplacedByToken { get; set; }
    
    [MaxLength(255)]
    public string? DeviceInfo { get; set; }
    
    [MaxLength(50)]
    public string? IpAddress { get; set; }
    
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    
    public bool IsActive => !IsRevoked && !IsExpired;
}