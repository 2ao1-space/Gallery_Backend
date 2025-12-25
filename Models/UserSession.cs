using System.ComponentModel.DataAnnotations;

namespace Gallery.Models;

public class UserSession
{
    public Guid Id { get; set; }
    
    public Guid UserId { get; set; }
    public virtual User User { get; set; } = null!;
    
    [Required]
    public string RefreshTokenId { get; set; } = string.Empty;
    
    [MaxLength(255)]
    public string DeviceInfo { get; set; } = string.Empty;
    
    [MaxLength(50)]
    public string IpAddress { get; set; } = string.Empty;
    
    [MaxLength(100)]
    public string? UserAgent { get; set; }
    
    [MaxLength(50)]
    public string? Browser { get; set; }
    
    [MaxLength(50)]
    public string? OperatingSystem { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;
    
    public bool IsActive { get; set; } = true;
}