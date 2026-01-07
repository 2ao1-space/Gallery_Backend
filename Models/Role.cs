using System.ComponentModel.DataAnnotations;

namespace Gallery.Models;

public class Role
{
    public Guid Id { get; set; }
    
    [Required]
    [MaxLength(50)]
    public string Name { get; set; } = string.Empty;
    
    [MaxLength(255)]
    public string? Description { get; set; }
    
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

public class Permission
{
    public Guid Id { get; set; }
    
    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;
    
    [MaxLength(255)]
    public string? Description { get; set; }
    
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

public class UserRole
{
    public Guid UserId { get; set; }
    public virtual User User { get; set; } = null!;
    
    public Guid RoleId { get; set; }
    public virtual Role Role { get; set; } = null!;
    
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
}

public class RolePermission
{
    public Guid RoleId { get; set; }
    public virtual Role Role { get; set; } = null!;
    
    public Guid PermissionId { get; set; }
    public virtual Permission Permission { get; set; } = null!;
}