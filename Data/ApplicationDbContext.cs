using Microsoft.EntityFrameworkCore;
using Gallery.Models;
using Gallery.Services;

namespace Gallery.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) 
        : base(options)
    {
    }
    
    public DbSet<User> Users { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<OtpCode> OtpCodes { get; set; }
    public DbSet<UserSession> UserSessions { get; set; }
    public DbSet<Role> Roles { get; set; }
    public DbSet<Permission> Permissions { get; set; }
    public DbSet<UserRole> UserRoles { get; set; }
    public DbSet<RolePermission> RolePermissions { get; set; }
    public DbSet<AuditLog> AuditLogs { get; set; }
    public DbSet<PendingEmailChange> PendingEmailChanges { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // User
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Email).IsUnique();
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.GoogleId);
        });
        
        // RefreshToken
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Token).IsUnique();
            entity.HasOne(e => e.User)
                .WithMany(u => u.RefreshTokens)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
        
        // OtpCode
        modelBuilder.Entity<OtpCode>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.Email, e.Purpose });
        });
        
        // UserSession
        modelBuilder.Entity<UserSession>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasOne(e => e.User)
                .WithMany(u => u.Sessions)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
        
        // UserRole
        modelBuilder.Entity<UserRole>(entity =>
        {
            entity.HasKey(e => new { e.UserId, e.RoleId });
            entity.HasOne(e => e.User)
                .WithMany(u => u.UserRoles)
                .HasForeignKey(e => e.UserId);
            entity.HasOne(e => e.Role)
                .WithMany(r => r.UserRoles)
                .HasForeignKey(e => e.RoleId);
        });
        
        // RolePermission
        modelBuilder.Entity<RolePermission>(entity =>
        {
            entity.HasKey(e => new { e.RoleId, e.PermissionId });
            entity.HasOne(e => e.Role)
                .WithMany(r => r.RolePermissions)
                .HasForeignKey(e => e.RoleId);
            entity.HasOne(e => e.Permission)
                .WithMany(p => p.RolePermissions)
                .HasForeignKey(e => e.PermissionId);
        });
        
        // AuditLog
        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasOne(e => e.User)
                .WithMany(u => u.AuditLogs)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
        
        // PendingEmailChange
        modelBuilder.Entity<PendingEmailChange>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.UserId, e.IsCompleted });
        });
        
        // Seed Default Roles
        SeedRoles(modelBuilder);
        SeedPermissions(modelBuilder);
    }
    
    private void SeedRoles(ModelBuilder modelBuilder)
    {
        var userRoleId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var adminRoleId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var modRoleId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        
        modelBuilder.Entity<Role>().HasData(
            new Role { Id = userRoleId, Name = "User", Description = "Default user role" },
            new Role { Id = adminRoleId, Name = "Admin", Description = "Administrator role" },
            new Role { Id = modRoleId, Name = "Moderator", Description = "Moderator role" }
        );
    }
    
    private void SeedPermissions(ModelBuilder modelBuilder)
    {
        var permissions = new[]
        {
            new Permission { Id = Guid.NewGuid(), Name = "create_pin", Description = "Create pins" },
            new Permission { Id = Guid.NewGuid(), Name = "edit_pin", Description = "Edit own pins" },
            new Permission { Id = Guid.NewGuid(), Name = "delete_pin", Description = "Delete own pins" },
            new Permission { Id = Guid.NewGuid(), Name = "save_pin", Description = "Save pins" },
            new Permission { Id = Guid.NewGuid(), Name = "comment", Description = "Comment on pins" },
            new Permission { Id = Guid.NewGuid(), Name = "moderate_content", Description = "Moderate content" },
            new Permission { Id = Guid.NewGuid(), Name = "manage_users", Description = "Manage users" }
        };
        
        modelBuilder.Entity<Permission>().HasData(permissions);
    }
}