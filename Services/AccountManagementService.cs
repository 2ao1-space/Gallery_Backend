using Microsoft.EntityFrameworkCore;
using Gallery.Data;
using Gallery.DTOs;
using Gallery.Models;
using BC = BCrypt.Net.BCrypt;

namespace Gallery.Services;

public interface IAccountManagementService
{
    Task<ApiResponse> SetPasswordAsync(Guid userId, SetPasswordRequest request, string ipAddress);
    Task<ApiResponse> LinkGoogleAccountAsync(Guid userId, string googleIdToken, string ipAddress);
    Task<ApiResponse> UnlinkGoogleAccountAsync(Guid userId, string password, string ipAddress);
    Task<ApiResponse> DeactivateAccountAsync(Guid userId, string password, string ipAddress);
    Task<ApiResponse> DeleteAccountAsync(Guid userId, string password, string ipAddress);
    Task<ApiResponse> ReactivateAccountAsync(string email, string password, string ipAddress);
}

public class AccountManagementService : IAccountManagementService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<AccountManagementService> _logger;
    
    public AccountManagementService(
        ApplicationDbContext context,
        ILogger<AccountManagementService> logger)
    {
        _context = context;
        _logger = logger;
    }
    
    // Google Users
    public async Task<ApiResponse> SetPasswordAsync(
        Guid userId, 
        SetPasswordRequest request, 
        string ipAddress)
    {
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        if (user.PasswordHash != null)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Account already has a password. Use 'Change Password' instead." 
            };
        }
        
        if (user.AuthProvider != AuthProvider.Google)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "This operation is only for Google accounts" 
            };
        }
        
        user.PasswordHash = BC.HashPassword(request.Password);
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = "Password Set",
            Details = "Password added to Google account",
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Password set for Google user {UserId}", userId);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Password set successfully. You can now login with email and password." 
        };
    }
    
    public async Task<ApiResponse> LinkGoogleAccountAsync(
        Guid userId, 
        string googleIdToken, 
        string ipAddress)
    {
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        if (!string.IsNullOrEmpty(user.GoogleId))
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Google account already linked" 
            };
        }
        
        try
        {
            var payload = await Google.Apis.Auth.GoogleJsonWebSignature.ValidateAsync(googleIdToken);
            
            if (await _context.Users.AnyAsync(u => u.GoogleId == payload.Subject))
            {
                return new ApiResponse 
                { 
                    Success = false, 
                    Message = "This Google account is already linked to another user" 
                };
            }
            
            user.GoogleId = payload.Subject;
            
            _context.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Action = AuditActions.GoogleLinked,
                Details = "Google account linked",
                IpAddress = ipAddress
            });
            
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Google account linked for user {UserId}", userId);
            
            return new ApiResponse 
            { 
                Success = true, 
                Message = "Google account linked successfully" 
            };
        }
        catch
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Invalid Google token" 
            };
        }
    }
    
    public async Task<ApiResponse> UnlinkGoogleAccountAsync(
        Guid userId, 
        string password, 
        string ipAddress)
    {
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        if (string.IsNullOrEmpty(user.GoogleId))
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "No Google account linked" 
            };
        }
        
        if (user.PasswordHash == null)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Please set a password before unlinking your Google account" 
            };
        }
        
        if (!BC.Verify(password, user.PasswordHash))
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Incorrect password" 
            };
        }
        
        user.GoogleId = null;
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = AuditActions.GoogleUnlinked,
            Details = "Google account unlinked",
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Google account unlinked for user {UserId}", userId);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Google account unlinked successfully" 
        };
    }
    
    public async Task<ApiResponse> DeactivateAccountAsync(
        Guid userId, 
        string password, 
        string ipAddress)
    {
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        if (user.Status == AccountStatus.Deleted)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Account is already deleted" 
            };
        }
        
        if (user.PasswordHash != null)
        {
            if (!BC.Verify(password, user.PasswordHash))
            {
                return new ApiResponse 
                { 
                    Success = false, 
                    Message = "Incorrect password" 
                };
            }
        }
        
        user.Status = AccountStatus.Suspended;
        
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == user.Id && rt.IsActive)
            .ToListAsync();
        
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }
        
        var sessions = await _context.UserSessions
            .Where(s => s.UserId == user.Id && s.IsActive)
            .ToListAsync();
        
        foreach (var session in sessions)
        {
            session.IsActive = false;
        }
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = AuditActions.AccountDeactivated,
            Details = "Account deactivated by user",
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Account deactivated for user {UserId}", userId);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Account deactivated successfully. You can reactivate it anytime by logging in." 
        };
    }
    
    public async Task<ApiResponse> DeleteAccountAsync(
        Guid userId, 
        string password, 
        string ipAddress)
    {
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        if (user.PasswordHash != null)
        {
            if (!BC.Verify(password, user.PasswordHash))
            {
                return new ApiResponse 
                { 
                    Success = false, 
                    Message = "Incorrect password" 
                };
            }
        }
        
        user.Status = AccountStatus.Deleted;
        
        user.Email = $"deleted_{user.Id}@deleted.com";
        user.Username = $"deleted_{user.Id}";
        user.PasswordHash = null;
        user.GoogleId = null;
        
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == user.Id && rt.IsActive)
            .ToListAsync();
        
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }
        
        var sessions = await _context.UserSessions
            .Where(s => s.UserId == user.Id && s.IsActive)
            .ToListAsync();
        
        foreach (var session in sessions)
        {
            session.IsActive = false;
        }
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = AuditActions.AccountDeleted,
            Details = "Account permanently deleted by user",
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Account deleted for user {UserId}", userId);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Account deleted successfully. Your data has been anonymized." 
        };
    }
    
    public async Task<ApiResponse> ReactivateAccountAsync(
        string email, 
        string password, 
        string ipAddress)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);
        
        if (user == null)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Invalid email or password" 
            };
        }
        
        if (user.Status != AccountStatus.Suspended)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Account is not deactivated" 
            };
        }
        
        if (user.PasswordHash == null || !BC.Verify(password, user.PasswordHash))
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Invalid email or password" 
            };
        }
        
        user.Status = AccountStatus.Active;
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = "Account Reactivated",
            Details = "Account reactivated by user",
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Account reactivated for user {UserId}", user.Id);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Account reactivated successfully. You can now login." 
        };
    }
}