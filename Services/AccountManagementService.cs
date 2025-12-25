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
    
    // Set Password for Google Users
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
        
        // Check if user already has a password
        if (user.PasswordHash != null)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Account already has a password. Use 'Change Password' instead." 
            };
        }
        
        // Check if user registered with Google
        if (user.AuthProvider != AuthProvider.Google)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "This operation is only for Google accounts" 
            };
        }
        
        // Set password
        user.PasswordHash = BC.HashPassword(request.Password);
        
        // Log audit
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
    
    // Link Google Account
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
            // Verify Google token
            var payload = await Google.Apis.Auth.GoogleJsonWebSignature.ValidateAsync(googleIdToken);
            
            // Check if Google ID is already used by another user
            if (await _context.Users.AnyAsync(u => u.GoogleId == payload.Subject))
            {
                return new ApiResponse 
                { 
                    Success = false, 
                    Message = "This Google account is already linked to another user" 
                };
            }
            
            // Link Google account
            user.GoogleId = payload.Subject;
            
            // Log audit
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
    
    // Unlink Google Account
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
        
        // Check if user has a password (can't unlink if no alternative login method)
        if (user.PasswordHash == null)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Please set a password before unlinking your Google account" 
            };
        }
        
        // Verify password
        if (!BC.Verify(password, user.PasswordHash))
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Incorrect password" 
            };
        }
        
        // Unlink Google account
        user.GoogleId = null;
        
        // Log audit
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
    
    // Deactivate Account (Temporary)
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
        
        // Verify password (if user has one)
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
        
        // Deactivate account
        user.Status = AccountStatus.Suspended;
        
        // Revoke all tokens
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == user.Id && rt.IsActive)
            .ToListAsync();
        
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }
        
        // Deactivate all sessions
        var sessions = await _context.UserSessions
            .Where(s => s.UserId == user.Id && s.IsActive)
            .ToListAsync();
        
        foreach (var session in sessions)
        {
            session.IsActive = false;
        }
        
        // Log audit
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
    
    // Delete Account (Permanent)
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
        
        // Verify password (if user has one)
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
        
        // Mark as deleted (soft delete)
        user.Status = AccountStatus.Deleted;
        
        // Anonymize data (GDPR compliance)
        user.Email = $"deleted_{user.Id}@deleted.com";
        user.Username = $"deleted_{user.Id}";
        user.PasswordHash = null;
        user.GoogleId = null;
        
        // Revoke all tokens
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == user.Id && rt.IsActive)
            .ToListAsync();
        
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }
        
        // Deactivate all sessions
        var sessions = await _context.UserSessions
            .Where(s => s.UserId == user.Id && s.IsActive)
            .ToListAsync();
        
        foreach (var session in sessions)
        {
            session.IsActive = false;
        }
        
        // Log audit
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
    
    // Reactivate Account
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
        
        // Verify password
        if (user.PasswordHash == null || !BC.Verify(password, user.PasswordHash))
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Invalid email or password" 
            };
        }
        
        // Reactivate account
        user.Status = AccountStatus.Active;
        
        // Log audit
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