using Microsoft.EntityFrameworkCore;
using Gallery.Data;
using Gallery.DTOs;
using Gallery.Models;
using BC = BCrypt.Net.BCrypt;

namespace Gallery.Services;

public interface IEmailChangeService
{
    Task<ApiResponse> InitiateEmailChangeAsync(Guid userId, ChangeEmailRequest request);
    Task<ApiResponse> VerifyNewEmailAsync(Guid userId, VerifyNewEmailRequest request, string ipAddress);
}

public class EmailChangeService : IEmailChangeService
{
    private readonly ApplicationDbContext _context;
    private readonly IOtpService _otpService;
    private readonly IEmailService _emailService;
    private readonly ILogger<EmailChangeService> _logger;
    
    public EmailChangeService(
        ApplicationDbContext context,
        IOtpService otpService,
        IEmailService emailService,
        ILogger<EmailChangeService> logger)
    {
        _context = context;
        _otpService = otpService;
        _emailService = emailService;
        _logger = logger;
    }
    
    public async Task<ApiResponse> InitiateEmailChangeAsync(Guid userId, ChangeEmailRequest request)
    {
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        // Check if new email is same as current
        if (user.Email == request.NewEmail)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "New email is the same as current email" 
            };
        }
        
        // Check if new email already exists
        if (await _context.Users.AnyAsync(u => u.Email == request.NewEmail))
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "This email is already registered" 
            };
        }
        
        // Verify password (except for Google users without password)
        if (user.PasswordHash != null)
        {
            if (!BC.Verify(request.Password, user.PasswordHash))
            {
                return new ApiResponse 
                { 
                    Success = false, 
                    Message = "Incorrect password" 
                };
            }
        }
        
        // Generate OTP for old email (confirmation)
        var oldEmailOtp = await _otpService.GenerateOtpAsync(
            user.Email, 
            OtpPurpose.EmailChange
        );
        
        // Generate OTP for new email (verification)
        var newEmailOtp = await _otpService.GenerateOtpAsync(
            request.NewEmail, 
            OtpPurpose.EmailChange
        );
        
        // Send OTPs
        await _emailService.SendEmailChangeVerificationAsync(
            user.Email, 
            user.Username, 
            oldEmailOtp
        );
        
        await _emailService.SendEmailChangeVerificationAsync(
            request.NewEmail, 
            user.Username, 
            newEmailOtp
        );
        
        // Store pending email change in temporary table or cache
        var pendingChange = new PendingEmailChange
        {
            UserId = userId,
            OldEmail = user.Email,
            NewEmail = request.NewEmail,
            ExpiresAt = DateTime.UtcNow.AddMinutes(15)
        };
        
        _context.PendingEmailChanges.Add(pendingChange);
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Email change initiated for user {UserId}", userId);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Verification codes sent to both old and new email addresses" 
        };
    }
    
    public async Task<ApiResponse> VerifyNewEmailAsync(
        Guid userId, 
        VerifyNewEmailRequest request, 
        string ipAddress)
    {
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        // Get pending email change
        var pendingChange = await _context.PendingEmailChanges
            .Where(p => p.UserId == userId && !p.IsCompleted)
            .OrderByDescending(p => p.CreatedAt)
            .FirstOrDefaultAsync();
        
        if (pendingChange == null)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "No pending email change found" 
            };
        }
        
        if (pendingChange.IsExpired)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Email change request expired" 
            };
        }
        
        // Verify OTP for new email
        var isValid = await _otpService.ValidateOtpAsync(
            pendingChange.NewEmail, 
            request.Otp, 
            OtpPurpose.EmailChange
        );
        
        if (!isValid)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Invalid or expired verification code" 
            };
        }
        
        // Update user email
        user.Email = pendingChange.NewEmail;
        
        // Mark pending change as completed
        pendingChange.IsCompleted = true;
        pendingChange.CompletedAt = DateTime.UtcNow;
        
        // Invalidate all refresh tokens (security measure)
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
            Action = AuditActions.EmailChanged,
            Details = $"Changed from {pendingChange.OldEmail} to {pendingChange.NewEmail}",
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Email changed for user {UserId}", userId);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Email changed successfully. Please login again with your new email." 
        };
    }
}

// New Model for Pending Email Changes
public class PendingEmailChange
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string OldEmail { get; set; } = string.Empty;
    public string NewEmail { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public bool IsCompleted { get; set; } = false;
    public DateTime? CompletedAt { get; set; }
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
}