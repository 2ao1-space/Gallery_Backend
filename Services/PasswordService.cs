using Microsoft.EntityFrameworkCore;
using Gallery.Data;
using Gallery.DTOs;
using Gallery.Models;
using BC = BCrypt.Net.BCrypt;

namespace Gallery.Services;

public interface IPasswordService
{
    Task<ApiResponse> ForgotPasswordAsync(ForgotPasswordRequest request);
    Task<ApiResponse> VerifyResetOtpAsync(VerifyResetOtpRequest request);
    Task<ApiResponse> ResetPasswordAsync(ResetPasswordRequest request, string ipAddress);
    Task<ApiResponse> ChangePasswordAsync(Guid userId, ChangePasswordRequest request, string ipAddress);
}

public class PasswordService : IPasswordService
{
    private readonly ApplicationDbContext _context;
    private readonly IOtpService _otpService;
    private readonly IEmailService _emailService;
    private readonly ILogger<PasswordService> _logger;
    
    public PasswordService(
        ApplicationDbContext context,
        IOtpService otpService,
        IEmailService emailService,
        ILogger<PasswordService> logger)
    {
        _context = context;
        _otpService = otpService;
        _emailService = emailService;
        _logger = logger;
    }
    
    public async Task<ApiResponse> ForgotPasswordAsync(ForgotPasswordRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        
        if (user == null)
        {
            return new ApiResponse 
            { 
                Success = true, 
                Message = "If the email exists, a reset code has been sent" 
            };
        }
        
        if (user.AuthProvider == AuthProvider.Google && user.PasswordHash == null)
        {
            return new ApiResponse
            {
                Success = false,
                Message = "This account was created with Google. Please sign in with Google."
            };
        }
        
        var canResend = await _otpService.CanResendOtpAsync(request.Email, OtpPurpose.PasswordReset);
        
        if (!canResend)
        {
            return new ApiResponse 
            { 
                Success = false, 
                Message = "Please wait before requesting another code" 
            };
        }
        
        var otp = await _otpService.GenerateOtpAsync(request.Email, OtpPurpose.PasswordReset);
        await _emailService.SendPasswordResetEmailAsync(user.Email, user.Username, otp);
        
        _logger.LogInformation("Password reset requested for {Email}", request.Email);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "If the email exists, a reset code has been sent" 
        };
    }
    
    public async Task<ApiResponse> VerifyResetOtpAsync(VerifyResetOtpRequest request)
    {
        var isValid = await _otpService.ValidateOtpAsync(
            request.Email, 
            request.Otp, 
            OtpPurpose.PasswordReset
        );
        
        if (!isValid)
        {
            return new ApiResponse { Success = false, Message = "Invalid or expired OTP" };
        }
        
        return new ApiResponse { Success = true, Message = "OTP verified. You can now reset your password" };
    }
    
    public async Task<ApiResponse> ResetPasswordAsync(ResetPasswordRequest request, string ipAddress)
    {
        var isValid = await _otpService.ValidateOtpAsync(
            request.Email, 
            request.Otp, 
            OtpPurpose.PasswordReset
        );
        
        if (!isValid)
        {
            return new ApiResponse { Success = false, Message = "Invalid or expired OTP" };
        }
        
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        user.PasswordHash = BC.HashPassword(request.NewPassword);
        
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == user.Id && rt.IsActive)
            .ToListAsync();
        
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;
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
            Action = AuditActions.PasswordReset,
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Password reset for {Email}", user.Email);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Password reset successfully. Please login with your new password" 
        };
    }
    
    // Google users 
    public async Task<ApiResponse> ChangePasswordAsync(
        Guid userId, 
        ChangePasswordRequest request, 
        string ipAddress)
    {
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        if (user.PasswordHash == null)
        {
            return new ApiResponse
            {
                Success = false,
                Message = "This account doesn't have a password. Please use 'Set Password' instead."
            };
        }
        
        if (!BC.Verify(request.CurrentPassword, user.PasswordHash))
        {
            return new ApiResponse { Success = false, Message = "Current password is incorrect" };
        }
        
        user.PasswordHash = BC.HashPassword(request.NewPassword);
        
        var refreshTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == user.Id && rt.IsActive)
            .ToListAsync();
        
        foreach (var token in refreshTokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = AuditActions.PasswordChanged,
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Password changed for user {UserId}", userId);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Password changed successfully. Please login again." 
        };
    }
}