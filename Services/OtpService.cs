using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Gallery.Data;
using Gallery.Models;

namespace Gallery.Services;

public interface IOtpService
{
    Task<string> GenerateOtpAsync(string email, OtpPurpose purpose);
    Task<bool> ValidateOtpAsync(string email, string otp, OtpPurpose purpose);
    Task<bool> CanResendOtpAsync(string email, OtpPurpose purpose);
    Task InvalidateOtpAsync(string email, OtpPurpose purpose);
}

public class OtpService : IOtpService
{
    private readonly ApplicationDbContext _context;
    private readonly OtpSettings _otpSettings;
    private readonly ILogger<OtpService> _logger;
    
    public OtpService(
        ApplicationDbContext context,
        IOptions<OtpSettings> otpSettings,
        ILogger<OtpService> logger)
    {
        _context = context;
        _otpSettings = otpSettings.Value;
        _logger = logger;
    }
    
    public async Task<string> GenerateOtpAsync(string email, OtpPurpose purpose)
    {
        await InvalidateOtpAsync(email, purpose);
        
        var otp = GenerateRandomOtp();
        
        var otpHash = HashOtp(otp);
        
        var otpCode = new OtpCode
        {
            Email = email,
            CodeHash = otpHash,
            Purpose = purpose,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_otpSettings.ExpirationMinutes)
        };
        
        _context.OtpCodes.Add(otpCode);
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("OTP generated for {Email} with purpose {Purpose}", email, purpose);
        
        return otp;
    }
    
    public async Task<bool> ValidateOtpAsync(string email, string otp, OtpPurpose purpose)
    {
        var otpHash = HashOtp(otp);
        
        var otpCode = await _context.OtpCodes
            .Where(o => o.Email == email && o.Purpose == purpose && o.IsValid)
            .OrderByDescending(o => o.CreatedAt)
            .FirstOrDefaultAsync();
        
        if (otpCode == null)
        {
            _logger.LogWarning("No valid OTP found for {Email}", email);
            return false;
        }
        
        otpCode.AttemptCount++;
        
        if (otpCode.AttemptCount > _otpSettings.MaxResendAttempts)
        {
            otpCode.IsUsed = true;
            await _context.SaveChangesAsync();
            _logger.LogWarning("Max OTP attempts exceeded for {Email}", email);
            return false;
        }
        
        if (otpCode.CodeHash != otpHash)
        {
            await _context.SaveChangesAsync();
            _logger.LogWarning("Invalid OTP attempt for {Email}", email);
            return false;
        }
        
        otpCode.IsUsed = true;
        otpCode.UsedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("OTP validated successfully for {Email}", email);
        return true;
    }
    
    public async Task<bool> CanResendOtpAsync(string email, OtpPurpose purpose)
    {
        var lastOtp = await _context.OtpCodes
            .Where(o => o.Email == email && o.Purpose == purpose)
            .OrderByDescending(o => o.CreatedAt)
            .FirstOrDefaultAsync();
        
        if (lastOtp == null) return true;
        
        var timeSinceLastOtp = DateTime.UtcNow - lastOtp.CreatedAt;
        return timeSinceLastOtp.TotalSeconds >= _otpSettings.ResendCooldownSeconds;
    }
    
    public async Task InvalidateOtpAsync(string email, OtpPurpose purpose)
    {
        var oldOtps = await _context.OtpCodes
            .Where(o => o.Email == email && o.Purpose == purpose && !o.IsUsed)
            .ToListAsync();
        
        foreach (var otp in oldOtps)
        {
            otp.IsUsed = true;
        }
        
        await _context.SaveChangesAsync();
    }
    
    private string GenerateRandomOtp()
    {
        var otp = "";
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        
        rng.GetBytes(bytes);
        var randomNumber = BitConverter.ToUInt32(bytes, 0);
        otp = (randomNumber % (int)Math.Pow(10, _otpSettings.Length)).ToString($"D{_otpSettings.Length}");
        
        return otp;
    }
    
    private string HashOtp(string otp)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(otp));
        return Convert.ToBase64String(bytes);
    }
}

public class OtpSettings
{
    public int ExpirationMinutes { get; set; }
    public int Length { get; set; }
    public int MaxResendAttempts { get; set; }
    public int ResendCooldownSeconds { get; set; }
}