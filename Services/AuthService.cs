using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Gallery.Data;
using Gallery.DTOs;
using Gallery.Models;
using BC = BCrypt.Net.BCrypt;

namespace Gallery.Services;

public interface IAuthService
{
    Task<ApiResponse> RegisterAsync(RegisterRequest request, string ipAddress);
    Task<LoginResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent);
    Task<ApiResponse> VerifyEmailAsync(VerifyEmailRequest request);
    Task<ApiResponse> ResendOtpAsync(ResendOtpRequest request);
    Task<LoginResponse> RefreshTokenAsync(string refreshToken, string ipAddress, string userAgent);
    Task<ApiResponse> LogoutAsync(Guid userId, string refreshToken);
    Task<UserDto> GetCurrentUserAsync(Guid userId);
}

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _context;
    private readonly JwtService _jwtService;
    private readonly IOtpService _otpService;
    private readonly IEmailService _emailService;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<AuthService> _logger;
    
    public AuthService(
        ApplicationDbContext context,
        JwtService jwtService,
        IOtpService otpService,
        IEmailService emailService,
        IOptions<JwtSettings> jwtSettings,
        ILogger<AuthService> logger)
    {
        _context = context;
        _jwtService = jwtService;
        _otpService = otpService;
        _emailService = emailService;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
    }
    
    public async Task<ApiResponse> RegisterAsync(RegisterRequest request, string ipAddress)
    {
        if (await _context.Users.AnyAsync(u => u.Email == request.Email))
        {
            return new ApiResponse { Success = false, Message = "Email already registered" };
        }
        
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
        {
            return new ApiResponse { Success = false, Message = "Username already taken" };
        }
        
        if (!IsValidUsername(request.Username))
        {
            return new ApiResponse { Success = false, Message = "Invalid username format" };
        }
        
        var passwordHash = BC.HashPassword(request.Password);
        
        var user = new User
        {
            Email = request.Email,
            Username = request.Username,
            PasswordHash = passwordHash,
            IsVerified = false,
            Status = AccountStatus.Unverified,
            AuthProvider = AuthProvider.Local
        };
        
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        
        var userRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User");
        if (userRole != null)
        {
            _context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = userRole.Id });
            await _context.SaveChangesAsync();
        }
        
        var otp = await _otpService.GenerateOtpAsync(user.Email, OtpPurpose.EmailVerification);
        await _emailService.SendVerificationEmailAsync(user.Email, user.Username, otp);
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = AuditActions.AccountCreated,
            IpAddress = ipAddress
        });
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("User registered: {Email}", user.Email);
        
        return new ApiResponse 
        { 
            Success = true, 
            Message = "Registration successful. Please check your email for verification code." 
        };
    }
    
    public async Task<LoginResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                    .ThenInclude(r => r.RolePermissions)
                        .ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(u => u.Email == request.Email);
        
        if (user == null || user.PasswordHash == null)
        {
            throw new UnauthorizedAccessException("Invalid email or password");
        }
        
        if (!BC.Verify(request.Password, user.PasswordHash))
        {
            throw new UnauthorizedAccessException("Invalid email or password");
        }
        
        if (!user.IsVerified)
        {
            throw new UnauthorizedAccessException("Please verify your email before logging in");
        }
        
        if (user.Status == AccountStatus.Suspended)
        {
            throw new UnauthorizedAccessException("Your account has been suspended");
        }
        
        if (user.Status == AccountStatus.Deleted)
        {
            throw new UnauthorizedAccessException("Your account has been deleted");
        }
        
        var roles = user.UserRoles.Select(ur => ur.Role.Name).ToList();
        var permissions = user.UserRoles
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToList();
        
        var accessToken = _jwtService.GenerateAccessToken(user, roles, permissions);
        var refreshToken = _jwtService.GenerateRefreshToken();
        
        var refreshTokenEntity = new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
            IpAddress = ipAddress,
            DeviceInfo = userAgent
        };
        
        _context.RefreshTokens.Add(refreshTokenEntity);
        
        user.LastLoginAt = DateTime.UtcNow;
        
        var session = new UserSession
        {
            UserId = user.Id,
            RefreshTokenId = refreshToken,
            DeviceInfo = ExtractDeviceInfo(userAgent),
            IpAddress = ipAddress,
            UserAgent = userAgent
        };
        
        _context.UserSessions.Add(session);
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = AuditActions.UserLoggedIn,
            IpAddress = ipAddress,
            UserAgent = userAgent
        });
        
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("User logged in: {Email}", user.Email);
        
        return new LoginResponse
        {
            AccessToken = accessToken,
            User = MapToUserDto(user, roles, permissions),
            Message = "Login successful"
        };
    }
    
    public async Task<ApiResponse> VerifyEmailAsync(VerifyEmailRequest request)
    {
        var isValid = await _otpService.ValidateOtpAsync(request.Email, request.Otp, OtpPurpose.EmailVerification);
        
        if (!isValid)
        {
            return new ApiResponse { Success = false, Message = "Invalid or expired OTP" };
        }
        
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        user.IsVerified = true;
        user.Status = AccountStatus.Active;
        user.EmailVerifiedAt = DateTime.UtcNow;
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = AuditActions.EmailVerified,
            IpAddress = "N/A"
        });
        
        await _context.SaveChangesAsync();
        
        return new ApiResponse { Success = true, Message = "Email verified successfully" };
    }
    
    public async Task<ApiResponse> ResendOtpAsync(ResendOtpRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        
        if (user == null)
        {
            return new ApiResponse { Success = false, Message = "User not found" };
        }
        
        if (user.IsVerified)
        {
            return new ApiResponse { Success = false, Message = "Email already verified" };
        }
        
        var canResend = await _otpService.CanResendOtpAsync(request.Email, OtpPurpose.EmailVerification);
        
        if (!canResend)
        {
            return new ApiResponse { Success = false, Message = "Please wait before requesting another code" };
        }
        
        var otp = await _otpService.GenerateOtpAsync(request.Email, OtpPurpose.EmailVerification);
        await _emailService.SendVerificationEmailAsync(user.Email, user.Username, otp);
        
        return new ApiResponse { Success = true, Message = "Verification code sent" };
    }
    
    public async Task<LoginResponse> RefreshTokenAsync(string refreshToken, string ipAddress, string userAgent)
    {
        var token = await _context.RefreshTokens
            .Include(rt => rt.User)
                .ThenInclude(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                        .ThenInclude(r => r.RolePermissions)
                            .ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken);
        
        if (token == null || !token.IsActive)
        {
            throw new UnauthorizedAccessException("Invalid refresh token");
        }
        
        var user = token.User;
        
        var roles = user.UserRoles.Select(ur => ur.Role.Name).ToList();
        var permissions = user.UserRoles
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToList();
        
        var newAccessToken = _jwtService.GenerateAccessToken(user, roles, permissions);
        var newRefreshToken = _jwtService.GenerateRefreshToken();
        
        token.IsRevoked = true;
        token.RevokedAt = DateTime.UtcNow;
        token.ReplacedByToken = newRefreshToken;
        
        var newRefreshTokenEntity = new RefreshToken
        {
            Token = newRefreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
            IpAddress = ipAddress,
            DeviceInfo = userAgent
        };
        
        _context.RefreshTokens.Add(newRefreshTokenEntity);
        await _context.SaveChangesAsync();
        
        return new LoginResponse
        {
            AccessToken = newAccessToken,
            User = MapToUserDto(user, roles, permissions),
            Message = "Token refreshed successfully"
        };
    }
    
    public async Task<ApiResponse> LogoutAsync(Guid userId, string refreshToken)
    {
        var token = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.UserId == userId);
        
        if (token != null)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
            
            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.RefreshTokenId == refreshToken);
            
            if (session != null)
            {
                session.IsActive = false;
            }
            
            _context.AuditLogs.Add(new AuditLog
            {
                UserId = userId,
                Action = AuditActions.UserLoggedOut,
                IpAddress = token.IpAddress ?? "N/A"
            });
            
            await _context.SaveChangesAsync();
        }
        
        return new ApiResponse { Success = true, Message = "Logged out successfully" };
    }
    
    public async Task<UserDto> GetCurrentUserAsync(Guid userId)
    {
        var user = await _context.Users
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
                    .ThenInclude(r => r.RolePermissions)
                        .ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(u => u.Id == userId);
        
        if (user == null)
        {
            throw new Exception("User not found");
        }
        
        var roles = user.UserRoles.Select(ur => ur.Role.Name).ToList();
        var permissions = user.UserRoles
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToList();
        
        return MapToUserDto(user, roles, permissions);
    }
    
    private bool IsValidUsername(string username)
    {
        if (username.Contains(" ")) return false;
        if (username.Length < 3) return false;
        
        var bannedWords = new[] { "admin", "root", "moderator", "fuck", "shit" };
        return !bannedWords.Any(w => username.ToLower().Contains(w));
    }
    
    private string ExtractDeviceInfo(string userAgent)
    {
        if (string.IsNullOrEmpty(userAgent)) return "Unknown";
        
        if (userAgent.Contains("Mobile")) return "Mobile Device";
        if (userAgent.Contains("Windows")) return "Windows PC";
        if (userAgent.Contains("Mac")) return "Mac";
        if (userAgent.Contains("Linux")) return "Linux";
        
        return "Unknown Device";
    }
    
    private UserDto MapToUserDto(User user, List<string> roles, List<string> permissions)
    {
        return new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            Username = user.Username,
            IsVerified = user.IsVerified,
            Status = user.Status.ToString(),
            AuthProvider = user.AuthProvider.ToString(),
            Roles = roles,
            Permissions = permissions,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt
        };
    }
}