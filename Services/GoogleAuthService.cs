using Google.Apis.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Gallery.Data;
using Gallery.DTOs;
using Gallery.Models;

namespace Gallery.Services;

public interface IGoogleAuthService
{
    Task<LoginResponse> AuthenticateGoogleUserAsync(string idToken, string ipAddress, string userAgent);
}

public class GoogleAuthService : IGoogleAuthService
{
    private readonly ApplicationDbContext _context;
    private readonly JwtService _jwtService;
    private readonly GoogleAuthSettings _googleSettings;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<GoogleAuthService> _logger;
    
    public GoogleAuthService(
        ApplicationDbContext context,
        JwtService jwtService,
        IOptions<GoogleAuthSettings> googleSettings,
        IOptions<JwtSettings> jwtSettings,
        ILogger<GoogleAuthService> logger)
    {
        _context = context;
        _jwtService = jwtService;
        _googleSettings = googleSettings.Value;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
    }
    
    public async Task<LoginResponse> AuthenticateGoogleUserAsync(
        string idToken, 
        string ipAddress, 
        string userAgent)
    {
        try
        {
            var payload = await GoogleJsonWebSignature.ValidateAsync(
                idToken,
                new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { _googleSettings.ClientId }
                }
            );
            
            var email = payload.Email;
            var googleId = payload.Subject;
            var name = payload.Name ?? email.Split('@')[0];
            
            var user = await _context.Users
                .Include(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                        .ThenInclude(r => r.RolePermissions)
                            .ThenInclude(rp => rp.Permission)
                .FirstOrDefaultAsync(u => u.Email == email || u.GoogleId == googleId);
            
            if (user == null)
            {
                user = await CreateGoogleUserAsync(email, googleId, name, ipAddress);
            }
            else
            {
                if (string.IsNullOrEmpty(user.GoogleId))
                {
                    user.GoogleId = googleId;
                    user.AuthProvider = AuthProvider.Google;
                }
                
                if (user.Status == AccountStatus.Suspended)
                {
                    throw new UnauthorizedAccessException("Your account has been suspended");
                }
                
                if (user.Status == AccountStatus.Deleted)
                {
                    throw new UnauthorizedAccessException("Your account has been deleted");
                }
                
                if (!user.IsVerified)
                {
                    user.IsVerified = true;
                    user.Status = AccountStatus.Active;
                    user.EmailVerifiedAt = DateTime.UtcNow;
                }
                
                user.LastLoginAt = DateTime.UtcNow;
            }
            
            await _context.SaveChangesAsync();
            
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
                Details = "Google OAuth",
                IpAddress = ipAddress,
                UserAgent = userAgent
            });
            
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Google user authenticated: {Email}", email);
            
            return new LoginResponse
            {
                AccessToken = accessToken,
                User = MapToUserDto(user, roles, permissions),
                Message = "Login successful"
            };
        }
        catch (InvalidJwtException)
        {
            throw new UnauthorizedAccessException("Invalid Google token");
        }
    }
    
    private async Task<User> CreateGoogleUserAsync(
        string email, 
        string googleId, 
        string name, 
        string ipAddress)
    {
        var username = await GenerateUniqueUsernameAsync(name);
        
        var user = new User
        {
            Email = email,
            Username = username,
            GoogleId = googleId,
            IsVerified = true,
            Status = AccountStatus.Active,
            AuthProvider = AuthProvider.Google,
            EmailVerifiedAt = DateTime.UtcNow
        };
        
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        
        var userRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User");
        if (userRole != null)
        {
            _context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = userRole.Id });
            await _context.SaveChangesAsync();
        }
        
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = AuditActions.AccountCreated,
            Details = "Google OAuth",
            IpAddress = ipAddress
        });
        
        await _context.SaveChangesAsync();
        
        return user;
    }
    
    private async Task<string> GenerateUniqueUsernameAsync(string name)
    {
        var baseUsername = name.ToLower()
            .Replace(" ", "")
            .Replace(".", "")
            .Replace("-", "");
        
        if (baseUsername.Length < 3)
        {
            baseUsername = "user" + baseUsername;
        }
        
        var username = baseUsername;
        var counter = 1;
        
        while (await _context.Users.AnyAsync(u => u.Username == username))
        {
            username = $"{baseUsername}{counter}";
            counter++;
        }
        
        return username;
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

public class GoogleAuthSettings
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
}