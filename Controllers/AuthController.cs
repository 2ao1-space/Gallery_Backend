using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Gallery.DTOs;
using Gallery.Middleware;
using Gallery.Services;
using System.Security.Claims;

namespace Gallery.Controllers
{
    [ApiController]
    [Route("auth")]
    public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IPasswordService _passwordService;
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(
        IAuthService authService,
        IPasswordService passwordService,
        ILogger<AuthController> logger)
    {
        _authService = authService;
        _passwordService = passwordService;
        _logger = logger;
    }
    
    // POST /api/auth/register
    // Max 3 registrations per hour per IP
    [HttpPost("register")]
    [RateLimit(3, 60)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        try
        {
            var ipAddress = GetIpAddress();
            var result = await _authService.RegisterAsync(request, ipAddress);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred during registration" 
            });
        }
    }
    
    // POST /api/auth/verify-email
    // Max 5 attempts per 10 minutes per IP
    [HttpPost("verify-email")]
    [RateLimit(5, 10)]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
    {
        try
        {
            var result = await _authService.VerifyEmailAsync(request);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email verification error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred during verification" 
            });
        }
    }
    
    // POST /api/auth/resend-otp
    // Max 3 resends per 15 minutes per IP
    [HttpPost("resend-otp")]
    [RateLimit(3, 15)]
    public async Task<IActionResult> ResendOtp([FromBody] ResendOtpRequest request)
    {
        try
        {
            var result = await _authService.ResendOtpAsync(request);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Resend OTP error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred while resending OTP" 
            });
        }
    }
    
    // POST /api/auth/login
    // Max 5 login attempts per 15 minutes per IP
    [HttpPost("login")]
    [RateLimit(5, 15)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var ipAddress = GetIpAddress();
            var userAgent = GetUserAgent();
            
            var result = await _authService.LoginAsync(request, ipAddress, userAgent);
            
            // Set refresh token in HttpOnly cookie
            SetRefreshTokenCookie(result.AccessToken);
            
            return Ok(result);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new ApiResponse { Success = false, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred during login" 
            });
        }
    }
    
    // POST /api/auth/refresh-token
    // Max 10 refreshes per 5 minutes
    [HttpPost("refresh-token")]
    [RateLimit(10, 5)]
    public async Task<IActionResult> RefreshToken()
    {
        try
        {
            var refreshToken = Request.Cookies["refreshToken"];
            
            if (string.IsNullOrEmpty(refreshToken))
            {
                return Unauthorized(new ApiResponse 
                { 
                    Success = false, 
                    Message = "Refresh token not found" 
                });
            }
            
            var ipAddress = GetIpAddress();
            var userAgent = GetUserAgent();
            
            var result = await _authService.RefreshTokenAsync(refreshToken, ipAddress, userAgent);
            
            // Update refresh token cookie
            SetRefreshTokenCookie(result.AccessToken);
            
            return Ok(result);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new ApiResponse { Success = false, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred during token refresh" 
            });
        }
    }
    
    // POST /api/auth/logout
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        try
        {
            var userId = GetUserId();
            var refreshToken = Request.Cookies["refreshToken"];
            
            if (!string.IsNullOrEmpty(refreshToken))
            {
                await _authService.LogoutAsync(userId, refreshToken);
            }
            
            // Clear refresh token cookie
            Response.Cookies.Delete("refreshToken");
            
            return Ok(new ApiResponse { Success = true, Message = "Logged out successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred during logout" 
            });
        }
    }
    
    // GET /api/auth/me
    // Max 30 requests per minute (authenticated users)
    [Authorize]
    [HttpGet("me")]
    [RateLimit(30, 1, ByIpAddress = false)]
    public async Task<IActionResult> GetCurrentUser()
    {
        try
        {
            var userId = GetUserId();
            var user = await _authService.GetCurrentUserAsync(userId);
            
            return Ok(new ApiResponse 
            { 
                Success = true, 
                Data = user 
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Get current user error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred while fetching user data" 
            });
        }
    }
    
    // POST /api/auth/forgot-password
    // Max 3 requests per 30 minutes per IP
    [HttpPost("forgot-password")]
    [RateLimit(3, 30)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        try
        {
            var result = await _passwordService.ForgotPasswordAsync(request);
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Forgot password error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred while processing your request" 
            });
        }
    }
    
    // POST /api/auth/verify-reset-otp
    // Max 5 attempts per 10 minutes per IP
    [HttpPost("verify-reset-otp")]
    [RateLimit(5, 10)]
    public async Task<IActionResult> VerifyResetOtp([FromBody] VerifyResetOtpRequest request)
    {
        try
        {
            var result = await _passwordService.VerifyResetOtpAsync(request);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Verify reset OTP error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred during OTP verification" 
            });
        }
    }
    
    // POST /api/auth/reset-password
    // Max 3 resets per 30 minutes per IP
    [HttpPost("reset-password")]
    [RateLimit(3, 30)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        try
        {
            var ipAddress = GetIpAddress();
            var result = await _passwordService.ResetPasswordAsync(request, ipAddress);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Reset password error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred while resetting password" 
            });
        }
    }
    
    // POST /api/auth/change-password
    // Max 5 changes per hour (authenticated users)
    [Authorize]
    [HttpPost("change-password")]
    [RateLimit(5, 60, ByIpAddress = false)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        try
        {
            var userId = GetUserId();
            var ipAddress = GetIpAddress();
            
            var result = await _passwordService.ChangePasswordAsync(userId, request, ipAddress);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Change password error");
            return StatusCode(500, new ApiResponse 
            { 
                Success = false, 
                Message = "An error occurred while changing password" 
            });
        }
    }
    
    // Helper Methods
    private Guid GetUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.Parse(userIdClaim ?? throw new UnauthorizedAccessException());
    }
    
    private string GetIpAddress()
    {
        if (Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
        {
            return forwardedFor.ToString().Split(',')[0].Trim();
        }
        
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    }
    
    private string GetUserAgent()
    {
        return Request.HttpContext.Request.Headers.UserAgent.ToString();
    }
    
    private void SetRefreshTokenCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddDays(7)
        };
        
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }
}
}
