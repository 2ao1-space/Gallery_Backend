using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Gallery.DTOs;
using Gallery.Middleware;
using Gallery.Services;
using System.Security.Claims;

namespace Gallery.Controllers;

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
    
    // POST /auth/register
    [HttpPost("register")]
    [RateLimit(3, 20)]
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
    
    // POST /auth/verify-email
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
    
    // POST /auth/resend-otp
    [HttpPost("resend-otp")]
    [RateLimit(3, 10)]
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
    
    // POST /auth/login
    [HttpPost("login")]
    [RateLimit(5, 10)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var ipAddress = GetIpAddress();
            var userAgent = GetUserAgent();
            
            var result = await _authService.LoginAsync(request, ipAddress, userAgent);
            
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
    
    // POST /auth/refresh-token
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
    
    // POST /auth/logout
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
    
    // GET /auth/me
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
    
    // POST /auth/forgot-password
    [HttpPost("forgot-password")]
    [RateLimit(3, 15)]
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
    
    // POST /auth/verify-reset-otp
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
    
    // POST /auth/reset-password
    [HttpPost("reset-password")]
    [RateLimit(3, 15)]
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
    
    // POST /auth/change-password
    [Authorize]
    [HttpPost("change-password")]
    [RateLimit(5, 30, ByIpAddress = false)]
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
    
    private Guid GetUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.Parse(userIdClaim ?? throw new UnauthorizedAccessException());
    }
    
    private string GetIpAddress()
    {
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
        {
            return Request.Headers["X-Forwarded-For"].ToString().Split(',')[0].Trim();
        }
        
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    }
    
    private string GetUserAgent()
    {
        return Request.Headers["User-Agent"].ToString();
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