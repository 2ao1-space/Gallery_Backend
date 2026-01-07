using Microsoft.AspNetCore.Mvc;
using Gallery.DTOs;
using Gallery.Services;

namespace Gallery.Controllers;

[ApiController]
[Route("api/auth")]
public class GoogleAuthController : ControllerBase
{
    private readonly IGoogleAuthService _googleAuthService;
    private readonly ILogger<GoogleAuthController> _logger;
    
    public GoogleAuthController(
        IGoogleAuthService googleAuthService,
        ILogger<GoogleAuthController> logger)
    {
        _googleAuthService = googleAuthService;
        _logger = logger;
    }
    
    // POST /auth/google
    [HttpPost("google")]
    public async Task<IActionResult> GoogleAuth([FromBody] GoogleAuthRequest request)
    {
        try
        {
            var ipAddress = GetIpAddress();
            var userAgent = GetUserAgent();
            
            var result = await _googleAuthService.AuthenticateGoogleUserAsync(
                request.IdToken, 
                ipAddress, 
                userAgent
            );
            
            SetRefreshTokenCookie(result.AccessToken);
            
            return Ok(result);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new ApiResponse { Success = false, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Google authentication error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred during Google authentication"
            });
        }
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