using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Gallery.DTOs;
using Gallery.Services;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;

namespace Gallery.Controllers;

[ApiController]
[Route("auth")]
public class AccountController : ControllerBase
{
    private readonly IEmailChangeService _emailChangeService;
    private readonly IAccountManagementService _accountManagementService;
    private readonly ILogger<AccountController> _logger;
    
    public AccountController(
        IEmailChangeService emailChangeService,
        IAccountManagementService accountManagementService,
        ILogger<AccountController> logger)
    {
        _emailChangeService = emailChangeService;
        _accountManagementService = accountManagementService;
        _logger = logger;
    }
        
    // POST /auth/change-email
    [Authorize]
    [HttpPost("change-email")]
    public async Task<IActionResult> ChangeEmail([FromBody] ChangeEmailRequest request)
    {
        try
        {
            var userId = GetUserId();
            var result = await _emailChangeService.InitiateEmailChangeAsync(userId, request);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email change initiation error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while initiating email change"
            });
        }
    }
    
    // POST /auth/verify-new-email
    [Authorize]
    [HttpPost("verify-new-email")]
    public async Task<IActionResult> VerifyNewEmail([FromBody] VerifyNewEmailRequest request)
    {
        try
        {
            var userId = GetUserId();
            var ipAddress = GetIpAddress();
            
            var result = await _emailChangeService.VerifyNewEmailAsync(userId, request, ipAddress);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            Response.Cookies.Delete("refreshToken");
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email verification error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while verifying email"
            });
        }
    }
    
    
    // POST /auth/set-password
    [Authorize]
    [HttpPost("set-password")]
    public async Task<IActionResult> SetPassword([FromBody] SetPasswordRequest request)
    {
        try
        {
            var userId = GetUserId();
            var ipAddress = GetIpAddress();
            
            var result = await _accountManagementService.SetPasswordAsync(userId, request, ipAddress);
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Set password error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while setting password"
            });
        }
    }
    
    
    // POST /auth/link-google
    [Authorize]
    [HttpPost("link-google")]
    public async Task<IActionResult> LinkGoogle([FromBody] GoogleAuthRequest request)
    {
        try
        {
            var userId = GetUserId();
            var ipAddress = GetIpAddress();
            
            var result = await _accountManagementService.LinkGoogleAccountAsync(
                userId, 
                request.IdToken, 
                ipAddress
            );
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Link Google error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while linking Google account"
            });
        }
    }
    
    // POST /auth/unlink-google
    [Authorize]
    [HttpPost("unlink-google")]
    public async Task<IActionResult> UnlinkGoogle([FromBody] UnlinkGoogleRequest request)
    {
        try
        {
            var userId = GetUserId();
            var ipAddress = GetIpAddress();
            
            var result = await _accountManagementService.UnlinkGoogleAccountAsync(
                userId, 
                request.Password, 
                ipAddress
            );
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unlink Google error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while unlinking Google account"
            });
        }
    }
    
    
    // POST /auth/deactivate
    [Authorize]
    [HttpPost("deactivate")]
    public async Task<IActionResult> Deactivate([FromBody] DeactivateAccountRequest request)
    {
        try
        {
            var userId = GetUserId();
            var ipAddress = GetIpAddress();
            
            var result = await _accountManagementService.DeactivateAccountAsync(
                userId, 
                request.Password, 
                ipAddress
            );
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            Response.Cookies.Delete("refreshToken");
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Deactivate account error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while deactivating account"
            });
        }
    }
    
    // DELETE //auth/me
    [Authorize]
    [HttpDelete("me")]
    public async Task<IActionResult> DeleteAccount([FromBody] DeleteAccountRequest request)
    {
        try
        {
            var userId = GetUserId();
            var ipAddress = GetIpAddress();
            
            var result = await _accountManagementService.DeleteAccountAsync(
                userId, 
                request.Password, 
                ipAddress
            );
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            Response.Cookies.Delete("refreshToken");
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Delete account error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while deleting account"
            });
        }
    }
    
    // POST /auth/reactivate
    [HttpPost("reactivate")]
    public async Task<IActionResult> Reactivate([FromBody] ReactivateAccountRequest request)
    {
        try
        {
            var ipAddress = GetIpAddress();
            
            var result = await _accountManagementService.ReactivateAccountAsync(
                request.Email, 
                request.Password, 
                ipAddress
            );
            
            if (!result.Success)
            {
                return BadRequest(result);
            }
            
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Reactivate account error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while reactivating account"
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
}

public class UnlinkGoogleRequest
{
    [Required]
    public string Password { get; set; } = string.Empty;
}

public class DeactivateAccountRequest
{
    [Required]
    public string Password { get; set; } = string.Empty;
}

public class DeleteAccountRequest
{
    [Required]
    public string Password { get; set; } = string.Empty;
    
    [Required]
    public bool Confirm { get; set; }
}

public class ReactivateAccountRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    public string Password { get; set; } = string.Empty;
}