using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Gallery.Data;
using Gallery.DTOs;
using Gallery.Models;
using System.Security.Claims;

namespace Gallery.Controllers;

[Authorize]
[ApiController]
[Route("auth")]
public class SessionController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<SessionController> _logger;
    
    public SessionController(ApplicationDbContext context, ILogger<SessionController> logger)
    {
        _context = context;
        _logger = logger;
    }
    
    // GET /auth/sessions
    [HttpGet("sessions")]
    public async Task<IActionResult> GetSessions()
    {
        try
        {
            var userId = GetUserId();
            var currentRefreshToken = Request.Cookies["refreshToken"];
            
            var sessions = await _context.UserSessions
                .Where(s => s.UserId == userId && s.IsActive)
                .OrderByDescending(s => s.LastActivityAt)
                .ToListAsync();
            
            var sessionDtos = sessions.Select(s => new SessionDto
            {
                Id = s.Id,
                DeviceInfo = s.DeviceInfo,
                IpAddress = s.IpAddress,
                Browser = s.Browser,
                OperatingSystem = s.OperatingSystem,
                CreatedAt = s.CreatedAt,
                LastActivityAt = s.LastActivityAt,
                IsCurrentSession = s.RefreshTokenId == currentRefreshToken
            }).ToList();
            
            return Ok(new ApiResponse
            {
                Success = true,
                Data = sessionDtos
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Get sessions error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while fetching sessions"
            });
        }
    }
    
    // DELETE /auth/sessions/{id}
    [HttpDelete("sessions/{id}")]
    public async Task<IActionResult> RevokeSession(Guid id)
    {
        try
        {
            var userId = GetUserId();
            
            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.Id == id && s.UserId == userId);
            
            if (session == null)
            {
                return NotFound(new ApiResponse
                {
                    Success = false,
                    Message = "Session not found"
                });
            }
            
            session.IsActive = false;
            
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == session.RefreshTokenId);
            
            if (refreshToken != null)
            {
                refreshToken.IsRevoked = true;
                refreshToken.RevokedAt = DateTime.UtcNow;
            }
            
            _context.AuditLogs.Add(new AuditLog
            {
                UserId = userId,
                Action = AuditActions.SessionRevoked,
                Details = $"Session {id} revoked",
                IpAddress = GetIpAddress()
            });
            
            await _context.SaveChangesAsync();
            
            return Ok(new ApiResponse
            {
                Success = true,
                Message = "Session revoked successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Revoke session error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while revoking session"
            });
        }
    }
    
    // DELETE /auth/sessions
    [HttpDelete("sessions")]
    public async Task<IActionResult> RevokeAllSessions()
    {
        try
        {
            var userId = GetUserId();
            var currentRefreshToken = Request.Cookies["refreshToken"];
            
            var sessions = await _context.UserSessions
                .Where(s => s.UserId == userId && s.IsActive && s.RefreshTokenId != currentRefreshToken)
                .ToListAsync();
            
            foreach (var session in sessions)
            {
                session.IsActive = false;
                
                var refreshToken = await _context.RefreshTokens
                    .FirstOrDefaultAsync(rt => rt.Token == session.RefreshTokenId);
                
                if (refreshToken != null)
                {
                    refreshToken.IsRevoked = true;
                    refreshToken.RevokedAt = DateTime.UtcNow;
                }
            }
            
            _context.AuditLogs.Add(new AuditLog
            {
                UserId = userId,
                Action = "All Sessions Revoked Except Current",
                Details = $"{sessions.Count} sessions revoked",
                IpAddress = GetIpAddress()
            });
            
            await _context.SaveChangesAsync();
            
            return Ok(new ApiResponse
            {
                Success = true,
                Message = $"{sessions.Count} sessions revoked successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Revoke all sessions error");
            return StatusCode(500, new ApiResponse
            {
                Success = false,
                Message = "An error occurred while revoking sessions"
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