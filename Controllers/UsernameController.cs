using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Gallery.Data;
using Gallery.DTOs;

namespace Gallery.Controllers;

[ApiController]
[Route("auth")]
public class UsernameController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    
    public UsernameController(ApplicationDbContext context)
    {
        _context = context;
    }
    
    // GET /auth/check-username?username=username
    [HttpGet("check-username")]
    public async Task<IActionResult> CheckUsername([FromQuery] string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(new UsernameCheckResponse
            {
                IsAvailable = false,
                Message = "Username is required"
            });
        }
        
        if (username.Length < 3)
        {
            return Ok(new UsernameCheckResponse
            {
                IsAvailable = false,
                Message = "Username must be at least 3 characters"
            });
        }
        
        if (username.Length > 50)
        {
            return Ok(new UsernameCheckResponse
            {
                IsAvailable = false,
                Message = "Username cannot exceed 50 characters"
            });
        }
        
        if (!System.Text.RegularExpressions.Regex.IsMatch(username, @"^[a-zA-Z0-9_-]+$"))
        {
            return Ok(new UsernameCheckResponse
            {
                IsAvailable = false,
                Message = "Username can only contain letters, numbers, underscores, and hyphens"
            });
        }
        
        var exists = await _context.Users.AnyAsync(u => u.Username == username);
        
        if (exists)
        {
            return Ok(new UsernameCheckResponse
            {
                IsAvailable = false,
                Message = "Username is already taken"
            });
        }
        
        return Ok(new UsernameCheckResponse
        {
            IsAvailable = true,
            Message = "Username is available"
        });
    }
}