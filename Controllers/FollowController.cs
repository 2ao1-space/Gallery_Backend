
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Gallery.Data;
using Gallery.Models.Entities;
using Gallery.Models.DTOs;
using System.Security.Claims;
using Gallery.Models.DTPs;

namespace Gallery.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FollowController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly UserManager<User> _userManager;

        public FollowController(AppDbContext context, UserManager<User> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [HttpPost("{username}")]
        [Authorize]
        public async Task<ActionResult> ToggleFollow(string username)
        {
            var targetUser = await _userManager.Users
                .FirstOrDefaultAsync(u => u.CustomUsername == username || u.UserName == username);

            if (targetUser == null)
                return NotFound(new { message = "User not found" });

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (currentUserId == targetUser.Id)
                return BadRequest(new { message = "You cannot follow yourself" });

            var existingFollow = await _context.Follows
                .FirstOrDefaultAsync(f => 
                    f.FollowerId == currentUserId && 
                    f.FollowingId == targetUser.Id);

            if (existingFollow != null)
            {
                _context.Follows.Remove(existingFollow);
                
                var follower = await _userManager.FindByIdAsync(currentUserId!);
                if (follower != null)
                {
                    follower.FollowingCount--;
                    await _userManager.UpdateAsync(follower);
                }
                
                targetUser.FollowersCount--;
                await _userManager.UpdateAsync(targetUser);
                
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    success = true,
                    message = $"Unfollowed {username}",
                    isFollowing = false,
                    followersCount = targetUser.FollowersCount
                });
            }
            else
            {
                var follow = new Follow
                {
                    FollowerId = currentUserId!,
                    FollowingId = targetUser.Id,
                    CreatedAt = DateTime.UtcNow
                };

                _context.Follows.Add(follow);
                
                var follower = await _userManager.FindByIdAsync(currentUserId!);
                if (follower != null)
                {
                    follower.FollowingCount++;
                    await _userManager.UpdateAsync(follower);
                }
                
                targetUser.FollowersCount++;
                await _userManager.UpdateAsync(targetUser);
                
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    success = true,
                    message = $"Now following {username}",
                    isFollowing = true,
                    followersCount = targetUser.FollowersCount
                });
            }
        }

        [HttpGet("{username}/followers")]
        public async Task<ActionResult<PaginatedResponseDto<UserDto>>> GetFollowers(
            string username,
            [FromQuery] int page = 1,
            [FromQuery] int limit = 20)
        {
            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.CustomUsername == username || u.UserName == username);

            if (user == null)
                return NotFound(new { message = "User not found" });

            var query = _context.Follows
                .Include(f => f.Follower)
                .Where(f => f.FollowingId == user.Id)
                .OrderByDescending(f => f.CreatedAt);

            var total = await query.CountAsync();
            var follows = await query
                .Skip((page - 1) * limit)
                .Take(limit)
                .ToListAsync();

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var userDtos = new List<UserDto>();
            foreach (var follow in follows)
            {
                var isFollowedByMe = false;
                if (!string.IsNullOrEmpty(currentUserId))
                {
                    isFollowedByMe = await _context.Follows
                        .AnyAsync(f => f.FollowerId == currentUserId && f.FollowingId == follow.Follower.Id);
                }

                userDtos.Add(new UserDto
                {
                    Id = follow.Follower.Id,
                    FullName = follow.Follower.FullName,
                    Email = follow.Follower.Email!,
                    ProfilePicture = follow.Follower.ProfilePicture,
                    CreatedAt = follow.Follower.CreatedAt
                });
            }

            return Ok(new PaginatedResponseDto<UserDto>
            {
                Success = true,
                Data = userDtos,
                Pagination = new PaginationDto
                {
                    Total = total,
                    Page = page,
                    Limit = limit,
                    TotalPages = (int)Math.Ceiling(total / (double)limit),
                    HasNext = page * limit < total,
                    HasPrev = page > 1
                }
            });
        }

        [HttpGet("{username}/following")]
        public async Task<ActionResult<PaginatedResponseDto<UserDto>>> GetFollowing(
            string username,
            [FromQuery] int page = 1,
            [FromQuery] int limit = 20)
        {
            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.CustomUsername == username || u.UserName == username);

            if (user == null)
                return NotFound(new { message = "User not found" });

            var query = _context.Follows
                .Include(f => f.Following)
                .Where(f => f.FollowerId == user.Id)
                .OrderByDescending(f => f.CreatedAt);

            var total = await query.CountAsync();
            var follows = await query
                .Skip((page - 1) * limit)
                .Take(limit)
                .ToListAsync();

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var userDtos = new List<UserDto>();
            foreach (var follow in follows)
            {
                userDtos.Add(new UserDto
                {
                    Id = follow.Following.Id,
                    FullName = follow.Following.FullName,
                    Email = follow.Following.Email!,
                    ProfilePicture = follow.Following.ProfilePicture,
                    CreatedAt = follow.Following.CreatedAt
                });
            }

            return Ok(new PaginatedResponseDto<UserDto>
            {
                Success = true,
                Data = userDtos,
                Pagination = new PaginationDto
                {
                    Total = total,
                    Page = page,
                    Limit = limit,
                    TotalPages = (int)Math.Ceiling(total / (double)limit),
                    HasNext = page * limit < total,
                    HasPrev = page > 1
                }
            });
        }
    }
}