using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Gallery.Data;
using Gallery.Models.Entities;
using Gallery.Models.DTOs;
using Gallery.Services;
using System.Security.Claims;
using System.Text.Json;

namespace Gallery.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly AppDbContext _context;
        private readonly CloudinaryService _cloudinaryService;

        public UserController(
            UserManager<User> userManager,
            AppDbContext context,
            CloudinaryService cloudinaryService)
        {
            _userManager = userManager;
            _context = context;
            _cloudinaryService = cloudinaryService;
        }

        [HttpGet("profile")]
        [Authorize]
        public async Task<ActionResult<UserProfileDto>> GetMyProfile()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId!);

            if (user == null)
                return NotFound(new { message = "User not found" });

            var stats = await GetUserStatsAsync(userId!);

            var socialLinks = string.IsNullOrEmpty(user.SocialLinksJson)
                ? null
                : JsonSerializer.Deserialize<SocialLinksDto>(user.SocialLinksJson);

            return Ok(new UserProfileDto
            {
                Id = user.Id,
                Username = user.CustomUsername ?? user.UserName!,
                Email = user.Email!,
                FullName = user.FullName,
                ProfilePicture = user.ProfilePicture,
                Bio = user.Bio,
                JobTitle = user.JobTitle,
                PhoneNumber = user.PhoneNumber,
                BirthDate = user.BirthDate,
                SocialLinks = socialLinks,
                Stats = stats,
                CreatedAt = user.CreatedAt,
                IsUsernameChanged = user.IsUsernameChanged,
                IsFollowedByMe = false 
            });
        }

       
        [HttpGet("profile/{username}")]
        public async Task<ActionResult<UserProfileDto>> GetUserProfile(string username)
        {
            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.CustomUsername == username || u.UserName == username);

            if (user == null)
                return NotFound(new { message = "User not found" });

            var stats = await GetUserStatsAsync(user.Id);

            var socialLinks = string.IsNullOrEmpty(user.SocialLinksJson)
                ? null
                : JsonSerializer.Deserialize<SocialLinksDto>(user.SocialLinksJson);

            var isFollowedByMe = false;
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            if (!string.IsNullOrEmpty(currentUserId))
            {
                isFollowedByMe = await _context.Follows
                    .AnyAsync(f => f.FollowerId == currentUserId && f.FollowingId == user.Id);
            }

            return Ok(new UserProfileDto
            {
                Id = user.Id,
                Username = user.CustomUsername ?? user.UserName!,
                Email = user.Email!,
                FullName = user.FullName,
                ProfilePicture = user.ProfilePicture,
                Bio = user.Bio,
                JobTitle = user.JobTitle,
                PhoneNumber = user.PhoneNumber,
                BirthDate = user.BirthDate,
                SocialLinks = socialLinks,
                Stats = stats,
                CreatedAt = user.CreatedAt,
                IsUsernameChanged = user.IsUsernameChanged,
                IsFollowedByMe = isFollowedByMe
            });
        }

       
        [HttpPatch("profile")]
        [Authorize]
        public async Task<ActionResult> UpdateProfile([FromBody] UpdateProfileDto dto)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId!);

            if (user == null)
                return NotFound();

            if (dto.FullName != null)
                user.FullName = dto.FullName;

            if (dto.Bio != null)
                user.Bio = dto.Bio;

            if (dto.JobTitle != null)
                user.JobTitle = dto.JobTitle;

            if (dto.PhoneNumber != null)
                user.PhoneNumber = dto.PhoneNumber;

            if (dto.BirthDate.HasValue)
                user.BirthDate = dto.BirthDate;

            if (dto.SocialLinks != null)
            {
                user.SocialLinksJson = JsonSerializer.Serialize(dto.SocialLinks);
            }

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return BadRequest(new { 
                    message = "Update failed",
                    errors = result.Errors 
                });
            }

            return Ok(new { message = "Profile updated successfully" });
        }

        
        [HttpPost("profile/picture")]
        [Authorize]
        public async Task<ActionResult> UploadProfilePicture(IFormFile image)
        {
            if (image == null || image.Length == 0)
                return BadRequest(new { message = "No image provided" });

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId!);

            if (user == null)
                return NotFound();

            try
            {
                if (!string.IsNullOrEmpty(user.ProfilePicturePublicId))
                {
                    await _cloudinaryService.DeleteFileAsync(user.ProfilePicturePublicId);
                }

                var uploadResult = await _cloudinaryService.UploadProfilePictureAsync(
                    image, 
                    userId!
                );

                user.ProfilePicture = uploadResult.Url;
                user.ProfilePicturePublicId = uploadResult.PublicId;

                await _userManager.UpdateAsync(user);

                return Ok(new
                {
                    message = "Profile picture uploaded successfully",
                    imageUrl = uploadResult.Url
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

    
        [HttpDelete("profile/picture")]
        [Authorize]
        public async Task<ActionResult> DeleteProfilePicture()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId!);

            if (user == null)
                return NotFound();

            if (!string.IsNullOrEmpty(user.ProfilePicturePublicId))
            {
                await _cloudinaryService.DeleteFileAsync(user.ProfilePicturePublicId);
            }

            user.ProfilePicture = null;
            user.ProfilePicturePublicId = null;

            await _userManager.UpdateAsync(user);

            return Ok(new { message = "Profile picture deleted successfully" });
        }

       
        [HttpPatch("username")]
        [Authorize]
        public async Task<ActionResult> UpdateUsername([FromBody] UpdateUsernameDto dto)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId!);

            if (user == null)
                return NotFound();

            if (user.IsUsernameChanged)
            {
                return BadRequest(new { 
                    message = "Username can only be changed once" 
                });
            }

            var existingUser = await _userManager.Users
                .FirstOrDefaultAsync(u => u.CustomUsername == dto.Username);

            if (existingUser != null)
            {
                return BadRequest(new { 
                    message = "Username is already taken" 
                });
            }

            user.CustomUsername = dto.Username;
            user.IsUsernameChanged = true;

            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                return BadRequest(new { 
                    message = "Failed to update username" 
                });
            }

            return Ok(new { 
                message = "Username updated successfully",
                username = dto.Username
            });
        }

        
        [HttpGet("{username}/stats")]
        public async Task<ActionResult<UserStatsDto>> GetUserStats(string username)
        {
            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.CustomUsername == username || u.UserName == username);

            if (user == null)
                return NotFound();

            var stats = await GetUserStatsAsync(user.Id);

            return Ok(stats);
        }

       
        private async Task<UserStatsDto> GetUserStatsAsync(string userId)
        {
            var followersCount = await _context.Follows
                .CountAsync(f => f.FollowingId == userId);

            var followingCount = await _context.Follows
                .CountAsync(f => f.FollowerId == userId);

            var postsCount = await _context.Posts
                .CountAsync(p => p.AuthorId == userId && !p.IsDeleted);

            return new UserStatsDto
            {
                FollowersCount = followersCount,
                FollowingCount = followingCount,
                PostsCount = postsCount
            };
        }
    }
}