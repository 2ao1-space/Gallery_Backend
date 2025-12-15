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
    public class PostsController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly CloudinaryService _cloudinaryService;

        public PostsController(
            AppDbContext context,
            UserManager<User> userManager,
            CloudinaryService cloudinaryService)
        {
            _context = context;
            _userManager = userManager;
            _cloudinaryService = cloudinaryService;
        }

       
        [HttpPost]
        [Authorize]
        public async Task<ActionResult<PostDto>> CreatePost(
            [FromForm] CreatePostDto dto,
            [FromForm] IFormFile media)
        {
            if (media == null || media.Length == 0)
                return BadRequest(new { message = "No media file provided" });

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId!);

            if (user == null)
                return NotFound();

            try
            {
                var uploadResult = await _cloudinaryService.UploadPostMediaAsync(
                    media,
                    userId!,
                    user.FullName
                );

                var post = new Post
                {
                    Title = dto.Title,
                    Description = dto.Description,
                    MediaUrl = uploadResult.Url,
                    MediaPublicId = uploadResult.PublicId,
                    WatermarkedUrl = uploadResult.WatermarkedUrl,
                    DownloadUrl = uploadResult.DownloadUrl,
                    MediaType = uploadResult.MediaType == "video" 
                        ? PostMediaType.Video 
                        : PostMediaType.Image,
                    Width = uploadResult.Width,
                    Height = uploadResult.Height,
                    FileSizeBytes = uploadResult.FileSizeBytes,
                    Format = uploadResult.Format,
                    DurationSeconds = uploadResult.DurationSeconds,
                    TagsJson = dto.Tags != null 
                        ? JsonSerializer.Serialize(dto.Tags) 
                        : null,
                    AuthorId = userId!,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                _context.Posts.Add(post);
                await _context.SaveChangesAsync();

                user.PostsCount++;
                await _userManager.UpdateAsync(user);

                var postDto = await MapToPostDtoAsync(post, userId);

                return CreatedAtAction(
                    nameof(GetPost), 
                    new { postId = post.Id }, 
                    new { success = true, message = "Post created successfully", post = postDto }
                );
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpGet("{postId}")]
        public async Task<ActionResult<PostDto>> GetPost(string postId)
        {
            var post = await _context.Posts
                .Include(p => p.Author)
                .FirstOrDefaultAsync(p => p.Id == postId && !p.IsDeleted);

            if (post == null)
                return NotFound(new { message = "Post not found" });

            post.ViewsCount++;
            await _context.SaveChangesAsync();

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var postDto = await MapToPostDtoAsync(post, currentUserId);

            return Ok(postDto);
        }

        [HttpGet("user/{username}")]
        public async Task<ActionResult<PaginatedResponseDto<PostDto>>> GetUserPosts(
            string username,
            [FromQuery] int page = 1,
            [FromQuery] int limit = 20)
        {
            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.CustomUsername == username || u.UserName == username);

            if (user == null)
                return NotFound(new { message = "User not found" });

            var query = _context.Posts
                .Include(p => p.Author)
                .Where(p => p.AuthorId == user.Id && !p.IsDeleted)
                .OrderByDescending(p => p.CreatedAt);

            var total = await query.CountAsync();
            var posts = await query
                .Skip((page - 1) * limit)
                .Take(limit)
                .ToListAsync();

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var postDtos = new List<PostDto>();
            foreach (var post in posts)
            {
                postDtos.Add(await MapToPostDtoAsync(post, currentUserId));
            }

            return Ok(new PaginatedResponseDto<PostDto>
            {
                Success = true,
                Data = postDtos,
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

        
        [HttpPatch("{postId}")]
        [Authorize]
        public async Task<ActionResult> UpdatePost(
            string postId,
            [FromBody] UpdatePostDto dto)
        {
            var post = await _context.Posts.FindAsync(postId);

            if (post == null)
                return NotFound(new { message = "Post not found" });

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (post.AuthorId != userId)
                return Forbid();

            if (dto.Title != null)
                post.Title = dto.Title;

            if (dto.Description != null)
                post.Description = dto.Description;

            if (dto.Tags != null)
                post.TagsJson = JsonSerializer.Serialize(dto.Tags);

            post.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return Ok(new { message = "Post updated successfully" });
        }

        [HttpDelete("{postId}")]
        [Authorize]
        public async Task<ActionResult> DeletePost(string postId)
        {
            var post = await _context.Posts.FindAsync(postId);

            if (post == null)
                return NotFound(new { message = "Post not found" });

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (post.AuthorId != userId)
                return Forbid();

            post.IsDeleted = true;
            await _context.SaveChangesAsync();

            var user = await _userManager.FindByIdAsync(userId!);
            if (user != null)
            {
                user.PostsCount--;
                await _userManager.UpdateAsync(user);
            }

            // await _cloudinaryService.DeleteFileAsync(post.MediaPublicId);

            return Ok(new { message = "Post deleted successfully" });
        }

        [HttpPost("{postId}/like")]
        [Authorize]
        public async Task<ActionResult> ToggleLike(string postId)
        {
            var post = await _context.Posts.FindAsync(postId);
            if (post == null)
                return NotFound(new { message = "Post not found" });

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var existingLike = await _context.Likes
                .FirstOrDefaultAsync(l => l.UserId == userId && l.PostId == postId);

            if (existingLike != null)
            {
                _context.Likes.Remove(existingLike);
                post.LikesCount--;
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    success = true,
                    message = "Post unliked",
                    isLiked = false,
                    likesCount = post.LikesCount
                });
            }
            else
            {
                var like = new Like
                {
                    UserId = userId!,
                    PostId = postId,
                    CreatedAt = DateTime.UtcNow
                };

                _context.Likes.Add(like);
                post.LikesCount++;
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    success = true,
                    message = "Post liked",
                    isLiked = true,
                    likesCount = post.LikesCount
                });
            }
        }

        [HttpPost("{postId}/save")]
        [Authorize]
        public async Task<ActionResult> ToggleSave(string postId)
        {
            var post = await _context.Posts.FindAsync(postId);
            if (post == null)
                return NotFound(new { message = "Post not found" });

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var existingSave = await _context.Saves
                .FirstOrDefaultAsync(s => s.UserId == userId && s.PostId == postId);

            if (existingSave != null)
            {
                _context.Saves.Remove(existingSave);
                post.SavesCount--;
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    success = true,
                    message = "Post unsaved",
                    isSaved = false,
                    savesCount = post.SavesCount
                });
            }
            else
            {
                var save = new Save
                {
                    UserId = userId!,
                    PostId = postId,
                    CreatedAt = DateTime.UtcNow
                };

                _context.Saves.Add(save);
                post.SavesCount++;
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    success = true,
                    message = "Post saved",
                    isSaved = true,
                    savesCount = post.SavesCount
                });
            }
        }

        [HttpPost("{postId}/share")]
        public async Task<ActionResult> SharePost(string postId)
        {
            var post = await _context.Posts.FindAsync(postId);
            if (post == null)
                return NotFound(new { message = "Post not found" });

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var share = new Share
            {
                UserId = userId,
                PostId = postId,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                CreatedAt = DateTime.UtcNow
            };

            _context.Shares.Add(share);
            post.SharesCount++;
            await _context.SaveChangesAsync();

            return Ok(new
            {
                success = true,
                message = "Post shared",
                sharesCount = post.SharesCount
            });
        }

        [HttpGet("saved")]
        [Authorize]
        public async Task<ActionResult<PaginatedResponseDto<PostDto>>> GetSavedPosts(
            [FromQuery] int page = 1,
            [FromQuery] int limit = 20)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var query = _context.Saves
                .Include(s => s.Post)
                    .ThenInclude(p => p.Author)
                .Where(s => s.UserId == userId && !s.Post.IsDeleted)
                .OrderByDescending(s => s.CreatedAt);

            var total = await query.CountAsync();
            var saves = await query
                .Skip((page - 1) * limit)
                .Take(limit)
                .ToListAsync();

            var postDtos = new List<PostDto>();
            foreach (var save in saves)
            {
                postDtos.Add(await MapToPostDtoAsync(save.Post, userId));
            }

            return Ok(new PaginatedResponseDto<PostDto>
            {
                Success = true,
                Data = postDtos,
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

        private async Task<PostDto> MapToPostDtoAsync(Post post, string? currentUserId)
        {
            var tags = string.IsNullOrEmpty(post.TagsJson)
                ? new List<string>()
                : JsonSerializer.Deserialize<List<string>>(post.TagsJson) ?? new List<string>();

            var isLiked = false;
            var isSaved = false;
            var isFollowed = false;

            if (!string.IsNullOrEmpty(currentUserId))
            {
                isLiked = await _context.Likes
                    .AnyAsync(l => l.UserId == currentUserId && l.PostId == post.Id);

                isSaved = await _context.Saves
                    .AnyAsync(s => s.UserId == currentUserId && s.PostId == post.Id);

                isFollowed = await _context.Follows
                    .AnyAsync(f => f.FollowerId == currentUserId && f.FollowingId == post.AuthorId);
            }

            return new PostDto
            {
                Id = post.Id,
                Title = post.Title,
                Description = post.Description,
                MediaUrl = post.MediaUrl,
                WatermarkedUrl = post.WatermarkedUrl,
                DownloadUrl = post.DownloadUrl,
                MediaType = post.MediaType == PostMediaType.Video ? "video" : "image",
                Width = post.Width,
                Height = post.Height,
                Format = post.Format,
                DurationSeconds = post.DurationSeconds,
                Tags = tags,
                Author = new PostAuthorDto
                {
                    Id = post.Author.Id,
                    Username = post.Author.CustomUsername ?? post.Author.UserName!,
                    FullName = post.Author.FullName,
                    ProfilePicture = post.Author.ProfilePicture,
                    IsFollowedByMe = isFollowed
                },
                Stats = new PostStatsDto
                {
                    LikesCount = post.LikesCount,
                    CommentsCount = post.CommentsCount,
                    SharesCount = post.SharesCount,
                    SavesCount = post.SavesCount,
                    ViewsCount = post.ViewsCount
                },
                IsLikedByMe = isLiked,
                IsSavedByMe = isSaved,
                CreatedAt = post.CreatedAt,
                UpdatedAt = post.UpdatedAt
            };
        }
    }
}
