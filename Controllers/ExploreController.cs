using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Gallery.Data;
using Gallery.Models.DTOs;
using System.Security.Claims;

namespace Gallery.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ExploreController : ControllerBase
    {
        private readonly AppDbContext _context;

        public ExploreController(AppDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<PaginatedResponseDto<PostDto>>> GetAllPosts(
            [FromQuery] int page = 1,
            [FromQuery] int limit = 20,
            [FromQuery] string sort = "latest") 
        {
            var query = _context.Posts
                .Include(p => p.Author)
                .Where(p => !p.IsDeleted);

            query = sort.ToLower() switch
            {
                "popular" => query.OrderByDescending(p => p.LikesCount),
                "trending" => query.OrderByDescending(p => 
                    (p.LikesCount * 2) + p.SharesCount + (p.ViewsCount / 10)),
                _ => query.OrderByDescending(p => p.CreatedAt)
            };

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

        [HttpGet("trending")]
        public async Task<ActionResult<List<PostDto>>> GetTrendingPosts(
            [FromQuery] string timeframe = "week", 
            [FromQuery] int limit = 10)
        {
            var startDate = timeframe.ToLower() switch
            {
                "day" => DateTime.UtcNow.AddDays(-1),
                "month" => DateTime.UtcNow.AddMonths(-1),
                _ => DateTime.UtcNow.AddDays(-7)
            };

            var posts = await _context.Posts
                .Include(p => p.Author)
                .Where(p => !p.IsDeleted && p.CreatedAt >= startDate)
                .OrderByDescending(p => 
                    (p.LikesCount * 3) + (p.SharesCount * 2) + (p.ViewsCount / 5))
                .Take(limit)
                .ToListAsync();

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var postDtos = new List<PostDto>();
            foreach (var post in posts)
            {
                postDtos.Add(await MapToPostDtoAsync(post, currentUserId));
            }

            return Ok(postDtos);
        }

        [HttpGet("search")]
        public async Task<ActionResult<PaginatedResponseDto<PostDto>>> SearchPosts(
            [FromQuery] string q,
            [FromQuery] int page = 1,
            [FromQuery] int limit = 20)
        {
            if (string.IsNullOrWhiteSpace(q))
                return BadRequest(new { message = "Search query is required" });

            var query = _context.Posts
                .Include(p => p.Author)
                .Where(p => !p.IsDeleted && 
                    (p.Title.Contains(q) || 
                     (p.Description != null && p.Description.Contains(q))))
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

        private async Task<PostDto> MapToPostDtoAsync(Models.Entities.Post post, string? currentUserId)
        {
            var tags = string.IsNullOrEmpty(post.TagsJson)
                ? new List<string>()
                : System.Text.Json.JsonSerializer.Deserialize<List<string>>(post.TagsJson) ?? new List<string>();

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
                MediaType = post.MediaType == Models.Entities.PostMediaType.Video ? "video" : "image",
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
