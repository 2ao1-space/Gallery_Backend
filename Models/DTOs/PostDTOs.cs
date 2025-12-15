using System.ComponentModel.DataAnnotations;

namespace Gallery.Models.DTOs
{
    public class CreatePostDto
    {
        [Required]
        [MaxLength(200)]
        public string Title { get; set; } = string.Empty;

        [MaxLength(2000)]
        public string? Description { get; set; }

        public List<string>? Tags { get; set; }
    }

    public class UpdatePostDto
    {
        [MaxLength(200)]
        public string? Title { get; set; }

        [MaxLength(2000)]
        public string? Description { get; set; }

        public List<string>? Tags { get; set; }
    }

    public class PostDto
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string? Description { get; set; }
        public string MediaUrl { get; set; } = string.Empty;
        public string WatermarkedUrl { get; set; } = string.Empty;
        public string DownloadUrl { get; set; } = string.Empty;
        public string MediaType { get; set; } = string.Empty; 
        public int Width { get; set; }
        public int Height { get; set; }
        public string Format { get; set; } = string.Empty;
        public int? DurationSeconds { get; set; }
        public List<string> Tags { get; set; } = new();
        public PostAuthorDto Author { get; set; } = new();
        public PostStatsDto Stats { get; set; } = new();
        public bool IsLikedByMe { get; set; }
        public bool IsSavedByMe { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    public class PostAuthorDto
    {
        public string Id { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string? ProfilePicture { get; set; }
        public bool IsFollowedByMe { get; set; }
    }

    public class PostStatsDto
    {
        public int LikesCount { get; set; }
        public int CommentsCount { get; set; }
        public int SharesCount { get; set; }
        public int SavesCount { get; set; }
        public int ViewsCount { get; set; }
    }

    public class PaginatedResponseDto<T>
    {
        public bool Success { get; set; }
        public List<T> Data { get; set; } = new();
        public PaginationDto Pagination { get; set; } = new();
    }

    public class PaginationDto
    {
        public int Total { get; set; }
        public int Page { get; set; }
        public int Limit { get; set; }
        public int TotalPages { get; set; }
        public bool HasNext { get; set; }
        public bool HasPrev { get; set; }
    }
}