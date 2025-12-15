using System.ComponentModel.DataAnnotations;

namespace Gallery.Models.DTOs
{
    public class UpdateProfileDto
    {
        [MaxLength(100)]
        public string? FullName { get; set; }

        [MaxLength(500)]
        public string? Bio { get; set; }

        [MaxLength(100)]
        public string? JobTitle { get; set; }

        [Phone]
        public string? PhoneNumber { get; set; }

        public DateTime? BirthDate { get; set; }

        public SocialLinksDto? SocialLinks { get; set; }
    }

    public class SocialLinksDto
    {
        [Url]
        public string? Facebook { get; set; }

        [Url]
        public string? LinkedIn { get; set; }

        [Url]
        public string? GitHub { get; set; }

        [Url]
        public string? Behance { get; set; }

        [Url]
        public string? Website { get; set; }

        [Url]
        public string? Instagram { get; set; }

        [Url]
        public string? Twitter { get; set; }
    }

    public class UpdateUsernameDto
    {
        [Required]
        [MinLength(3, ErrorMessage = "Username must be at least 3 characters")]
        [MaxLength(50)]
        [RegularExpression(@"^[a-zA-Z0-9_]+$", 
            ErrorMessage = "Username can only contain letters, numbers, and underscores")]
        public string Username { get; set; } = string.Empty;
    }

    public class UserProfileDto
    {
        public string Id { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string? ProfilePicture { get; set; }
        public string? Bio { get; set; }
        public string? JobTitle { get; set; }
        public string? PhoneNumber { get; set; }
        public DateTime? BirthDate { get; set; }
        public SocialLinksDto? SocialLinks { get; set; }
        public UserStatsDto Stats { get; set; } = new();
        public DateTime CreatedAt { get; set; }
        public bool IsUsernameChanged { get; set; }
        public bool IsFollowedByMe { get; set; } 
    }

    public class UserStatsDto
    {
        public int FollowersCount { get; set; }
        public int FollowingCount { get; set; }
        public int PostsCount { get; set; }
    }
}