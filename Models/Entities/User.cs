using Microsoft.AspNetCore.Identity;

namespace Gallery.Models.Entities
{
    public class User : IdentityUser
    {
        public string FullName { get; set; } = string.Empty;
        
        public string? CustomUsername { get; set; }
        public bool IsUsernameChanged { get; set; } = false;
        
        public string? ProfilePicture { get; set; }
        public string? ProfilePicturePublicId { get; set; }
        
        public string? Bio { get; set; }
        public string? JobTitle { get; set; }
        public DateTime? BirthDate { get; set; }
        
        public string? SocialLinksJson { get; set; }
        
        public string? GoogleId { get; set; }
        public string? BehanceId { get; set; }
        
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiry { get; set; }
        
        public string? OtpCode { get; set; }
        public DateTime? OtpExpiry { get; set; }
        
        public int PostsCount { get; set; } = 0;
        public int FollowersCount { get; set; } = 0;
        public int FollowingCount { get; set; } = 0;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastLogin { get; set; }
        
        public virtual ICollection<Post> Posts { get; set; } = new List<Post>();
        public virtual ICollection<Follow> Followers { get; set; } = new List<Follow>();
        public virtual ICollection<Follow> Following { get; set; } = new List<Follow>();
        public virtual ICollection<Like> Likes { get; set; } = new List<Like>();
        public virtual ICollection<Save> Saves { get; set; } = new List<Save>();
        public virtual ICollection<Comment> Comments { get; set; } = new List<Comment>();
    }
}