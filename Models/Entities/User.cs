
using Microsoft.AspNetCore.Identity;

namespace Gallery.Models.Entities
{
    public class User:IdentityUser
    {
        public string FullName{get;set;}=string.Empty;
        public string? ProfilePicture {get;set;}
        public string? ProfilePicturePublicId { get; set; }
        public DateTime CreatedAt {get;set;}=DateTime.UtcNow;
        public DateTime? LastLogin {get;set;}

        public string? CustomUsername { get; set; }
        public bool IsUsernameChanged { get; set; } = false;

        public string? Bio { get; set; }
        public string? JobTitle { get; set; }
        public new string? PhoneNumber { get; set; }
        public DateTime? BirthDate { get; set; }

         public string? SocialLinksJson { get; set; }

// OAuth
        public string? GoogleId {get;set;}
        public string? BehanceId{get;set;}
        public string? BehanceAccessToken{get;set;}

        // OTP
        public string? OtpCode {get;set;}
        public DateTime? OtpExpiry{get;set;}

        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiry { get; set; }

        public int FollowersCount { get; set; } = 0;
        public int FollowingCount { get; set; } = 0;
        public int PostsCount { get; set; } = 0;

         public virtual ICollection<Post> Posts { get; set; } = new List<Post>();
        public virtual ICollection<Follow> Followers { get; set; } = new List<Follow>();
        public virtual ICollection<Follow> Following { get; set; } = new List<Follow>();
        public virtual ICollection<Like> Likes { get; set; } = new List<Like>();
        public virtual ICollection<Save> Saves { get; set; } = new List<Save>();
        public virtual ICollection<Comment> Comments { get; set; } = new List<Comment>();
    }

    public class SocialLinks
    {
        public string? Facebook { get; set; }
        public string? LinkedIn { get; set; }
        public string? GitHub { get; set; }
        public string? Behance { get; set; }
        public string? Website { get; set; }
        public string? Instagram { get; set; }
        public string? Twitter { get; set; }
    }
}