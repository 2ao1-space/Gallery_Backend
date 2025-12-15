namespace Gallery.Models.Entities
{
    public class Post
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Title { get; set; } = string.Empty;
        public string? Description { get; set; }

        public string MediaUrl { get; set; } = string.Empty;
        public string MediaPublicId { get; set; } = string.Empty;
        public string WatermarkedUrl { get; set; } = string.Empty;
        public string DownloadUrl { get; set; } = string.Empty;
        public PostMediaType MediaType { get; set; } 
        public int Width { get; set; }
        public int Height { get; set; }
        public long FileSizeBytes { get; set; }
        public string Format { get; set; } = string.Empty; 
        public int? DurationSeconds { get; set; } 

        public string? TagsJson { get; set; } 

        public string AuthorId { get; set; } = string.Empty;
        public virtual User Author { get; set; } = null!;

        public int LikesCount { get; set; } = 0;
        public int CommentsCount { get; set; } = 0;
        public int SharesCount { get; set; } = 0;
        public int SavesCount { get; set; } = 0;
        public int ViewsCount { get; set; } = 0;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public bool IsDeleted { get; set; } = false; 

        public virtual ICollection<Like> Likes { get; set; } = new List<Like>();
        public virtual ICollection<Save> Saves { get; set; } = new List<Save>();
        public virtual ICollection<Comment> Comments { get; set; } = new List<Comment>();
        public virtual ICollection<Share> Shares { get; set; } = new List<Share>();
    }

    public enum PostMediaType
    {
        Image = 1,
        Video = 2
    }
}