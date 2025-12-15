namespace Gallery.Models.Entities
{
    public class Comment
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        public string Text { get; set; } = string.Empty;
        
        public string UserId { get; set; } = string.Empty;
        public virtual User User { get; set; } = null!;
        
        public string PostId { get; set; } = string.Empty;
        public virtual Post Post { get; set; } = null!;
        
        public int LikesCount { get; set; } = 0;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public bool IsDeleted { get; set; } = false;
    }
}