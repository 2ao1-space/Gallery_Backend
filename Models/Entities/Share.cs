namespace Gallery.Models.Entities
{
    public class Share
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        public string? UserId { get; set; } 
        public virtual User? User { get; set; }
        
        public string PostId { get; set; } = string.Empty;
        public virtual Post Post { get; set; } = null!;
        
        public string? IpAddress { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}