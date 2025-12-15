namespace Gallery.Models.Entities
{
    public class Save
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        public string UserId { get; set; } = string.Empty;
        public virtual User User { get; set; } = null!;
        
        public string PostId { get; set; } = string.Empty;
        public virtual Post Post { get; set; } = null!;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}