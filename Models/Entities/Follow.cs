namespace Gallery.Models.Entities
{
    public class Follow
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        public string FollowerId { get; set; } = string.Empty;
        public virtual User Follower { get; set; } = null!;
        
        public string FollowingId { get; set; } = string.Empty;
        public virtual User Following { get; set; } = null!;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}