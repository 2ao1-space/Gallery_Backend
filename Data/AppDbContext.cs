using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Gallery.Models.Entities;

namespace Gallery.Data
{
    public class AppDbContext:IdentityDbContext<User>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) 
            : base(options)
        {
        }

        public DbSet<Post> Posts { get; set; }
        public DbSet<Follow> Follows { get; set; }
        public DbSet<Like> Likes { get; set; }
        public DbSet<Save> Saves { get; set; }
        public DbSet<Share> Shares { get; set; }
        public DbSet<Comment> Comments { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<User>(entity =>
            {
                entity.Property(e => e.FullName).HasMaxLength(100);
                entity.Property(e => e.CustomUsername).HasMaxLength(50);
                entity.Property(e => e.Bio).HasMaxLength(500);
                entity.Property(e => e.JobTitle).HasMaxLength(100);
                
                entity.HasIndex(e => e.CustomUsername).IsUnique();
                entity.HasIndex(e => e.GoogleId).IsUnique();
                entity.HasIndex(e => e.BehanceId).IsUnique();
            });

            builder.Entity<Post>(entity =>
            {
                entity.Property(e => e.Title).HasMaxLength(200).IsRequired();
                entity.Property(e => e.Description).HasMaxLength(2000);
                
                entity.HasOne(p => p.Author)
                      .WithMany(u => u.Posts)
                      .HasForeignKey(p => p.AuthorId)
                      .OnDelete(DeleteBehavior.Cascade);
                
                entity.HasIndex(e => e.AuthorId);
                entity.HasIndex(e => e.CreatedAt);
                entity.HasIndex(e => e.IsDeleted);
            });

            builder.Entity<Follow>(entity =>
            {
                entity.HasOne(f => f.Follower)
                      .WithMany(u => u.Following)
                      .HasForeignKey(f => f.FollowerId)
                      .OnDelete(DeleteBehavior.Restrict);
                
                entity.HasOne(f => f.Following)
                      .WithMany(u => u.Followers)
                      .HasForeignKey(f => f.FollowingId)
                      .OnDelete(DeleteBehavior.Restrict);
                
                entity.HasIndex(e => new { e.FollowerId, e.FollowingId }).IsUnique();
            });

            builder.Entity<Like>(entity =>
            {
                entity.HasOne(l => l.User)
                      .WithMany(u => u.Likes)
                      .HasForeignKey(l => l.UserId)
                      .OnDelete(DeleteBehavior.NoAction);
                
                entity.HasOne(l => l.Post)
                      .WithMany(p => p.Likes)
                      .HasForeignKey(l => l.PostId)
                      .OnDelete(DeleteBehavior.Cascade);
                
                entity.HasIndex(e => new { e.UserId, e.PostId }).IsUnique();
            });

           
            builder.Entity<Save>(entity =>
            {
                entity.HasOne(s => s.User)
                      .WithMany(u => u.Saves)
                      .HasForeignKey(s => s.UserId)
                      .OnDelete(DeleteBehavior.NoAction);
                
                entity.HasOne(s => s.Post)
                      .WithMany(p => p.Saves)
                      .HasForeignKey(s => s.PostId)
                      .OnDelete(DeleteBehavior.Cascade);
                
                entity.HasIndex(e => new { e.UserId, e.PostId }).IsUnique();
            });

           
            builder.Entity<Share>(entity =>
            {
                entity.HasOne(s => s.Post)
                      .WithMany(p => p.Shares)
                      .HasForeignKey(s => s.PostId)
                      .OnDelete(DeleteBehavior.Cascade);
                
                entity.HasIndex(e => e.PostId);
            });

            
            builder.Entity<Comment>(entity =>
            {
                entity.Property(e => e.Text).HasMaxLength(1000).IsRequired();
                
                entity.HasOne(c => c.User)
                      .WithMany(u => u.Comments)
                      .HasForeignKey(c => c.UserId)
                      .OnDelete(DeleteBehavior.NoAction);
                
                entity.HasOne(c => c.Post)
                      .WithMany(p => p.Comments)
                      .HasForeignKey(c => c.PostId)
                      .OnDelete(DeleteBehavior.Cascade);
                
                entity.HasIndex(e => e.PostId);
            });
        }
    
    }
}