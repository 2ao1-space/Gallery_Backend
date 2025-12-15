using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace Gallery.Data
{
    public class AppDbContextFactory 
        : IDesignTimeDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext(string[] args)
        {
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .Build();

            var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();

            var connectionString =
                config.GetConnectionString("DefaultConnection")
                ?? $"Server={Environment.GetEnvironmentVariable("DB_SERVER")};" +
                   $"Database={Environment.GetEnvironmentVariable("DB_NAME")};" +
                   $"User Id={Environment.GetEnvironmentVariable("DB_USER")};" +
                   $"Password={Environment.GetEnvironmentVariable("DB_PASSWORD")};" +
                   "Encrypt=True;TrustServerCertificate=True;";

            optionsBuilder.UseSqlServer(connectionString);

            return new AppDbContext(optionsBuilder.Options);
        }
    }
}
