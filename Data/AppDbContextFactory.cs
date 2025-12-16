using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using DotNetEnv;

namespace Gallery.Data
{
    public class AppDbContextFactory 
        : IDesignTimeDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext(string[] args)
        {
            try
            {
                Env.Load();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Could not load .env file: {ex.Message}");
            }

            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .Build();

            var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();

            var connectionString = config.GetConnectionString("DefaultConnection");

            if (string.IsNullOrEmpty(connectionString) || 
                connectionString == "CONFIGURED_VIA_ENVIRONMENT_VARIABLES")
            {
                var dbServer = Environment.GetEnvironmentVariable("DB_SERVER");
                var dbName = Environment.GetEnvironmentVariable("DB_NAME");
                var dbUser = Environment.GetEnvironmentVariable("DB_USER");
                var dbPassword = Environment.GetEnvironmentVariable("DB_PASSWORD");

                if (string.IsNullOrEmpty(dbServer) || string.IsNullOrEmpty(dbName) || 
                    string.IsNullOrEmpty(dbUser) || string.IsNullOrEmpty(dbPassword))
                {
                    connectionString = $"Server={dbServer};" +
                                      $"Database={dbName};" +
                                      $"User Id={dbUser};" +
                                      $"Password={dbPassword};" +
                                      "Encrypt=True;TrustServerCertificate=True;MultipleActiveResultSets=True;";
                }
            }

            optionsBuilder.UseSqlServer(connectionString);

            return new AppDbContext(optionsBuilder.Options);
        }
    }
}