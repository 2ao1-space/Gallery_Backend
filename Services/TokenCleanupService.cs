using Gallery.Models.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Gallery.Services
{
    public class TokenCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<TokenCleanupService> _logger;

        public TokenCleanupService(
            IServiceProvider serviceProvider,
            ILogger<TokenCleanupService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Token Cleanup Service started");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
                    await CleanupExpiredTokens();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in Token Cleanup Service");
                }
            }
        }

        private async Task CleanupExpiredTokens()
        {
            using var scope = _serviceProvider.CreateScope();
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<User>>();

            var usersWithExpiredTokens = userManager.Users
                .Where(u => u.RefreshToken != null 
                    && u.RefreshTokenExpiry < DateTime.UtcNow)
                .ToList();

            foreach (var user in usersWithExpiredTokens)
            {
                user.RefreshToken = null;
                user.RefreshTokenExpiry = null;
                await userManager.UpdateAsync(user);
            }

            _logger.LogInformation(
                $"Cleaned up {usersWithExpiredTokens.Count} expired tokens"
            );
        }
    }
}

