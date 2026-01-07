using Microsoft.Extensions.Caching.Memory;
using System.Net;

namespace Gallery.Middleware;

public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IMemoryCache _cache;
    private readonly ILogger<RateLimitingMiddleware> _logger;
    
    public RateLimitingMiddleware(
        RequestDelegate next,
        IMemoryCache cache,
        ILogger<RateLimitingMiddleware> logger)
    {
        _next = next;
        _cache = cache;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        var rateLimitAttribute = endpoint?.Metadata.GetMetadata<RateLimitAttribute>();
        
        if (rateLimitAttribute != null)
        {
            var key = GenerateKey(context, rateLimitAttribute);
            var cacheKey = $"rate_limit:{key}";
            
            if (!_cache.TryGetValue(cacheKey, out RateLimitCounter counter))
            {
                counter = new RateLimitCounter
                {
                    Count = 0,
                    FirstRequestTime = DateTime.UtcNow
                };
            }
            
            var timeWindow = TimeSpan.FromMinutes(rateLimitAttribute.WindowMinutes);
            var timeSinceFirstRequest = DateTime.UtcNow - counter.FirstRequestTime;
            
            if (timeSinceFirstRequest > timeWindow)
            {
                counter = new RateLimitCounter
                {
                    Count = 1,
                    FirstRequestTime = DateTime.UtcNow
                };
            }
            else
            {
                counter.Count++;
            }
            
            if (counter.Count > rateLimitAttribute.MaxRequests)
            {
                _logger.LogWarning(
                    "Rate limit exceeded for {Key}. Limit: {Limit}, Window: {Window}min",
                    key,
                    rateLimitAttribute.MaxRequests,
                    rateLimitAttribute.WindowMinutes
                );
                
                context.Response.StatusCode = (int)HttpStatusCode.TooManyRequests;
                context.Response.ContentType = "application/json";
                
                var retryAfter = (timeWindow - timeSinceFirstRequest).TotalSeconds;
                context.Response.Headers["Retry-After"] = ((int)retryAfter).ToString();
                
                await context.Response.WriteAsJsonAsync(new
                {
                    success = false,
                    message = $"Too many requests. Please try again in {(int)retryAfter} seconds.",
                    retryAfter = (int)retryAfter
                });
                
                return;
            }
            
            var cacheOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = timeWindow
            };
            
            _cache.Set(cacheKey, counter, cacheOptions);
        }
        
        await _next(context);
    }
    
    private string GenerateKey(HttpContext context, RateLimitAttribute attribute)
    {
        var identifier = attribute.ByIpAddress
            ? GetIpAddress(context)
            : context.User.Identity?.Name ?? "anonymous";
        
        var endpoint = context.GetEndpoint()?.DisplayName ?? context.Request.Path;
        
        return $"{endpoint}:{identifier}";
    }
    
    private string GetIpAddress(HttpContext context)
    {
        if (context.Request.Headers.ContainsKey("X-Forwarded-For"))
        {
            return context.Request.Headers["X-Forwarded-For"].ToString().Split(',')[0].Trim();
        }
        
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public class RateLimitAttribute : Attribute
{
    public int MaxRequests { get; set; }
    public int WindowMinutes { get; set; }
    public bool ByIpAddress { get; set; } = true;
    
    public RateLimitAttribute(int maxRequests, int windowMinutes)
    {
        MaxRequests = maxRequests;
        WindowMinutes = windowMinutes;
    }
}

public class RateLimitCounter
{
    public int Count { get; set; }
    public DateTime FirstRequestTime { get; set; }
}