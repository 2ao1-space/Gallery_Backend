using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Threading.RateLimiting;
using Gallery.Data;
using Gallery.Models.Entities;
using Gallery.Services;
using Gallery.Middleware;
using Microsoft.AspNetCore.RateLimiting;
using Serilog;
using DotNetEnv;
using Microsoft.OpenApi.Models;


try
{
    Env.Load();
    Console.WriteLine(".env file loaded successfully");
}
catch (Exception ex)
{
    Console.WriteLine($"Warning: Could not load .env file: {ex.Message}");
}

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .AddEnvironmentVariables()
        .Build())
    .CreateLogger();

try
{
    Log.Information("Starting Gallery API...");

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog();

var connectionString = $"Server={Environment.GetEnvironmentVariable("DB_SERVER")};" +
                          $"Database={Environment.GetEnvironmentVariable("DB_NAME")};" +
                          $"User Id={Environment.GetEnvironmentVariable("DB_USER")};" +
                          $"Password={Environment.GetEnvironmentVariable("DB_PASSWORD")};" +
                          "Encrypt=True;TrustServerCertificate=True;MultipleActiveResultSets=True;";


builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlServer(connectionString));

builder.Services.AddIdentity<User, IdentityRole>(options =>
{
    options.Password.RequireDigit=true;
    options.Password.RequiredLength=8;
    // options.Password.RequireNonAlphanumeric=true;
    // options.Password.RequireUppercase=true;
    // options.Password.RequireLowercase=true;

    options.User.RequireUniqueEmail=true;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") 
            ?? builder.Configuration["Jwt:Key"];

var emailPassword = Environment.GetEnvironmentVariable("EMAIL_PASSWORD")
            ?? builder.Configuration["Email:Password"];
var googleClientId =
    Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID")
    ?? builder.Configuration["OAuth:Google:ClientId"];

if (string.IsNullOrEmpty(jwtKey))
    {
        throw new InvalidOperationException("JWT Key is not configured!");
    }

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
 .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.Zero
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Log.Warning("Authentication failed: {Message}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Log.Information("Token validated for user: {User}", 
                    context.Principal?.Identity?.Name ?? "Unknown");
                return Task.CompletedTask;
            }
        };
});

builder.Services.AddCors(options =>
{
   options.AddPolicy("AllowReactApp", policy =>
        {
            var allowedOrigins = builder.Configuration
                .GetSection("AllowedOrigins")
                .Get<string[]>() ?? new[] {
                "http://localhost:5173",      
                "http://localhost:3000",     
                "https://gallery.2ao1.space",        
                "https://www.gallery.2ao1.space",        
                "https://gallery-eight-sigma.vercel.app"
            };

            policy.WithOrigins(allowedOrigins)
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials()
                  .SetIsOriginAllowedToAllowWildcardSubdomains();
        });
    });

 builder.Services.AddRateLimiter(options =>
    {
        options.AddFixedWindowLimiter("refresh", opt =>
        {
            opt.Window = TimeSpan.FromMinutes(15);
            opt.PermitLimit = 3; 
            opt.QueueLimit = 0;
        });

        options.AddFixedWindowLimiter("auth", opt =>
        {
            opt.Window = TimeSpan.FromMinutes(5);
            opt.PermitLimit = 5; 
            opt.QueueLimit = 0;
        });

        options.AddFixedWindowLimiter("general", opt =>
        {
            opt.Window = TimeSpan.FromMinutes(1);
            opt.PermitLimit = 60; 
            opt.QueueLimit = 0;
        });

        options.OnRejected = async (context, token) =>
        {
            context.HttpContext.Response.StatusCode = 429;
            
            Log.Warning("Rate limit exceeded for IP: {IP}", 
                context.HttpContext.Connection.RemoteIpAddress);

            await context.HttpContext.Response.WriteAsJsonAsync(new
            {
                success = false,
                message = "Too many requests. Please try again later.",
                retryAfter = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) 
                    ? (double?)retryAfter.TotalSeconds 
                    : null
            }, cancellationToken: token);
        };
    });


builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<EmailService>();
builder.Services.AddScoped<CloudinaryService>();
if (!builder.Environment.IsEnvironment("Migration"))
{
    builder.Services.AddHostedService<TokenCleanupService>();
}

builder.Services.AddControllers();
builder.Services.AddHttpClient();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Gallery API",
        Version = "v1",
        Description = "API for Gallery - Social Media Platform",
        Contact = new OpenApiContact
        {
            Name = "2ao1",
            Email = "2ao1.space@gmail.com"
        }
    });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter JWT Token: Bearer {token}"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

app.UseMiddleware<GlobalExceptionMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseSerilogRequestLogging();

app.UseCors("AllowReactApp");
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

Log.Information("Gallery API started successfully");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application failed to start");
}
finally
{
    Log.CloseAndFlush();
}