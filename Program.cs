using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Gallery.Data;
using Gallery.Middleware;
using Gallery.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

var connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING") 
    ?? builder.Configuration.GetConnectionString("DefaultConnection");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

var jwtSecretKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY") 
    ?? builder.Configuration["JwtSettings:SecretKey"]!;

builder.Services.Configure<JwtSettings>(options =>
{
    options.SecretKey = jwtSecretKey;
    options.Issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") 
        ?? builder.Configuration["JwtSettings:Issuer"]!;
    options.Audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") 
        ?? builder.Configuration["JwtSettings:Audience"]!;
    options.AccessTokenExpirationMinutes = int.Parse(
        Environment.GetEnvironmentVariable("JWT_ACCESS_TOKEN_MINUTES") 
        ?? builder.Configuration["JwtSettings:AccessTokenExpirationMinutes"]!);
    options.RefreshTokenExpirationDays = int.Parse(
        Environment.GetEnvironmentVariable("JWT_REFRESH_TOKEN_DAYS") 
        ?? builder.Configuration["JwtSettings:RefreshTokenExpirationDays"]!);
});

builder.Services.Configure<EmailSettings>(options =>
{
    options.SmtpHost = Environment.GetEnvironmentVariable("SMTP_HOST") 
        ?? builder.Configuration["EmailSettings:SmtpHost"]!;
    options.SmtpPort = int.Parse(
        Environment.GetEnvironmentVariable("SMTP_PORT") 
        ?? builder.Configuration["EmailSettings:SmtpPort"]!);
    options.SenderEmail = Environment.GetEnvironmentVariable("SMTP_SENDER_EMAIL") 
        ?? builder.Configuration["EmailSettings:SenderEmail"]!;
    options.SenderName = Environment.GetEnvironmentVariable("SMTP_SENDER_NAME") 
        ?? builder.Configuration["EmailSettings:SenderName"]!;
    options.Password = Environment.GetEnvironmentVariable("SMTP_PASSWORD") 
        ?? builder.Configuration["EmailSettings:Password"]!;
    options.EnableSsl = bool.Parse(
        Environment.GetEnvironmentVariable("SMTP_ENABLE_SSL") 
        ?? builder.Configuration["EmailSettings:EnableSsl"]!);
});

builder.Services.Configure<GoogleAuthSettings>(options =>
{
    options.ClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID") 
        ?? builder.Configuration["GoogleAuth:ClientId"]!;
    options.ClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET") 
        ?? builder.Configuration["GoogleAuth:ClientSecret"]!;
});

builder.Services.Configure<OtpSettings>(options =>
{
    options.ExpirationMinutes = int.Parse(
        Environment.GetEnvironmentVariable("OTP_EXPIRATION_MINUTES") 
        ?? builder.Configuration["OtpSettings:ExpirationMinutes"]!);
    options.Length = int.Parse(
        Environment.GetEnvironmentVariable("OTP_LENGTH") 
        ?? builder.Configuration["OtpSettings:Length"]!);
    options.MaxResendAttempts = int.Parse(
        Environment.GetEnvironmentVariable("OTP_MAX_RESEND_ATTEMPTS") 
        ?? builder.Configuration["OtpSettings:MaxResendAttempts"]!);
    options.ResendCooldownSeconds = int.Parse(
        Environment.GetEnvironmentVariable("OTP_RESEND_COOLDOWN_SECONDS") 
        ?? builder.Configuration["OtpSettings:ResendCooldownSeconds"]!);
});

builder.Services.AddMemoryCache();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey)),
        ValidateIssuer = true,
        ValidIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") 
            ?? builder.Configuration["JwtSettings:Issuer"],
        ValidateAudience = true,
        ValidAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") 
            ?? builder.Configuration["JwtSettings:Audience"],
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

var corsOrigins = Environment.GetEnvironmentVariable("CORS_ORIGINS")?.Split(',') 
    ?? new[] { "http://localhost:3000", "http://localhost:5173" };

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins(corsOrigins)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

builder.Services.AddScoped<JwtService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IPasswordService, PasswordService>();
builder.Services.AddScoped<IGoogleAuthService, GoogleAuthService>();
builder.Services.AddScoped<IEmailChangeService, EmailChangeService>();
builder.Services.AddScoped<IAccountManagementService, AccountManagementService>();

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo 
    { 
        Title = "Gallery API", 
        Version = "v1",
        Description = "Complete Authentication & Authorization API with Advanced Features"
    });
    
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using Bearer scheme. Example: 'Bearer {token}'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
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

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors("AllowFrontend");

app.UseMiddleware<RateLimitingMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();