using System.Net.Http.Headers;
using System.Text.Json;
using Gallery.Models.DTPs;
using Gallery.Models.Entities;
using Gallery.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Gallery.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class OAuthController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly TokenService _tokenService;
        private readonly IConfiguration _config;
        private readonly IHttpClientFactory _httpClientFactory;

        public OAuthController(
            UserManager<User> userManager,
            TokenService tokenService,
            IConfiguration config,
            IHttpClientFactory httpClientFactory)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _config = config;
            _httpClientFactory = httpClientFactory;
        }

        private async Task<(string accessToken, string refreshToken)> GenerateAndSaveTokens(User user)
        {
            var accessToken = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user);

            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            });

            return (accessToken, refreshToken);
        }

        [HttpPost("google")]
        public async Task<ActionResult<AuthResponseDto>> GoogleAuth([FromBody] OAuthLoginDto dto)
        {
            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Authorization = 
                    new AuthenticationHeaderValue("Bearer", dto.AccessToken);

                var response = await client.GetAsync(
                    "https://www.googleapis.com/oauth2/v2/userinfo"
                );

                if (!response.IsSuccessStatusCode)
                {
                    return BadRequest(new AuthResponseDto
                    {
                        Success = false,
                        Message = "Invalid Google token"
                    });
                }

                var content = await response.Content.ReadAsStringAsync();
                var googleUser = JsonSerializer.Deserialize<GoogleUserInfo>(content);

                if (googleUser == null || string.IsNullOrEmpty(googleUser.email))
                {
                    return BadRequest(new AuthResponseDto
                    {
                        Success = false,
                        Message = "Failed to get user info from Google"
                    });
                }

                var user = await _userManager.FindByEmailAsync(googleUser.email);
                
                if (user == null)
                {
                    user = new User
                    {
                        UserName = googleUser.email,
                        Email = googleUser.email,
                        FullName = googleUser.name ?? "User" + googleUser.email,
                        GoogleId = googleUser.id,
                        ProfilePicture = googleUser.picture,
                        EmailConfirmed = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    var createResult = await _userManager.CreateAsync(user);

                    if (!createResult.Succeeded)
                    {
                        return BadRequest(new AuthResponseDto
                        {
                            Success = false,
                            Message = "Failed to create user"
                        });
                    }
                }
                else
                {
                    if (string.IsNullOrEmpty(user.GoogleId))
                    {
                        user.GoogleId = googleUser.id;
                    }
                    user.ProfilePicture = googleUser.picture ?? user.ProfilePicture;
                    user.LastLogin = DateTime.UtcNow;
                    await _userManager.UpdateAsync(user);
                }

                var (accessToken, refreshToken) = await GenerateAndSaveTokens(user);

                return Ok(new AuthResponseDto
                {
                    Success = true,
                    Message = "Google login successful",
                    Token = accessToken,
                    RefreshToken = refreshToken,
                    User = new UserDto
                    {
                        Id = user.Id,
                        FullName = user.FullName,
                        Email = user.Email!,
                        ProfilePicture = user.ProfilePicture,
                        CreatedAt = user.CreatedAt
                    }
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new AuthResponseDto
                {
                    Success = false,
                    Message = $"Google OAuth error: {ex.Message}"
                });
            }
        }

        public class GoogleUserInfo
        {
            public string id { get; set; } = string.Empty;
            public string email { get; set; } = string.Empty;
            public string name { get; set; } = string.Empty;
            public string picture { get; set; } = string.Empty;
            public bool verified_email { get; set; }
        }
    }
}