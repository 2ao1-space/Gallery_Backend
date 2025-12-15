using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Gallery.Models.Entities;
using Gallery.Models.DTPs;
using Gallery.Services;
using Microsoft.AspNetCore.RateLimiting;

namespace Gallery.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly TokenService _tokenService;
        private readonly EmailService _emailService;

        public AuthController(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            TokenService tokenService,
            EmailService emailService
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenService = tokenService;
            _emailService = emailService;
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

        [HttpPost("register")]
        public async Task<ActionResult<AuthResponseDto>> Register(RegisterDto dto)
        {
            var existingUser = await _userManager.FindByEmailAsync(dto.Email);
            if (existingUser != null)
            {
                return BadRequest(new AuthResponseDto
                {
                    Success = false,
                    Message = "Email already exists"
                });
            }

            var user = new User
            {
                UserName = dto.Email,
                Email = dto.Email,
                FullName = dto.Name,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
            {
                return BadRequest(new AuthResponseDto
                {
                    Success = false,
                    Message = string.Join(", ", result.Errors.Select(e => e.Description))
                });
            }

            var (accessToken, refreshToken) = await GenerateAndSaveTokens(user);

            return Ok(new AuthResponseDto
            {
                Success = true,
                Message = "Registration successful",
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

        [HttpPost("login")]
        [EnableRateLimiting("auth")]
        public async Task<ActionResult<AuthResponseDto>> Login(LoginDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                return Unauthorized(new AuthResponseDto
                {
                    Success = false,
                    Message = "Invalid email or password"
                });
            }

            var result = await _signInManager.CheckPasswordSignInAsync(
                user, dto.Password, lockoutOnFailure: false
            );
            if (!result.Succeeded)
            {
                return Unauthorized(new AuthResponseDto
                {
                    Success = false,
                    Message = "Invalid email or password"
                });
            }

            user.LastLogin = DateTime.UtcNow;

            var (accessToken, refreshToken) = await GenerateAndSaveTokens(user);

            return Ok(new AuthResponseDto
            {
                Success = true,
                Message = "Login successful",
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

        [HttpPost("refresh")]
        [EnableRateLimiting("refresh")]
        public async Task<ActionResult<AuthResponseDto>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return Unauthorized(new AuthResponseDto
                {
                    Success = false,
                    Message = "Refresh token not found"
                });
            }

            var users = _userManager.Users.Where(u => u.RefreshToken == refreshToken);
            var user = users.FirstOrDefault();

            if (user == null)
            {
                return Unauthorized(new AuthResponseDto
                {
                    Success = false,
                    Message = "Invalid refresh token"
                });
            }

            if (user.RefreshTokenExpiry < DateTime.UtcNow)
            {
                return Unauthorized(new AuthResponseDto
                {
                    Success = false,
                    Message = "Refresh token expired"
                });
            }

            var (accessToken, newRefreshToken) = await GenerateAndSaveTokens(user);

            return Ok(new AuthResponseDto
            {
                Success = true,
                Message = "Token refreshed successfully",
                Token = accessToken,
                RefreshToken = newRefreshToken 
            });
        }

        [HttpPost("logout")]
        public async Task<ActionResult<AuthResponseDto>> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (!string.IsNullOrEmpty(refreshToken))
            {
                var users = _userManager.Users.Where(u => u.RefreshToken == refreshToken);
                var user = users.FirstOrDefault();
                
                if (user != null)
                {
                    user.RefreshToken = null;
                    user.RefreshTokenExpiry = null;
                    await _userManager.UpdateAsync(user);
                }
            }

            Response.Cookies.Delete("refreshToken");

            return Ok(new AuthResponseDto
            {
                Success = true,
                Message = "Logged out successfully"
            });
        }

        [HttpPost("forget-password")]
        public async Task<ActionResult<AuthResponseDto>> ForgetPassword(ForgetPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                return Ok(new AuthResponseDto
                {
                    Success = true,
                    Message = "If your email exists, you will receive an OTP"
                });
            }

            var random = new Random();
            var otp = random.Next(100000, 999999).ToString();

            user.OtpCode = otp;
            user.OtpExpiry = DateTime.UtcNow.AddMinutes(10);
            await _userManager.UpdateAsync(user);

            await _emailService.SendOtpEmailAsync(user.Email!, otp);

            return Ok(new AuthResponseDto
            {
                Success = true,
                Message = "OTP sent to your email"
            });
        }

        [HttpPost("verify-otp")]
        public async Task<ActionResult<AuthResponseDto>> VerifyOtp(VerifyOtpDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email!);
            if (user == null)
            {
                return BadRequest(new AuthResponseDto
                {
                    Success = false,
                    Message = "Invalid email"
                });
            }

            if (user.OtpCode != dto.Otp)
            {
                return BadRequest(new AuthResponseDto
                {
                    Success = false,
                    Message = "Invalid OTP"
                });
            }

            if (user.OtpExpiry < DateTime.UtcNow)
            {
                return BadRequest(new AuthResponseDto
                {
                    Success = false,
                    Message = "OTP expired"
                });
            }

            return Ok(new AuthResponseDto
            {
                Success = true,
                Message = "OTP verified successfully"
            });
        }

        [HttpPost("reset-password")]
        public async Task<ActionResult<AuthResponseDto>> ResetPassword(ResetPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                return BadRequest(new AuthResponseDto
                {
                    Success = false,
                    Message = "Invalid request"
                });
            }

            if (user.OtpCode != dto.Otp || user.OtpExpiry < DateTime.UtcNow)
            {
                return BadRequest(new AuthResponseDto
                {
                    Success = false,
                    Message = "Invalid or expired OTP"
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, dto.NewPassword);

            if (!result.Succeeded)
            {
                return BadRequest(new AuthResponseDto
                {
                    Success = false,
                    Message = string.Join(", ", result.Errors.Select(e => e.Description))
                });
            }

            user.OtpCode = null;
            user.OtpExpiry = null;

            var (accessToken, refreshToken) = await GenerateAndSaveTokens(user);

            return Ok(new AuthResponseDto
            {
                Success = true,
                Message = "Password reset successfully",
                Token = accessToken,
                RefreshToken = refreshToken
            });
        }
    }
}