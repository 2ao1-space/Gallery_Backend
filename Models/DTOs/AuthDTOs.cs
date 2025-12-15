using System.ComponentModel.DataAnnotations;

namespace Gallery.Models.DTPs
{
    public class RegisterDto
    {
        [Required(ErrorMessage ="Name is Required")]
        [MinLength(2,ErrorMessage ="Name must be at least 2 characcters")]
        public string Name {get;set;}=string.Empty;

        [Required(ErrorMessage ="Email is Required")]
        [EmailAddress(ErrorMessage ="Invalid email format")]
        public string Email {get;set;}=string.Empty;

        [Required(ErrorMessage ="Password is required")]
        [MinLength(8,ErrorMessage ="Password must be at least 8 characters")]
        public string Password {get;set;}=string.Empty;
    }

    public class LoginDto
    {
        [Required(ErrorMessage ="Email is Required")]
        [EmailAddress(ErrorMessage ="Invalid email format")]
        public string Email {get;set;}=string.Empty;

        [Required(ErrorMessage ="Password is required")]
        public string Password {get;set;}=string.Empty;
    }

    public class ForgetPasswordDto
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = string.Empty;
    }

    public class VerifyOtpDto
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage ="OTP is required")]
        [StringLength(6,MinimumLength =6,ErrorMessage ="OTP must be 6 digits")]
        public string Otp {get;set;}=string.Empty;
    }

    public class ResetPasswordDto
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage ="OTP is required")]
        public string Otp{get;set;}=string.Empty;

        [Required(ErrorMessage ="New password is required")]
        [MinLength(8,ErrorMessage ="Password must be at least 8 characters")]
        public string NewPassword{get;set;}=string.Empty;

        [Required(ErrorMessage ="Confirm password is required")]
        [Compare("NewPassword",ErrorMessage ="Password don't match")]
        public string ConfirmPassword {get;set;}=string.Empty;
    }

    public class OAuthLoginDto
    {
        [Required(ErrorMessage ="Access token is required")]
        public string AccessToken{get;set;}=string.Empty;

        public string Provider {get;set;}=string.Empty;
    }

    public class RefreshTokenDto
    {
        [Required(ErrorMessage = "Refresh token is required")]
        public string RefreshToken { get; set; } = string.Empty;
    }
    
    public class AuthResponseDto
    {
        public bool Success{get;set;}
        public string Message {get;set;}=string.Empty;
        public string? Token{get;set;}
        public string? RefreshToken { get; set; }
        public UserDto? User{get;set;}
    }

    public class UserDto
    {
        public string Id {get;set;}=string.Empty;
        public string FullName {get;set;}=string.Empty;
        public string Email {get;set;}=string.Empty;
        public string? ProfilePicture{get;set;}
        public DateTime CreatedAt {get;set;}

    }
}