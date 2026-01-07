using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;

namespace Gallery.Services;

public interface IEmailService
{
    Task SendVerificationEmailAsync(string toEmail, string username, string otp);
    Task SendPasswordResetEmailAsync(string toEmail, string username, string otp);
    Task SendEmailChangeVerificationAsync(string toEmail, string username, string otp);
}

public class EmailService : IEmailService
{
    private readonly EmailSettings _emailSettings;
    private readonly ILogger<EmailService> _logger;
    
    public EmailService(IOptions<EmailSettings> emailSettings, ILogger<EmailService> logger)
    {
        _emailSettings = emailSettings.Value;
        _logger = logger;
    }
    
    public async Task SendVerificationEmailAsync(string toEmail, string username, string otp)
    {
        var subject = "Verify Your Email - Pinterest Clone";
        var body = $@"
            <html>
            <body style='font-family: Arial, sans-serif;'>
                <h2>Welcome {username}!</h2>
                <p>Thank you for registering. Please verify your email address using the code below:</p>
                <div style='background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;'>
                    <h1 style='color: #e60023; letter-spacing: 5px;'>{otp}</h1>
                </div>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't create this account, please ignore this email.</p>
            </body>
            </html>
        ";
        
        await SendEmailAsync(toEmail, subject, body);
    }
    
    public async Task SendPasswordResetEmailAsync(string toEmail, string username, string otp)
    {
        var subject = "Reset Your Password - Pinterest Clone";
        var body = $@"
            <html>
            <body style='font-family: Arial, sans-serif;'>
                <h2>Hi {username},</h2>
                <p>You requested to reset your password. Use the code below:</p>
                <div style='background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;'>
                    <h1 style='color: #e60023; letter-spacing: 5px;'>{otp}</h1>
                </div>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
            </body>
            </html>
        ";
        
        await SendEmailAsync(toEmail, subject, body);
    }
    
    public async Task SendEmailChangeVerificationAsync(string toEmail, string username, string otp)
    {
        var subject = "Verify Your New Email - Pinterest Clone";
        var body = $@"
            <html>
            <body style='font-family: Arial, sans-serif;'>
                <h2>Hi {username},</h2>
                <p>You requested to change your email address. Please verify your new email using the code below:</p>
                <div style='background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;'>
                    <h1 style='color: #e60023; letter-spacing: 5px;'>{otp}</h1>
                </div>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't request this change, please contact support immediately.</p>
            </body>
            </html>
        ";
        
        await SendEmailAsync(toEmail, subject, body);
    }
    
    private async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        try
        {
            using var message = new MailMessage();
            message.From = new MailAddress(_emailSettings.SenderEmail, _emailSettings.SenderName);
            message.To.Add(toEmail);
            message.Subject = subject;
            message.Body = body;
            message.IsBodyHtml = true;
            
            using var client = new SmtpClient(_emailSettings.SmtpHost, _emailSettings.SmtpPort);
            client.EnableSsl = _emailSettings.EnableSsl;
            client.Credentials = new NetworkCredential(_emailSettings.SenderEmail, _emailSettings.Password);
            
            await client.SendMailAsync(message);
            _logger.LogInformation("Email sent successfully to {Email}", toEmail);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {Email}", toEmail);
            throw;
        }
    }
}

public class EmailSettings
{
    public string SmtpHost { get; set; } = string.Empty;
    public int SmtpPort { get; set; }
    public string SenderEmail { get; set; } = string.Empty;
    public string SenderName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool EnableSsl { get; set; }
}