using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace Gallery.Services
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendOtpEmailAsync(string email,string otp)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(
                _config["Email:SenderName"],
                _config["Email:SenderEmail"]
            ));
            message.To.Add(new MailboxAddress("",email));
            message.Subject="Password Reset OTP - Gallery";

            message.Body=new TextPart("html")
            {
              Text=$@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2>Password Reset Request</h2>
                        <p>Your OTP code is:</p>
                        <h1 style='color: #d1202d; font-size: 32px; letter-spacing: 5px;'>{otp}</h1>
                        <p>This code will expire in 10 minutes.</p>
                        <p>If you didn't request this, please ignore this email.</p>
                </body>
                </html>
              "  
            };

            using var client = new SmtpClient();
            await client.ConnectAsync(
                _config["Email:SmtpServer"],
                int.Parse(_config["Email:Port"]!),
                SecureSocketOptions.StartTls
            );
            await client.AuthenticateAsync(
                _config["Email:Username"],
                _config["Email:Password"]
            );
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
    }
}