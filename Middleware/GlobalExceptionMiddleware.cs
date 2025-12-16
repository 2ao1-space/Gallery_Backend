using System.Net;
using System.Text.Json;
using Serilog;

namespace Gallery.Middleware
{
    public class GlobalExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IWebHostEnvironment _env;

        public GlobalExceptionMiddleware(
            RequestDelegate next,
            IWebHostEnvironment env)
        {
            _next = next;
            _env = env;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Unhandled exception occurred. Path: {Path}, Method: {Method}", 
                    context.Request.Path, 
                    context.Request.Method);
                
                await HandleExceptionAsync(context, ex);
            }
        }

        private Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            var statusCode = HttpStatusCode.InternalServerError;
            var message = "An error occurred while processing your request.";
            string? details = null;

            Log.Error(exception, "Exception Details - Type: {Type}, Message: {Message}, StackTrace: {StackTrace}",
                exception.GetType().Name,
                exception.Message,
                exception.StackTrace);

            if (exception is UnauthorizedAccessException)
            {
                statusCode = HttpStatusCode.Unauthorized;
                message = "Unauthorized access.";
            }
            else if (exception is ArgumentException argEx)
            {
                statusCode = HttpStatusCode.BadRequest;
                message = argEx.Message;
            }
            else if (exception is InvalidOperationException invalidOpEx)
            {
                statusCode = HttpStatusCode.BadRequest;
                message = invalidOpEx.Message;
                Log.Error("InvalidOperationException: {Message}", invalidOpEx.Message);
            }
            else if (exception is DbException dbEx)
            {
                statusCode = HttpStatusCode.InternalServerError;
                message = "Database error occurred.";
                Log.Error(dbEx, "Database Exception: {Message}", dbEx.Message);
            }

            if (_env.IsDevelopment())
            {
                details = exception.ToString();
            }

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)statusCode;

            var response = new
            {
                success = false,
                message = message,
                statusCode = (int)statusCode,
                error = _env.IsDevelopment() ? new
                {
                    type = exception.GetType().Name,
                    message = exception.Message,
                    stackTrace = exception.StackTrace,
                    innerException = exception.InnerException?.Message
                } : null
            };

            var result = JsonSerializer.Serialize(response);
            return context.Response.WriteAsync(result);
        }
    }

    public class DbException : Exception
    {
        public DbException(string message) : base(message) { }
        public DbException(string message, Exception innerException) : base(message, innerException) { }
    }
}