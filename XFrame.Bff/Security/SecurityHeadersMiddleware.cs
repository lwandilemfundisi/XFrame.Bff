using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using XFrame.Bff.Options;

namespace XFrame.Bff.Security;

public sealed class SecurityHeadersMiddleware(
    RequestDelegate next,
    IOptions<XFrameBffOptions> options)
{
    private readonly XFrameBffOptions _options = options.Value;

    public async Task InvokeAsync(HttpContext context)
    {
        if (_options.EnableSecurityHeaders)
        {
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            context.Response.Headers["Permissions-Policy"] =
                "camera=(), microphone=(), geolocation=()";

            if (_options.RequireHttps)
                context.Response.Headers["Strict-Transport-Security"] =
                    "max-age=31536000; includeSubDomains";
        }

        await next(context);
    }
}
