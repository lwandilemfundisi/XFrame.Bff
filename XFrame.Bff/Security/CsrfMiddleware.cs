using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using XFrame.Bff.Options;

namespace XFrame.Bff.Security;

public sealed class CsrfMiddleware(
    RequestDelegate next,
    IAntiforgery antiforgery,
    IOptions<XFrameBffOptions> options)
{
    private readonly XFrameBffOptions _options = options.Value;

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_options.EnableAntiforgery ||
            !context.Request.Path.StartsWithSegments(_options.ApiPathPrefix) ||
            !IsUnsafe(context.Request.Method))
        {
            await next(context);
            return;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid CSRF token.");
            return;
        }

        await next(context);
    }

    private static bool IsUnsafe(string method) =>
        HttpMethods.IsPost(method) || HttpMethods.IsPut(method) ||
        HttpMethods.IsPatch(method) || HttpMethods.IsDelete(method);
}
