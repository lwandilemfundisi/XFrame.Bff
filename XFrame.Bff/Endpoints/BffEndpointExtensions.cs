using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using XFrame.Bff.Models;
using XFrame.Bff.Options;
using XFrame.Bff.Session;
using XFrame.Bff.Tokens;

namespace XFrame.Bff.Endpoints;

public static class BffEndpointExtensions
{
    public static IEndpointRouteBuilder MapXFrameBffEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        var options = endpoints.ServiceProvider
            .GetRequiredService<IOptions<XFrameBffOptions>>().Value;

        endpoints.MapGet(options.LoginPath, Login).AllowAnonymous();
        endpoints.MapPost(options.LogoutPath, Logout).RequireAuthorization();
        endpoints.MapGet(options.UserPath, User).RequireAuthorization();
        endpoints.MapGet(options.AntiforgeryPath, Antiforgery).RequireAuthorization();

        return endpoints;
    }

    private static async Task<IResult> Login(
        HttpContext context,
        IOptions<XFrameBffOptions> options,
        IOptions<FrontendOptions> frontendOptions)
    {
        var returnUrl = SafeReturnUrl(context.Request.Query["returnUrl"].ToString());

        Console.WriteLine($"Redirecting to login with return URL: {frontendOptions.Value.BaseUrl + returnUrl}");

        await context.ChallengeAsync(
            "xframe-oidc",
            new AuthenticationProperties { RedirectUri = frontendOptions.Value.BaseUrl + returnUrl });

        return Results.Empty;
    }

    public static async Task<IResult> Logout(
    HttpContext context,
    ISessionManager sessionManager,
    ITokenService tokenService,
    IAntiforgery antiforgery,
    IOptions<FrontendOptions> frontendOptions)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.BadRequest("Invalid CSRF token.");
        }

        var returnUrl = context.Request.Query["returnUrl"].ToString();
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = "/";
        }

        var session = await sessionManager.GetAsync(context, context.RequestAborted);
        if (session is not null)
        {
            try
            {
                await tokenService.RevokeAsync(session, context.RequestAborted);
            }
            catch
            {
                /* Selectively log or handle token revocation failure gracefully */
            }

            await sessionManager.DeleteAsync(context);
        }

        var props = new AuthenticationProperties
        {
            RedirectUri = frontendOptions.Value.BaseUrl + returnUrl
        };

        return Results.SignOut(
            properties: props,
            authenticationSchemes: new[]
            {
                "xframe-cookie", 
                "xframe-oidc" 
            }
        );
    }


    private static async Task<IResult> User(
        HttpContext context,
        ISessionManager sessions)
    {
        var session = await sessions.GetAsync(context, context.RequestAborted);
        if (session is null)
            return Results.Unauthorized();

        return Results.Ok(new BffUser(
            true,
            session.Subject,
            session.Username,
            session.DisplayName,
            session.Email,
            session.Claims));
    }

    private static async Task<IResult> Antiforgery(
        HttpContext context,
        IAntiforgery antiforgery)
    {
        var tokens = antiforgery.GetAndStoreTokens(context);
        return Results.Ok(new { token = tokens.RequestToken });
    }

    private static string SafeReturnUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "/";

        if (Uri.TryCreate(value, UriKind.Relative, out var uri) &&
            !uri.OriginalString.StartsWith("//", StringComparison.Ordinal))
            return uri.OriginalString;

        return "/";
    }
}
