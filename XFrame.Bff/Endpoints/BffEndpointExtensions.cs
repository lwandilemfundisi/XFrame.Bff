using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
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
        IOptions<XFrameBffOptions> options)
    {
        var returnUrl = SafeReturnUrl(context.Request.Query["returnUrl"].ToString());

        await context.ChallengeAsync(
            "xframe-oidc",
            new AuthenticationProperties { RedirectUri = returnUrl });

        return Results.Empty;
    }

    private static async Task<IResult> Logout(
        HttpContext context,
        ISessionManager sessions,
        ITokenService tokens,
        IAntiforgery antiforgery,
        IOptions<KeycloakOptions> keycloak)
    {
        try { await antiforgery.ValidateRequestAsync(context); }
        catch (AntiforgeryValidationException) { return Results.BadRequest("Invalid CSRF token."); }

        var session = await sessions.GetAsync(context, context.RequestAborted);

        if (session is not null)
        {
            try { await tokens.RevokeAsync(session, context.RequestAborted); }
            catch { /* local logout still proceeds */ }

            await sessions.DeleteAsync(context, context.RequestAborted);
        }

        await context.SignOutAsync("xframe-cookie");

        var kc = keycloak.Value;
        var logout = $"{kc.Authority.TrimEnd('/')}/protocol/openid-connect/logout";
        if (session?.IdToken is not null)
        {
            logout += "?id_token_hint=" + Uri.EscapeDataString(session.IdToken) +
                      "&post_logout_redirect_uri=" + Uri.EscapeDataString("https://localhost/") +
                      "&client_id=" + Uri.EscapeDataString(kc.ClientId);
        }

        return Results.Redirect(logout);
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
