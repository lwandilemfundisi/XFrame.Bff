using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;
using XFrame.Bff.Models;
using XFrame.Bff.Options;

namespace XFrame.Bff.Session;

public sealed class BffSessionManager(
    ISessionStore store,
    IOptions<XFrameBffOptions> options) : ISessionManager
{
    private readonly XFrameBffOptions _options = options.Value;

    public async Task<BffSession> CreateAsync(
        ClaimsPrincipal principal,
        AuthenticationProperties properties,
        CancellationToken ct = default)
    {
        var subject = principal.FindFirstValue("sub")
            ?? throw new InvalidOperationException("Keycloak did not return a subject.");

        var claims = principal.Claims
            .GroupBy(c => c.Type, StringComparer.Ordinal)
            .ToDictionary(
                g => g.Key,
                g => g.Select(x => x.Value).Distinct(StringComparer.Ordinal).ToArray(),
                StringComparer.Ordinal);

        var expires = DateTimeOffset.UtcNow.AddMinutes(5);
        var expiresAt = properties.GetTokenValue("expires_at");
        if (DateTimeOffset.TryParse(expiresAt, out var parsed))
            expires = parsed;

        var session = new BffSession
        {
            SessionId = GenerateId(),
            Subject = subject,
            Username = principal.FindFirstValue("preferred_username"),
            DisplayName = principal.FindFirstValue("name"),
            Email = principal.FindFirstValue("email"),
            AccessToken = properties.GetTokenValue("access_token"),
            RefreshToken = properties.GetTokenValue("refresh_token"),
            IdToken = properties.GetTokenValue("id_token"),
            AccessTokenExpiresAt = expires,
            CreatedAt = DateTimeOffset.UtcNow,
            LastSeenAt = DateTimeOffset.UtcNow,
            Claims = claims
        };

        await store.CreateAsync(session, _options.SessionLifetime, ct);
        return session;
    }

    public async Task<BffSession?> GetAsync(HttpContext context, CancellationToken ct = default)
    {
        var sessionId = context.User.FindFirstValue(SessionClaimType);
        if (string.IsNullOrWhiteSpace(sessionId))
            return null;

        var session = await store.GetAsync(sessionId, ct);
        if (session is null)
            return null;

        session.LastSeenAt = DateTimeOffset.UtcNow;
        await store.UpdateAsync(session, _options.SessionLifetime, ct);
        return session;
    }

    public Task<BffSession?> GetByIdAsync(string sessionId, CancellationToken ct = default) =>
        store.GetAsync(sessionId, ct);

    public async Task DeleteAsync(HttpContext context, CancellationToken ct = default)
    {
        var sessionId = context.User.FindFirstValue(SessionClaimType);
        if (!string.IsNullOrWhiteSpace(sessionId))
            await store.DeleteAsync(sessionId, ct);

        context.Response.Cookies.Delete(_options.SessionCookieName, new CookieOptions
        {
            Path = "/",
            Secure = _options.RequireHttps,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax
        });
    }

    public const string SessionClaimType = "xframe_session_id";

    private static string GenerateId()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
