using Microsoft.Extensions.Options;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using XFrame.Bff.Models;
using XFrame.Bff.Options;
using XFrame.Bff.Session;

namespace XFrame.Bff.Tokens;

public sealed class KeycloakTokenService(
    IHttpClientFactory clients,
    ISessionStore store,
    IOptions<KeycloakOptions> keycloak,
    IOptions<XFrameBffOptions> bff) : ITokenService
{
    private readonly KeycloakOptions _kc = keycloak.Value;
    private readonly XFrameBffOptions _bff = bff.Value;

    private string Endpoint(string path) =>
        $"{_kc.Authority.TrimEnd('/')}/protocol/openid-connect/{path}";

    public async Task<string?> GetAccessTokenAsync(BffSession session, CancellationToken ct = default)
    {
        if (!string.IsNullOrWhiteSpace(session.AccessToken) &&
            session.AccessTokenExpiresAt > DateTimeOffset.UtcNow.Add(_bff.AccessTokenRefreshSkew))
            return session.AccessToken;

        if (string.IsNullOrWhiteSpace(session.RefreshToken))
            return null;

        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint("token"))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string,string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = _kc.ClientId,
                ["client_secret"] = _kc.ClientSecret,
                ["refresh_token"] = session.RefreshToken
            })
        };

        using var response = await clients.CreateClient("xframe-keycloak")
            .SendAsync(request, ct);

        if (!response.IsSuccessStatusCode)
        {
            await store.DeleteAsync(session.SessionId, ct);
            return null;
        }

        var token = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct);
        if (token?.AccessToken is null)
            return null;

        session.AccessToken = token.AccessToken;
        session.AccessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn);
        if (!string.IsNullOrWhiteSpace(token.RefreshToken))
            session.RefreshToken = token.RefreshToken;

        await store.UpdateAsync(session, _bff.SessionLifetime, ct);
        return session.AccessToken;
    }

    public async Task RevokeAsync(BffSession session, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.RefreshToken))
            return;

        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint("revoke"))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string,string>
            {
                ["client_id"] = _kc.ClientId,
                ["client_secret"] = _kc.ClientSecret,
                ["token"] = session.RefreshToken,
                ["token_type_hint"] = "refresh_token"
            })
        };

        await clients.CreateClient("xframe-keycloak").SendAsync(request, ct);
    }

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);
}
