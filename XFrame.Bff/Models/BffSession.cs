namespace XFrame.Bff.Models;

public sealed class BffSession
{
    public required string SessionId { get; init; }
    public required string Subject { get; init; }
    public string? Username { get; init; }
    public string? DisplayName { get; init; }
    public string? Email { get; init; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public string? IdToken { get; set; }
    public DateTimeOffset AccessTokenExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset LastSeenAt { get; set; }
    public Dictionary<string,string[]> Claims { get; init; } = new(StringComparer.Ordinal);
}
