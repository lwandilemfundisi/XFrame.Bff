namespace XFrame.Bff.Models;

public sealed record BffUser(
    bool Authenticated,
    string Subject,
    string? Username,
    string? DisplayName,
    string? Email,
    IReadOnlyDictionary<string,string[]> Claims);
