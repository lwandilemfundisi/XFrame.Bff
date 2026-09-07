using XFrame.Bff.Models;
namespace XFrame.Bff.Tokens;
public interface ITokenService
{
    Task<string?> GetAccessTokenAsync(BffSession session, CancellationToken ct = default);
    Task RevokeAsync(BffSession session, CancellationToken ct = default);
}
