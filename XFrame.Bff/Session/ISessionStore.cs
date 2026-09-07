using XFrame.Bff.Models;
namespace XFrame.Bff.Session;
public interface ISessionStore
{
    Task CreateAsync(BffSession session, TimeSpan lifetime, CancellationToken ct = default);
    Task<BffSession?> GetAsync(string sessionId, CancellationToken ct = default);
    Task UpdateAsync(BffSession session, TimeSpan lifetime, CancellationToken ct = default);
    Task DeleteAsync(string sessionId, CancellationToken ct = default);
}
