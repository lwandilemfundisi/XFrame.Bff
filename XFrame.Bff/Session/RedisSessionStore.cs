using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using System.Text.Json;
using XFrame.Bff.Models;
using XFrame.Bff.Options;

namespace XFrame.Bff.Session;

public sealed class RedisSessionStore(
    IDistributedCache cache,
    IOptions<RedisOptions> options) : ISessionStore
{
    private readonly string _prefix = options.Value.InstanceName;

    private string Key(string id) => $"{_prefix}session:{id}";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public Task CreateAsync(BffSession session, TimeSpan lifetime, CancellationToken ct = default) =>
        WriteAsync(session, lifetime, ct);

    public async Task<BffSession?> GetAsync(string sessionId, CancellationToken ct = default)
    {
        var bytes = await cache.GetAsync(Key(sessionId), ct);
        return bytes is null ? null : JsonSerializer.Deserialize<BffSession>(bytes, JsonOptions);
    }

    public Task UpdateAsync(BffSession session, TimeSpan lifetime, CancellationToken ct = default) =>
        WriteAsync(session, lifetime, ct);

    public Task DeleteAsync(string sessionId, CancellationToken ct = default) =>
        cache.RemoveAsync(Key(sessionId), ct);

    private Task WriteAsync(BffSession session, TimeSpan lifetime, CancellationToken ct) =>
        cache.SetAsync(
            Key(session.SessionId),
            JsonSerializer.SerializeToUtf8Bytes(session, JsonOptions),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = lifetime },
            ct);
}
