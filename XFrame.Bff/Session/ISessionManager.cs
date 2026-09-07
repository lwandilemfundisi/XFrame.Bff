using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using XFrame.Bff.Models;
namespace XFrame.Bff.Session;
public interface ISessionManager
{
    Task<BffSession> CreateAsync(
        ClaimsPrincipal principal,
        AuthenticationProperties properties,
        CancellationToken ct = default);
    Task<BffSession?> GetAsync(HttpContext context, CancellationToken ct = default);
    Task DeleteAsync(HttpContext context, CancellationToken ct = default);
    Task<BffSession?> GetByIdAsync(string sessionId, CancellationToken ct = default);
}
