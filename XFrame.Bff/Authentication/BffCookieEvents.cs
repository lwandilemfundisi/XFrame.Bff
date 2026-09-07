using Microsoft.AspNetCore.Authentication.Cookies;
using XFrame.Bff.Session;

namespace XFrame.Bff.Authentication;

public sealed class BffCookieEvents(ISessionManager sessions) : CookieAuthenticationEvents
{
    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        var sessionId = context.Principal?.FindFirst(BffSessionManager.SessionClaimType)?.Value;

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            context.RejectPrincipal();
            return;
        }

        var session = await sessions.GetByIdAsync(sessionId, context.HttpContext.RequestAborted);
        if (session is null)
            context.RejectPrincipal();
    }
}
