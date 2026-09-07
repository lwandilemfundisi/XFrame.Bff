using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;
using XFrame.Bff.Session;

namespace XFrame.Bff.Authentication;

public static class BffAuthenticationEvents
{
    public static Task ConfigureTicketReceived(
        TicketReceivedContext context)
    {
        var manager = context.HttpContext.RequestServices.GetRequiredService<ISessionManager>();

        return CreateSession(context, manager);
    }

    private static async Task CreateSession(
        TicketReceivedContext context,
        ISessionManager manager)
    {
        var session = await manager.CreateAsync(
            context.Principal!,
            context.Properties!,
            context.HttpContext.RequestAborted);

        var identity = new ClaimsIdentity("xframe-cookie");
        identity.AddClaim(new Claim("sub", session.Subject));
        identity.AddClaim(new Claim(
            BffSessionManager.SessionClaimType,
            session.SessionId));

        if (session.Username is not null)
            identity.AddClaim(new Claim("preferred_username", session.Username));

        if (session.Email is not null)
            identity.AddClaim(new Claim("email", session.Email));

        context.Principal = new ClaimsPrincipal(identity);

        // Critical: tokens must never be serialized into the browser cookie.
        context.Properties!.StoreTokens([]);

        context.Properties!.IsPersistent = false;
        context.Properties!.AllowRefresh = false;
    }
}
