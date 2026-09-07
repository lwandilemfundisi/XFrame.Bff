using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using XFrame.Bff.Authentication;
using XFrame.Bff.Endpoints;
using XFrame.Bff.Options;
using XFrame.Bff.Security;
using XFrame.Bff.Session;
using XFrame.Bff.Tokens;
using Yarp.ReverseProxy.Configuration;

namespace XFrame.Bff.Extensions;

public static class XFrameBffServiceCollectionExtensions
{
    public static IServiceCollection AddXFrameBff(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<XFrameBffOptions>? configure = null)
    {
        services.Configure<XFrameBffOptions>(
            configuration.GetSection(XFrameBffOptions.SectionName));

        services.Configure<KeycloakOptions>(
            configuration.GetSection(KeycloakOptions.SectionName));

        services.Configure<RedisOptions>(
            configuration.GetSection(RedisOptions.SectionName));

        services.Configure<FrontendOptions>(
            configuration.GetSection(FrontendOptions.SectionName));

        if (configure is not null)
            services.Configure(configure);

        services.AddOptions<XFrameBffOptions>()
            .Validate(x => Uri.TryCreate(x.ApiBaseAddress, UriKind.Absolute, out _),
                "ApiBaseAddress must be an absolute URI.")
            .ValidateOnStart();

        services.AddOptions<KeycloakOptions>()
            .Validate(x => Uri.TryCreate(x.Authority, UriKind.Absolute, out _),
                "Keycloak Authority must be an absolute URI.")
            .Validate(x => !string.IsNullOrWhiteSpace(x.ClientId), "ClientId is required.")
            .Validate(x => !string.IsNullOrWhiteSpace(x.ClientSecret), "ClientSecret is required.")
            .ValidateOnStart();

        services.AddOptions<RedisOptions>()
            .Validate(x => !string.IsNullOrWhiteSpace(x.ConnectionString),
                "Redis ConnectionString is required.")
            .ValidateOnStart();

        var redis = configuration.GetSection(RedisOptions.SectionName).Get<RedisOptions>()
            ?? throw new InvalidOperationException("XFrameBff:Redis configuration is missing.");

        services.AddStackExchangeRedisCache(x =>
        {
            x.Configuration = redis.ConnectionString;
            x.InstanceName = redis.InstanceName;
        });

        services.AddHttpClient("xframe-keycloak");

        services.AddSingleton<ISessionStore, RedisSessionStore>();
        services.AddSingleton<ISessionManager, BffSessionManager>();
        services.AddScoped<ITokenService, KeycloakTokenService>();

        var kc = configuration.GetSection(KeycloakOptions.SectionName).Get<KeycloakOptions>()
            ?? throw new InvalidOperationException("XFrameBff:Keycloak configuration is missing.");

        var bff = configuration.GetSection(XFrameBffOptions.SectionName).Get<XFrameBffOptions>()
            ?? throw new InvalidOperationException("XFrameBff configuration is missing.");

        services.AddAuthentication(x =>
        {
            x.DefaultAuthenticateScheme = "xframe-cookie";
            x.DefaultSignInScheme = "xframe-cookie";
            x.DefaultChallengeScheme = "xframe-oidc";
        })
        .AddCookie("xframe-cookie", x =>
        {
            x.Cookie.Name = bff.SessionCookieName;
            x.Cookie.HttpOnly = true;
            x.Cookie.SecurePolicy = bff.RequireHttps
                ? CookieSecurePolicy.Always
                : CookieSecurePolicy.SameAsRequest;
            x.Cookie.SameSite = SameSiteMode.Lax;
            x.Cookie.Path = "/";
            x.ExpireTimeSpan = bff.SessionLifetime;
            x.SlidingExpiration = false;
            x.EventsType = typeof(BffCookieEvents);

            x.Events.OnRedirectToLogin = ctx =>
            {
                if (ctx.Request.Path.StartsWithSegments(bff.ApiPathPrefix))
                {
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                }

                ctx.Response.Redirect(bff.LoginPath);
                return Task.CompletedTask;
            };

            x.Events.OnRedirectToAccessDenied = ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        })
        .AddOpenIdConnect("xframe-oidc", x =>
        {
            x.Authority = kc.Authority;
            x.ClientId = kc.ClientId;
            x.ClientSecret = kc.ClientSecret;
            x.RequireHttpsMetadata = kc.RequireHttpsMetadata;
            x.ResponseType = "code";
            x.UsePkce = true;
            x.DisableTelemetry = true;
            x.SaveTokens = true;
            x.GetClaimsFromUserInfoEndpoint = true;

            x.Scope.Clear();
            foreach (var scope in kc.Scopes)
                x.Scope.Add(scope);

            x.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "preferred_username"
            };

            x.Events.OnTicketReceived = BffAuthenticationEvents.ConfigureTicketReceived;
        });

        services.AddScoped<BffCookieEvents>();

        services.AddAuthorization(options => options.AddPolicy("xframe-authenticated", p => p.RequireAuthenticatedUser()));

        services.AddAntiforgery(x =>
        {
            x.Cookie.Name = "__Host-XFrameCSRF";
            x.Cookie.HttpOnly = false;
            x.Cookie.SecurePolicy = bff.RequireHttps
                ? CookieSecurePolicy.Always
                : CookieSecurePolicy.SameAsRequest;
            x.Cookie.SameSite = SameSiteMode.Strict;
            x.HeaderName = "X-XFrame-CSRF";
        });

        services.AddReverseProxy().LoadFromMemory(
            [
                new RouteConfig
                {
                    RouteId = "xframe-api",
                    ClusterId = "xframe-api-cluster",
                    Match = new RouteMatch { Path = $"{bff.ApiPathPrefix}/{{**catch-all}}" },
                    AuthorizationPolicy = "xframe-authenticated",
                    Transforms = [new Dictionary<string,string> { ["RequestHeaderRemove"] = "Cookie" }]
                }
            ],
            [
                new ClusterConfig
                {
                    ClusterId = "xframe-api-cluster",
                    Destinations = new Dictionary<string, DestinationConfig>
                    {
                        ["api"] = new() { Address = bff.ApiBaseAddress.TrimEnd('/') + "/" }
                    }
                }
            ]);

        return services;
    }

    public static IApplicationBuilder UseXFrameBff(
        this WebApplication app)
    {
        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseMiddleware<CsrfMiddleware>();

        app.MapXFrameBffEndpoints();

        app.MapReverseProxy(proxyPipeline =>
        {
            proxyPipeline.Use(async (context, next) =>
            {
                var sessions = context.RequestServices.GetRequiredService<ISessionManager>();
                var tokens = context.RequestServices.GetRequiredService<ITokenService>();
                var session = await sessions.GetAsync(context, context.RequestAborted);

                if (session is null)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }

                var accessToken = await tokens.GetAccessTokenAsync(session, context.RequestAborted);

                if (accessToken is null)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }

                context.Request.Headers.Authorization = $"Bearer {accessToken}";
                await next();
            });
        });

        return app;
    }
}
