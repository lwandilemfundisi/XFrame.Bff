namespace XFrame.Bff.Options;

public sealed class XFrameBffOptions
{
    public const string SectionName = "XFrameBff";
    public string SessionCookieName { get; set; } = "__Host-XFrameSession";
    public string LoginPath { get; set; } = "/bff/login";
    public string LogoutPath { get; set; } = "/bff/logout";
    public string UserPath { get; set; } = "/bff/user";
    public string AntiforgeryPath { get; set; } = "/bff/antiforgery";
    public string ApiPathPrefix { get; set; } = "/api";
    public required string ApiBaseAddress { get; set; }
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(8);
    public TimeSpan AccessTokenRefreshSkew { get; set; } = TimeSpan.FromMinutes(1);
    public bool RequireHttps { get; set; } = true;
    public bool EnableSecurityHeaders { get; set; } = true;
    public bool EnableAntiforgery { get; set; } = true;
    public string CookieSameSite { get; set; } = "Lax";
    public bool AllowApiRedirects { get; set; } = false;
}
