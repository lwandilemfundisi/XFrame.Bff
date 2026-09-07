namespace XFrame.Bff.Options;

public sealed class KeycloakOptions
{
    public const string SectionName = "XFrameBff:Keycloak";
    public required string Authority { get; set; }
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public bool RequireHttpsMetadata { get; set; } = true;
    public string[] Scopes { get; set; } = ["openid", "profile", "email", "offline_access"];
}
