namespace XFrame.Bff.Options;

public sealed class RedisOptions
{
    public const string SectionName = "XFrameBff:Redis";
    public required string ConnectionString { get; set; }
    public string InstanceName { get; set; } = "xframe:bff:";
}
