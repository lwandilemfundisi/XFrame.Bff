using Yarp.ReverseProxy.Transforms;

namespace XFrame.Bff.Proxy;

public sealed class BffProxyTransform : RequestTransform
{
    public override ValueTask ApplyAsync(
        RequestTransformContext context)
    {
        context.ProxyRequest.Headers.Remove("Cookie");
        context.ProxyRequest.Headers.Remove("Authorization");
        return ValueTask.CompletedTask;
    }
}
