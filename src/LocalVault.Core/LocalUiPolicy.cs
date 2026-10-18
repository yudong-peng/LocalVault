namespace LocalVault.Core;

public static class LocalUiPolicy
{
    public const string Origin = "https://localvault.invalid";
    public const string Page = Origin + "/index.html";
    public static bool IsTrustedPage(string? address) => IsLocal(address, out var uri) && uri!.AbsolutePath == "/index.html";
    public static bool IsLocalResource(string? address) => IsLocal(address, out var uri) &&
        uri!.AbsolutePath is "/index.html" or "/style.css" or "/app.js" or "/app-icon.png";
    private static bool IsLocal(string? address, out Uri? uri)
    {
        return Uri.TryCreate(address, UriKind.Absolute, out uri) && uri.Scheme == "https" &&
            uri.Host.Equals("localvault.invalid", StringComparison.OrdinalIgnoreCase) && uri.IsDefaultPort &&
            uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0;
    }
}
