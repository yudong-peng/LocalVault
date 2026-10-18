using System.Security.Cryptography;
using System.Text;

namespace LocalVault.Core;

// The binding is INSIDE the encrypted envelope. Editing a public sidecar fingerprint
// cannot reuse a key slot after master-password change, restore or another vault.
internal static class DeviceUnlockPayload
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("LocalVaultHello3\0");
    public static byte[] Create(byte[] key, string header)
    {
        if (key.Length != 32) throw new CryptographicException();
        var payload = new byte[Magic.Length + 32 + 32];
        Magic.CopyTo(payload, 0);
        SHA256.HashData(Encoding.UTF8.GetBytes(header)).CopyTo(payload, Magic.Length);
        key.CopyTo(payload, Magic.Length + 32);
        return payload;
    }
    public static byte[] ExtractKey(byte[] payload, string header)
    {
        var fingerprint = SHA256.HashData(Encoding.UTF8.GetBytes(header));
        if (payload.Length != Magic.Length + 64 ||
            !CryptographicOperations.FixedTimeEquals(payload.AsSpan(0, Magic.Length), Magic) ||
            !CryptographicOperations.FixedTimeEquals(payload.AsSpan(Magic.Length, 32), fingerprint))
            throw new CryptographicException("设备解锁凭据已失效。");
        return payload.AsSpan(Magic.Length + 32, 32).ToArray();
    }
}
