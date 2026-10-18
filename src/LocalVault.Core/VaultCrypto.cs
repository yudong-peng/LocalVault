using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;

namespace LocalVault.Core;

internal static class VaultCrypto
{
    private const int Memory = 65536, Iterations = 3, Parallelism = 2;
    public static void CheckNewPassword(string password)
    {
        if (password.Length is < 12 or > 1024)
            throw new ArgumentException("主密码应为 12～1024 个字符，建议使用容易记忆的长口令。");
    }

    private static byte[] Derive(string password, VaultHeader h)
    {
        // All reader versions accept one bounded configuration, so hostile backup headers
        // cannot request unbounded memory or CPU. New KDF policies require a format migration.
        if (h.Version is not (1 or 2 or 3 or 4) || h.VaultId == Guid.Empty || h.Kdf != "Argon2id" || h.MemoryKiB != Memory ||
            h.Iterations != Iterations || h.Parallelism != Parallelism || h.Salt is not { Length: 16 } ||
            password.Length > 1024)
            throw new InvalidDataException("不支持的保险库格式或密钥参数。");
        var bytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var kdf = new Argon2id(bytes)
            { Salt = h.Salt, MemorySize = h.MemoryKiB, Iterations = h.Iterations, DegreeOfParallelism = h.Parallelism };
            return kdf.GetBytes(32);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    // Crypto suite stays v1; header Version is the minimum reader capability.
    // Keeping this AAD stable lets a session migrate without retaining the master password.
    private static byte[] KeyAad(VaultHeader h) => Encoding.UTF8.GetBytes($"LocalVault/v1/key/{h.VaultId:D}");
    public static VaultHeader Wrap(string password, byte[] dataKey, Guid? vaultId = null)
    {
        CheckNewPassword(password);
        var h = new VaultHeader(4, vaultId ?? Guid.NewGuid(), "Argon2id", Memory, Iterations, Parallelism,
            RandomNumberGenerator.GetBytes(16), new SealedBlob([], [], []));
        var kek = Derive(password, h);
        try { return h with { WrappedKey = Seal(dataKey, kek, KeyAad(h)) }; }
        finally { CryptographicOperations.ZeroMemory(kek); }
    }

    public static byte[] Unwrap(string password, VaultHeader h)
    {
        var kek = Derive(password, h);
        try
        {
            var key = Open(h.WrappedKey, kek, KeyAad(h));
            if (key.Length != 32) { CryptographicOperations.ZeroMemory(key); throw new InvalidDataException(); }
            return key;
        }
        finally { CryptographicOperations.ZeroMemory(kek); }
    }

    public static SealedBlob Seal(byte[] plain, byte[] key, byte[] aad)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plain.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plain, ciphertext, tag, aad);
        return new(nonce, ciphertext, tag);
    }

    public static byte[] Open(SealedBlob blob, byte[] key, byte[] aad)
    {
        if (blob is null || blob.Nonce is not { Length: 12 } || blob.Tag is not { Length: 16 } ||
            blob.Ciphertext is null || blob.Ciphertext.Length > VaultStore.MaxBytes)
            throw new InvalidDataException("加密数据格式无效。");
        var result = new byte[blob.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(blob.Nonce, blob.Ciphertext, blob.Tag, result, aad);
            return result;
        }
        catch { CryptographicOperations.ZeroMemory(result); throw; }
    }

    public static byte[] EncodeData(VaultData data) => JsonSerializer.SerializeToUtf8Bytes(data);
}
