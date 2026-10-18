using System.Security.Cryptography;
using System.Text;

namespace LocalVault.Desktop;

// This dedicated, deterministic signature is SECRET wrapping material. Never store,
// log, transmit or reuse it for network authentication. The public challenge is scoped
// to one randomly named application key and this versioned protocol.
internal static class HelloSignatureEnvelope
{
    private static ReadOnlySpan<byte> Magic => "LVHSIG02"u8;
    private static readonly byte[] Domain = Encoding.UTF8.GetBytes("LocalVault/Hello/signature-wrap/v2");
    // Core DeviceUnlockPayload: 17-byte marker + 32-byte header hash + 32-byte data key.
    internal const int PayloadLength = 81;
    internal const int EnvelopeLength = 8 + 32 + 12 + 16 + PayloadLength;

    internal static byte[] SignatureHash(byte[] challenge)
    {
        if (challenge.Length != 32) throw new CryptographicException();
        var message = new byte[Domain.Length + 32];
        Domain.CopyTo(message, 0); challenge.CopyTo(message, Domain.Length);
        return SHA256.HashData(message);
    }

    internal static byte[] VerifyAndDerive(byte[] signature, byte[] challenge, RSAParameters publicKey)
    {
        try
        {
            if (signature.Length != 256 || publicKey.Modulus is not { Length: 256 } ||
                publicKey.D is not null || publicKey.P is not null || publicKey.Q is not null ||
                publicKey.DP is not null || publicKey.DQ is not null || publicKey.InverseQ is not null)
                throw new CryptographicException();
            using var verifier = RSA.Create(); verifier.ImportParameters(publicKey);
            if (!verifier.VerifyHash(SignatureHash(challenge), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                throw new CryptographicException();
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, signature, 32, challenge, Domain);
        }
        catch (Exception error) { throw HelloOperationException.Capture(HelloStage.VerifySignature, error); }
    }

    internal static byte[] Challenge(byte[] envelope)
    {
        if (envelope.Length != EnvelopeLength || !envelope.AsSpan(0, 8).SequenceEqual(Magic))
            throw new CryptographicException();
        return envelope.AsSpan(8, 32).ToArray();
    }

    internal static byte[] Seal(byte[] payload, byte[] key, byte[] challenge)
    {
        if (payload.Length != PayloadLength || key.Length != 32 || challenge.Length != 32)
            throw new CryptographicException();
        var result = new byte[EnvelopeLength];
        Magic.CopyTo(result); challenge.CopyTo(result, 8);
        RandomNumberGenerator.Fill(result.AsSpan(40, 12));
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(result.AsSpan(40, 12), payload, result.AsSpan(68, PayloadLength), result.AsSpan(52, 16), result.AsSpan(0, 40));
        return result;
    }

    internal static byte[] Open(byte[] envelope, byte[] key)
    {
        _ = Challenge(envelope);
        if (key.Length != 32) throw new CryptographicException();
        var result = new byte[PayloadLength];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(envelope.AsSpan(40, 12), envelope.AsSpan(68, PayloadLength), envelope.AsSpan(52, 16), result, envelope.AsSpan(0, 40));
            return result;
        }
        catch { CryptographicOperations.ZeroMemory(result); throw; }
    }

    internal static void AssertSilentSigningDenied(int status)
    {
        if (status == 0) throw new HelloOperationException(HelloStage.SilentSignCheck, unchecked((int)0xA0040003));
        if (status != unchecked((int)0x80090022)) throw new HelloOperationException(HelloStage.SilentSignCheck, status);
    }
}

internal sealed class PreparedHelloProtection(byte[] key, byte[] challenge) : IDisposable
{
    private bool disposed;
    internal byte[] Protect(byte[] payload)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        try { return HelloSignatureEnvelope.Seal(payload, key, challenge); }
        catch (Exception error) { throw HelloOperationException.Capture(HelloStage.Encrypt, error); }
    }
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(key);
        disposed = true;
    }
}
