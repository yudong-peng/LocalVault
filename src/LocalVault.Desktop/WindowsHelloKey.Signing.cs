using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace LocalVault.Desktop;

internal sealed partial class WindowsHelloKey
{
    public PreparedHelloProtection PrepareProtection(string name)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        return new PreparedHelloProtection(DeriveSigningKey(name, challenge), challenge);
    }

    private byte[] DecryptSignedEnvelope(string name, byte[] envelope)
    {
        var challenge = HelloSignatureEnvelope.Challenge(envelope);
        var key = DeriveSigningKey(name, challenge);
        try { return HelloSignatureEnvelope.Open(envelope, key); }
        catch (Exception error) { throw HelloOperationException.Capture(HelloStage.DecryptEnvelope, error); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private byte[] DeriveSigningKey(string name, byte[] challenge)
    {
        using var key = Open(name, CngKeyUsages.Signing);
        RequireFreshGesture(key); AssertSilentSigningDenied(key, challenge); RequireFreshGesture(key);
        var signature = new byte[256];
        try
        {
            var hash = HelloSignatureEnvelope.SignatureHash(challenge);
            var padding = new SignaturePaddingInfo { Algorithm = "SHA256" };
            using var handle = key.Handle;
            NativeCheck(NCryptSignHash(handle, ref padding, hash, hash.Length, signature, signature.Length,
                out var written, 0x2), HelloStage.Sign); // PKCS#1 signature padding; NOT RSA encryption
            if (written != signature.Length) throw new HelloOperationException(HelloStage.Sign, unchecked((int)0xA0050001));
            using var rsa = new RSACng(key);
            return HelloSignatureEnvelope.VerifyAndDerive(signature, challenge, HelloPublicKeyProtector.ReadPublicKey(rsa));
        }
        finally { CryptographicOperations.ZeroMemory(signature); }
    }

    private static void AssertSilentSigningDenied(CngKey key, byte[] challenge)
    {
        var buffer = new byte[256];
        try
        {
            var hash = HelloSignatureEnvelope.SignatureHash(challenge);
            var padding = new SignaturePaddingInfo { Algorithm = "SHA256" };
            using var handle = key.Handle;
            var status = NCryptSignHash(handle, ref padding, hash, hash.Length, buffer, buffer.Length,
                out _, 0x2 | 0x40); // PKCS#1 SHA-256 signature + NCRYPT_SILENT_FLAG; real output buffer
            HelloSignatureEnvelope.AssertSilentSigningDenied(status);
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SignaturePaddingInfo
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Algorithm;
    }

    [DllImport("ncrypt.dll", ExactSpelling = true)]
    private static extern int NCryptSignHash(SafeNCryptKeyHandle key, ref SignaturePaddingInfo padding,
        byte[] hash, int hashLength, [Out] byte[] signature, int signatureLength, out int written, int flags);
}
