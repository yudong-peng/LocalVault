using System.Security.Cryptography;
using LocalVault.Core;
using LocalVault.Desktop;

internal static class HelloSignatureChecks
{
    public static void Run(string root, Action<bool,string> check, Action<Action,string> reject)
    {
        using var rsa = RSA.Create(2048);
        using var publicExportOnly = new PublicExportOnlyKey(rsa);
        var publicKey = HelloPublicKeyProtector.ReadPublicKey(publicExportOnly);
        check(publicExportOnly.PublicExports == 1 && publicExportOnly.PrivateExports == 0, "Hello verification exports public parameters only");
        var challenge = RandomNumberGenerator.GetBytes(32);
        var signature = rsa.SignHash(HelloSignatureEnvelope.SignatureHash(challenge), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var key = HelloSignatureEnvelope.VerifyAndDerive(signature, challenge, publicKey);
        try
        {
            var nextSignature = rsa.SignHash(HelloSignatureEnvelope.SignatureHash(challenge), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var nextKey = HelloSignatureEnvelope.VerifyAndDerive(nextSignature, challenge, publicKey);
            try { check(nextSignature.SequenceEqual(signature) && nextKey.SequenceEqual(key), "deterministic SHA-256 signatures reproduce wrapping keys without persistence"); }
            finally { CryptographicOperations.ZeroMemory(nextSignature); CryptographicOperations.ZeroMemory(nextKey); }
            var payload = RandomNumberGenerator.GetBytes(HelloSignatureEnvelope.PayloadLength);
            try
            {
                var envelope = HelloSignatureEnvelope.Seal(payload, key, challenge);
                var recovered = HelloSignatureEnvelope.Open(envelope, key);
                try { check(recovered.SequenceEqual(payload) && envelope.Length == HelloSignatureEnvelope.EnvelopeLength, "signature-derived AES-256-GCM envelope preserves complete device payload"); }
                finally { CryptographicOperations.ZeroMemory(recovered); }
                check(HelloSignatureEnvelope.Challenge(envelope).SequenceEqual(challenge), "device envelope retains its public challenge");
                check(!Contains(envelope, signature) && !Contains(envelope, key) && !Contains(envelope, payload), "serialized envelope contains no signature, wrapping key or plaintext");
                check(!HelloSignatureEnvelope.Seal(payload, key, challenge).SequenceEqual(envelope), "each credential envelope has a fresh GCM nonce");
                foreach (var index in new[] { 8, 40, 52, 68 })
                {
                    var modified = envelope.ToArray(); modified[index] ^= 1;
                    reject(() => HelloSignatureEnvelope.Open(modified, key), "modified challenge/nonce/tag/ciphertext is rejected at offset " + index);
                }
                var invalid = envelope.ToArray(); invalid[0] ^= 1;
                reject(() => HelloSignatureEnvelope.Challenge(invalid), "unknown signature envelope magic is rejected");
                reject(() => HelloSignatureEnvelope.Challenge(envelope[..^1]), "truncated signature envelope is rejected");
                reject(() => HelloSignatureEnvelope.Open(envelope, RandomNumberGenerator.GetBytes(32)), "wrong wrapping key cannot decrypt credentials");
                var ownedKey = key.ToArray();
                var prepared = new PreparedHelloProtection(ownedKey, challenge);
                var fromPrepared = HelloSignatureEnvelope.Open(prepared.Protect(payload), key);
                try { check(fromPrepared.SequenceEqual(payload), "prepared envelope works without retaining a native signing session"); }
                finally { CryptographicOperations.ZeroMemory(fromPrepared); }
                prepared.Dispose();
                check(ownedKey.All(b => b == 0), "prepared wrapping key is zeroed on disposal");
                reject(() => prepared.Protect(payload), "disposed preparation cannot wrap credentials");
                reject(() => HelloSignatureEnvelope.Seal(new byte[79], key, challenge), "unexpected core payload length is rejected");
            }
            finally { CryptographicOperations.ZeroMemory(payload); }
            var badSignature = signature.ToArray(); badSignature[50] ^= 1;
            reject(() => HelloSignatureEnvelope.VerifyAndDerive(badSignature, challenge, publicKey), "modified signature cannot derive a wrapping key");
            var wrongChallenge = challenge.ToArray(); wrongChallenge[0] ^= 1;
            reject(() => HelloSignatureEnvelope.VerifyAndDerive(signature, wrongChallenge, publicKey), "signature for another challenge is rejected");
            using var another = RSA.Create(2048);
            reject(() => HelloSignatureEnvelope.VerifyAndDerive(signature, challenge, another.ExportParameters(false)), "signature from another system key is rejected");
            var pss = rsa.SignHash(HelloSignatureEnvelope.SignatureHash(challenge), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            reject(() => HelloSignatureEnvelope.VerifyAndDerive(pss, challenge, publicKey), "randomized PSS cannot silently replace deterministic PKCS1 signatures");
            reject(() => HelloSignatureEnvelope.VerifyAndDerive(signature, challenge, rsa.ExportParameters(true)), "signature verifier refuses private key parameters");
            HelloSignatureEnvelope.AssertSilentSigningDenied(unchecked((int)0x80090022));
            check(true, "only NTE_SILENT_CONTEXT proves that signing needs interaction");
            foreach (var code in new[] { 0, unchecked((int)0x80090027), unchecked((int)0x80090005), unchecked((int)0x80070005) })
            {
                HelloOperationException? error = null;
                try { HelloSignatureEnvelope.AssertSilentSigningDenied(code); } catch (HelloOperationException caught) { error = caught; }
                check(error?.Stage == HelloStage.SilentSignCheck && error.Code == (code == 0 ? unchecked((int)0xA0040003) : code), "silent success or unrelated failure never authorizes unlock: " + unchecked((uint)code).ToString("X8"));
            }
            const string password = "Public Signature Test Password 2026!";
            var store = new VaultStore(Path.Combine(root, "signed-device", "vault.db"));
            using var session = store.Create(password);
            var protectedPayload = session.ProtectForDevice(password, bytes => HelloSignatureEnvelope.Seal(bytes, key, challenge));
            var proof = HelloSignatureEnvelope.Open(protectedPayload, key);
            try
            {
                using var unlocked = store.UnlockDevicePayload(proof);
                check(unlocked.Snapshot().FormatVersion == 4, "signature envelope unlocks actual vault payload without database migration");
                session.ChangePassword(password, password + "changed");
                reject(() => store.UnlockDevicePayload(proof), "master password change invalidates signature-wrapped old credentials");
            }
            finally { CryptographicOperations.ZeroMemory(proof); }
            publicExportOnly.ExportFailure = new CryptographicException(unchecked((int)0x80090027));
            HelloOperationException? exportError = null;
            try { HelloPublicKeyProtector.ReadPublicKey(publicExportOnly); } catch (HelloOperationException error) { exportError = error; }
            check(exportError?.Stage == HelloStage.ExportPublicKey && exportError.Code == unchecked((int)0x80090027), "public export errors retain exact safe diagnostic stage and code");
        }
        finally { CryptographicOperations.ZeroMemory(signature); CryptographicOperations.ZeroMemory(key); }
    }
    private static bool Contains(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle) >= 0;
    private sealed class PublicExportOnlyKey(RSA key) : RSA
    {
        public int PublicExports { get; private set; }
        public int PrivateExports { get; private set; }
        public Exception? ExportFailure { get; set; }
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters) { PrivateExports++; throw new InvalidOperationException(); }
            PublicExports++;
            if (ExportFailure is not null) throw ExportFailure;
            return key.ExportParameters(false);
        }
        public override void ImportParameters(RSAParameters parameters) => throw new NotSupportedException();
        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => throw new NotSupportedException();
        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) => throw new NotSupportedException();
        public override byte[] SignHash(byte[] hash, HashAlgorithmName algorithm, RSASignaturePadding padding) => throw new NotSupportedException();
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName algorithm, RSASignaturePadding padding) => throw new NotSupportedException();
    }
}
