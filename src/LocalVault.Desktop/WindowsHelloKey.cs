using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Windows.Security.Credentials.UI;

namespace LocalVault.Desktop;

internal sealed record HelloRecord(int Version, string KeyName, string HeaderBinding, byte[] Ciphertext);

internal sealed partial class WindowsHelloKey
{
    private const string Provider = "Microsoft Passport Key Storage Provider";
    private const int SilentContext = unchecked((int)0x80090022);
    private readonly string recordPath;
    private readonly IntPtr owner;
    private static string KeyPrefix => (WindowsIdentity.GetCurrent().User?.Value ?? throw new CryptographicException()) + "//LocalVault/OfflineVault/";
    public WindowsHelloKey(string folder, IntPtr owner)
    { recordPath = Path.Combine(folder, "hello.json"); this.owner = owner; }
    public bool Enabled => File.Exists(recordPath);
    public static async Task<bool> IsAvailableAsync()
    {
        try { return await UserConsentVerifier.CheckAvailabilityAsync() == UserConsentVerifierAvailability.Available; }
        catch { return false; }
    }
    public string NewKeyName() => KeyPrefix + Guid.NewGuid().ToString("N");
    public void Create(string name)
    {
        CheckName(name);
        var openStatus = NCryptOpenStorageProvider(out var provider, Provider, 0);
        using (provider)
        {
            NativeCheck(openStatus, HelloStage.OpenProvider);
            var createStatus = NCryptCreatePersistedKey(provider, out var nativeKey, "RSA", name, 0, 0);
            using (nativeKey)
            {
                NativeCheck(createStatus, HelloStage.CreateKey);
                // Use flags=0 before finalization. CngKey creation's standard KeyUsage /
                // ExportPolicy setters add persistence flags not accepted by every KSP.
                NativeSet(nativeKey, "Length", BitConverter.GetBytes(2048), HelloStage.SetLength);
                NativeSet(nativeKey, "Key Usage", BitConverter.GetBytes((int)CngKeyUsages.Signing), HelloStage.SetUsage);
                var policy = BitConverter.GetBytes(1);
                var status = NCryptSetProperty(nativeKey, "NgcCacheType", policy, policy.Length, 0);
                if (HelloOperationException.IsUnsupportedProperty(status))
                    status = NCryptSetProperty(nativeKey, "NgcCacheTypeProperty", policy, policy.Length, 0);
                NativeCheck(status, HelloStage.SetCachePolicy);
                NativeSet(nativeKey, "HWND Handle", PointerBytes(owner), HelloStage.SetWindow);
                NativeSet(nativeKey, "Use Context", Encoding.Unicode.GetBytes("启用 LocalVault 快捷解锁\0"), HelloStage.SetWindow);
                NativeCheck(NCryptFinalizeKey(nativeKey, 0), HelloStage.FinalizeKey);
            }
        }
        // No assumption about defaults: reject exportable or non-mandatory keys.
        using var key = Open(name, CngKeyUsages.Signing);
    }
    public byte[] Decrypt(string name, byte[] ciphertext, int version) => version switch
    {
        1 => DecryptLegacy(name, ciphertext),
        2 => DecryptSignedEnvelope(name, ciphertext),
        _ => throw new CryptographicException()
    };
    private byte[] DecryptLegacy(string name, byte[] ciphertext)
    {
        if (ciphertext.Length != 256) throw new CryptographicException();
        using var key = Open(name);
        RequireFreshGesture(key);
        // A provider that decrypts silently is never accepted, even if Windows reports
        // that a biometric device exists. Do not fall back to DPAPI or weaker caching.
        AssertSilentDecryptionDenied(key, ciphertext);
        RequireFreshGesture(key);
        try
        {
            using var rsa = new RSACng(key);
            return rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        }
        catch (Exception error) { throw HelloOperationException.Capture(HelloStage.Decrypt, error); }
    }
    public void VerifyNoCachedUnlock(string name, byte[] ciphertext, int version)
    {
        if (version == 2)
        {
            var challenge = HelloSignatureEnvelope.Challenge(ciphertext);
            using var signingKey = Open(name, CngKeyUsages.Signing);
            RequireFreshGesture(signingKey); AssertSilentSigningDenied(signingKey, challenge); return;
        }
        if (version != 1) throw new CryptographicException();
        using var key = Open(name); RequireFreshGesture(key); AssertSilentDecryptionDenied(key, ciphertext);
    }
    private CngKey Open(string name, CngKeyUsages usage = CngKeyUsages.Decryption)
    {
        CheckName(name);
        CngKey key;
        try { key = CngKey.Open(name, new CngProvider(Provider)); }
        catch (Exception error) { throw HelloOperationException.Capture(HelloStage.OpenKey, error); }
        try
        {
            Validate(key, usage); NativeSet(key.Handle, "HWND Handle", PointerBytes(owner), HelloStage.SetWindow); return key;
        }
        catch { key.Dispose(); throw; }
    }
    private static void CheckName(string name)
    {
        if (!name.StartsWith(KeyPrefix, StringComparison.Ordinal) ||
            !Guid.TryParseExact(name[KeyPrefix.Length..], "N", out _)) throw new CryptographicException();
    }
    private static void Validate(CngKey key, CngKeyUsages usage)
    {
        try
        {
            byte[]? cache;
            try { cache = key.GetProperty("NgcCacheType", CngPropertyOptions.None).GetValue(); }
            catch (CryptographicException error) when (HelloOperationException.IsUnsupportedProperty(error.HResult))
            { cache = key.GetProperty("NgcCacheTypeProperty", CngPropertyOptions.None).GetValue(); }
            if (key.Provider?.Provider != Provider || key.AlgorithmGroup != CngAlgorithmGroup.Rsa ||
                key.ExportPolicy != CngExportPolicies.None || cache is not { Length: 4 } || BitConverter.ToInt32(cache) != 1 ||
                (key.KeyUsage & usage) != usage)
                throw new HelloOperationException(HelloStage.ReadPolicy, unchecked((int)0xA0040001));
        }
        catch (Exception error) { throw HelloOperationException.Capture(HelloStage.ReadPolicy, error); }
    }
    private void RequireFreshGesture(CngKey key)
    {
        NativeSet(key.Handle, "HWND Handle", PointerBytes(owner), HelloStage.SetWindow);
        NativeSet(key.Handle, "Use Context", Encoding.Unicode.GetBytes("解锁本地保险库\0"), HelloStage.RequireGesture);
        NativeSet(key.Handle, "PinCacheIsGestureRequired", BitConverter.GetBytes(1), HelloStage.RequireGesture);
    }
    private static byte[] PointerBytes(IntPtr value) => IntPtr.Size == 8 ? BitConverter.GetBytes(value.ToInt64()) : BitConverter.GetBytes(value.ToInt32());
    private static void NativeCheck(int status, HelloStage stage)
    { if (status != 0) throw new HelloOperationException(stage, status); }
    private static void NativeSet(SafeNCryptKeyHandle key, string name, byte[] bytes, HelloStage stage) =>
        NativeCheck(NCryptSetProperty(key, name, bytes, bytes.Length, 0), stage);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NCryptOpenStorageProvider(out SafeNCryptProviderHandle provider, string name, int flags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NCryptCreatePersistedKey(SafeNCryptProviderHandle provider, out SafeNCryptKeyHandle key,
        string algorithm, string name, int legacyKeySpec, int flags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NCryptSetProperty(SafeNCryptKeyHandle key, string name, byte[] value, int size, int flags);
    [DllImport("ncrypt.dll", ExactSpelling = true)]
    private static extern int NCryptFinalizeKey(SafeNCryptKeyHandle key, int flags);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct OaepInfo
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Algorithm;
        public IntPtr Label;
        public int LabelLength;
    }
    [DllImport("ncrypt.dll")]
    private static extern int NCryptDecrypt(SafeNCryptKeyHandle key, byte[] input, int inputLength,
        ref OaepInfo padding, byte[] output, int outputLength, out int resultLength, int flags);
    private static void AssertSilentDecryptionDenied(CngKey key, byte[] ciphertext)
    {
        var buffer = new byte[256];
        try
        {
            var padding = new OaepInfo { Algorithm = "SHA256" };
            var status = NCryptDecrypt(key.Handle, ciphertext, ciphertext.Length, ref padding,
                buffer, buffer.Length, out _, 0x4 | 0x40); // OAEP + NCRYPT_SILENT_FLAG
            if (status == 0) throw new HelloOperationException(HelloStage.SilentCheck, unchecked((int)0xA0040002));
            if (status != SilentContext) throw new HelloOperationException(HelloStage.SilentCheck, status);
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
    public HelloRecord Read()
    {
        if (new FileInfo(recordPath).Length > 8192) throw new CryptographicException();
        var record = JsonSerializer.Deserialize<HelloRecord>(File.ReadAllBytes(recordPath)) ?? throw new CryptographicException();
        if (record.HeaderBinding?.Length != 64 || record.Ciphertext is null) throw new CryptographicException();
        if (record.Version == 1) { if (record.Ciphertext.Length != 256) throw new CryptographicException(); }
        else if (record.Version == 2) { _ = HelloSignatureEnvelope.Challenge(record.Ciphertext); }
        else throw new CryptographicException();
        CheckName(record.KeyName); return record;
    }
    public void Write(HelloRecord record)
    {
        var temporary = recordPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(record)); File.Move(temporary, recordPath, true); }
        finally { File.Delete(temporary); }
    }
    public void DeleteKey(string name)
    {
        CheckName(name);
        if (!CngKey.Exists(name, new CngProvider(Provider))) return;
        using var key = CngKey.Open(name, new CngProvider(Provider)); key.Delete();
    }
    public void Disable()
    {
        if (Enabled)
        {
            HelloRecord record;
            try { record = Read(); }
            catch (Exception error) when (error is CryptographicException or JsonException or InvalidDataException or NullReferenceException or ArgumentException)
            {
                // A malformed record cannot identify an owned native key safely. Revoke
                // the unusable local shortcut without guessing or deleting other keys.
                File.Delete(recordPath); return;
            }
            DeleteKey(record.KeyName); File.Delete(recordPath);
        }
    }
}
