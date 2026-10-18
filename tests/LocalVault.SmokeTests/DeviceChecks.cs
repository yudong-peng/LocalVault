using System.Security.Cryptography;
using LocalVault.Core;

internal static class DeviceChecks
{
    public static void Run(string root, Action<bool, string> check, Action<Action, string> reject)
    {
        const string password = "Hello-test-only Password 2026!";
        var store = new VaultStore(Path.Combine(root, "hello-tests", "vault.db"));
        using var session = store.Create(password);
        var data = session.Snapshot(); data.Entries.Add(new VaultEntry { Title = "设备解锁测试", Fields = [new() { Name = "密码", Value = "DEVICE-SECRET", Secret = true }] }); session.Save(data);
        using var protector = RSA.Create(2048);
        byte[]? borrowed = null;
        reject(() => session.ProtectForDevice("wrong-password", p => { borrowed = p; return []; }), "device enrollment requires actual master password");
        check(borrowed is null, "failed enrollment never invokes protector");
        var ciphertext = session.ProtectForDevice(password, p => { borrowed = p; return protector.Encrypt(p, RSAEncryptionPadding.OaepSHA256); });
        check(borrowed!.All(b => b == 0), "enrollment clears temporary key envelope after callback");
        var payload = protector.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        try
        {
            using (var unlocked = store.UnlockDevicePayload(payload)) check(unlocked.Snapshot().Entries[0].Fields[0].Value == "DEVICE-SECRET", "protected device envelope unlocks full encrypted vault");
            reject(() => store.UnlockDevicePayload([]), "empty device payload rejected");
            reject(() => store.UnlockDevicePayload(payload[..^1]), "truncated device payload rejected");
            foreach (var offset in new[] { 0, 18, payload.Length - 1 })
            {
                var changed = (byte[])payload.Clone(); changed[offset] ^= 1;
                reject(() => store.UnlockDevicePayload(changed), $"tampered device envelope at {offset} rejected");
            }
            var otherStore = new VaultStore(Path.Combine(root, "hello-other", "vault.db"));
            using (otherStore.Create(password)) { }
            reject(() => otherStore.UnlockDevicePayload(payload), "device envelope cannot unlock another vault with same password");
            var edited = session.Snapshot(); edited.Entries[0].Title = "修改后"; session.Save(edited);
            using (var unlocked = store.UnlockDevicePayload(payload)) check(unlocked.Snapshot().Entries[0].Title == "修改后", "device enrollment survives ordinary data edits");
            var portable = Path.Combine(root, "hello-portable.lvault"); session.ExportBackup(portable);
            using (var unlocked = new VaultStore(portable).Unlock(password)) check(unlocked.Snapshot().Entries.Count == 1, "portable backup needs only master password, no native key");
            check(!Directory.EnumerateFiles(root, "hello.json", SearchOption.AllDirectories).Any(), "core never persists plaintext device key or native sidecar");
            session.ChangePassword(password, "Changed Hello-test Password 2026!");
            reject(() => store.UnlockDevicePayload(payload), "password rotation invalidates old protected header binding");
        }
        finally { CryptographicOperations.ZeroMemory(payload); }
        reject(() => session.ProtectForDevice("Changed Hello-test Password 2026!", p => { borrowed = p; throw new IOException(); }), "protector failure propagates without enrollment");
        check(borrowed!.All(b => b == 0), "failed protector also clears temporary key envelope");
        var disposed = store.Unlock("Changed Hello-test Password 2026!"); disposed.Dispose();
        reject(() => disposed.ProtectForDevice(password, _ => []), "disposed session cannot enroll a device");
        check(LocalUiPolicy.IsTrustedPage(LocalUiPolicy.Page), "only local entry page may send native commands");
        check(LocalUiPolicy.IsTrustedPage("https://LOCALVAULT.invalid:443/index.html"), "canonical local HTTPS host with default port accepted");
        foreach (var resource in new[] { "index.html", "app.js", "style.css", "app-icon.png" }) check(LocalUiPolicy.IsLocalResource(LocalUiPolicy.Origin + "/" + resource), "local resource allowed: " + resource);
        foreach (var address in new[] { "https://localvault.invalid.evil/index.html", "https://evil.localvault.invalid/index.html", "http://localvault.invalid/index.html", "https://localvault.invalid:444/index.html", "https://user@localvault.invalid/index.html", "https://localvault.invalid/index.html?x=1", "https://localvault.invalid/index.html#secret", "file:///index.html", "data:text/html,example", "https://example.com/index.html", "https://localvault.invalid/vault.db", "https://localvault.invalid/app.js?x=1" })
            check(!LocalUiPolicy.IsLocalResource(address) && !LocalUiPolicy.IsTrustedPage(address), "untrusted navigation/resource blocked: " + address);
        check(!LocalUiPolicy.IsTrustedPage(LocalUiPolicy.Origin + "/app.js"), "static script cannot impersonate native entry page");
        check(!LocalUiPolicy.IsTrustedPage(null) && !LocalUiPolicy.IsLocalResource(null), "missing native message origin rejected");
    }
}
