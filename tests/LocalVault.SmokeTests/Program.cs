using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using LocalVault.Core;
using Microsoft.Data.Sqlite;

var root = Path.Combine(Path.GetTempPath(), "LocalVault-Tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
const string password = "Test-only Long Password 2026!";
const string nextPassword = "Changed Test-only Password 2026!";
int passed = 0;
void Check(bool value, string message)
{ if (!value) throw new Exception("FAIL: " + message); Console.WriteLine("PASS: " + message); passed++; }
void Reject(Action action, string message)
{
    bool rejected = false;
    try { action(); } catch { rejected = true; }
    Check(rejected, message);
}
void Sql(string path, string sql)
{
    using var db = new SqliteConnection($"Data Source={path};Pooling=False"); db.Open();
    using var cmd = db.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery();
}
try
{
    var store = new VaultStore(Path.Combine(root, "vault.db"));
    Reject(() => store.Create("short"), "short master password rejected");
    Check(!File.Exists(store.FilePath), "failed creation leaves no vault");
    using (var session = store.Create(password))
    {
        Check(session.Snapshot().Entries.Count == 0, "new vault initially empty");
        Reject(() => store.Create(password), "second account/vault creation cannot overwrite existing vault");
        var candidate = session.Snapshot();
        candidate.Entries.Add(new VaultEntry { Title = "TITLE-SENTINEL-秘密平台", Category = Categories.All[0],
            Notes = "NOTES-SENTINEL", Tags = "TAGS-SENTINEL", Fields = [
                new() { Name = "账号", Value = "USERNAME-SENTINEL" },
                new() { Name = "密码", Value = "PASSWORD-SENTINEL", Secret = true },
                new() { Name = "私钥", Value = "-----BEGIN PRIVATE KEY-----\nMULTILINE-SENTINEL\n-----END PRIVATE KEY-----", Secret = true }] });
        session.Save(candidate);
        Check(session.Snapshot().Entries[0].Fields[2].Value.Contains('\n'), "multiline secret preserved");
        candidate.Entries.Clear();
        Check(session.Snapshot().Entries.Count == 1, "save owns a separate snapshot");
        var invalid = session.Snapshot(); invalid.Entries.Add(invalid.Entries[0].Clone());
        Reject(() => session.Save(invalid), "duplicate IDs rejected without changing stored data");
        session.VerifyPassword(password);
        Reject(() => session.VerifyPassword("wrong password"), "reauthentication checks actual encryption key");
    }
    var raw = Encoding.UTF8.GetString(File.ReadAllBytes(store.FilePath));
    Check(!new[] { "TITLE-SENTINEL", "USERNAME-SENTINEL", "PASSWORD-SENTINEL", "NOTES-SENTINEL", "TAGS-SENTINEL", "MULTILINE-SENTINEL" }.Any(raw.Contains),
        "titles, accounts, passwords, notes, tags and private keys absent from SQLite plaintext");
    Reject(() => store.Unlock("wrong password"), "incorrect master password rejected");
    using (var session = store.Unlock(password))
        Check(session.Snapshot().Entries[0].Fields[1].Value == "PASSWORD-SENTINEL", "encrypted data survives close and reopen");
    var backup = Path.Combine(root, "export.lvault"); store.Backup(backup);
    Check(File.Exists(backup), "full encrypted backup exported");
    Reject(() => store.Backup(backup), "existing backup cannot be silently overwritten");
    Reject(() => store.Backup(store.FilePath), "export cannot overwrite active vault");
    var beforeFailedRestore = SHA256.HashData(File.ReadAllBytes(store.FilePath));
    Reject(() => store.Restore(backup, "wrong password"), "wrong backup password rejected");
    Check(beforeFailedRestore.SequenceEqual(SHA256.HashData(File.ReadAllBytes(store.FilePath))), "failed restore preserves current file byte for byte");
    using (var session = store.Unlock(password))
    {
        session.ChangePassword(password, nextPassword);
        session.VerifyPassword(nextPassword);
        Reject(() => session.VerifyPassword(password), "old master password rejected in changed session");
    }
    Reject(() => store.Unlock(password), "old master password cannot unlock changed vault");
    using (var changed = store.Unlock(nextPassword)) Check(changed.Snapshot().Entries.Count == 1, "password change retains data");
    using (var oldBackup = new VaultStore(backup).Unlock(password)) Check(oldBackup.Snapshot().Entries.Count == 1, "old backup retains original password");
    using (var left = store.Unlock(nextPassword))
    using (var right = store.Unlock(nextPassword))
    {
        var data = left.Snapshot(); data.IdleMinutes = 10; left.Save(data);
        Reject(() => right.Save(right.Snapshot()), "stale session cannot overwrite newer revision");
    }
    var freshMachine = new VaultStore(Path.Combine(root, "new-device", "vault.db"));
    freshMachine.Restore(backup, password);
    using (var restored = freshMachine.Unlock(password)) Check(restored.Snapshot().Entries.Count == 1, "backup restores in a clean directory without device keys");
    var corrupt = Path.Combine(root, "corrupt.lvault"); File.Copy(backup, corrupt);
    Sql(corrupt, "UPDATE vault SET tag=zeroblob(16) WHERE id=1");
    Reject(() => new VaultStore(corrupt).Unlock(password), "modified authentication tag rejected");
    Reject(() => freshMachine.Restore(corrupt, password), "tampered backup cannot replace vault");
    using (var valid = freshMachine.Unlock(password)) Check(valid.Snapshot().Entries.Count == 1, "rejected tampered restore keeps current data");
    var headerTamper = Path.Combine(root, "header-tamper.lvault"); File.Copy(backup, headerTamper);
    Sql(headerTamper, "UPDATE vault SET header=replace(header,'65536','65536000')");
    Reject(() => new VaultStore(headerTamper).Unlock(password), "unbounded KDF memory request rejected");
    var aadTamper = Path.Combine(root, "aad-tamper.lvault"); File.Copy(backup, aadTamper);
    using (var db = new SqliteConnection($"Data Source={aadTamper};Pooling=False"))
    {
        db.Open(); using var read = db.CreateCommand(); read.CommandText = "SELECT header FROM vault";
        var node = JsonNode.Parse((string)read.ExecuteScalar()!)!.AsObject(); node["Unused"] = "altered";
        using var write = db.CreateCommand(); write.CommandText = "UPDATE vault SET header=$h";
        write.Parameters.AddWithValue("$h", node.ToJsonString()); write.ExecuteNonQuery();
    }
    Reject(() => new VaultStore(aadTamper).Unlock(password), "entire stored header authenticated as payload AAD");
    store.Restore(backup, password);
    Check(Directory.EnumerateFiles(store.BackupDirectory, "before-restore-*.lvault").Any(), "successful restore preserves previous vault");
    using (var restored = store.Unlock(password)) Check(restored.Snapshot().Entries[0].Title.StartsWith("TITLE-SENTINEL"), "successful restore recovers expected content");
    var disposed = store.Unlock(password); disposed.Dispose();
    Reject(() => disposed.Snapshot(), "locked/disposed session cannot access data");
    Check(Directory.EnumerateFiles(root, "*.tmp", SearchOption.AllDirectories).Count() == 0, "temporary files cleaned after success and failure");
    UpgradeChecks.Run(root, Check, Reject);
    DeviceChecks.Run(root, Check, Reject);
    QuickFillChecks.Run(root, Check, Reject);
    HelloDiagnosticChecks.Run(Check);
    HelloSignatureChecks.Run(root, Check, Reject);
    ThirdPartyChecks.Run(root, Check, Reject);
    Console.WriteLine($"RESULT: {passed} checks passed.");
}
finally { SqliteConnection.ClearAllPools(); Directory.Delete(root, true); }
