using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using LocalVault.Core;
using Microsoft.Data.Sqlite;

internal static class QuickFillChecks
{
    public static void Run(string root, Action<bool, string> check, Action<Action, string> reject)
    {
        const string password = "Legacy v030 Test Password 2026!";
        var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", "legacy-v030.fixture");
        var path = Path.Combine(root,"quick-fill","vault.db"); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.Copy(fixture,path);
        var originalHash = SHA256.HashData(File.ReadAllBytes(path)); var store = new VaultStore(path);
        using var session = store.Unlock(password);
        check(session.NeedsUpgrade && session.Snapshot().FormatVersion == 2 && session.Snapshot().QuickFillPresets.Count == 0,
            "original v0.3 fixture opens with empty presets without migration");
        check(originalHash.SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))) && !Directory.Exists(store.BackupDirectory),
            "read-only v0.3 unlock preserves original file bytes");
        var phone = new QuickFillPreset { Label="PHONE-LABEL-SENTINEL", Kind=QuickFillKinds.Phone, Value="PHONE-VALUE-SENTINEL" };
        session.UpsertQuickFillPreset(phone,session.Snapshot().ContentRevision);
        check(!session.NeedsUpgrade && session.Snapshot().FormatVersion == 4 && session.Snapshot().Entries[0].IsFavorite,
            "first preset write upgrades to format 4 and preserves old entry metadata");
        var rollback = Directory.EnumerateFiles(store.BackupDirectory,"before-upgrade-v0.5-*.lvault").Single();
        using (var before = new VaultStore(rollback).Unlock(password)) check(before.NeedsUpgrade && before.Snapshot().QuickFillPresets.Count==0,
            "format-2 rollback snapshot is preserved before new feature write");
        var secret = new QuickFillPreset { Label="PASSWORD-LABEL-SENTINEL", Kind=QuickFillKinds.Password, Value="  PASSWORD-VALUE-SENTINEL \n" };
        session.UpsertQuickFillPreset(secret,session.Snapshot().ContentRevision);
        phone.Value="UNSAVED-MUTATION";
        check(session.Snapshot().QuickFillPresets.Single(p=>p.Id==phone.Id).Value=="PHONE-VALUE-SENTINEL", "presets own separate snapshots, not caller references");
        var freshSnapshot=session.Snapshot();freshSnapshot.QuickFillPresets.Clear();
        check(session.Snapshot().QuickFillPresets.Count==2,"caller cannot mutate stored presets through snapshots");
        using (var reopened = store.Unlock(password)) check(reopened.Snapshot().QuickFillPresets.Single(p=>p.Id==secret.Id).Value==secret.Value,
            "common passwords retain exact whitespace and newlines through encrypted reopen");
        var raw=Encoding.UTF8.GetString(File.ReadAllBytes(path));
        check(!new[]{"PHONE-LABEL-SENTINEL","PHONE-VALUE-SENTINEL","PASSWORD-LABEL-SENTINEL","PASSWORD-VALUE-SENTINEL"}.Any(raw.Contains),
            "all common labels and values are absent from database plaintext");
        using (var db=new SqliteConnection($"Data Source={path};Pooling=False"))
        { db.Open();using var command=db.CreateCommand();command.CommandText="SELECT header FROM vault";check(JsonNode.Parse((string)command.ExecuteScalar()!)!["Version"]!.GetValue<int>()==4,"format-4 header prevents old readers from silently dropping presets"); }
        var revision=session.Snapshot().ContentRevision;
        reject(()=>session.UpsertQuickFillPreset(new(){Label="stale",Value="old"},revision-1),"stale preset save rejected");
        reject(()=>session.DeleteQuickFillPreset(secret.Id,revision-1),"stale preset deletion rejected");
        reject(()=>session.UpsertQuickFillPreset(new(){Label="",Value="value"},revision),"blank preset label rejected");
        reject(()=>session.UpsertQuickFillPreset(new(){Label="name",Value=""},revision),"empty preset value rejected");
        reject(()=>session.UpsertQuickFillPreset(new(){Label="name",Value="value",Kind="unknown"},revision),"unsupported preset type rejected");
        reject(()=>session.UpsertQuickFillPreset(new(){Label="name",Value=new string('p',4097)},revision),"unbounded preset value rejected");
        var duplicate=session.Snapshot();duplicate.QuickFillPresets.Add(duplicate.QuickFillPresets[0].Clone());
        reject(()=>session.Save(duplicate),"duplicate preset IDs rejected without saving");
        var full=session.Snapshot();full.QuickFillPresets=Enumerable.Range(0,101).Select(i=>new QuickFillPreset{Label="Test "+i,Value="test"}).ToList();
        reject(()=>session.Save(full),"preset count over 100 rejected");
        check(session.Snapshot().ContentRevision==revision,"rejected preset mutations do not change revision");
        var backup=Path.Combine(root,"quick-portable.lvault");session.ExportBackup(backup);
        var other=new VaultStore(Path.Combine(root,"quick-other","vault.db"));other.Restore(backup,password);
        using(var restored=other.Unlock(password))check(restored.Snapshot().QuickFillPresets.Count==2&&restored.Snapshot().QuickFillPresets[1].Value==secret.Value,"portable backup preserves common presets without local files");
        var copied=session.Snapshot();var savedEntry=new VaultEntry {Title="Copied preset",Fields=[new(){Name="账号",Value=copied.QuickFillPresets[0].Value},new(){Name="密码",Secret=true,Value=copied.QuickFillPresets[1].Value}]};copied.Entries.Add(savedEntry);session.Save(copied);
        var changed=secret.Clone();changed.Value="CHANGED-PRESET";session.UpsertQuickFillPreset(changed,session.Snapshot().ContentRevision);
        check(session.Snapshot().Entries.Single(e=>e.Id==savedEntry.Id).Fields[1].Value==secret.Value,"updating a preset does not alter previously saved entries");
        session.DeleteQuickFillPreset(secret.Id,session.Snapshot().ContentRevision);
        check(session.Snapshot().QuickFillPresets.Count==1&&session.Snapshot().Entries.Single(e=>e.Id==savedEntry.Id).Fields[1].Value==secret.Value,"deleting a preset retains independent entry copies");
        session.ChangePassword(password,"Changed Quick-fill Password 2026!");
        using(var changedSession=store.Unlock("Changed Quick-fill Password 2026!")) check(changedSession.Snapshot().QuickFillPresets.Count==1,"master-password rotation retains encrypted common presets");
        // Preserve the format-3 file for a separate original-v0.3 reader rejection check.
        var probe=Environment.GetEnvironmentVariable("LOCALVAULT_FORMAT3_PROBE");if(!string.IsNullOrEmpty(probe))store.Backup(probe);
    }
}
