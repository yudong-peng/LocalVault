using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using LocalVault.Core;
using Microsoft.Data.Sqlite;

internal static class UpgradeChecks
{
    public static void Run(string root, Action<bool, string> check, Action<Action, string> reject)
    {
        const string password = "Legacy Test Password 2026!";
        var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", "legacy-v010.fixture");
        var path = Path.Combine(root, "legacy", "vault.db"); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.Copy(fixture, path);
        var store = new VaultStore(path);
        var hash = SHA256.HashData(File.ReadAllBytes(path));
        reject(() => store.Unlock("wrong password"), "legacy wrong password cannot trigger migration");
        using (var session = store.Unlock(password))
        {
            var old = session.Snapshot(); var id = old.Entries.Single().Id;
            check(session.NeedsUpgrade && old.FormatVersion == 1, "original v0.1 fixture opens as legacy without migration");
            check(!old.Entries[0].IsFavorite && old.Entries[0].DeletedAt is null && old.TrashRetentionDays == 30,
                "legacy entries receive safe defaults for favorites, trash and retention");
            check(old.Entries[0].Fields[2].Value == "line1\nline2", "legacy multiline data preserved");
            check(hash.SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))) && !Directory.Exists(store.BackupDirectory),
                "read-only legacy unlock leaves original file unchanged");
            session.ToggleFavorite(id);
            check(!session.NeedsUpgrade && session.Snapshot().FormatVersion == 4, "first mutation upgrades reader capability and data format atomically");
            check(session.Snapshot().Entries[0].IsFavorite, "favorite change persists during migration");
            var before = Directory.EnumerateFiles(store.BackupDirectory, "before-upgrade-*.lvault").Single();
            using (var original = new VaultStore(before).Unlock(password))
                check(original.NeedsUpgrade && !original.Snapshot().Entries[0].IsFavorite, "upgrade backup retains original readable data and password");
            check(session.LatestAutomaticBackupUtc() is not null, "same-vault automatic snapshot time available");
            check(VaultQuery.Filter(session.Snapshot(), VaultView.Favorites).Count == 1, "favorites view includes starred active entry");
            check(VaultQuery.Filter(session.Snapshot(), tag: "学习").Count == 1 &&
                  VaultQuery.Filter(session.Snapshot(), tag: "学").Count == 0, "tag filter matches complete tags rather than substrings");
            check(VaultQuery.ParseTags(" 开发,开发，学习;API；api\n实习 ").SequenceEqual(new[] { "开发", "学习", "API", "实习" }),
                "Chinese and English tag separators, whitespace and duplicate case normalized");
            check(VaultQuery.Filter(session.Snapshot(), search: "LEGACY-SECRET-SENTINEL").Count == 0 &&
                  VaultQuery.Filter(session.Snapshot(), search: "legacy-example-user").Count == 1, "search excludes secret values and includes public account field");
            check(VaultQuery.Summary(new VaultEntry { Fields = [new() { Name = "账号", Value = "SHOULD-NOT-SHOW", Secret = true }] }) == Categories.All[0],
                "list summary never uses sensitive account field");
            session.MoveToTrash(id);
            check(VaultQuery.Filter(session.Snapshot()).Count == 0 && VaultQuery.Filter(session.Snapshot(), VaultView.Favorites).Count == 0 &&
                  VaultQuery.Filter(session.Snapshot(), VaultView.Trash).Count == 1, "trash excluded from active and favorites views");
            var raw = Encoding.UTF8.GetString(File.ReadAllBytes(path));
            check(!raw.Contains("Legacy account") && !raw.Contains("LEGACY-SECRET-SENTINEL") && !raw.Contains("IsFavorite") && !raw.Contains("DeletedAt"),
                "trash content, favorite flags and deletion timestamps remain encrypted");
            using (var reopened = store.Unlock(password))
                check(reopened.Snapshot().Entries[0].DeletedAt is not null, "trash survives close and reopen");
            session.RestoreEntry(id);
            check(session.Snapshot().Entries[0].IsFavorite && session.Snapshot().Entries[0].DeletedAt is null,
                "restoring a trashed entry retains favorite and fields");
            reject(() => session.PermanentlyDelete(id), "permanent deletion refuses active entries");
            var backup = Path.Combine(root, "new-format.lvault");
            var revision = session.Snapshot().ContentRevision;
            var result = session.ExportBackup(backup);
            check(result.StatusRecorded && !session.Snapshot().HasUnexportedChanges && session.Snapshot().ContentRevision == revision,
                "successful export records coverage without fabricating a content change");
            using (var reopened = store.Unlock(password))
                check(reopened.Snapshot().LastManualBackupUtc == result.ExportedAtUtc && !reopened.Snapshot().HasUnexportedChanges,
                    "manual backup receipt persists across restart");
            session.ToggleFavorite(id);
            check(session.Snapshot().HasUnexportedChanges, "changes after export are marked unexported");
            var receipt = session.Snapshot().LastManualBackupUtc;
            reject(() => session.ExportBackup(backup), "failed export cannot overwrite an existing file");
            check(session.Snapshot().LastManualBackupUtc == receipt && session.Snapshot().HasUnexportedChanges,
                "failed export does not falsify last backup time or coverage");
            var spoof = session.Snapshot(); spoof.LastManualBackupUtc = DateTimeOffset.UtcNow; spoof.LastManualBackupContentRevision = spoof.ContentRevision + 1;
            session.Save(spoof);
            check(session.Snapshot().LastManualBackupUtc == receipt && session.Snapshot().HasUnexportedChanges,
                "normal edits cannot spoof a successful backup receipt");
            session.MoveToTrash(id);
            var trashBackup = Path.Combine(root, "trash-snapshot.lvault"); session.ExportBackup(trashBackup);
            using (var backed = new VaultStore(trashBackup).Unlock(password))
                check(VaultQuery.Filter(backed.Snapshot(), VaultView.Trash).Count == 1, "full backup includes encrypted trash for recovery");
            session.PermanentlyDelete(id);
            check(session.Snapshot().Entries.Count == 0, "permanent deletion removes selected trash entry");
            check(Directory.EnumerateFiles(store.BackupDirectory, "before-upgrade-*.lvault").Count() == 1,
                "upgrade backup created once per successful format migration");
        }
        using (var db = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            db.Open(); using var cmd = db.CreateCommand(); cmd.CommandText = "SELECT header FROM vault";
            check(JsonNode.Parse((string)cmd.ExecuteScalar()!)!["Version"]!.GetValue<int>() == 4, "new header blocks reader v0.1 capability check");
        }
        var downgraded = Path.Combine(root, "downgraded.lvault"); File.Copy(path, downgraded);
        Sql(downgraded, "UPDATE vault SET header=replace(header,'\"Version\":4','\"Version\":1')");
        reject(() => new VaultStore(downgraded).Unlock(password), "downgrade of authenticated header is detected");

        // Fault injection: a SQLite trigger aborts the receipt write after a successful export.
        var receiptStore = new VaultStore(Path.Combine(root, "receipt-failure", "vault.db"));
        using (var session = receiptStore.Create(password))
        {
            Sql(receiptStore.FilePath, "CREATE TRIGGER deny_receipt BEFORE UPDATE ON vault BEGIN SELECT RAISE(ABORT,'test write failure'); END;");
            var exported = Path.Combine(root, "receipt-file-exists.lvault");
            var result = session.ExportBackup(exported);
            check(File.Exists(exported) && !result.StatusRecorded && session.Snapshot().LastManualBackupUtc is null,
                "successful export plus failed receipt write is reported truthfully");
        }

        var blocked = new VaultStore(Path.Combine(root, "blocked-upgrade", "vault.db"));
        Directory.CreateDirectory(Path.GetDirectoryName(blocked.FilePath)!); File.Copy(fixture, blocked.FilePath);
        File.WriteAllText(blocked.BackupDirectory, "block backup directory");
        var beforeBlocked = SHA256.HashData(File.ReadAllBytes(blocked.FilePath));
        using (var session = blocked.Unlock(password))
        {
            reject(() => session.ToggleFavorite(session.Snapshot().Entries[0].Id), "upgrade aborts if pre-upgrade backup cannot be created");
            check(session.NeedsUpgrade && !session.Snapshot().Entries[0].IsFavorite &&
                beforeBlocked.SequenceEqual(SHA256.HashData(File.ReadAllBytes(blocked.FilePath))), "failed migration leaves memory and file unchanged");
        }

        var concurrentLegacy = new VaultStore(Path.Combine(root, "concurrent-legacy", "vault.db"));
        Directory.CreateDirectory(Path.GetDirectoryName(concurrentLegacy.FilePath)!); File.Copy(fixture, concurrentLegacy.FilePath);
        using (var left = concurrentLegacy.Unlock(password))
        using (var right = concurrentLegacy.Unlock(password))
        {
            var id = left.Snapshot().Entries[0].Id; left.ToggleFavorite(id);
            reject(() => right.ToggleFavorite(id), "stale legacy session cannot migrate a newer file");
            var snapshots = Directory.EnumerateFiles(concurrentLegacy.BackupDirectory, "before-upgrade-*.lvault").ToList();
            using var preserved = new VaultStore(snapshots.Single()).Unlock(password);
            check(preserved.NeedsUpgrade, "concurrent migration cannot label v2 content as a legacy rollback snapshot");
        }

        var retentionStore = new VaultStore(Path.Combine(root, "retention", "vault.db"));
        using (var session = retentionStore.Create(password))
        {
            var now = new DateTimeOffset(2026, 10, 17, 14, 0, 0, TimeSpan.Zero);
            var data = session.Snapshot();
            var active = new VaultEntry { Title = "Active entry" };
            data.Entries = [active, new() { Title = "Expired", DeletedAt = now.AddDays(-30) },
                new() { Title = "Recent", DeletedAt = now.AddDays(-29) }, new() { Title = "Future clock", DeletedAt = now.AddDays(1) }];
            session.Save(data);
            check(session.PurgeExpiredTrash(now) == 1 && session.Snapshot().Entries.Count == 3,
                "retention removes only expired trash at the exact boundary");
            data = session.Snapshot(); data.TrashRetentionDays = 0; session.Save(data);
            check(session.PurgeExpiredTrash(now.AddYears(2)) == 0, "permanent retention disables automatic purge");
            check(session.EmptyTrash() == 2 && session.Snapshot().Entries.Single().Id == active.Id,
                "empty trash preserves all active entries");
            data = session.Snapshot(); data.TrashRetentionDays = 15;
            reject(() => session.Save(data), "unsupported retention settings rejected");
            var content = session.Snapshot(); content.Entries.Add(new() { Title = "Z item" }); content.Entries.Add(new() { Title = "B item", Category = Categories.All[1] });
            session.Save(content);
            check(VaultQuery.Filter(session.Snapshot(), sort: EntrySort.NameAscending).Select(e => e.Title)
                .SequenceEqual(new[] { "Active entry", "B item", "Z item" }), "name ordering uses stable entry data");
            check(VaultQuery.Filter(session.Snapshot(), category: Categories.All[1], search: "B item").Count == 1,
                "category and search filters combine correctly");
            var cleanHash = SHA256.HashData(File.ReadAllBytes(retentionStore.FilePath));
            check(session.PurgeExpiredTrash(now) == 0 && cleanHash.SequenceEqual(SHA256.HashData(File.ReadAllBytes(retentionStore.FilePath))),
                "no-op expiry does not rewrite vault or create false changes");
        }
    }
    private static void Sql(string path, string sql)
    {
        using var db = new SqliteConnection($"Data Source={path};Pooling=False"); db.Open();
        using var cmd = db.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery();
    }
}
