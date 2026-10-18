using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LocalVault.Core;

public sealed class VaultStore
{
    public const int MaxBytes = 64 * 1024 * 1024;
    public string FilePath { get; }
    public string BackupDirectory => Path.Combine(Path.GetDirectoryName(FilePath)!, "backups");
    public VaultStore(string path) { FilePath = Path.GetFullPath(path); }
    public string HeaderBinding() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Read().Header)));

    private static SqliteConnection Connect(string path, bool readOnly)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = path, Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate,
          Pooling = false }.ToString());
        connection.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = readOnly ? "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;" :
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;";
        cmd.ExecuteNonQuery();
        return connection;
    }

    internal (string Header, SealedBlob Blob, long Revision) Read()
    {
        if (!File.Exists(FilePath) || new FileInfo(FilePath).Length > MaxBytes * 2L)
            throw new InvalidDataException("保险库不存在或文件过大。");
        using var db = Connect(FilePath, true);
        using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT header,nonce,ciphertext,tag,revision FROM vault WHERE id=1";
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) throw new InvalidDataException("保险库缺少数据。");
        var header = reader.GetString(0);
        if (header.Length > 8192) throw new InvalidDataException("保险库头部过大。");
        return (header, new((byte[])reader[1], (byte[])reader[2], (byte[])reader[3]), reader.GetInt64(4));
    }

    public VaultSession Create(string password)
    {
        if (File.Exists(FilePath)) throw new IOException("本机已有保险库，请直接解锁。");
        VaultCrypto.CheckNewPassword(password);
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var dataKey = RandomNumberGenerator.GetBytes(32);
        var temporary = FilePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var header = VaultCrypto.Wrap(password, dataKey);
            var json = JsonSerializer.Serialize(header);
            var data = new VaultData { FormatVersion = 4 };
            var plain = VaultCrypto.EncodeData(data);
            SealedBlob blob;
            try { blob = VaultCrypto.Seal(plain, dataKey, Encoding.UTF8.GetBytes(json)); }
            finally { CryptographicOperations.ZeroMemory(plain); }
            using (var db = Connect(temporary, false))
            {
                using var cmd = db.CreateCommand();
                cmd.CommandText = "CREATE TABLE vault(id INTEGER PRIMARY KEY CHECK(id=1),header TEXT NOT NULL," +
                    "nonce BLOB NOT NULL,ciphertext BLOB NOT NULL,tag BLOB NOT NULL,revision INTEGER NOT NULL);" +
                    "INSERT INTO vault VALUES(1,$h,$n,$c,$t,0);";
                Parameters(cmd, json, blob);
                cmd.ExecuteNonQuery();
            }
            File.Move(temporary, FilePath, false);
            return new VaultSession(this, dataKey, header, data, 0);
        }
        catch { CryptographicOperations.ZeroMemory(dataKey); throw; }
        finally { File.Delete(temporary); }
    }

    public VaultSession Unlock(string password)
    {
        byte[]? key = null;
        try
        {
            var saved = Read();
            var header = JsonSerializer.Deserialize<VaultHeader>(saved.Header) ?? throw new InvalidDataException();
            key = VaultCrypto.Unwrap(password, header);
            var plain = VaultCrypto.Open(saved.Blob, key, Encoding.UTF8.GetBytes(saved.Header));
            VaultData data;
            try { data = JsonSerializer.Deserialize<VaultData>(plain) ?? throw new InvalidDataException(); }
            finally { CryptographicOperations.ZeroMemory(plain); }
            data.Validate();
            if (data.FormatVersion > header.Version) throw new InvalidDataException();
            return new VaultSession(this, key, header, data, saved.Revision);
        }
        catch (Exception e) when (e is CryptographicException or JsonException or InvalidDataException or NullReferenceException or FormatException)
        { if (key is not null) CryptographicOperations.ZeroMemory(key); throw new VaultAuthenticationException(); }
        catch { if (key is not null) CryptographicOperations.ZeroMemory(key); throw; }
    }

    public VaultSession UnlockDevicePayload(byte[] payload)
    {
        byte[]? key = null;
        try
        {
            var saved = Read();
            key = DeviceUnlockPayload.ExtractKey(payload, saved.Header);
            var header = JsonSerializer.Deserialize<VaultHeader>(saved.Header) ?? throw new InvalidDataException();
            if (header.Version is not (1 or 2 or 3 or 4)) throw new InvalidDataException();
            var plain = VaultCrypto.Open(saved.Blob, key, Encoding.UTF8.GetBytes(saved.Header));
            VaultData data;
            try { data = JsonSerializer.Deserialize<VaultData>(plain) ?? throw new InvalidDataException(); }
            finally { CryptographicOperations.ZeroMemory(plain); }
            data.Validate();
            if (data.FormatVersion > header.Version) throw new InvalidDataException();
            return new VaultSession(this, key, header, data, saved.Revision);
        }
        catch
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            throw new VaultAuthenticationException();
        }
    }

    internal long Write(string header, SealedBlob blob, long expectedRevision)
    {
        using var db = Connect(FilePath, false);
        using var tx = db.BeginTransaction();
        using var cmd = db.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "UPDATE vault SET header=$h,nonce=$n,ciphertext=$c,tag=$t,revision=revision+1 WHERE id=1 AND revision=$r";
        Parameters(cmd, header, blob);
        cmd.Parameters.AddWithValue("$r", expectedRevision);
        if (cmd.ExecuteNonQuery() != 1) throw new IOException("保险库已被其他进程修改，请锁定后重新打开。");
        tx.Commit();
        return expectedRevision + 1;
    }

    private static void Parameters(SqliteCommand cmd, string header, SealedBlob blob)
    {
        cmd.Parameters.AddWithValue("$h", header); cmd.Parameters.AddWithValue("$n", blob.Nonce);
        cmd.Parameters.AddWithValue("$c", blob.Ciphertext); cmd.Parameters.AddWithValue("$t", blob.Tag);
    }

    private static bool SamePath(string a, string b) => string.Equals(Path.GetFullPath(a), Path.GetFullPath(b),
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    public void Backup(string destination)
    {
        if (SamePath(destination, FilePath)) throw new IOException("备份位置不能是当前保险库。");
        var full = Path.GetFullPath(destination);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var temp = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var source = Connect(FilePath, true))
            using (var target = Connect(temp, false)) source.BackupDatabase(target);
            File.Move(temp, full, false); // Never silently overwrite an existing backup.
        }
        finally { File.Delete(temp); }
    }

    internal void PreserveBeforeUpgrade(Guid vaultId, long expectedRevision, int expectedVersion)
    {
        Directory.CreateDirectory(BackupDirectory);
        var backup = Path.Combine(BackupDirectory, $"before-upgrade-v0.5-{vaultId:N}-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.lvault");
        Backup(backup);
        try
        {
            var copied = new VaultStore(backup).Read();
            var previous = JsonSerializer.Deserialize<VaultHeader>(copied.Header);
            if (previous?.Version != expectedVersion || previous.VaultId != vaultId || copied.Revision != expectedRevision)
                throw new IOException("保险库已被其他会话修改，不能生成升级前快照。");
        }
        catch { File.Delete(backup); throw; }
    }

    public DateTimeOffset? LatestAutomaticBackupUtc(Guid vaultId)
    {
        if (!Directory.Exists(BackupDirectory)) return null;
        var files = Directory.EnumerateFiles(BackupDirectory, $"auto-????????-{vaultId:N}-*.lvault").ToList();
        return files.Count == 0 ? null : files.Max(f => new DateTimeOffset(File.GetLastWriteTimeUtc(f)));
    }

    internal void DailyBackup(Guid vaultId)
    {
        Directory.CreateDirectory(BackupDirectory);
        var date = DateTime.Now.ToString("yyyyMMdd");
        var prefix = $"auto-{date}-{vaultId:N}-";
        if (Directory.EnumerateFiles(BackupDirectory, prefix + "*.lvault").Any()) return;
        Backup(Path.Combine(BackupDirectory, prefix + Guid.NewGuid().ToString("N") + ".lvault"));
        foreach (var file in Directory.EnumerateFiles(BackupDirectory, "auto-*.lvault")
                     .OrderByDescending(Path.GetFileName).Skip(14)) File.Delete(file);
    }

    // Validate a private staging copy, so changing the source after validation cannot swap in unverified bytes.
    // UI must dispose any active session first; each backup keeps its own original master password.
    public void Restore(string source, string backupPassword)
    {
        if (SamePath(source, FilePath)) throw new IOException("不能把当前保险库作为恢复来源。");
        if (!File.Exists(source) || new FileInfo(source).Length > MaxBytes * 2L)
            throw new InvalidDataException("备份文件不存在或过大。");
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var temp = FilePath + ".restore-" + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.Copy(source, temp, false);
            using (var checkedSession = new VaultStore(temp).Unlock(backupPassword)) { }
            if (File.Exists(FilePath))
            {
                Directory.CreateDirectory(BackupDirectory);
                var before = Path.Combine(BackupDirectory, $"before-restore-{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.lvault");
                File.Replace(temp, FilePath, before);
            }
            else File.Move(temp, FilePath, false);
        }
        finally { File.Delete(temp); }
    }
}

public sealed class VaultSession : IDisposable
{
    private readonly VaultStore store;
    private readonly byte[] key;
    private VaultHeader header;
    private VaultData data;
    private long revision;
    private bool disposed;
    internal VaultSession(VaultStore store, byte[] key, VaultHeader header, VaultData data, long revision)
    { this.store = store; this.key = key; this.header = header; this.data = data; this.revision = revision; }
    public VaultData Snapshot() { ObjectDisposedException.ThrowIf(disposed, this); return data.Clone(); }
    public int IdleMinutes { get { ObjectDisposedException.ThrowIf(disposed, this); return data.IdleMinutes; } }
    public bool NeedsUpgrade { get { ObjectDisposedException.ThrowIf(disposed, this); return header.Version < 4; } }
    public DateTimeOffset? LatestAutomaticBackupUtc()
    { ObjectDisposedException.ThrowIf(disposed, this); return store.LatestAutomaticBackupUtc(header.VaultId); }
    public void Save(VaultData candidate)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var copy = candidate.Clone();
        copy.FormatVersion = 4;
        copy.ContentRevision = checked(data.ContentRevision + 1);
        // Receipt fields can only be changed by a completed export, never by arbitrary edits.
        copy.LastManualBackupUtc = data.LastManualBackupUtc;
        copy.LastManualBackupContentRevision = data.LastManualBackupContentRevision;
        copy.Validate();
        header = Persist(copy, header with { Version = 4 });
        data = copy;
    }
    private VaultHeader Persist(VaultData candidate, VaultHeader nextHeader)
    {
        var plain = VaultCrypto.EncodeData(candidate);
        try
        {
            if (plain.Length > VaultStore.MaxBytes) throw new InvalidDataException("保险库超过第一版的 64 MiB 内容限制。");
            var json = JsonSerializer.Serialize(nextHeader);
            var blob = VaultCrypto.Seal(plain, key, Encoding.UTF8.GetBytes(json));
            if (header.Version < 4) store.PreserveBeforeUpgrade(header.VaultId, revision, header.Version);
            store.DailyBackup(header.VaultId); // Any required backup failure aborts the mutation.
            revision = store.Write(json, blob, revision);
            return nextHeader;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public void VerifyPassword(string password)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        byte[]? other = null;
        try
        {
            other = VaultCrypto.Unwrap(password, header);
            if (!CryptographicOperations.FixedTimeEquals(key, other)) throw new VaultAuthenticationException();
        }
        catch (CryptographicException) { throw new VaultAuthenticationException(); }
        finally { if (other is not null) CryptographicOperations.ZeroMemory(other); }
    }

    // Only ciphertext leaves this API. The native protector must require a system gesture
    // when decrypting it. No password or raw data key is persisted in browser storage.
    public byte[] ProtectForDevice(string currentPassword, Func<byte[], byte[]> encrypt)
    {
        VerifyPassword(currentPassword);
        if (NeedsUpgrade) Save(Snapshot());
        var saved = store.Read();
        if (saved.Revision != revision || saved.Header != JsonSerializer.Serialize(header))
            throw new IOException("保险库已被其他会话修改。");
        var payload = DeviceUnlockPayload.Create(key, saved.Header);
        try { return encrypt(payload); }
        finally { CryptographicOperations.ZeroMemory(payload); }
    }
    public void ChangePassword(string currentPassword, string newPassword)
    {
        VerifyPassword(currentPassword);
        var next = VaultCrypto.Wrap(newPassword, key, header.VaultId);
        var candidate = data.Clone();
        candidate.FormatVersion = 4;
        candidate.ContentRevision = checked(data.ContentRevision + 1);
        header = Persist(candidate, next);
        data = candidate;
    }
    public BackupResult ExportBackup(string destination)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (store.Read().Revision != revision) throw new IOException("保险库已被其他进程修改。");
        store.Backup(destination);
        var exportedAt = DateTimeOffset.UtcNow;
        // The file already exists if receipt persistence fails. Do not report export failure
        // or falsely mark newer changes as covered. The caller gets this distinction explicitly.
        try
        {
            var candidate = data.Clone(); candidate.FormatVersion = 4;
            candidate.LastManualBackupUtc = exportedAt;
            candidate.LastManualBackupContentRevision = data.ContentRevision;
            header = Persist(candidate, header with { Version = 4 });
            data = candidate;
            return new(exportedAt, true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or SqliteException)
        { return new(exportedAt, false); }
    }
    public void UpsertQuickFillPreset(QuickFillPreset preset, long expectedContentRevision)
    {
        var candidate = Snapshot();
        if (expectedContentRevision != candidate.ContentRevision) throw new InvalidOperationException("内容已更新，请重新打开常用项。");
        preset.Validate();
        var copy = preset.Clone(); copy.UpdatedAt = DateTimeOffset.UtcNow;
        var existing = candidate.QuickFillPresets.FindIndex(p => p.Id == copy.Id);
        if (existing < 0) candidate.QuickFillPresets.Add(copy); else candidate.QuickFillPresets[existing] = copy;
        Save(candidate);
    }
    public void DeleteQuickFillPreset(Guid id, long expectedContentRevision)
    {
        var candidate = Snapshot();
        if (expectedContentRevision != candidate.ContentRevision || candidate.QuickFillPresets.RemoveAll(p => p.Id == id) != 1)
            throw new InvalidOperationException("常用项已改变，请重新打开。");
        Save(candidate);
    }
    public void ToggleFavorite(Guid id)
    {
        var candidate = Snapshot(); var entry = candidate.Entries.Single(e => e.Id == id && e.DeletedAt is null);
        entry.IsFavorite = !entry.IsFavorite; Save(candidate);
    }
    public void MoveToTrash(Guid id, DateTimeOffset? now = null)
    {
        var candidate = Snapshot(); var entry = candidate.Entries.Single(e => e.Id == id && e.DeletedAt is null);
        entry.DeletedAt = now ?? DateTimeOffset.UtcNow; Save(candidate);
    }
    public void RestoreEntry(Guid id)
    {
        var candidate = Snapshot(); var entry = candidate.Entries.Single(e => e.Id == id && e.DeletedAt is not null);
        entry.DeletedAt = null; entry.UpdatedAt = DateTimeOffset.UtcNow; Save(candidate);
    }
    public void PermanentlyDelete(Guid id)
    {
        var candidate = Snapshot();
        if (candidate.Entries.RemoveAll(e => e.Id == id && e.DeletedAt is not null) != 1)
            throw new InvalidOperationException("仅能彻底删除回收站中的条目。");
        Save(candidate);
    }
    public int EmptyTrash()
    {
        var candidate = Snapshot(); var count = candidate.Entries.RemoveAll(e => e.DeletedAt is not null);
        if (count > 0) Save(candidate);
        return count;
    }
    public int PurgeExpiredTrash(DateTimeOffset now)
    {
        var candidate = Snapshot();
        if (candidate.TrashRetentionDays == 0) return 0;
        var cutoff = now.AddDays(-candidate.TrashRetentionDays);
        var count = candidate.Entries.RemoveAll(e => e.DeletedAt is not null && e.DeletedAt <= cutoff);
        if (count > 0) Save(candidate);
        return count;
    }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        CryptographicOperations.ZeroMemory(key);
        data = new VaultData(); // Managed strings cannot be guaranteed erased; see SECURITY.md.
    }
}

public sealed record BackupResult(DateTimeOffset ExportedAtUtc, bool StatusRecorded);
