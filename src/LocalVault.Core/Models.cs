using System.Text.Json;

namespace LocalVault.Core;

public static class Categories
{
    public static readonly string[] All = ["账号与密码", "大模型 API", "哈希与密钥", "其他敏感信息"];
    public static (string Name, bool Secret)[] Template(string category) => category switch
    {
        "账号与密码" => [("账号", false), ("密码", true), ("登录网址", false), ("手机号", false), ("邮箱", false)],
        "大模型 API" => [("服务商", false), ("项目名称", false), ("API Key", true), ("接口地址", false), ("用途", false), ("到期时间", false)],
        "哈希与密钥" => [("类型", false), ("内容", true), ("关联项目", false), ("用途", false), ("有效期", false)],
        _ => [("正文", true)]
    };
}

public sealed class VaultField
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public bool Secret { get; set; }
}

public sealed class VaultEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Category { get; set; } = Categories.All[0];
    public string Title { get; set; } = "";
    public string Tags { get; set; } = "";
    public string Notes { get; set; } = "";
    public bool IsFavorite { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<LoginMethod> LoginMethods { get; set; } = [];
    public List<VaultField> Fields { get; set; } = [];
    public VaultEntry Clone() => JsonSerializer.Deserialize<VaultEntry>(JsonSerializer.Serialize(this))!;
}

public sealed class VaultData
{
    // Missing properties in v0.1 JSON intentionally deserialize to format 1/defaults.
    public int FormatVersion { get; set; } = 1;
    public List<VaultEntry> Entries { get; set; } = [];
    public List<QuickFillPreset> QuickFillPresets { get; set; } = [];
    public int IdleMinutes { get; set; } = 5;
    public int TrashRetentionDays { get; set; } = 30;
    public long ContentRevision { get; set; }
    public DateTimeOffset? LastManualBackupUtc { get; set; }
    public long? LastManualBackupContentRevision { get; set; }
    public bool HasUnexportedChanges => LastManualBackupContentRevision != ContentRevision;
    public VaultData Clone() => JsonSerializer.Deserialize<VaultData>(JsonSerializer.Serialize(this))!;
    public void Validate()
    {
        if (FormatVersion is < 1 or > 4 || ContentRevision < 0 ||
            TrashRetentionDays is not (0 or 30 or 90) ||
            LastManualBackupUtc.HasValue != LastManualBackupContentRevision.HasValue ||
            LastManualBackupContentRevision is < 0 || LastManualBackupContentRevision > ContentRevision ||
            Entries is null || Entries.Count > 100_000 || IdleMinutes is < 1 or > 60)
            throw new InvalidDataException("保险库内容格式无效。");
        if (QuickFillPresets is null || QuickFillPresets.Count > 100 ||
            (FormatVersion < 3 && QuickFillPresets.Count > 0)) throw new InvalidDataException("常用项格式无效。");
        var presetIds = new HashSet<Guid>();
        foreach (var preset in QuickFillPresets)
        {
            if (preset is null || !presetIds.Add(preset.Id)) throw new InvalidDataException("常用项标识无效。");
            preset.Validate();
        }
        var ids = new HashSet<Guid>();
        foreach (var entry in Entries)
        {
            if (entry is null || !ids.Add(entry.Id) || !Categories.All.Contains(entry.Category) ||
                string.IsNullOrWhiteSpace(entry.Title) || entry.Title.Length > 200 || entry.Fields is null ||
                entry.Fields.Count > 100 || entry.Notes is null || entry.Tags is null ||
                entry.Fields.Any(f => f is null || string.IsNullOrWhiteSpace(f.Name) || f.Value is null))
                throw new InvalidDataException("保险库条目格式无效。");
            if (entry.LoginMethods is null || entry.LoginMethods.Count > 12 ||
                (entry.LoginMethods.Count > 0 && (FormatVersion < 4 || entry.Category != Categories.All[0])))
                throw new InvalidDataException("登录方式格式无效。");
            var methodIds = new HashSet<Guid>();
            foreach (var method in entry.LoginMethods)
            {
                if (method is null || !methodIds.Add(method.Id)) throw new InvalidDataException("登录方式标识无效。");
                method.Validate(entry.Id);
            }
        }
        var byId = Entries.ToDictionary(e => e.Id);
        foreach (var method in Entries.SelectMany(e => e.LoginMethods))
            if (method.LinkedEntryId is Guid target && byId.TryGetValue(target, out var linked) && linked.Category != Categories.All[0])
                throw new InvalidDataException("通行证必须关联账号类条目。");
    }
}

internal sealed record SealedBlob(byte[] Nonce, byte[] Ciphertext, byte[] Tag);
internal sealed record VaultHeader(int Version, Guid VaultId, string Kdf, int MemoryKiB,
    int Iterations, int Parallelism, byte[] Salt, SealedBlob WrappedKey);

public sealed class VaultAuthenticationException : Exception
{
    public VaultAuthenticationException() : base("主密码错误，或保险库已损坏、被修改。") { }
}
