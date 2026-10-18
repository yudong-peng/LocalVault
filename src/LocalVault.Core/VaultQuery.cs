namespace LocalVault.Core;

public enum VaultView { All, Favorites, Trash }
public enum EntrySort { UpdatedDescending, NameAscending, CategoryAscending }

public static class VaultQuery
{
    public static IReadOnlyList<string> ParseTags(string text) => text
        .Split([',', '，', ';', '；', '\n', '\r'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    public static IReadOnlyList<VaultEntry> Filter(VaultData data, VaultView view = VaultView.All,
        string? category = null, string? tag = null, string? search = null, EntrySort sort = EntrySort.UpdatedDescending)
    {
        var term = search?.Trim() ?? "";
        var entries = data.Entries.Where(e => view == VaultView.Trash ? e.DeletedAt is not null : e.DeletedAt is null)
            .Where(e => view != VaultView.Favorites || e.IsFavorite)
            .Where(e => category is null || e.Category == category)
            .Where(e => tag is null || ParseTags(e.Tags).Contains(tag, StringComparer.OrdinalIgnoreCase))
            .Where(e => term.Length == 0 || new[] { e.Title, e.Tags, e.Notes }
                .Concat(e.LoginMethods.SelectMany(m => new[] { m.DisplayName, m.Identity }))
                .Concat(e.Fields.Where(f => !f.Secret).SelectMany(f => new[] { f.Name, f.Value }))
                .Any(v => v.Contains(term, StringComparison.OrdinalIgnoreCase)));
        return (sort switch
        {
            EntrySort.NameAscending => entries.OrderBy(e => e.Title, StringComparer.CurrentCultureIgnoreCase).ThenBy(e => e.Id),
            EntrySort.CategoryAscending => entries.OrderBy(e => e.Category, StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(e => e.Title, StringComparer.CurrentCultureIgnoreCase).ThenBy(e => e.Id),
            _ => entries.OrderByDescending(e => view == VaultView.Trash ? e.DeletedAt : e.UpdatedAt).ThenBy(e => e.Id)
        }).ToList();
    }

    public static string Summary(VaultEntry entry)
    {
        var methods = entry.LoginMethods.Where(m => m.Kind != "password").Select(m => m.DisplayName).Distinct().ToArray();
        if (methods.Length > 0) return string.Join(" / ", methods);
        var summary = entry.Fields.FirstOrDefault(f => !f.Secret && !string.IsNullOrWhiteSpace(f.Value) &&
            f.Name is "账号" or "项目名称" or "服务商" or "用途");
        var value = summary?.Value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return string.IsNullOrEmpty(value) ? entry.Category : value.Length > 60 ? value[..60] + "…" : value;
    }
}
