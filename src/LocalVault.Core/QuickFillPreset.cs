namespace LocalVault.Core;

public static class QuickFillKinds
{
    public const string Account = "account", Phone = "phone", Email = "email", Password = "password";
    public static readonly string[] All = [Account, Phone, Email, Password];
}

public sealed class QuickFillPreset
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Label { get; set; } = "";
    public string Kind { get; set; } = QuickFillKinds.Account;
    public string Value { get; set; } = "";
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public void Validate()
    {
        if (Id == Guid.Empty || string.IsNullOrWhiteSpace(Label) || Label.Length > 80 ||
            !QuickFillKinds.All.Contains(Kind) || string.IsNullOrEmpty(Value) || Value.Length > 4096)
            throw new InvalidDataException("常用项需要名称、有效类型和内容；名称最多 80 字符，内容最多 4096 字符。");
    }
    public QuickFillPreset Clone() => new() { Id = Id, Label = Label, Kind = Kind, Value = Value, UpdatedAt = UpdatedAt };
}
