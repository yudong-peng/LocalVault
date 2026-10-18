namespace LocalVault.Core;

public sealed class LoginMethod
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Kind { get; set; } = "password";
    public string Provider { get; set; } = "";
    public string CustomProvider { get; set; } = "";
    public string Identity { get; set; } = "";
    public Guid? LinkedEntryId { get; set; }
    public static readonly string[] Providers = ["QQ", "微信", "Apple", "Google", "Microsoft", "GitHub", "支付宝", "其他"];
    public string DisplayName => Kind switch
    {
        "thirdParty" => (Provider == "其他" ? CustomProvider : Provider) + " 登录",
        "sms" => "手机验证码", "emailCode" => "邮箱验证码", _ => "账号密码"
    };
    public void Validate(Guid owner)
    {
        if (Id == Guid.Empty || Kind is not ("password" or "sms" or "emailCode" or "thirdParty") ||
            Provider is null || Provider.Length > 80 || CustomProvider is null || Identity is null || Identity.Length > 200 || CustomProvider.Length > 80 ||
            LinkedEntryId == Guid.Empty || LinkedEntryId == owner ||
            (Kind != "thirdParty" && LinkedEntryId is not null) ||
            (Kind == "thirdParty" && (!Providers.Contains(Provider) || (Provider == "其他" && string.IsNullOrWhiteSpace(CustomProvider)))))
            throw new InvalidDataException("登录方式格式无效。");
    }
}
