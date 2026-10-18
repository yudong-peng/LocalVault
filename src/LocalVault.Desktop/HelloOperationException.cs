namespace LocalVault.Desktop;

internal enum HelloStage
{
    RemovePrevious, OpenProvider, CreateKey, SetLength, SetUsage, SetCachePolicy, SetWindow,
    FinalizeKey, OpenKey, ReadPolicy, Encrypt, RequireGesture, SilentCheck, Decrypt, ValidatePayload, SaveRecord,
    ExportPublicKey, SilentSignCheck, Sign, VerifySignature, DecryptEnvelope
}

// Deliberately carries no provider message, key name, path, password, ciphertext or stack trace.
internal sealed class HelloOperationException(HelloStage stage, int code) : Exception("Windows Hello 操作未完成。")
{
    public HelloStage Stage { get; } = stage;
    public int Code { get; } = code;
    public static bool IsUnsupportedProperty(int code) => unchecked((uint)code) is
        0x80090029 or 0x80090011 or 0x80090027 or 0x8009000A or 0x80070032 or 0x00000032;
    public static HelloOperationException Capture(HelloStage stage, Exception error) =>
        error as HelloOperationException ?? new(stage, error.HResult);
    public string UserMessage()
    {
        var step = Stage switch
        {
            HelloStage.RemovePrevious => "清理本应用旧快捷解锁记录",
            HelloStage.OpenProvider => "打开 Windows Hello 密钥提供程序",
            HelloStage.CreateKey => "创建本应用的系统密钥",
            HelloStage.SetLength => "设置密钥长度",
            HelloStage.SetUsage => "设置密钥用途",
            HelloStage.SetCachePolicy => "设置每次验证策略",
            HelloStage.SetWindow => "绑定系统验证窗口",
            HelloStage.FinalizeKey => "完成系统密钥创建",
            HelloStage.OpenKey => "打开系统密钥",
            HelloStage.ReadPolicy => "核对不可导出与每次验证策略",
            HelloStage.Encrypt => "封装设备解锁凭据",
            HelloStage.RequireGesture => "要求新的系统验证",
            HelloStage.SilentCheck => "检查是否禁止静默解密",
            HelloStage.Decrypt => "请求系统验证并解密",
            HelloStage.ExportPublicKey => "读取系统密钥的公钥",
            HelloStage.SilentSignCheck => "检查是否禁止静默签名",
            HelloStage.Sign => "请求系统验证并生成签名",
            HelloStage.VerifySignature => "核对系统签名",
            HelloStage.DecryptEnvelope => "解密本机快捷解锁凭据",
            HelloStage.ValidatePayload => "验证保险库与设备凭据匹配",
            _ => "保存本机快捷解锁记录"
        };
        var canceled = unchecked((uint)Code) is 0x80090036 or 0x800704C7 or 0x8010006E;
        var reason = canceled ? "系统验证已取消。" : "Windows Hello 操作未完成。";
        return $"{reason}\n失败步骤：{step}\n诊断码：0x{unchecked((uint)Code):X8}\n主密码仍可使用。若 Windows 登录选项中的 Hello 正常，请将这一步骤和诊断码提供给维护者；无需先重置 Windows Hello。";
    }
}
