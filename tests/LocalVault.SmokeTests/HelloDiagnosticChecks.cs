using System.Security.Cryptography;
using LocalVault.Desktop;

internal static class HelloDiagnosticChecks
{
    public static void Run(Action<bool,string> check)
    {
        check(HelloOperationException.IsUnsupportedProperty(unchecked((int)0x80090029)) && HelloOperationException.IsUnsupportedProperty(unchecked((int)0x80090011)), "unsupported KSP property may try equivalent legacy property name");
        check(HelloOperationException.IsUnsupportedProperty(unchecked((int)0x80090027)), "unknown KSP property parameter may try equivalent legacy name");
        check(!HelloOperationException.IsUnsupportedProperty(unchecked((int)0x80070005)), "access denied must not trigger compatibility retry");
        check(!HelloOperationException.IsUnsupportedProperty(unchecked((int)0x80090005)), "invalid cryptographic data must not trigger compatibility retry");
        var inner=new CryptographicException("SENSITIVE-TEST-PASSWORD api-secret C:\\private\\vault.db");
        var error=HelloOperationException.Capture(HelloStage.CreateKey,inner);
        check(!error.UserMessage().Contains("SENSITIVE")&&!error.UserMessage().Contains("api-secret")&&!error.UserMessage().Contains("private")&&error.InnerException is null,"Hello diagnostics never expose exception text, credentials or file paths");
        check(error.UserMessage().Contains("创建本应用的系统密钥")&&error.UserMessage().Contains($"0x{unchecked((uint)inner.HResult):X8}"),"Hello error reports exact safe stage and eight-digit native code");
        check(ReferenceEquals(error,HelloOperationException.Capture(HelloStage.Encrypt,error)),"outer operation preserves precise inner failing stage");
        check(new HelloOperationException(HelloStage.Decrypt,unchecked((int)0x80090036)).UserMessage().Contains("已取消"),"native user cancellation is distinguished from unsupported hardware");
        check(new HelloOperationException(HelloStage.SilentCheck,unchecked((int)0xA0040002)).UserMessage().Contains("检查是否禁止静默解密"),"silent-unlock rejection retains explicit application diagnostic");
        check(Enum.GetValues<HelloStage>().All(stage=>new HelloOperationException(stage,1).UserMessage().Contains("失败步骤：")),"every Hello stage has a user-visible diagnostic description");
    }
}
